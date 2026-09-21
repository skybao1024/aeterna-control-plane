from datetime import UTC, datetime, timedelta
from typing import Dict, Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import AuthBase
from app.db.session import transaction
from app.exceptions.http_exceptions import APIException
from app.models.token import Token
from app.models.user import User
from app.services.common.email import EmailService, get_email_service
from app.services.common.redis import RedisClient
from app.services.common.verification_code import (
    VerificationCodeService, get_verification_code_service)


class ClientAuthService(AuthBase):
    """Client authentication service"""

    def __init__(
        self,
        verification_code_service: VerificationCodeService = None,
        email_service: EmailService = None,
    ):
        """Initialize ClientAuthService with dependencies"""
        self.verification_code_service = (
            verification_code_service or VerificationCodeService()
        )
        self.email_service = email_service or EmailService()

    # ==================== Email Registration ====================

    async def signup(
        self,
        db: AsyncSession,
        redis: RedisClient,
        email: str,
        password: str,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
    ) -> Dict:
        """
        Register new user (Step 1)
        Create unverified user and send verification code
        Handle existing unverified user scenario
        """
        async with transaction(db):
            # Check if email is already registered
            user_query = select(User).where(User.email == email)
            result = await db.execute(user_query)
            existing_user = result.scalar_one_or_none()

            if existing_user:
                # User exists but not verified - allow re-registration with new verification code
                if not existing_user.is_verified:
                    # Update password (user may have forgotten previous password)
                    existing_user.hashed_password = User.get_password_hash(password)
                    if first_name:
                        existing_user.first_name = first_name
                    if last_name:
                        existing_user.last_name = last_name
                    await db.flush()

                    code = self.verification_code_service.generate_code(
                        settings.VERIFICATION_CODE_LENGTH
                    )
                    await self.verification_code_service.send_verification_code(
                        redis, email, code
                    )

                    # Send verification email
                    await self.email_service.send_with_template(
                        to_emails=email,
                        template_name="auth/verification.html",
                        template_params={
                            "verification_code": code,
                            "app_name": settings.PROJECT_NAME,
                        },
                        subject=f"Your verification code: {code}",
                    )

                    return {
                        "email": email,
                        "message": "Verification code sent to your email",
                        "require_verification": True,
                    }

                # User exists and verified - cannot re-register
                raise APIException(
                    status_code=400, message="Email already registered, please login"
                )

            # Create new user (unverified status)
            hashed_password = User.get_password_hash(password)
            new_user = User(
                email=email,
                hashed_password=hashed_password,
                first_name=first_name,
                last_name=last_name,
                is_active=True,
                is_verified=False,  # Unverified status
            )
            db.add(new_user)
            await db.flush()

            code = self.verification_code_service.generate_code(
                settings.VERIFICATION_CODE_LENGTH
            )
            await self.verification_code_service.send_verification_code(
                redis, email, code
            )

            # Send verification email
            await self.email_service.send_with_template(
                to_emails=email,
                template_name="auth/verification.html",
                template_params={
                    "verification_code": code,
                    "app_name": settings.PROJECT_NAME,
                },
                subject=f"Your verification code: {code}",
            )

            return {
                "email": email,
                "message": "Verification code sent to your email",
            }

    async def verify_email(
        self, db: AsyncSession, redis: RedisClient, email: str, code: str
    ) -> Dict:
        """
        Verify email (Step 2)
        Mark user as verified after successful code verification and return token
        """
        async with transaction(db):
            # Check if user exists
            user_query = select(User).where(User.email == email)
            result = await db.execute(user_query)
            user = result.scalar_one_or_none()

            if not user:
                raise APIException(status_code=400, message="Email not registered")

            if user.is_verified:
                raise APIException(
                    status_code=400, message="Email already verified, please login"
                )

            # Verify verification code
            await self.verification_code_service.verify_code(redis, email, code)

            # Mark user as verified
            user.is_verified = True
            await db.flush()

            # Generate token (automatic login)
            access_token = AuthBase.create_access_token(
                str(user.id),
                scope="client",
                expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
            )
            refresh_token = AuthBase.create_refresh_token(str(user.id))

            # Store refresh token
            hashed_token = AuthBase.hash_token(refresh_token)
            token = Token(
                user_id=user.id,
                token=hashed_token,
                expires_at=datetime.now(UTC)
                + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
                is_active=True,
            )
            db.add(token)
            await db.flush()

            return {
                "message": "Email verified successfully",
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
                "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            }

    async def resend_verification(
        self, db: AsyncSession, redis: RedisClient, email: str
    ) -> Dict:
        """Resend verification code"""
        # Check if user exists and is unverified
        user_query = select(User).where(User.email == email)
        result = await db.execute(user_query)
        user = result.scalar_one_or_none()

        if not user:
            raise APIException(status_code=400, message="Email not registered")

        if user.is_verified:
            raise APIException(
                status_code=400, message="Email already verified, please login"
            )

        # Generate new verification code
        code = self.verification_code_service.generate_code(
            settings.VERIFICATION_CODE_LENGTH
        )
        await self.verification_code_service.send_verification_code(redis, email, code)

        # Send verification email
        await self.email_service.send_with_template(
            to_emails=email,
            template_name="auth/verification.html",
            template_params={
                "verification_code": code,
                "app_name": settings.PROJECT_NAME,
            },
            subject=f"Your verification code: {code}",
        )

        return {
            "message": "Verification code sent",
            "cooldown_seconds": settings.VERIFICATION_CODE_COOLDOWN_SECONDS,
        }

    # ==================== Email Password Login ====================

    async def authenticate_user(
        self, db: AsyncSession, email: str, password: str
    ) -> Optional[User]:
        """Authenticate user credentials"""
        user_query = select(User).where(User.email == email)
        result = await db.execute(user_query)
        user = result.scalar_one_or_none()

        if not user or not user.verify_password(password):
            return None
        return user

    async def login(self, db: AsyncSession, email: str, password: str) -> Dict:
        """User login"""
        async with transaction(db):
            user = await self.authenticate_user(db, email, password)
            if not user:
                raise APIException(status_code=400, message="Invalid email or password")

            if not user.is_verified:
                raise APIException(
                    status_code=400,
                    message="Please verify your email first",
                )

            if not user.is_active:
                raise APIException(status_code=400, message="Account has been disabled")

            # Mark old tokens as invalid
            stmt = (
                update(Token)
                .where((Token.user_id == user.id) & (Token.is_active == True))
                .values(is_active=False)
            )
            await db.execute(stmt)

            # Generate new token
            access_token = AuthBase.create_access_token(
                str(user.id),
                scope="client",
                expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
            )
            refresh_token = AuthBase.create_refresh_token(str(user.id))

            # Store refresh token
            hashed_token = AuthBase.hash_token(refresh_token)
            token = Token(
                user_id=user.id,
                token=hashed_token,
                expires_at=datetime.now(UTC)
                + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
                is_active=True,
            )
            db.add(token)
            await db.flush()

            # Update last active time
            user.last_active_at = datetime.now(UTC)

            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
                "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            }

    # ==================== Token Refresh and Logout ====================

    async def refresh_token(self, db: AsyncSession, refresh_token: str) -> Dict:
        """Refresh access token"""
        payload = AuthBase.verify_token(refresh_token, scope="refresh")
        if not payload:
            raise APIException(status_code=401, message="Invalid refresh token")

        user_id = int(payload.get("sub"))
        token_query = select(Token).where(
            (Token.user_id == user_id) & (Token.is_active == True)
        )
        result = await db.execute(token_query)
        token = result.scalar_one_or_none()

        if not token or not AuthBase.verify_token_hash(refresh_token, token.token):
            raise APIException(
                status_code=401, message="Invalid or expired refresh token"
            )

        token.last_used_at = datetime.now(UTC)
        await db.commit()

        access_token = AuthBase.create_access_token(
            user_id,
            scope="client",
            expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        )
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        }

    async def logout(self, db: AsyncSession, refresh_token: str) -> None:
        """User logout"""
        payload = AuthBase.verify_token(refresh_token, scope="refresh")
        if not payload:
            return  # Ignore invalid token

        user_id = int(payload.get("sub"))
        token_query = select(Token).where(
            (Token.user_id == user_id) & (Token.is_active == True)
        )
        result = await db.execute(token_query)
        token = result.scalar_one_or_none()

        if token:
            token.is_active = False
            await db.commit()

    # ==================== Password Reset ====================

    async def request_password_reset(
        self, db: AsyncSession, redis: RedisClient, email: str
    ) -> Dict:
        """Request password reset"""
        # Find user
        user_query = select(User).where(User.email == email)
        result = await db.execute(user_query)
        user = result.scalar_one_or_none()

        if not user:
            # Security: don't reveal if user exists
            return {
                "message": "If this email is registered, you will receive a password reset email"
            }

        # Check cooldown period
        cooldown_key = f"password_reset_cooldown:{email}"
        if await redis.check_cooldown(cooldown_key):
            raise APIException(
                status_code=400,
                message="Please wait 60 seconds before resending password reset email",
            )

        # Generate password reset token (JWT)
        reset_token = AuthBase.create_access_token(
            str(user.id),
            scope="password_reset",
            expires_delta=timedelta(
                minutes=settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES
            ),
        )

        # Generate reset link
        reset_url = settings.PASSWORD_RESET_URL_TEMPLATE.format(
            frontend_url=settings.FRONTEND_URL, token=reset_token
        )

        # Send email
        await self.email_service.send_with_template(
            to_emails=email,
            template_name="auth/password-reset.html",
            template_params={
                "first_name": user.first_name,
                "reset_url": reset_url,
                "app_name": settings.PROJECT_NAME,
            },
            subject="Reset your password",
        )

        # Set cooldown period
        await redis.set_cooldown(
            cooldown_key, settings.VERIFICATION_CODE_COOLDOWN_SECONDS
        )

        return {
            "message": "If this email is registered, you will receive a password reset email"
        }

    async def reset_password(
        self, db: AsyncSession, token: str, new_password: str
    ) -> Dict:
        """Reset password"""
        async with transaction(db):
            # Verify token
            payload = AuthBase.verify_token(token, scope="password_reset")
            if not payload:
                raise APIException(
                    status_code=400, message="Password reset link is invalid or expired"
                )

            user_id = payload.get("sub")

            # Find user
            user_query = select(User).where(User.id == int(user_id))
            result = await db.execute(user_query)
            user = result.scalar_one_or_none()

            if not user:
                raise APIException(status_code=400, message="User does not exist")

            # Update password
            user.hashed_password = User.get_password_hash(new_password)

            # Mark all tokens as invalid (force re-login)
            stmt = (
                update(Token)
                .where((Token.user_id == user.id) & (Token.is_active == True))
                .values(is_active=False)
            )
            await db.execute(stmt)

            await db.flush()

            return {
                "message": "Password reset successful, please login with your new password"
            }


def get_client_auth_service() -> ClientAuthService:
    """Get ClientAuthService instance (dependency injection)"""
    verification_code_service = get_verification_code_service()
    email_service = get_email_service()
    return ClientAuthService(
        verification_code_service=verification_code_service,
        email_service=email_service,
    )
