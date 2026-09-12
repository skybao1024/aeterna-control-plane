from fastapi import APIRouter, Depends, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.client.deps import (ClientAuthService, get_client_auth_service,
                                 get_redis)
from app.db.session import get_db
from app.schemas.client.auth import (GoogleLogin, Login, Logout,
                                     MessageResponse, RefreshToken,
                                     RequestPasswordReset, ResendVerification,
                                     ResendVerificationResponse, ResetPassword,
                                     SignUp, SignUpResponse, Token,
                                     VerifyEmail, VerifyEmailResponse)
from app.schemas.response import ApiResponse
from app.services.common.redis import RedisClient

router = APIRouter()

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)


# ==================== Registration ====================


@router.post("/signup", response_model=SignUpResponse)
@limiter.limit("5/minute")  # SECURITY: Limit to 5 signups per minute
async def signup(
    request: Request,  # Required for rate limiting
    signup_data: SignUp,
    db: AsyncSession = Depends(get_db),
    redis: RedisClient = Depends(get_redis),
    service: ClientAuthService = Depends(get_client_auth_service),
):
    """
    Step 1: Create account and send verification code

    - Create unverified user account
    - Generate 4-digit verification code
    - Valid for 5 minutes, 60 seconds cooldown between sends
    - Send email to specified address
    """
    result = await service.signup(
        db=db,
        redis=redis,
        email=signup_data.email,
        password=signup_data.password,
        first_name=signup_data.first_name,
        last_name=signup_data.last_name,
    )
    return ApiResponse.success(data=result)


@router.post("/verify-email", response_model=VerifyEmailResponse)
@limiter.limit("10/minute")  # SECURITY: Limit to 10 verification attempts per minute
async def verify_email(
    request: Request,  # Required for rate limiting
    data: VerifyEmail,
    db: AsyncSession = Depends(get_db),
    redis: RedisClient = Depends(get_redis),
    service: ClientAuthService = Depends(get_client_auth_service),
):
    """
    Step 2: Verify email

    - Verify 4-digit code
    - Mark user as verified
    - Auto-login and return token
    """
    result = await service.verify_email(
        db=db,
        redis=redis,
        email=data.email,
        code=data.code,
    )
    return ApiResponse.success(data=result)


@router.post("/resend-verification", response_model=ResendVerificationResponse)
@limiter.limit("3/minute")  # SECURITY: Limit to 3 resend requests per minute
async def resend_verification(
    request: Request,  # Required for rate limiting
    data: ResendVerification,
    db: AsyncSession = Depends(get_db),
    redis: RedisClient = Depends(get_redis),
    service: ClientAuthService = Depends(get_client_auth_service),
):
    """
    Resend verification code

    - 60 seconds cooldown between sends
    - Code valid for 5 minutes
    """
    result = await service.resend_verification(
        db=db,
        redis=redis,
        email=data.email,
    )
    return ApiResponse.success(data=result)


# ==================== Login ====================


@router.post("/login", response_model=Token)
@limiter.limit("5/minute")  # SECURITY: Limit to 5 login attempts per minute
async def login(
    request: Request,  # Required for rate limiting
    login_data: Login,
    db: AsyncSession = Depends(get_db),
    service: ClientAuthService = Depends(get_client_auth_service),
):
    """
    Email and password login

    SECURITY: Rate limited to 5 attempts per minute to prevent brute-force attacks

    - Verify email and password
    - Return access_token and refresh_token
    """
    result = await service.login(db, login_data.email, login_data.password)
    return ApiResponse.success(data=result)


@router.post("/google-login", response_model=Token)
@limiter.limit("10/minute")  # SECURITY: Limit Google login attempts
async def google_login(
    request: Request,  # Required for rate limiting
    data: GoogleLogin,
    db: AsyncSession = Depends(get_db),
    service: ClientAuthService = Depends(get_client_auth_service),
):
    """
    Google SSO login

    - Verify Google ID Token
    - Create or update user account
    - Return access_token and refresh_token
    """
    result = await service.google_login(db, data.id_token)
    return ApiResponse.success(data=result)


@router.post("/refresh", response_model=Token)
async def refresh_token(
    request: RefreshToken,
    db: AsyncSession = Depends(get_db),
    service: ClientAuthService = Depends(get_client_auth_service),
):
    """
    Refresh access token

    - Verify refresh_token
    - Return new access_token
    """
    result = await service.refresh_token(db, request.refresh_token)
    return ApiResponse.success(data=result)


@router.post("/logout")
async def logout(
    request: Logout,
    db: AsyncSession = Depends(get_db),
    service: ClientAuthService = Depends(get_client_auth_service),
):
    """
    User logout

    - Mark refresh_token as invalid
    """
    await service.logout(db, request.refresh_token)
    return ApiResponse.success_without_data()


# ==================== Password Reset ====================


@router.post("/request-password-reset", response_model=MessageResponse)
@limiter.limit("3/minute")  # SECURITY: Limit to 3 password reset requests per minute
async def request_password_reset(
    request: Request,  # Required for rate limiting
    data: RequestPasswordReset,
    db: AsyncSession = Depends(get_db),
    redis: RedisClient = Depends(get_redis),
    service: ClientAuthService = Depends(get_client_auth_service),
):
    """
    Request password reset

    - Send password reset link to email
    - Link valid for 30 minutes
    - 60 seconds cooldown between sends
    """
    result = await service.request_password_reset(db, redis, data.email)
    return ApiResponse.success(data=result)


@router.post("/reset-password", response_model=MessageResponse)
@limiter.limit("5/minute")  # SECURITY: Limit to 5 password reset attempts per minute
async def reset_password(
    request: Request,  # Required for rate limiting
    data: ResetPassword,
    db: AsyncSession = Depends(get_db),
    service: ClientAuthService = Depends(get_client_auth_service),
):
    """
    Reset password

    - Verify reset token
    - Update password
    - Invalidate all tokens (force re-login)
    """
    result = await service.reset_password(db, data.token, data.new_password)
    return ApiResponse.success(data=result)
