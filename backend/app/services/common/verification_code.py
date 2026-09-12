import secrets
import string
from typing import Optional

from app.core.config import settings
from app.exceptions.http_exceptions import APIException
from app.services.common.redis import RedisClient


class VerificationCodeService:
    """Verification code service - using Redis storage"""

    def generate_code(self, length: int = 6) -> str:
        """Generate cryptographically secure random digit verification code"""
        return "".join(secrets.choice(string.digits) for _ in range(length))

    async def send_verification_code(
        self, redis: RedisClient, email: str, code: str
    ) -> None:
        """
        Store verification code in Redis

        Args:
            redis: Redis client instance
            email: Email address
            code: Verification code

        Raises:
            APIException: If within cooldown period
        """
        key = f"verification_code:{email}"
        cooldown_key = f"verification_cooldown:{email}"

        # Check cooldown period
        if await redis.check_cooldown(cooldown_key):
            raise APIException(
                status_code=400,
                message="Please wait 60 seconds before resending verification code",
            )

        # Store verification code (valid for 5 minutes)
        await redis.set_with_ttl(key, code, settings.VERIFICATION_CODE_EXPIRE_SECONDS)

        # Set cooldown period (60 seconds)
        await redis.set_cooldown(
            cooldown_key, settings.VERIFICATION_CODE_COOLDOWN_SECONDS
        )

    async def verify_code(self, redis: RedisClient, email: str, code: str) -> bool:
        """
        Verify verification code

        Args:
            redis: Redis client instance
            email: Email address
            code: User-entered verification code

        Returns:
            bool: Whether verification succeeded

        Raises:
            APIException: Verification code expired or incorrect
        """
        key = f"verification_code:{email}"
        stored_code = await redis.get(key)

        if not stored_code:
            raise APIException(
                status_code=400,
                message="Verification code has expired or does not exist",
            )

        if stored_code != code:
            raise APIException(
                status_code=400, message="Verification code is incorrect"
            )

        # Delete verification code after successful verification
        await redis.delete(key)
        return True


def get_verification_code_service() -> VerificationCodeService:
    """Get VerificationCodeService instance (dependency injection)"""
    return VerificationCodeService()
