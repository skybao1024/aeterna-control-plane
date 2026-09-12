from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import AuthBase
from app.db.session import get_db
from app.models.user import User

http_bearer = HTTPBearer()
http_bearer_optional = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(http_bearer),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Get current authenticated user (required)"""
    token = credentials.credentials
    payload = AuthBase.verify_token(token, scope="client")
    if not payload:
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user_id = payload.get("sub")
    user_query = select(User).where(User.id == int(user_id))
    result = await db.execute(user_query)
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(
            status_code=401, detail="Invalid authentication credentials"
        )
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Inactive user")
    return user


# ==================== Redis Layer Dependency Injection ====================

from typing import AsyncGenerator

from app.services.common.redis import RedisClient


async def get_redis() -> AsyncGenerator[RedisClient, None]:
    """
    Redis client-side dependency injection, automatic lifecycle management

    Usage:
        @router.post("/endpoint")
        async def endpoint(redis: RedisClient = Depends(get_redis)):
            # Automatically manage Redis connection opening and closing
            await redis.set_with_ttl(...)
    """
    redis = RedisClient()
    try:
        yield redis
    finally:
        await redis.close()


# ==================== Service Layer Dependency Injection ====================

from app.services.client.auth import ClientAuthService, get_client_auth_service

__all__ = [
    "get_current_user",
    "get_redis",
    "get_client_auth_service",
    "ClientAuthService",
]
