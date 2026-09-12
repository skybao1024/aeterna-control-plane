from redis.asyncio import Redis

from app.core.config import settings


class RedisClient:
    def __init__(self):
        # Build Redis connection parameters
        redis_params = {
            "host": settings.REDIS_HOST,
            "port": settings.REDIS_PORT,
            "decode_responses": True,
        }

        # Only add password parameter when password is not empty
        if hasattr(settings, "REDIS_PASSWORD") and settings.REDIS_PASSWORD:
            redis_params["password"] = settings.REDIS_PASSWORD

        self.redis = Redis(**redis_params)

    async def set_with_ttl(self, key: str, value: str, ttl_seconds: int):
        """Set key-value pair with expiration time"""
        await self.redis.setex(key, ttl_seconds, value)

    async def get(self, key: str) -> str:
        """Get value"""
        return await self.redis.get(key)

    async def delete(self, key: str):
        """Delete key"""
        await self.redis.delete(key)

    async def set_cooldown(self, key: str, ttl_seconds: int):
        """Set cooldown time"""
        await self.redis.setex(key, ttl_seconds, "1")

    async def check_cooldown(self, key: str) -> bool:
        """Check if in cooldown"""
        return bool(await self.redis.exists(key))

    def pipeline(self, *args, **kwargs):
        """
        Compatible with native redis-py pipeline usage, forward directly to underlying redis instance.
        Note: If underlying uses redis.asyncio.Redis, returns async pipeline.
        """
        return self.redis.pipeline(*args, **kwargs)

    async def brpop(self, key, timeout=1):
        return await self.redis.brpop(key, timeout=timeout)

    async def close(self):
        """Close Redis connection"""
        await self.redis.close()


redis_client = RedisClient()
