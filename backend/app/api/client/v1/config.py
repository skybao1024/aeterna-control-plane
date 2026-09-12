from fastapi import APIRouter
from sqlalchemy import text

from app.common.release import RELEASE_CONFIG
from app.db.session import get_db
from app.schemas.response import ApiResponse
from app.services.common.redis import redis_client

router = APIRouter()


@router.get("/health")
async def health_check():
    """
    Health check endpoint
    Check application status, database connection and Redis connection
    """
    health_status = {
        "status": "healthy",
        "services": {"api": "up", "database": "unknown", "redis": "unknown"},
    }

    # Check database connection
    try:
        async for db in get_db():
            result = await db.execute(text("SELECT 1"))
            if result.scalar() == 1:
                health_status["services"]["database"] = "up"
            break
    except Exception:
        health_status["services"]["database"] = "down"
        health_status["status"] = "unhealthy"

    # Check Redis connection
    try:
        # Use Redis PING command to test connection
        await redis_client.redis.ping()
        health_status["services"]["redis"] = "up"
    except Exception:
        health_status["services"]["redis"] = "down"
        health_status["status"] = "unhealthy"

    # If any service is unhealthy, return 503 status code
    if health_status["status"] == "unhealthy":
        return ApiResponse.failed(
            message="Service unhealthy",
            body_code=503,
            http_code=503,
            data=health_status,
        )

    return ApiResponse.success(data=health_status)


@router.get("/release")
async def get_release_config():
    return ApiResponse.success(data=RELEASE_CONFIG)
