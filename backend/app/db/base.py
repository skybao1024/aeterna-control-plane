from sqlalchemy.ext.asyncio import (AsyncSession, async_sessionmaker,
                                    create_async_engine)

from app.core.config import settings

from .models import Base

# Build database URL with optional SSL
SQLALCHEMY_DATABASE_URL = (
    f"postgresql+asyncpg://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}"
    f"@{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}"
)

# Add SSL requirement for production
if settings.POSTGRES_SSL_REQUIRE:
    SQLALCHEMY_DATABASE_URL += "?ssl=require"

# Lazy engine creation to avoid import issues during Alembic migrations
engine = None
AsyncSessionLocal = None


def get_engine():
    """Get or create the async database engine"""
    global engine
    if engine is None:
        engine = create_async_engine(
            SQLALCHEMY_DATABASE_URL,
            echo=settings.ENV == "development",  # Only log SQL in development
            future=True,
            pool_pre_ping=True,
            # Enhanced connection pool configuration for better stability
            pool_recycle=1800,  # Recycle connections within 30 minutes
            pool_timeout=30,  # Connection acquisition timeout
            max_overflow=10,  # Maximum connection overflow count
            pool_size=20,  # Connection pool size
        )
    return engine


def get_session_local():
    """Get or create the async session factory"""
    global AsyncSessionLocal
    if AsyncSessionLocal is None:
        AsyncSessionLocal = async_sessionmaker(
            bind=get_engine(), class_=AsyncSession, expire_on_commit=False
        )
    return AsyncSessionLocal


# Create a separate engine and session factory for scheduled tasks
# This ensures each scheduled task uses its own connection pool and event loop
def create_scheduler_engine():
    """Create independent database engine for scheduled tasks, ensuring no event loop sharing with main application"""
    return create_async_engine(
        SQLALCHEMY_DATABASE_URL,
        echo=settings.ENV == "development",  # Only log SQL in development
        future=True,
        pool_pre_ping=True,
        pool_recycle=1800,
        pool_timeout=30,
        max_overflow=5,
        pool_size=5,
    )


def create_scheduler_session_factory(engine):
    """Create independent session factory for scheduled tasks"""
    return async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)


async def close_db_engine():
    """Close database engine and connection pool"""
    if engine is not None:
        await engine.dispose()
