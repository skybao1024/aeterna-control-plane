from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession

from .base import get_session_local


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    AsyncSessionLocal = get_session_local()
    async with AsyncSessionLocal() as session:
        yield session


@asynccontextmanager
async def transaction(db: AsyncSession):
    """Transaction context manager with automatic commit or rollback"""
    try:
        yield db
        await db.commit()
    except Exception:
        await db.rollback()
        raise


@asynccontextmanager
async def async_session():
    """Create an async session context manager for scheduled tasks"""
    AsyncSessionLocal = get_session_local()
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
