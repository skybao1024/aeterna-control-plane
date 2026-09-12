from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import AuthBase
from app.db.session import get_db
from app.models.admin import Admin

http_bearer = HTTPBearer()


async def get_current_admin(
    credentials: HTTPAuthorizationCredentials = Depends(http_bearer),
    db: AsyncSession = Depends(get_db),
) -> Admin:
    token = credentials.credentials
    payload = AuthBase.verify_token(token, scope="backoffice")
    if not payload:
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    admin_id = payload.get("sub")
    admin_query = select(Admin).where(Admin.id == int(admin_id))
    result = await db.execute(admin_query)
    admin = result.scalar_one_or_none()
    if admin is None or not admin.is_active:
        raise HTTPException(status_code=403, detail="Inactive admin")
    return admin


# ==================== Service Layer Dependency Injection ====================

from app.services.backoffice.admin import AdminService, get_admin_service
from app.services.backoffice.auth import (BackofficeAuthService,
                                          get_backoffice_auth_service)

__all__ = [
    "get_current_admin",
    "get_admin_service",
    "AdminService",
    "get_backoffice_auth_service",
    "BackofficeAuthService",
]
