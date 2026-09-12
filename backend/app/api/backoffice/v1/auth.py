from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.backoffice.deps import (BackofficeAuthService,
                                     get_backoffice_auth_service)
from app.db.session import get_db
from app.schemas.backoffice.auth import Login, Logout, RefreshToken, Token
from app.schemas.response import ApiResponse

router = APIRouter()


@router.post("/login", response_model=Token)
async def login(
    login_data: Login,
    db: AsyncSession = Depends(get_db),
    service: BackofficeAuthService = Depends(get_backoffice_auth_service),
):
    """Admin login"""
    result = await service.login(db, login_data.email, login_data.password)
    return ApiResponse.success(data=result)


@router.post("/refresh", response_model=Token)
async def refresh(
    request: RefreshToken,
    db: AsyncSession = Depends(get_db),
    service: BackofficeAuthService = Depends(get_backoffice_auth_service),
):
    """Refresh admin token"""
    result = await service.refresh_token(db, request.refresh_token)
    return ApiResponse.success(data=result)


@router.post("/logout")
async def logout(
    request: Logout,
    db: AsyncSession = Depends(get_db),
    service: BackofficeAuthService = Depends(get_backoffice_auth_service),
):
    """Admin logout"""
    await service.logout(db, request.refresh_token)
    return ApiResponse.success_without_data()
