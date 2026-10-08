"""Verify administrator refresh and logout against real PostgreSQL."""

import uuid

import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from app.core.security import AuthBase
from app.db.base import get_session_local
from app.exceptions.http_exceptions import APIException
from app.models.admin import Admin
from app.models.token import AdminToken
from app.schemas.backoffice.admin import AdminCreate
from app.services.backoffice.admin import get_admin_service
from app.services.backoffice.auth import get_backoffice_auth_service

pytestmark = pytest.mark.asyncio(loop_scope="session")
SYNTHETIC_PASSWORD = "synthetic-backoffice-test-password"


@pytest_asyncio.fixture(loop_scope="session")
async def admin_account():
    session_factory = get_session_local()
    email = f"backoffice-{uuid.uuid4().hex}@example.com"
    async with session_factory.begin() as db:
        await get_admin_service().create_admin(
            db,
            AdminCreate(email=email, password=SYNTHETIC_PASSWORD, is_active=True),
        )
        admin_id = await db.scalar(select(Admin.id).where(Admin.email == email))
    try:
        yield email, admin_id
    finally:
        async with session_factory.begin() as db:
            await db.execute(delete(AdminToken).where(AdminToken.admin_id == admin_id))
            await db.execute(delete(Admin).where(Admin.id == admin_id))


async def sign_in(email: str) -> dict:
    session_factory = get_session_local()
    async with session_factory() as db:
        return await get_backoffice_auth_service().login(db, email, SYNTHETIC_PASSWORD)


async def test_refresh_accepts_the_string_subject_issued_by_login(admin_account):
    email, admin_id = admin_account
    tokens = await sign_in(email)
    session_factory = get_session_local()
    async with session_factory() as db:
        response = await get_backoffice_auth_service().refresh_token(
            db, tokens["refresh_token"]
        )
    claims = AuthBase.verify_token(response["access_token"], scope="backoffice")
    assert claims["sub"] == str(admin_id)


async def test_logout_revokes_the_refresh_token_issued_by_login(admin_account):
    email, admin_id = admin_account
    tokens = await sign_in(email)
    session_factory = get_session_local()
    async with session_factory() as db:
        await get_backoffice_auth_service().logout(db, tokens["refresh_token"])
    async with session_factory() as db:
        token = await db.scalar(
            select(AdminToken).where(AdminToken.admin_id == admin_id)
        )
        assert token is not None and token.is_active is False
        with pytest.raises(APIException) as error:
            await get_backoffice_auth_service().refresh_token(
                db, tokens["refresh_token"]
            )
        assert error.value.status_code == 401


@pytest.mark.parametrize("subject", ["invalid-admin", "", "2147483648"])
async def test_invalid_subjects_do_not_query_or_revoke_admin_sessions(
    admin_account, subject
):
    email, admin_id = admin_account
    await sign_in(email)
    invalid_token = AuthBase.create_refresh_token(subject)
    session_factory = get_session_local()
    async with session_factory() as db:
        with pytest.raises(APIException) as error:
            await get_backoffice_auth_service().refresh_token(db, invalid_token)
        assert error.value.status_code == 401
    async with session_factory() as db:
        await get_backoffice_auth_service().logout(db, invalid_token)
    async with session_factory() as db:
        token = await db.scalar(
            select(AdminToken).where(AdminToken.admin_id == admin_id)
        )
        assert token is not None and token.is_active is True
