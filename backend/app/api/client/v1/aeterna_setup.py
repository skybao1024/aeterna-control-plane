"""Signed Owner policy configuration and durable setup status."""

from collections.abc import Awaitable
from typing import TypeVar

from fastapi import APIRouter, Depends, Request
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.client.protocol import (
    openapi_request,
    parse_protocol_body,
    protocol_response,
)
from app.db.session import get_db
from app.exceptions.aeterna_protocol import AeternaProtocolException
from app.schemas.client.aeterna_protocol import ProtocolErrorResponse
from app.schemas.client.aeterna_setup import (
    PolicyConfigureRequest,
    PolicyConfigureResponse,
    SetupStatusRequest,
    SetupStatusResponse,
)
from app.services.client.aeterna_setup import (
    AeternaSetupService,
    get_aeterna_setup_service,
)

router = APIRouter()
T = TypeVar("T")
PROTOCOL_ERROR_RESPONSES = {
    status_code: {"model": ProtocolErrorResponse}
    for status_code in (400, 401, 403, 409, 413, 415, 503)
}


async def _database_call(
    db: AsyncSession, request_id: str, operation: Awaitable[T]
) -> T:
    try:
        return await operation
    except AeternaProtocolException:
        await db.rollback()
        raise
    except SQLAlchemyError:
        await db.rollback()
        raise AeternaProtocolException(
            503, "service.temporarily_unavailable", request_id
        ) from None


@router.put(
    "/policy",
    response_model=PolicyConfigureResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(PolicyConfigureRequest),
)
async def configure_policy(
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaSetupService = Depends(get_aeterna_setup_service),
):
    payload, document = await parse_protocol_body(request, PolicyConfigureRequest)
    data = await _database_call(
        db, payload.signed.request_id, service.configure_policy(db, payload, document)
    )
    return protocol_response(payload.signed.request_id, data, no_store=True)


@router.post(
    "/setup/status",
    response_model=SetupStatusResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(SetupStatusRequest),
)
async def setup_status(
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaSetupService = Depends(get_aeterna_setup_service),
):
    payload, document = await parse_protocol_body(request, SetupStatusRequest)
    data = await _database_call(
        db, payload.signed.request_id, service.status(db, payload, document)
    )
    return protocol_response(payload.signed.request_id, data, no_store=True)
