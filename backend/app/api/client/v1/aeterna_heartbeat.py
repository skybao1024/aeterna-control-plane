"""Public Aeterna signed heartbeat and device-status protocol v1 endpoints."""

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
from app.schemas.client.aeterna_protocol import (
    DeviceStatusChangeRequest,
    DeviceStatusChangeResponse,
    HeartbeatRequest,
    HeartbeatResponse,
    ProtocolErrorResponse,
)
from app.services.client.aeterna_heartbeat import (
    AeternaHeartbeatService,
    get_aeterna_heartbeat_service,
)

router = APIRouter()
T = TypeVar("T")
PROTOCOL_ERROR_RESPONSES = {
    status_code: {"model": ProtocolErrorResponse}
    for status_code in (400, 401, 403, 404, 409, 413, 415, 429, 503)
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


@router.post(
    "/heartbeats",
    response_model=HeartbeatResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(HeartbeatRequest),
)
async def submit_heartbeat(
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaHeartbeatService = Depends(get_aeterna_heartbeat_service),
):
    payload, document = await parse_protocol_body(request, HeartbeatRequest)
    data = await _database_call(
        db,
        payload.signed.request_id,
        service.submit_heartbeat(db, payload, document),
    )
    return protocol_response(payload.signed.request_id, data)


@router.post(
    "/device-status-changes",
    response_model=DeviceStatusChangeResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(DeviceStatusChangeRequest),
)
async def change_device_status(
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaHeartbeatService = Depends(get_aeterna_heartbeat_service),
):
    payload, document = await parse_protocol_body(request, DeviceStatusChangeRequest)
    data = await _database_call(
        db,
        payload.signed.request_id,
        service.change_device_status(db, payload, document),
    )
    return protocol_response(payload.signed.request_id, data)
