"""Aeterna v1 delayed-recovery provisioning and claim endpoints."""

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
from app.schemas.client.aeterna_recovery import (
    RecoveryClaimStartRequest,
    RecoveryClaimStartResponse,
    RecoveryClaimVerifyRequest,
    RecoveryClaimVerifyResponse,
    RecoveryRecordActionRequest,
    RecoveryRecordProvisionRequest,
    RecoveryRecordProvisionResponse,
    RecoveryRecordResponse,
    RecoverySecretRequest,
    RecoverySecretResponse,
)
from app.services.client.aeterna_recovery import (
    AeternaRecoveryService,
    get_aeterna_recovery_service,
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
    "/recovery/records/provision",
    response_model=RecoveryRecordProvisionResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(RecoveryRecordProvisionRequest),
)
async def provision_recovery_record(
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaRecoveryService = Depends(get_aeterna_recovery_service),
):
    payload, document = await parse_protocol_body(
        request, RecoveryRecordProvisionRequest
    )
    data = await _database_call(
        db,
        payload.signed.request_id,
        service.provision_record(db, payload, document),
    )
    return protocol_response(payload.signed.request_id, data, no_store=True)


@router.post(
    "/recovery/records/{recovery_id}/confirm",
    response_model=RecoveryRecordResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(RecoveryRecordActionRequest),
)
async def confirm_recovery_record(
    recovery_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaRecoveryService = Depends(get_aeterna_recovery_service),
):
    payload, document = await parse_protocol_body(request, RecoveryRecordActionRequest)
    if (
        payload.signed.operation != "recovery_record.confirm"
        or payload.signed.recovery_id != recovery_id
    ):
        raise AeternaProtocolException(
            400, "protocol.invalid_request", payload.signed.request_id
        )
    data = await _database_call(
        db,
        payload.signed.request_id,
        service.act_on_record(db, payload, document),
    )
    return protocol_response(payload.signed.request_id, data)


@router.post(
    "/recovery/records/{recovery_id}/abandon",
    response_model=RecoveryRecordResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(RecoveryRecordActionRequest),
)
async def abandon_recovery_record(
    recovery_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaRecoveryService = Depends(get_aeterna_recovery_service),
):
    payload, document = await parse_protocol_body(request, RecoveryRecordActionRequest)
    if (
        payload.signed.operation != "recovery_record.abandon"
        or payload.signed.recovery_id != recovery_id
    ):
        raise AeternaProtocolException(
            400, "protocol.invalid_request", payload.signed.request_id
        )
    data = await _database_call(
        db,
        payload.signed.request_id,
        service.act_on_record(db, payload, document),
    )
    return protocol_response(payload.signed.request_id, data)


@router.post(
    "/recovery/claim/start",
    response_model=RecoveryClaimStartResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(RecoveryClaimStartRequest),
)
async def start_recovery_claim(
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaRecoveryService = Depends(get_aeterna_recovery_service),
):
    payload, _document = await parse_protocol_body(request, RecoveryClaimStartRequest)
    data = await _database_call(
        db, payload.request_id, service.start_claim(db, payload)
    )
    return protocol_response(payload.request_id, data, no_store=True)


@router.post(
    "/recovery/claim/verify",
    response_model=RecoveryClaimVerifyResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(RecoveryClaimVerifyRequest),
)
async def verify_recovery_claim(
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaRecoveryService = Depends(get_aeterna_recovery_service),
):
    payload, _document = await parse_protocol_body(request, RecoveryClaimVerifyRequest)
    data = await _database_call(
        db, payload.request_id, service.verify_claim(db, payload)
    )
    return protocol_response(payload.request_id, data, no_store=True)


@router.post(
    "/recovery/{recovery_id}/release-secret",
    response_model=RecoverySecretResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(RecoverySecretRequest),
)
async def release_recovery_secret(
    recovery_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaRecoveryService = Depends(get_aeterna_recovery_service),
):
    payload, _document = await parse_protocol_body(request, RecoverySecretRequest)
    if payload.recovery_id != recovery_id:
        raise AeternaProtocolException(
            400, "protocol.invalid_request", payload.request_id
        )
    data = await _database_call(
        db, payload.request_id, service.release_secret(db, payload)
    )
    return protocol_response(payload.request_id, data, no_store=True)
