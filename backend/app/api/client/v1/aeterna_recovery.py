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
from app.schemas.client.aeterna_recipient_recovery import (
    RecipientRecoveryAbandonRequest,
    RecipientRecoveryAbandonResponse,
    RecipientRecoveryClaimResponse,
    RecipientRecoveryConfirmRequest,
    RecipientRecoveryPrepareRequest,
    RecipientRecoveryProvisionRequest,
    RecipientRecoveryProvisionResponse,
    RecipientRecoveryResponse,
    RecipientRecoverySecretRequest,
    RecipientRecoverySecretResponse,
    RecoveryCustodyChallengeRequest,
    RecoveryCustodyChallengeResponse,
    RecoveryCustodyVerifyRequest,
    RecoveryCustodyVerifyResponse,
)
from app.schemas.client.aeterna_recovery import (
    OwnerRecoveryActionRequest,
    OwnerRecoveryResponse,
    OwnerRecoverySecretResponse,
    OwnerRecoveryStartRequest,
    OwnerRecoveryVerifyRequest,
    RecoveryClaimStartRequest,
    RecoveryClaimStartResponse,
    RecoveryClaimVerifyRequest,
    RecoveryRecordActionRequest,
    RecoveryRecordEnrollRequest,
    RecoveryRecordProvisionRequest,
    RecoveryRecordProvisionResponse,
    RecoveryRecordResponse,
    RecoveryRotationConfirmRequest,
    RecoveryRotationProvisionRequest,
    RecoveryRotationProvisionResponse,
    RecoveryRotationResponse,
    RecoverySecretRequest,
)
from app.services.client.aeterna_recipient_recovery import (
    AeternaRecipientRecoveryService,
    get_aeterna_recipient_recovery_service,
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
    "/recovery/records/enroll",
    response_model=RecoveryRecordProvisionResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(RecoveryRecordEnrollRequest),
)
async def enroll_recovery_record(
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaRecoveryService = Depends(get_aeterna_recovery_service),
):
    payload, document = await parse_protocol_body(request, RecoveryRecordEnrollRequest)
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
    status_code=400,
    deprecated=True,
    response_model=ProtocolErrorResponse,
    response_description="Unsigned recovery is retired",
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(RecoveryClaimStartRequest),
)
async def start_recovery_claim(
    request: Request,
    service: AeternaRecoveryService = Depends(get_aeterna_recovery_service),
):
    payload, _document = await parse_protocol_body(request, RecoveryClaimStartRequest)
    service.reject_legacy_claim(payload.request_id)


@router.post(
    "/recovery/claim/verify",
    status_code=400,
    deprecated=True,
    response_model=ProtocolErrorResponse,
    response_description="Unsigned recovery is retired",
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(RecoveryClaimVerifyRequest),
)
async def verify_recovery_claim(
    request: Request,
    service: AeternaRecoveryService = Depends(get_aeterna_recovery_service),
):
    payload, _document = await parse_protocol_body(request, RecoveryClaimVerifyRequest)
    service.reject_legacy_claim(payload.request_id)


@router.post(
    "/recovery/{recovery_id}/release-secret",
    status_code=400,
    deprecated=True,
    response_model=ProtocolErrorResponse,
    response_description="Unsigned recovery is retired",
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(RecoverySecretRequest),
)
async def release_recovery_secret(
    recovery_id: str,
    request: Request,
    service: AeternaRecoveryService = Depends(get_aeterna_recovery_service),
):
    payload, _document = await parse_protocol_body(request, RecoverySecretRequest)
    service.reject_legacy_claim(payload.request_id)


@router.post(
    "/recovery/owner/start",
    response_model=OwnerRecoveryResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(OwnerRecoveryStartRequest),
)
async def start_owner_recovery(
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaRecoveryService = Depends(get_aeterna_recovery_service),
):
    payload, document = await parse_protocol_body(request, OwnerRecoveryStartRequest)
    data = await _database_call(
        db,
        payload.signed.request_id,
        service.start_owner_recovery(db, payload, document),
    )
    return protocol_response(payload.signed.request_id, data, no_store=True)


@router.post(
    "/recovery/owner/verify",
    response_model=OwnerRecoveryResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(OwnerRecoveryVerifyRequest),
)
async def verify_owner_recovery(
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaRecoveryService = Depends(get_aeterna_recovery_service),
):
    payload, _document = await parse_protocol_body(request, OwnerRecoveryVerifyRequest)
    data = await _database_call(
        db, payload.request_id, service.verify_owner_recovery(db, payload)
    )
    return protocol_response(payload.request_id, data, no_store=True)


@router.post(
    "/recovery/owner/{owner_recovery_id}/action",
    response_model=OwnerRecoveryResponse | OwnerRecoverySecretResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(OwnerRecoveryActionRequest),
)
async def act_on_owner_recovery(
    owner_recovery_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaRecoveryService = Depends(get_aeterna_recovery_service),
):
    payload, document = await parse_protocol_body(request, OwnerRecoveryActionRequest)
    if payload.signed.owner_recovery_id != owner_recovery_id:
        raise AeternaProtocolException(
            400, "protocol.invalid_request", payload.signed.request_id
        )
    data = await _database_call(
        db,
        payload.signed.request_id,
        service.act_on_owner_recovery(db, payload, document),
    )
    return protocol_response(payload.signed.request_id, data, no_store=True)


@router.post(
    "/recovery/rotations/provision",
    response_model=RecoveryRotationProvisionResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(RecoveryRotationProvisionRequest),
)
async def provision_recovery_rotation(
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaRecoveryService = Depends(get_aeterna_recovery_service),
):
    payload, document = await parse_protocol_body(
        request, RecoveryRotationProvisionRequest
    )
    data = await _database_call(
        db,
        payload.signed.request_id,
        service.provision_rotation(db, payload, document),
    )
    return protocol_response(payload.signed.request_id, data, no_store=True)


@router.post(
    "/recovery/rotations/{rotation_id}/confirm",
    response_model=RecoveryRotationResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(RecoveryRotationConfirmRequest),
)
async def confirm_recovery_rotation(
    rotation_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaRecoveryService = Depends(get_aeterna_recovery_service),
):
    payload, document = await parse_protocol_body(
        request, RecoveryRotationConfirmRequest
    )
    if payload.signed.rotation_id != rotation_id:
        raise AeternaProtocolException(
            400, "protocol.invalid_request", payload.signed.request_id
        )
    data = await _database_call(
        db,
        payload.signed.request_id,
        service.confirm_rotation(db, payload, document),
    )
    return protocol_response(payload.signed.request_id, data)


@router.post(
    "/recovery/recipient/claim/start",
    response_model=RecoveryClaimStartResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(RecoveryClaimStartRequest),
)
async def start_recipient_recovery_claim(
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaRecoveryService = Depends(get_aeterna_recovery_service),
):
    payload, _document = await parse_protocol_body(request, RecoveryClaimStartRequest)
    data = await _database_call(
        db, payload.request_id, service.start_recipient_claim(db, payload)
    )
    return protocol_response(payload.request_id, data, no_store=True)


@router.post(
    "/recovery/recipient/claim/verify",
    response_model=RecipientRecoveryClaimResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(RecoveryClaimVerifyRequest),
)
async def verify_recipient_recovery_claim(
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaRecoveryService = Depends(get_aeterna_recovery_service),
):
    payload, _document = await parse_protocol_body(request, RecoveryClaimVerifyRequest)
    data = await _database_call(
        db, payload.request_id, service.verify_recipient_claim(db, payload)
    )
    return protocol_response(payload.request_id, data, no_store=True)


@router.post(
    "/recovery/recipient/secret",
    response_model=RecipientRecoverySecretResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(RecipientRecoverySecretRequest),
)
async def release_recipient_recovery_secret(
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaRecipientRecoveryService = Depends(
        get_aeterna_recipient_recovery_service
    ),
):
    payload, document = await parse_protocol_body(
        request, RecipientRecoverySecretRequest
    )
    data = await _database_call(
        db, payload.signed.request_id, service.release_secret(db, payload, document)
    )
    return protocol_response(payload.signed.request_id, data, no_store=True)


@router.post(
    "/recovery/recipient/rotations/{rotation_id}/provision",
    response_model=RecipientRecoveryProvisionResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(RecipientRecoveryProvisionRequest),
)
async def provision_recipient_recovery_rotation(
    rotation_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaRecipientRecoveryService = Depends(
        get_aeterna_recipient_recovery_service
    ),
):
    payload, document = await parse_protocol_body(
        request, RecipientRecoveryProvisionRequest
    )
    if payload.signed.rotation_id != rotation_id:
        raise AeternaProtocolException(
            400, "protocol.invalid_request", payload.signed.request_id
        )
    data = await _database_call(
        db, payload.signed.request_id, service.provision(db, payload, document)
    )
    return protocol_response(payload.signed.request_id, data, no_store=True)


@router.post(
    "/recovery/recipient/rotations/{rotation_id}/prepare",
    response_model=RecipientRecoveryResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(RecipientRecoveryPrepareRequest),
)
async def prepare_recipient_recovery_rotation(
    rotation_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaRecipientRecoveryService = Depends(
        get_aeterna_recipient_recovery_service
    ),
):
    payload, document = await parse_protocol_body(
        request, RecipientRecoveryPrepareRequest
    )
    if payload.signed.rotation_id != rotation_id:
        raise AeternaProtocolException(
            400, "protocol.invalid_request", payload.signed.request_id
        )
    data = await _database_call(
        db, payload.signed.request_id, service.prepare(db, payload, document)
    )
    return protocol_response(payload.signed.request_id, data, no_store=True)


@router.post(
    "/recovery/recipient/rotations/{rotation_id}/confirm",
    response_model=RecipientRecoveryResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(RecipientRecoveryConfirmRequest),
)
async def confirm_recipient_recovery_rotation(
    rotation_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaRecipientRecoveryService = Depends(
        get_aeterna_recipient_recovery_service
    ),
):
    payload, document = await parse_protocol_body(
        request, RecipientRecoveryConfirmRequest
    )
    if payload.signed.rotation_id != rotation_id:
        raise AeternaProtocolException(
            400, "protocol.invalid_request", payload.signed.request_id
        )
    data = await _database_call(
        db, payload.signed.request_id, service.confirm(db, payload, document)
    )
    return protocol_response(payload.signed.request_id, data, no_store=True)


@router.post(
    "/recovery/recipient/rotations/{rotation_id}/abandon",
    response_model=RecipientRecoveryAbandonResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(RecipientRecoveryAbandonRequest),
)
async def abandon_recipient_recovery_rotation(
    rotation_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaRecipientRecoveryService = Depends(
        get_aeterna_recipient_recovery_service
    ),
):
    payload, document = await parse_protocol_body(
        request, RecipientRecoveryAbandonRequest
    )
    if payload.signed.rotation_id != rotation_id:
        raise AeternaProtocolException(
            400, "protocol.invalid_request", payload.signed.request_id
        )
    data = await _database_call(
        db, payload.signed.request_id, service.abandon(db, payload, document)
    )
    return protocol_response(payload.signed.request_id, data, no_store=True)


@router.post(
    "/recovery/custody/challenge",
    response_model=RecoveryCustodyChallengeResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(RecoveryCustodyChallengeRequest),
)
async def challenge_recovery_custody(
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaRecipientRecoveryService = Depends(
        get_aeterna_recipient_recovery_service
    ),
):
    await service.custody_limiter.check(
        "ip", request.client.host if request.client else "unknown", None
    )
    payload, document = await parse_protocol_body(
        request, RecoveryCustodyChallengeRequest
    )
    data = await _database_call(
        db, payload.signed.request_id, service.challenge_custody(db, payload, document)
    )
    return protocol_response(payload.signed.request_id, data, no_store=True)


@router.post(
    "/recovery/custody/verify",
    response_model=RecoveryCustodyVerifyResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(RecoveryCustodyVerifyRequest),
)
async def verify_recovery_custody(
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaRecipientRecoveryService = Depends(
        get_aeterna_recipient_recovery_service
    ),
):
    await service.custody_limiter.check(
        "ip", request.client.host if request.client else "unknown", None
    )
    payload, document = await parse_protocol_body(request, RecoveryCustodyVerifyRequest)
    data = await _database_call(
        db, payload.signed.request_id, service.verify_custody(db, payload, document)
    )
    return protocol_response(payload.signed.request_id, data, no_store=True)
