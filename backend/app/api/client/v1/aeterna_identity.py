"""Public Aeterna account and device-binding protocol v1 endpoints."""

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
    AccountChallengeRequest,
    AccountChallengeResponse,
    AccountChallengeVerificationRequest,
    AccountChallengeVerificationResponse,
    DeviceBindingApprovalRequest,
    DeviceBindingCancellationRequest,
    DeviceBindingDelayedConfirmationRequest,
    DeviceBindingRequest,
    DeviceBindingResponse,
    DeviceBindingStatusRequest,
    DeviceBindingStatusResponse,
    ProtocolErrorResponse,
)
from app.services.client.aeterna_identity import (
    AeternaIdentityService,
    get_aeterna_identity_service,
)
from app.services.common.aeterna_notifier import (
    AeternaAccountNotifier,
    get_aeterna_account_notifier,
)

router = APIRouter()
T = TypeVar("T")
PROTOCOL_ERROR_RESPONSES = {
    status_code: {"model": ProtocolErrorResponse}
    for status_code in (400, 401, 403, 404, 409, 413, 415, 429, 503)
}


def _bearer_token(request: Request, request_id: str) -> str:
    value = request.headers.get("authorization", "")
    if not value.startswith("Bearer ") or value.count(" ") != 1:
        raise AeternaProtocolException(401, "auth.binding_grant_invalid", request_id)
    return value[7:]


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
    "/account-challenges",
    status_code=202,
    response_model=AccountChallengeResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(AccountChallengeRequest),
)
async def initiate_account_challenge(
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaIdentityService = Depends(get_aeterna_identity_service),
    notifier: AeternaAccountNotifier = Depends(get_aeterna_account_notifier),
):
    payload, document = await parse_protocol_body(request, AccountChallengeRequest)
    client_address = request.client.host if request.client is not None else "unknown"
    data = await _database_call(
        db,
        payload.request_id,
        service.initiate_challenge(db, payload, document, client_address, notifier),
    )
    return protocol_response(payload.request_id, data, 202)


@router.post(
    "/account-challenges/{challenge_id}/verify",
    response_model=AccountChallengeVerificationResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(AccountChallengeVerificationRequest),
)
async def verify_account_challenge(
    challenge_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaIdentityService = Depends(get_aeterna_identity_service),
):
    payload, _document = await parse_protocol_body(
        request, AccountChallengeVerificationRequest
    )
    if challenge_id != payload.challenge_id:
        raise AeternaProtocolException(
            400, "protocol.invalid_request", payload.request_id
        )
    data = await _database_call(
        db, payload.request_id, service.verify_challenge(db, payload)
    )
    return protocol_response(payload.request_id, data)


@router.post(
    "/device-bindings",
    status_code=201,
    response_model=DeviceBindingResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(DeviceBindingRequest),
)
async def request_device_binding(
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaIdentityService = Depends(get_aeterna_identity_service),
):
    payload, document = await parse_protocol_body(request, DeviceBindingRequest)
    bearer = _bearer_token(request, payload.signed.request_id)
    status_code, data = await _database_call(
        db,
        payload.signed.request_id,
        service.request_binding(db, payload, document, bearer),
    )
    return protocol_response(payload.signed.request_id, data, status_code)


@router.post(
    "/device-bindings/{binding_id}/approvals",
    response_model=DeviceBindingResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(DeviceBindingApprovalRequest),
)
async def approve_device_binding(
    binding_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaIdentityService = Depends(get_aeterna_identity_service),
    notifier: AeternaAccountNotifier = Depends(get_aeterna_account_notifier),
):
    payload, document = await parse_protocol_body(request, DeviceBindingApprovalRequest)
    if binding_id != payload.signed.binding_id:
        raise AeternaProtocolException(
            400, "protocol.invalid_request", payload.signed.request_id
        )
    status_code, data = await _database_call(
        db,
        payload.signed.request_id,
        service.approve_binding(db, payload, document, notifier),
    )
    return protocol_response(payload.signed.request_id, data, status_code)


@router.post(
    "/device-bindings/status",
    response_model=DeviceBindingStatusResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(DeviceBindingStatusRequest),
)
async def read_device_binding_status(
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaIdentityService = Depends(get_aeterna_identity_service),
):
    payload, document = await parse_protocol_body(request, DeviceBindingStatusRequest)
    data = await _database_call(
        db,
        payload.signed.request_id,
        service.read_binding_status(db, payload, document),
    )
    return protocol_response(payload.signed.request_id, data, no_store=True)


@router.post(
    "/device-bindings/{binding_id}/delayed-confirmations",
    response_model=DeviceBindingResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(DeviceBindingDelayedConfirmationRequest),
)
async def confirm_delayed_device_binding(
    binding_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaIdentityService = Depends(get_aeterna_identity_service),
    notifier: AeternaAccountNotifier = Depends(get_aeterna_account_notifier),
):
    payload, document = await parse_protocol_body(
        request, DeviceBindingDelayedConfirmationRequest
    )
    if binding_id != payload.signed.binding_id:
        raise AeternaProtocolException(
            400, "protocol.invalid_request", payload.signed.request_id
        )
    bearer = _bearer_token(request, payload.signed.request_id)
    status_code, data = await _database_call(
        db,
        payload.signed.request_id,
        service.confirm_delayed_binding(db, payload, document, bearer, notifier),
    )
    return protocol_response(payload.signed.request_id, data, status_code)


@router.post(
    "/device-bindings/{binding_id}/cancellations",
    response_model=DeviceBindingResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(DeviceBindingCancellationRequest),
)
async def cancel_device_binding(
    binding_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaIdentityService = Depends(get_aeterna_identity_service),
    notifier: AeternaAccountNotifier = Depends(get_aeterna_account_notifier),
):
    payload, document = await parse_protocol_body(
        request, DeviceBindingCancellationRequest
    )
    if binding_id != payload.signed.binding_id:
        raise AeternaProtocolException(
            400, "protocol.invalid_request", payload.signed.request_id
        )
    bearer = _bearer_token(request, payload.signed.request_id)
    status_code, data = await _database_call(
        db,
        payload.signed.request_id,
        service.cancel_binding(db, payload, document, bearer, notifier),
    )
    return protocol_response(payload.signed.request_id, data, status_code)
