"""Signed post-release discovery; this endpoint returns no recovery capability."""

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
from app.schemas.client.aeterna_recovery_notice import (
    RecoveryNoticeRequest,
    RecoveryNoticeResendRequest,
    RecoveryNoticeResendResponse,
    RecoveryNoticeResponse,
)
from app.services.client.aeterna_recovery_notice import (
    AeternaRecoveryNoticeService,
    get_aeterna_recovery_notice_service,
)
from app.services.client.aeterna_recovery_notice_resend import (
    AeternaRecoveryNoticeResendService,
    get_aeterna_recovery_notice_resend_service,
)

router = APIRouter()


@router.post(
    "/recovery/notice/read",
    response_model=RecoveryNoticeResponse,
    responses={
        status: {"model": ProtocolErrorResponse}
        for status in (400, 401, 403, 404, 413, 415, 503)
    },
    openapi_extra=openapi_request(RecoveryNoticeRequest),
    summary="Read the current release notice on its bound computer",
    description=(
        "Verify the stored device signature. Active devices may read policy state; "
        "dormant devices may only read a RELEASED policy notice. Full recipient "
        "emails require supplied account-owned contact IDs and exact current "
        "release email events. This read grants no heartbeat, mailbox, recovery, "
        "or management authority and never returns content or recovery factors."
    ),
)
async def read_recovery_notice(
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaRecoveryNoticeService = Depends(
        get_aeterna_recovery_notice_service
    ),
):
    payload, document = await parse_protocol_body(request, RecoveryNoticeRequest)
    try:
        data = await service.read(db, payload, document)
    except AeternaProtocolException:
        await db.rollback()
        raise
    except SQLAlchemyError:
        await db.rollback()
        raise AeternaProtocolException(
            503, "service.temporarily_unavailable", payload.signed.request_id
        ) from None
    return protocol_response(payload.signed.request_id, data, no_store=True)


@router.post(
    "/recovery/notice/resend",
    response_model=RecoveryNoticeResendResponse,
    responses={
        status: {"model": ProtocolErrorResponse}
        for status in (400, 401, 403, 404, 409, 413, 415, 429, 503)
    },
    openapi_extra=openapi_request(RecoveryNoticeResendRequest),
    summary="Resend an existing target's latest post-release email",
    description=(
        "Verify the exact bound active or dormant device and current RELEASED "
        "policy. An existing unsuppressed account-owned contact receives one "
        "neutral invitation or a recovery entry for an available current grant "
        "on this authorizing device. No caller-controlled address, new contact, "
        "grant reactivation or recovery capability is returned. Atomic durable "
        "idempotency and target/account/device limits prevent duplicate sends."
    ),
)
async def resend_recovery_notice(
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaRecoveryNoticeResendService = Depends(
        get_aeterna_recovery_notice_resend_service
    ),
):
    payload, document = await parse_protocol_body(request, RecoveryNoticeResendRequest)
    try:
        data = await service.resend(db, payload, document)
    except AeternaProtocolException:
        await db.rollback()
        raise
    except SQLAlchemyError:
        await db.rollback()
        raise AeternaProtocolException(
            503, "service.temporarily_unavailable", payload.signed.request_id
        ) from None
    return protocol_response(payload.signed.request_id, data, no_store=True)
