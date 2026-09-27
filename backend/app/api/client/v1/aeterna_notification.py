"""Aeterna v1 contact consent and email notification endpoints."""

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
from app.schemas.client.aeterna_notification import (
    ContactActionRequest,
    ContactCreateRequest,
    ContactInvitationResponseRequest,
    ContactResponse,
    InvitationResponse,
    NotificationTemplateRequest,
    NotificationTemplateResponse,
)
from app.schemas.client.aeterna_protocol import ProtocolErrorResponse
from app.services.client.aeterna_notification import (
    AeternaNotificationService,
    get_aeterna_notification_service,
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


def _client_address(request: Request) -> str:
    return request.client.host if request.client is not None else "unavailable"


def _require_path_contact(contact_id: str, payload: ContactActionRequest) -> None:
    if payload.signed.contact_id != contact_id:
        raise AeternaProtocolException(
            400, "protocol.invalid_request", payload.signed.request_id
        )


@router.post(
    "/contacts",
    response_model=ContactResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(ContactCreateRequest),
)
async def create_contact(
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaNotificationService = Depends(get_aeterna_notification_service),
):
    payload, document = await parse_protocol_body(request, ContactCreateRequest)
    data = await _database_call(
        db,
        payload.signed.request_id,
        service.create_contact(db, payload, document, _client_address(request)),
    )
    return protocol_response(payload.signed.request_id, data)


@router.post(
    "/contacts/{contact_id}/invite",
    response_model=ContactResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(ContactActionRequest),
)
async def invite_contact(
    contact_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaNotificationService = Depends(get_aeterna_notification_service),
):
    payload, document = await parse_protocol_body(request, ContactActionRequest)
    _require_path_contact(contact_id, payload)
    data = await _database_call(
        db,
        payload.signed.request_id,
        service.invite_contact(db, payload, document, _client_address(request)),
    )
    return protocol_response(payload.signed.request_id, data)


@router.delete(
    "/contacts/{contact_id}",
    response_model=ContactResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(ContactActionRequest),
)
async def delete_contact(
    contact_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaNotificationService = Depends(get_aeterna_notification_service),
):
    payload, document = await parse_protocol_body(request, ContactActionRequest)
    _require_path_contact(contact_id, payload)
    data = await _database_call(
        db,
        payload.signed.request_id,
        service.delete_contact(db, payload, document),
    )
    return protocol_response(payload.signed.request_id, data)


@router.post(
    "/contacts/{contact_id}/status",
    response_model=ContactResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(ContactActionRequest),
)
async def contact_status(
    contact_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaNotificationService = Depends(get_aeterna_notification_service),
):
    payload, document = await parse_protocol_body(request, ContactActionRequest)
    _require_path_contact(contact_id, payload)
    data = await _database_call(
        db,
        payload.signed.request_id,
        service.contact_status(db, payload, document),
    )
    return protocol_response(payload.signed.request_id, data)


@router.post(
    "/notifications/test",
    response_model=ContactResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(ContactActionRequest),
)
async def queue_test_email(
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaNotificationService = Depends(get_aeterna_notification_service),
):
    payload, document = await parse_protocol_body(request, ContactActionRequest)
    data = await _database_call(
        db,
        payload.signed.request_id,
        service.queue_test_email(db, payload, document, _client_address(request)),
    )
    return protocol_response(payload.signed.request_id, data)


@router.put(
    "/notifications/template",
    response_model=NotificationTemplateResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(NotificationTemplateRequest),
)
async def update_notification_template(
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaNotificationService = Depends(get_aeterna_notification_service),
):
    payload, document = await parse_protocol_body(request, NotificationTemplateRequest)
    data = await _database_call(
        db,
        payload.signed.request_id,
        service.update_template(db, payload, document),
    )
    return protocol_response(payload.signed.request_id, data)


@router.post(
    "/contact-invitations/respond",
    response_model=InvitationResponse,
    responses=PROTOCOL_ERROR_RESPONSES,
    openapi_extra=openapi_request(ContactInvitationResponseRequest),
)
async def respond_to_contact_invitation(
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AeternaNotificationService = Depends(get_aeterna_notification_service),
):
    payload, document = await parse_protocol_body(
        request, ContactInvitationResponseRequest
    )
    data = await _database_call(
        db,
        payload.request_id,
        service.respond_to_invitation(db, payload, _client_address(request)),
    )
    return protocol_response(payload.request_id, data)
