"""Purpose-bound inactivity-test operations through strict protocol v1 parsing."""

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
from app.schemas.client.aeterna_trigger_test import (
    TriggerTestRequest,
    TriggerTestResponse,
)
from app.services.client.aeterna_trigger_test import (
    AeternaTriggerTestService,
    get_aeterna_trigger_test_service,
)

router = APIRouter()
OPERATIONS = (
    "read",
    "create",
    "provision",
    "activate",
    "warning-challenge",
    "warning-verify",
    "activity",
    "stop",
    "retry",
    "recipient-challenge",
    "recipient-verify",
    "release-secret",
    "rotation-confirm",
)
ERRORS = {
    status: {"model": ProtocolErrorResponse}
    for status in (400, 401, 403, 404, 409, 410, 413, 415, 429, 503)
}


def operation_handler(operation: str):
    async def handle(
        request: Request,
        db: AsyncSession = Depends(get_db),
        service: AeternaTriggerTestService = Depends(get_aeterna_trigger_test_service),
    ):
        payload, document = await parse_protocol_body(request, TriggerTestRequest)
        if payload.signed.operation != f"trigger_test.{operation.replace('-', '_')}":
            raise AeternaProtocolException(
                400, "protocol.invalid_request", payload.signed.request_id
            )
        try:
            data = await service.operate(db, payload, document)
        except AeternaProtocolException:
            await db.rollback()
            raise
        except SQLAlchemyError:
            await db.rollback()
            raise AeternaProtocolException(
                503, "service.temporarily_unavailable", payload.signed.request_id
            ) from None
        return protocol_response(payload.signed.request_id, data, no_store=True)

    handle.__name__ = f"trigger_test_{operation.replace('-', '_')}"
    return handle


for name in OPERATIONS:
    router.add_api_route(
        f"/trigger-tests/{name}",
        operation_handler(name),
        methods=["POST"],
        response_model=TriggerTestResponse,
        responses=ERRORS,
        openapi_extra=openapi_request(TriggerTestRequest),
        summary=f"{name.replace('-', ' ').title()} an isolated inactivity test",
    )
