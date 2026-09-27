"""Authenticated provider callback endpoints for Aeterna email delivery."""

from functools import lru_cache

from fastapi import APIRouter, Depends, Request
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import get_db
from app.exceptions.http_exceptions import APIException
from app.schemas.response import ApiResponse
from app.services.common.aeterna_aws_sns import (
    MAX_SNS_BODY_BYTES,
    AwsSnsMessageVerifier,
    AwsSnsUnavailableError,
    AwsSnsVerificationError,
)
from app.services.internal.aeterna_email_delivery import (
    AeternaEmailDeliveryService,
    DeliveryCallbackType,
    get_aeterna_email_callback_service,
)

router = APIRouter()


@lru_cache(maxsize=4)
def _verifier_for_topic(topic_arn: str) -> AwsSnsMessageVerifier:
    return AwsSnsMessageVerifier(topic_arn=topic_arn)


def get_aws_sns_message_verifier() -> AwsSnsMessageVerifier:
    """Build the verifier only for an explicitly enabled SES boundary."""

    if (
        settings.ENV != "production"
        or settings.AETERNA_EMAIL_PROVIDER != "aws-ses"
        or not settings.AWS_SES_SNS_TOPIC_ARN
    ):
        raise APIException(
            code=4103,
            message="Email callback service is unavailable",
            status_code=503,
        )
    try:
        return _verifier_for_topic(settings.AWS_SES_SNS_TOPIC_ARN)
    except ValueError:
        raise APIException(
            code=4103,
            message="Email callback service is unavailable",
            status_code=503,
        ) from None


@router.post("/aws-sns", include_in_schema=False)
async def receive_aws_sns_event(
    request: Request,
    db: AsyncSession = Depends(get_db),
    verifier: AwsSnsMessageVerifier = Depends(get_aws_sns_message_verifier),
    delivery: AeternaEmailDeliveryService = Depends(get_aeterna_email_callback_service),
):
    """Verify an SNS envelope before recording redacted SES transport state."""

    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip()
    if media_type not in {"text/plain", "application/json"}:
        raise APIException(
            code=4100,
            message="Unsupported callback media type",
            status_code=415,
        )
    raw = bytearray()
    async for chunk in request.stream():
        raw.extend(chunk)
        if len(raw) > MAX_SNS_BODY_BYTES:
            raise APIException(
                code=4100,
                message="Callback payload is too large",
                status_code=413,
            )
    try:
        event = await verifier.verify_and_extract(
            bytes(raw), request.headers.get("x-amz-sns-message-type")
        )
    except AwsSnsUnavailableError:
        raise APIException(
            code=4103,
            message="Callback verification is temporarily unavailable",
            status_code=503,
        ) from None
    except AwsSnsVerificationError:
        raise APIException(
            code=4101,
            message="Callback authentication failed",
            status_code=401,
        ) from None
    if event is None:
        return ApiResponse.success_without_data()
    try:
        await delivery.record_callback(
            db,
            provider_name="aws-ses",
            provider_message_id=event.provider_message_id,
            callback_id=event.callback_id,
            callback_type=DeliveryCallbackType(event.callback_type),
            occurred_at=event.occurred_at,
            reason_code=event.reason_code,
        )
    except (RuntimeError, SQLAlchemyError, ValueError):
        await db.rollback()
        raise APIException(
            code=4103,
            message="Callback processing is temporarily unavailable",
            status_code=503,
        ) from None
    return ApiResponse.success_without_data()
