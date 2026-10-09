"""SNS setup caches require signed input and explicit authenticated confirmation."""

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import httpx
import pytest
from botocore.exceptions import ClientError
from fastapi import FastAPI
from redis.exceptions import ConnectionError

from app.api.internal.v1 import aeterna_email_events as route
from app.services.common.aeterna_aws_sns import (
    SNS_CONFIRMATION_TTL_SECONDS,
    AwsSesCallbackEvent,
    AwsSnsSubscriptionConfirmation,
    AwsSnsVerificationError,
)
from app.services.common.aeterna_sns_subscription import AwsSnsSubscriptionService
from scripts import manage_sns_subscription as operator
from scripts.manage_sns_subscription import operate

NOW = datetime(2026, 10, 9, 12, tzinfo=UTC)
TOPIC = "arn:aws:sns:ap-southeast-1:123456789012:aeterna-ses-events"
ENDPOINT = "https://api.example.com/api/internal/v1/email-events/aws-sns"
TOKEN = "synthetic-operator-confirmation-token"
SUBSCRIPTION = TOPIC + ":11111111-2222-4333-8444-555555555555"


class MemoryRedis:
    def __init__(self):
        self.values = {}
        self.ttls = {}

    async def set_with_ttl(self, key, value, ttl_seconds):
        self.values[key] = value
        self.ttls[key] = ttl_seconds

    async def get(self, key):
        return self.values.get(key)

    async def delete(self, key):
        self.values.pop(key, None)


class OperatorClient:
    def __init__(self, endpoint=ENDPOINT):
        self.endpoint = endpoint
        self.calls = []

    def confirm_subscription(self, **kwargs):
        self.calls.append(kwargs)
        return {"SubscriptionArn": SUBSCRIPTION}

    def get_subscription_attributes(self, **kwargs):
        assert kwargs == {"SubscriptionArn": SUBSCRIPTION}
        return {
            "Attributes": {
                "TopicArn": TOPIC,
                "Protocol": "https",
                "Endpoint": self.endpoint,
                "ConfirmationWasAuthenticated": "true",
                "RawMessageDelivery": "false",
            }
        }


def synthetic_confirmation():
    return AwsSnsSubscriptionConfirmation(
        topic_arn=TOPIC,
        message_id="synthetic-confirmation-message",
        occurred_at=NOW,
        token=TOKEN,
        subscribe_url="https://sns.ap-southeast-1.amazonaws.com/synthetic-only",
    )


@pytest.mark.asyncio
async def test_cache_is_bounded_and_operator_confirmation_is_authenticated():
    redis = MemoryRedis()
    service = AwsSnsSubscriptionService(redis, TOPIC)
    await service.stage_confirmation(synthetic_confirmation())
    assert list(redis.ttls.values()) == [SNS_CONFIRMATION_TTL_SECONDS]
    client = OperatorClient()
    result = await operate(
        "confirm",
        endpoint=ENDPOINT,
        topic_arn=TOPIC,
        client=client,
        service=service,
        now=NOW,
    )
    assert client.calls == [
        {"TopicArn": TOPIC, "Token": TOKEN, "AuthenticateOnUnsubscribe": "true"}
    ]
    assert result == {"status": "confirmed", "subscription_arn": SUBSCRIPTION}
    assert TOKEN not in json.dumps(result)
    assert await service.get_confirmation() is None


@pytest.mark.asyncio
async def test_expired_material_never_calls_aws():
    service = AwsSnsSubscriptionService(MemoryRedis(), TOPIC)
    await service.stage_confirmation(synthetic_confirmation())
    client = OperatorClient()
    result = await operate(
        "confirm",
        endpoint=ENDPOINT,
        topic_arn=TOPIC,
        client=client,
        service=service,
        now=NOW + timedelta(minutes=16),
    )
    assert result == {"status": "confirmation-expired"}
    assert client.calls == []
    assert await service.get_confirmation() is None


@pytest.mark.asyncio
async def test_missing_confirmation_never_calls_aws():
    service = AwsSnsSubscriptionService(MemoryRedis(), TOPIC)
    client = OperatorClient()
    result = await operate(
        "confirm",
        endpoint=ENDPOINT,
        topic_arn=TOPIC,
        client=client,
        service=service,
        now=NOW,
    )
    assert result == {"status": "waiting-for-signed-confirmation"}
    assert client.calls == []


@pytest.mark.asyncio
async def test_confirmation_checks_the_actual_endpoint_before_claiming_success():
    service = AwsSnsSubscriptionService(MemoryRedis(), TOPIC)
    await service.stage_confirmation(synthetic_confirmation())
    with pytest.raises(ValueError, match="operator review"):
        await operate(
            "confirm",
            endpoint=ENDPOINT,
            topic_arn=TOPIC,
            client=OperatorClient(endpoint=ENDPOINT + "-other"),
            service=service,
            now=NOW,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "attribute,value",
    [
        ("ConfirmationWasAuthenticated", "false"),
        ("RawMessageDelivery", "true"),
        ("PendingConfirmation", "true"),
        ("TopicArn", TOPIC + "-other"),
    ],
)
async def test_confirmation_rejects_unsafe_result_attributes(attribute, value):
    class UnsafeClient(OperatorClient):
        def get_subscription_attributes(self, **kwargs):
            response = super().get_subscription_attributes(**kwargs)
            response["Attributes"][attribute] = value
            return response

    service = AwsSnsSubscriptionService(MemoryRedis(), TOPIC)
    await service.stage_confirmation(synthetic_confirmation())
    with pytest.raises(ValueError, match="operator review"):
        await operate(
            "confirm",
            endpoint=ENDPOINT,
            topic_arn=TOPIC,
            client=UnsafeClient(),
            service=service,
            now=NOW,
        )
    assert await service.get_confirmation() is not None


def test_operator_errors_never_print_provider_messages_or_tokens(monkeypatch, capsys):
    async def denied(_args):
        raise ClientError(
            {"Error": {"Code": "AuthorizationError", "Message": TOKEN}},
            "ConfirmSubscription",
        )

    monkeypatch.setattr(operator, "run", denied)
    assert operator.main(["confirm", "--endpoint", ENDPOINT]) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert json.loads(output.err) == {
        "status": "failed",
        "aws_error_code": "AuthorizationError",
    }
    assert TOKEN not in output.err


@pytest.mark.asyncio
async def test_setup_receipts_contain_no_recipient_or_provider_payload():
    redis = MemoryRedis()
    service = AwsSnsSubscriptionService(redis, TOPIC)
    event = AwsSesCallbackEvent(
        provider_message_id="synthetic-ses-message",
        callback_id="sns:synthetic-callback",
        callback_type="delivered",
        occurred_at=NOW,
    )
    await service.record_event_receipt(event)
    receipt = await service.get_event_receipt("delivered")
    assert set(receipt) == {
        "provider_message_id",
        "callback_id",
        "callback_type",
        "occurred_at",
    }
    assert list(redis.ttls.values()) == [SNS_CONFIRMATION_TTL_SECONDS]


@pytest.mark.asyncio
async def test_operator_test_registration_is_exact_topic_bound_and_expires():
    redis = MemoryRedis()
    service = AwsSnsSubscriptionService(redis, TOPIC)
    peer_topic = AwsSnsSubscriptionService(redis, TOPIC + "-other")
    result = await operate(
        "expect-event",
        endpoint=ENDPOINT,
        topic_arn=TOPIC,
        client=OperatorClient(),
        service=service,
        message_id="synthetic-ses-message",
    )
    assert result["status"] == "test-message-registered"
    assert await service.is_expected_test_message("synthetic-ses-message") is True
    assert await service.is_expected_test_message("other-message") is False
    assert await peer_topic.is_expected_test_message("synthetic-ses-message") is False
    assert list(redis.ttls.values()) == [SNS_CONFIRMATION_TTL_SECONDS]
    await service.clear_test_message("synthetic-ses-message")
    assert await service.is_expected_test_message("synthetic-ses-message") is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "enabled,registered,valid,status",
    [
        (True, True, True, 204),
        (True, False, True, 503),
        (False, True, True, 503),
        (True, True, False, 401),
    ],
)
async def test_only_registered_signed_tests_skip_business_outbox(
    monkeypatch, enabled, registered, valid, status
):
    monkeypatch.setattr(
        route.settings, "AWS_SES_SNS_CONFIRMATION_CAPTURE_ENABLED", enabled
    )
    subscription = AwsSnsSubscriptionService(MemoryRedis(), TOPIC)
    if registered:
        await subscription.expect_test_message("synthetic-ses-message")
    verifier = AsyncMock()
    verifier.verify_and_extract.return_value = AwsSesCallbackEvent(
        provider_message_id="synthetic-ses-message",
        callback_id="sns:synthetic-test",
        callback_type="delivered",
        occurred_at=NOW,
    )
    if not valid:
        verifier.verify_and_extract.side_effect = AwsSnsVerificationError("Rejected")
    delivery = AsyncMock()
    delivery.record_callback.side_effect = RuntimeError("Unknown business delivery")
    app = FastAPI()
    app.include_router(route.router, prefix="/api/internal/v1/email-events")
    app.dependency_overrides[route.get_db] = lambda: AsyncMock()
    app.dependency_overrides[route.get_aws_sns_message_verifier] = lambda: verifier
    app.dependency_overrides[route.get_aeterna_email_callback_service] = (
        lambda: delivery
    )
    app.dependency_overrides[route.get_aws_sns_subscription_service] = (
        lambda: subscription
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://test"
    ) as client:
        response = await client.post(
            "/api/internal/v1/email-events/aws-sns",
            content=b"{}",
            headers={
                "content-type": "text/plain",
                "x-amz-sns-message-type": "Notification",
            },
        )
    assert response.status_code == status
    assert (await subscription.get_event_receipt("delivered") is not None) == (
        status == 204
    )
    assert delivery.record_callback.call_count == int(valid and status != 204)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "enabled,valid,status", [(False, True, 401), (True, False, 401), (True, True, 204)]
)
async def test_callback_only_stages_verified_confirmation_when_opted_in(
    monkeypatch, enabled, valid, status
):
    monkeypatch.setattr(
        route.settings, "AWS_SES_SNS_CONFIRMATION_CAPTURE_ENABLED", enabled
    )
    subscription = AwsSnsSubscriptionService(MemoryRedis(), TOPIC)
    verifier = AsyncMock()
    verifier.verify_and_extract.side_effect = AwsSnsVerificationError("Rejected")
    if valid:
        verifier.verify_subscription_confirmation.return_value = (
            synthetic_confirmation()
        )
    else:
        verifier.verify_subscription_confirmation.side_effect = AwsSnsVerificationError(
            "Rejected"
        )
    delivery = AsyncMock()
    app = FastAPI()
    app.include_router(route.router, prefix="/api/internal/v1/email-events")
    app.dependency_overrides[route.get_db] = lambda: AsyncMock()
    app.dependency_overrides[route.get_aws_sns_message_verifier] = lambda: verifier
    app.dependency_overrides[route.get_aeterna_email_callback_service] = (
        lambda: delivery
    )
    app.dependency_overrides[route.get_aws_sns_subscription_service] = (
        lambda: subscription
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://test"
    ) as client:
        response = await client.post(
            "/api/internal/v1/email-events/aws-sns",
            content=b"{}",
            headers={
                "content-type": "text/plain",
                "x-amz-sns-message-type": "SubscriptionConfirmation",
            },
        )
    assert response.status_code == status
    assert (await subscription.get_confirmation() is not None) == (status == 204)
    assert TOKEN not in response.text
    delivery.record_callback.assert_not_called()


@pytest.mark.asyncio
async def test_callback_returns_retryable_failure_when_confirmation_cache_is_down(
    monkeypatch,
):
    monkeypatch.setattr(
        route.settings, "AWS_SES_SNS_CONFIRMATION_CAPTURE_ENABLED", True
    )
    verifier = AsyncMock()
    verifier.verify_subscription_confirmation.return_value = synthetic_confirmation()
    subscription = AsyncMock()
    subscription.stage_confirmation.side_effect = ConnectionError("synthetic-only")
    app = FastAPI()
    app.include_router(route.router, prefix="/api/internal/v1/email-events")
    app.dependency_overrides[route.get_db] = lambda: AsyncMock()
    app.dependency_overrides[route.get_aws_sns_message_verifier] = lambda: verifier
    app.dependency_overrides[route.get_aeterna_email_callback_service] = (
        lambda: AsyncMock()
    )
    app.dependency_overrides[route.get_aws_sns_subscription_service] = (
        lambda: subscription
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://test"
    ) as client:
        response = await client.post(
            "/api/internal/v1/email-events/aws-sns",
            content=b"{}",
            headers={
                "content-type": "text/plain",
                "x-amz-sns-message-type": "SubscriptionConfirmation",
            },
        )
    assert response.status_code == 503
    assert TOKEN not in response.text
