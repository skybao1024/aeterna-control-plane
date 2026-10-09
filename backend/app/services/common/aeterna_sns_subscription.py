"""Short-lived SNS setup evidence; subscription changes are operator-only."""

import hashlib
import json
from collections.abc import AsyncIterator

from app.core.config import settings
from app.services.common.aeterna_aws_sns import (
    SNS_CONFIRMATION_TTL_SECONDS,
    AwsSesCallbackEvent,
    AwsSnsSubscriptionConfirmation,
)
from app.services.common.redis import RedisClient


class AwsSnsSubscriptionService:
    """Keep verified setup material in Redis without logging tokens or payloads."""

    def __init__(self, redis: RedisClient, topic_arn: str):
        self.redis = redis
        self.topic_arn = topic_arn
        self.key_prefix = (
            "aeterna:sns-setup:" + hashlib.sha256(topic_arn.encode("utf-8")).hexdigest()
        )

    async def stage_confirmation(
        self, confirmation: AwsSnsSubscriptionConfirmation
    ) -> None:
        if confirmation.topic_arn != self.topic_arn:
            raise ValueError("SNS setup topic does not match")
        document = {
            "message_id": confirmation.message_id,
            "occurred_at": confirmation.occurred_at.isoformat(),
            "token": confirmation.token,
        }
        await self.redis.set_with_ttl(
            self.key_prefix + ":confirmation",
            json.dumps(document),
            SNS_CONFIRMATION_TTL_SECONDS,
        )

    async def get_confirmation(self) -> dict | None:
        value = await self.redis.get(self.key_prefix + ":confirmation")
        return json.loads(value) if value is not None else None

    async def clear_confirmation(self) -> None:
        await self.redis.delete(self.key_prefix + ":confirmation")

    def _test_message_key(self, provider_message_id: str) -> str:
        if (
            not provider_message_id
            or len(provider_message_id.encode("utf-8")) > 255
            or any(
                ord(character) < 33 or ord(character) == 127
                for character in provider_message_id
            )
        ):
            raise ValueError("Invalid setup message identifier")
        return (
            self.key_prefix
            + ":test:"
            + hashlib.sha256(provider_message_id.encode("utf-8")).hexdigest()
        )

    async def expect_test_message(self, provider_message_id: str) -> None:
        """Authorize only this explicit operator test to bypass business Outbox lookup."""
        await self.redis.set_with_ttl(
            self._test_message_key(provider_message_id),
            "1",
            SNS_CONFIRMATION_TTL_SECONDS,
        )

    async def is_expected_test_message(self, provider_message_id: str) -> bool:
        return await self.redis.get(self._test_message_key(provider_message_id)) == "1"

    async def clear_test_message(self, provider_message_id: str) -> None:
        await self.redis.delete(self._test_message_key(provider_message_id))

    async def record_event_receipt(self, event: AwsSesCallbackEvent) -> None:
        document = {
            "provider_message_id": event.provider_message_id,
            "callback_type": event.callback_type,
            "callback_id": event.callback_id,
            "occurred_at": event.occurred_at.isoformat(),
        }
        await self.redis.set_with_ttl(
            self.key_prefix + ":receipt:" + event.callback_type,
            json.dumps(document),
            SNS_CONFIRMATION_TTL_SECONDS,
        )

    async def get_event_receipt(self, callback_type: str) -> dict | None:
        value = await self.redis.get(self.key_prefix + ":receipt:" + callback_type)
        return json.loads(value) if value is not None else None


async def get_aws_sns_subscription_service() -> (
    AsyncIterator[AwsSnsSubscriptionService]
):
    redis = RedisClient()
    try:
        yield AwsSnsSubscriptionService(redis, settings.AWS_SES_SNS_TOPIC_ARN)
    finally:
        await redis.redis.aclose()
