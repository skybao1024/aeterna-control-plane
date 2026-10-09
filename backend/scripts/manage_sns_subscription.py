"""Manage SNS setup explicitly inside the backend Docker service.

Run from the repository root with the active production Compose configuration:
    docker compose exec backend python -m scripts.manage_sns_subscription \
        status --endpoint https://api.example.com/api/internal/v1/email-events/aws-sns

The request-confirmation and confirm commands require an authenticated operator
SDK profile with narrowly scoped SNS setup permissions. No token, URL, AWS
credential, provider error message, or notification payload is printed.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from app.core.config import settings
from app.services.common.aeterna_aws_sns import SNS_CONFIRMATION_TTL_SECONDS
from app.services.common.aeterna_sns_subscription import AwsSnsSubscriptionService
from app.services.common.redis import RedisClient

RECEIPT_TYPES = (
    "provider_accepted",
    "delivered",
    "bounced",
    "complained",
    "rejected",
)


def validate_endpoint(endpoint: str) -> None:
    parsed = urlsplit(endpoint)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != "/api/internal/v1/email-events/aws-sns"
    ):
        raise ValueError("Invalid SNS callback endpoint")


async def operate(
    command: str,
    *,
    endpoint: str,
    topic_arn: str,
    client: Any,
    service: AwsSnsSubscriptionService,
    now: datetime | None = None,
    message_id: str | None = None,
) -> dict:
    """Run one explicit operation and return only redacted setup evidence."""

    validate_endpoint(endpoint)
    if command == "expect-event":
        if not message_id:
            raise ValueError("An explicit setup message identifier is required")
        await service.expect_test_message(message_id)
        return {"status": "test-message-registered", "provider_message_id": message_id}
    if command == "request-confirmation":
        result = await asyncio.to_thread(
            client.subscribe,
            TopicArn=topic_arn,
            Protocol="https",
            Endpoint=endpoint,
            ReturnSubscriptionArn=True,
        )
        return {
            "status": "confirmation-requested",
            "subscription_arn": result.get("SubscriptionArn"),
        }
    if command == "confirm":
        confirmation = await service.get_confirmation()
        if confirmation is None:
            return {"status": "waiting-for-signed-confirmation"}
        token = confirmation.get("token")
        if not isinstance(token, str) or not 1 <= len(token) <= 4_096:
            raise ValueError("Invalid cached confirmation")
        timestamp = datetime.fromisoformat(confirmation["occurred_at"])
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("Invalid cached confirmation")
        age = (now or datetime.now(UTC)) - timestamp
        if (
            not timedelta(minutes=-5)
            <= age
            <= timedelta(seconds=SNS_CONFIRMATION_TTL_SECONDS)
        ):
            await service.clear_confirmation()
            return {"status": "confirmation-expired"}
        result = await asyncio.to_thread(
            client.confirm_subscription,
            TopicArn=topic_arn,
            Token=token,
            AuthenticateOnUnsubscribe="true",
        )
        subscription_arn = result["SubscriptionArn"]
        if not subscription_arn.startswith(topic_arn + ":"):
            raise ValueError("Unexpected confirmed subscription")
        attributes = (
            await asyncio.to_thread(
                client.get_subscription_attributes, SubscriptionArn=subscription_arn
            )
        )["Attributes"]
        if (
            attributes.get("TopicArn") != topic_arn
            or attributes.get("Protocol") != "https"
            or attributes.get("Endpoint") != endpoint
            or attributes.get("PendingConfirmation", "false") != "false"
            or attributes.get("ConfirmationWasAuthenticated") != "true"
            or attributes.get("RawMessageDelivery", "false") != "false"
        ):
            raise ValueError("Confirmed subscription requires operator review")
        await service.clear_confirmation()
        return {"status": "confirmed", "subscription_arn": subscription_arn}
    if command == "clear":
        await service.clear_confirmation()
        if message_id:
            await service.clear_test_message(message_id)
        return {"status": "confirmation-cache-cleared"}

    if command != "status":
        raise ValueError("Unsupported SNS setup operation")

    result = await asyncio.to_thread(
        client.list_subscriptions_by_topic, TopicArn=topic_arn
    )
    subscriptions = []
    while True:
        subscriptions.extend(result.get("Subscriptions", []))
        if not result.get("NextToken"):
            break
        result = await asyncio.to_thread(
            client.list_subscriptions_by_topic,
            TopicArn=topic_arn,
            NextToken=result["NextToken"],
        )
    matching = [
        item
        for item in subscriptions
        if item.get("Protocol") == "https" and item.get("Endpoint") == endpoint
    ]
    receipts = {}
    for callback_type in RECEIPT_TYPES:
        receipt = await service.get_event_receipt(callback_type)
        if receipt is not None:
            receipts[callback_type] = receipt
    return {
        "status": "inspected",
        "matching_subscriptions": [item.get("SubscriptionArn") for item in matching],
        "signed_confirmation_cached": await service.get_confirmation() is not None,
        "verified_event_receipts": receipts,
    }


async def run(args: argparse.Namespace) -> dict:
    topic_arn = settings.AWS_SES_SNS_TOPIC_ARN
    if (
        settings.ENV != "production"
        or settings.AETERNA_EMAIL_PROVIDER != "aws-ses"
        or not re.fullmatch(
            r"arn:aws:sns:[a-z0-9-]+:[0-9]{12}:[A-Za-z0-9_-]+", topic_arn
        )
        or topic_arn.split(":")[3] != settings.AWS_SES_REGION
    ):
        raise ValueError("SNS runtime configuration is incomplete")
    client = boto3.Session(profile_name=args.profile).client(
        "sns",
        region_name=settings.AWS_SES_REGION,
        config=Config(
            retries={"total_max_attempts": 1}, connect_timeout=10, read_timeout=20
        ),
    )
    redis = RedisClient()
    try:
        return await operate(
            args.command,
            endpoint=args.endpoint,
            topic_arn=topic_arn,
            client=client,
            service=AwsSnsSubscriptionService(redis, topic_arn),
            message_id=args.message_id,
        )
    finally:
        await redis.redis.aclose()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=("status", "request-confirmation", "confirm", "expect-event", "clear"),
    )
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--profile", help="Authenticated operator AWS SDK profile")
    parser.add_argument(
        "--message-id", help="SES identifier for one explicit setup test"
    )
    args = parser.parse_args(argv)
    try:
        result = asyncio.run(run(args))
    except ClientError as error:
        print(
            json.dumps(
                {"status": "failed", "aws_error_code": error.response["Error"]["Code"]}
            ),
            file=sys.stderr,
        )
        return 1
    except Exception:
        print(
            json.dumps({"status": "failed", "reason": "setup-operation-failed"}),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result))
    return (
        0
        if result["status"]
        not in {"waiting-for-signed-confirmation", "confirmation-expired"}
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
