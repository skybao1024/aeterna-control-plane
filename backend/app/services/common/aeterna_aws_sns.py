"""Authenticated Amazon SNS boundary for SES transport events."""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import httpx
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

MAX_SNS_BODY_BYTES = 65_536
MAX_SNS_CERTIFICATE_BYTES = 65_536
MAX_SES_EVENT_BYTES = 32_768
SNS_CONFIRMATION_TTL_SECONDS = 900


class AwsSnsVerificationError(RuntimeError):
    """Raised when a callback is malformed, unexpected, or unauthenticated."""


class AwsSnsUnavailableError(RuntimeError):
    """Raised when the trusted signing certificate cannot be retrieved."""


@dataclass(frozen=True, slots=True)
class AwsSesCallbackEvent:
    """Minimal redacted SES event passed to the delivery state machine."""

    provider_message_id: str
    callback_id: str
    callback_type: str
    occurred_at: datetime
    reason_code: str | None = None


@dataclass(frozen=True, slots=True)
class AwsSnsSubscriptionConfirmation:
    """Verified, short-lived confirmation material for an explicit operator action."""

    topic_arn: str
    message_id: str
    occurred_at: datetime
    token: str = field(repr=False)
    subscribe_url: str = field(repr=False)


CertificateLoader = Callable[[str], Awaitable[bytes]]


class AwsSnsMessageVerifier:
    """Verify SNS SignatureVersion 2 and extract only supported SES evidence."""

    def __init__(
        self,
        *,
        topic_arn: str,
        certificate_loader: CertificateLoader | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ):
        topic = re.fullmatch(
            r"arn:(aws|aws-us-gov|aws-cn):sns:([^:]+):[0-9]{12}:"
            r"[A-Za-z0-9_-]{1,256}",
            topic_arn,
        )
        if topic is None:
            raise ValueError("AWS SNS topic ARN is invalid")
        self.topic_arn = topic_arn
        self.partition = topic.group(1)
        self.region = topic.group(2)
        self.certificate_loader = certificate_loader or self._load_certificate
        self.clock = clock
        self._certificate_cache: dict[str, bytes] = {}

    async def verify_and_extract(
        self,
        body: bytes,
        message_type_header: str | None,
    ) -> AwsSesCallbackEvent | None:
        outer = await self._verify_message(body, message_type_header, "Notification")
        return self._extract_ses_event(outer)

    async def verify_subscription_confirmation(
        self,
        body: bytes,
        message_type_header: str | None,
    ) -> AwsSnsSubscriptionConfirmation:
        """Authenticate confirmation material without following any URL."""

        outer = await self._verify_message(
            body, message_type_header, "SubscriptionConfirmation"
        )
        occurred_at = self._timestamp(outer.get("Timestamp"))
        age = self.clock().astimezone(UTC) - occurred_at
        if (
            not timedelta(minutes=-5)
            <= age
            <= timedelta(seconds=SNS_CONFIRMATION_TTL_SECONDS)
        ):
            raise AwsSnsVerificationError("SNS confirmation timestamp is not accepted")
        token = self._text(outer, "Token", 4_096)
        subscribe_url = self._text(outer, "SubscribeURL", 8_192)
        self._validate_subscription_url(subscribe_url, token)
        return AwsSnsSubscriptionConfirmation(
            topic_arn=self.topic_arn,
            message_id=self._text(outer, "MessageId", 250),
            occurred_at=occurred_at,
            token=token,
            subscribe_url=subscribe_url,
        )

    async def _verify_message(
        self, body: bytes, message_type_header: str | None, expected_type: str
    ) -> dict:
        if not body or len(body) > MAX_SNS_BODY_BYTES:
            raise AwsSnsVerificationError("SNS callback body is invalid")
        outer = self._json_object(body)
        message_type = self._text(outer, "Type", 32)
        if message_type != expected_type or message_type_header != message_type:
            raise AwsSnsVerificationError("SNS message type is not accepted")
        if self._text(outer, "TopicArn", 512) != self.topic_arn:
            raise AwsSnsVerificationError("SNS topic is not accepted")
        if self._text(outer, "SignatureVersion", 8) != "2":
            raise AwsSnsVerificationError("SNS signature version is not accepted")
        try:
            base64.b64decode(self._text(outer, "Signature", 4_096), validate=True)
        except (ValueError, binascii.Error):
            raise AwsSnsVerificationError("SNS signature is invalid") from None
        self._canonical_message(outer)

        certificate_url = self._text(outer, "SigningCertURL", 1_024)
        self._validate_certificate_url(certificate_url)
        certificate_pem = self._certificate_cache.get(certificate_url)
        if certificate_pem is None:
            certificate_pem = await self.certificate_loader(certificate_url)
            if len(self._certificate_cache) >= 4:
                self._certificate_cache.pop(next(iter(self._certificate_cache)))
            self._certificate_cache[certificate_url] = certificate_pem
        self._verify_signature(outer, certificate_pem)
        return outer

    def _extract_ses_event(self, outer: dict) -> AwsSesCallbackEvent | None:
        message = self._text(outer, "Message", MAX_SES_EVENT_BYTES)
        inner = self._json_object(message.encode("utf-8"))
        event_type = inner.get("eventType", inner.get("notificationType"))
        if not isinstance(event_type, str):
            raise AwsSnsVerificationError("SES event type is invalid")
        if event_type in {"Open", "Click", "DeliveryDelay", "Subscription"}:
            return None

        mail = inner.get("mail")
        if not isinstance(mail, dict):
            raise AwsSnsVerificationError("SES mail evidence is invalid")
        provider_message_id = mail.get("messageId")
        if (
            not isinstance(provider_message_id, str)
            or not provider_message_id
            or len(provider_message_id.encode("utf-8")) > 255
        ):
            raise AwsSnsVerificationError("SES message identifier is invalid")

        callback_type: str
        reason_code: str | None = None
        timestamp_value: object = mail.get("timestamp", outer.get("Timestamp"))
        if event_type == "Send":
            callback_type = "provider_accepted"
        elif event_type == "Delivery":
            callback_type = "delivered"
            timestamp_value = self._nested_timestamp(inner, "delivery", timestamp_value)
        elif event_type == "Bounce":
            callback_type = "bounced"
            bounce = inner.get("bounce")
            if not isinstance(bounce, dict):
                raise AwsSnsVerificationError("SES bounce evidence is invalid")
            reason_code = (
                "hard-bounce"
                if bounce.get("bounceType") == "Permanent"
                else "provider-bounce"
            )
            timestamp_value = bounce.get("timestamp", timestamp_value)
        elif event_type == "Complaint":
            callback_type = "complained"
            reason_code = "provider-complaint"
            timestamp_value = self._nested_timestamp(
                inner, "complaint", timestamp_value
            )
        elif event_type in {"Reject", "Rendering Failure"}:
            callback_type = "rejected"
            reason_code = "provider-rejected"
        else:
            return None

        callback_id = f"sns:{self._text(outer, 'MessageId', 250)}"
        occurred_at = self._timestamp(timestamp_value)
        tags = mail.get("tags")
        if isinstance(tags, dict) and tags.get("aeterna-delivery") == ["immediate"]:
            # Immediate account mail has no Outbox delivery state to update.
            return None

        return AwsSesCallbackEvent(
            provider_message_id=provider_message_id,
            callback_id=callback_id,
            callback_type=callback_type,
            occurred_at=occurred_at,
            reason_code=reason_code,
        )

    def _verify_signature(self, outer: dict, certificate_pem: bytes) -> None:
        if not certificate_pem or len(certificate_pem) > MAX_SNS_CERTIFICATE_BYTES:
            raise AwsSnsVerificationError("SNS signing certificate is invalid")
        try:
            certificate = x509.load_pem_x509_certificate(certificate_pem)
        except ValueError:
            raise AwsSnsVerificationError(
                "SNS signing certificate is invalid"
            ) from None
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise RuntimeError("SNS verifier clock must be timezone-aware")
        now = now.astimezone(UTC)
        if not (
            certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc
        ):
            raise AwsSnsVerificationError("SNS signing certificate is expired")
        public_key = certificate.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise AwsSnsVerificationError("SNS signing key type is invalid")
        try:
            signature = base64.b64decode(
                self._text(outer, "Signature", 4_096), validate=True
            )
            public_key.verify(
                signature,
                self._canonical_message(outer),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except (InvalidSignature, ValueError, binascii.Error):
            raise AwsSnsVerificationError("SNS signature is invalid") from None

    def _canonical_message(self, outer: dict) -> bytes:
        fields = ["Message", "MessageId"]
        if outer["Type"] == "SubscriptionConfirmation":
            fields.extend(["SubscribeURL", "Timestamp", "Token", "TopicArn", "Type"])
        else:
            if "Subject" in outer:
                fields.append("Subject")
            fields.extend(["Timestamp", "TopicArn", "Type"])
        lines: list[str] = []
        for field in fields:
            lines.extend([field, self._text(outer, field, MAX_SES_EVENT_BYTES)])
        return ("\n".join(lines) + "\n").encode("utf-8")

    def _validate_subscription_url(self, value: str, token: str) -> None:
        suffix = "amazonaws.com.cn" if self.partition == "aws-cn" else "amazonaws.com"
        try:
            parsed = urlsplit(value)
            port = parsed.port
            query = parse_qs(parsed.query, strict_parsing=True)
        except ValueError:
            raise AwsSnsVerificationError("SNS confirmation URL is invalid") from None
        if (
            parsed.scheme != "https"
            or parsed.hostname != f"sns.{self.region}.{suffix}"
            or port is not None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path != "/"
            or parsed.fragment
            or query
            != {
                "Action": ["ConfirmSubscription"],
                "TopicArn": [self.topic_arn],
                "Token": [token],
            }
        ):
            raise AwsSnsVerificationError("SNS confirmation URL is invalid")

    def _validate_certificate_url(self, value: str) -> None:
        parsed = urlsplit(value)
        suffix = "amazonaws.com.cn" if self.partition == "aws-cn" else "amazonaws.com"
        expected_host = f"sns.{self.region}.{suffix}"
        try:
            port = parsed.port
        except ValueError:
            raise AwsSnsVerificationError(
                "SNS signing certificate URL is invalid"
            ) from None
        if (
            parsed.scheme != "https"
            or parsed.hostname != expected_host
            or port is not None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or re.fullmatch(
                r"/SimpleNotificationService-[A-Za-z0-9_-]+\.pem", parsed.path
            )
            is None
        ):
            raise AwsSnsVerificationError("SNS signing certificate URL is invalid")

    async def _load_certificate(self, url: str) -> bytes:
        try:
            async with httpx.AsyncClient(
                follow_redirects=False,
                timeout=httpx.Timeout(5.0),
            ) as client:
                async with client.stream("GET", url) as response:
                    response.raise_for_status()
                    content = bytearray()
                    async for chunk in response.aiter_bytes():
                        content.extend(chunk)
                        if len(content) > MAX_SNS_CERTIFICATE_BYTES:
                            raise AwsSnsVerificationError(
                                "SNS signing certificate is invalid"
                            )
        except httpx.HTTPError:
            raise AwsSnsUnavailableError(
                "SNS signing certificate is temporarily unavailable"
            ) from None
        return bytes(content)

    def _json_object(self, value: bytes) -> dict:
        def reject_duplicates(pairs):
            result = {}
            for key, item in pairs:
                if key in result:
                    raise AwsSnsVerificationError("JSON contains a duplicate member")
                result[key] = item
            return result

        try:
            parsed = json.loads(value, object_pairs_hook=reject_duplicates)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise AwsSnsVerificationError("Callback JSON is invalid") from None
        if not isinstance(parsed, dict):
            raise AwsSnsVerificationError("Callback JSON must be an object")
        return parsed

    def _text(self, document: dict, key: str, limit: int) -> str:
        value = document.get(key)
        if (
            not isinstance(value, str)
            or not value
            or len(value.encode("utf-8")) > limit
        ):
            raise AwsSnsVerificationError(f"Callback field {key} is invalid")
        return value

    def _timestamp(self, value: object) -> datetime:
        if not isinstance(value, str) or len(value) > 64:
            raise AwsSnsVerificationError("Callback timestamp is invalid")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise AwsSnsVerificationError("Callback timestamp is invalid") from None
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise AwsSnsVerificationError("Callback timestamp is invalid")
        return parsed.astimezone(UTC)

    def _nested_timestamp(self, document: dict, key: str, fallback: object) -> object:
        value = document.get(key)
        return value.get("timestamp", fallback) if isinstance(value, dict) else fallback
