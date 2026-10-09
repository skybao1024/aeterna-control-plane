"""Replaceable, constrained email boundary for Aeterna notifications."""

from __future__ import annotations

import asyncio
import hashlib
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from email.message import EmailMessage
from typing import Any, Callable, Protocol

import aiosmtplib
import boto3
from botocore.config import Config
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    ConnectionClosedError,
    ConnectTimeoutError,
    CredentialRetrievalError,
    EndpointConnectionError,
    NoCredentialsError,
    ParamValidationError,
    PartialCredentialsError,
    ReadTimeoutError,
)
from email_validator import EmailNotValidError, validate_email

from app.core.config import settings


@dataclass(frozen=True, slots=True)
class AeternaEmailEnvelope:
    """A fully rendered message with no caller-controlled headers or attachments."""

    recipient: str
    subject: str
    text_body: str
    html_body: str
    track_in_outbox: bool = True


@dataclass(frozen=True, slots=True)
class ProviderAcceptance:
    """Provider transport acceptance, which is not mailbox delivery or reading."""

    provider_name: str
    provider_message_id: str
    accepted_at: datetime


class EmailDeliveryFailure(RuntimeError):
    """A redacted provider failure classification safe for persistence."""

    def __init__(self, code: str, *, retryable: bool, ambiguous: bool = False):
        super().__init__(code)
        self.code = code
        self.retryable = retryable
        self.ambiguous = ambiguous


class AeternaEmailAdapter(Protocol):
    """Provider boundary that receives a stable event key and declares its guarantees."""

    provider_name: str
    supports_idempotency: bool

    async def send(
        self,
        envelope: AeternaEmailEnvelope,
        idempotency_key: str,
    ) -> ProviderAcceptance: ...


class SmtpDevelopmentEmailAdapter:
    """Development SMTP adapter; ambiguous failures are never auto-retried."""

    provider_name = "development-smtp"
    supports_idempotency = False

    async def send(
        self,
        envelope: AeternaEmailEnvelope,
        idempotency_key: str,
    ) -> ProviderAcceptance:
        if settings.ENV != "development":
            raise EmailDeliveryFailure(
                "development-smtp-environment-not-local",
                retryable=False,
            )
        if settings.MAIL_HOST not in {
            "localhost",
            "127.0.0.1",
            "::1",
            "mailpit",
            "mailhog",
        }:
            raise EmailDeliveryFailure(
                "development-smtp-host-not-local",
                retryable=False,
            )
        message = EmailMessage()
        message["From"] = f"{settings.MAIL_FROM_NAME} <{settings.MAIL_FROM_ADDRESS}>"
        message["To"] = envelope.recipient
        message["Subject"] = envelope.subject
        message_id = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()
        message["Message-ID"] = f"<{message_id}@aeterna.invalid>"
        message.set_content(envelope.text_body)
        message.add_alternative(envelope.html_body, subtype="html")

        use_tls = settings.MAIL_ENCRYPTION.lower() == "ssl"
        start_tls = settings.MAIL_ENCRYPTION.lower() == "tls"
        try:
            await aiosmtplib.send(
                message,
                hostname=settings.MAIL_HOST,
                port=settings.MAIL_PORT,
                username=settings.MAIL_USERNAME or None,
                password=settings.MAIL_PASSWORD or None,
                use_tls=use_tls,
                start_tls=start_tls,
                timeout=10,
            )
        except Exception:
            raise EmailDeliveryFailure(
                "smtp-delivery-ambiguous",
                retryable=False,
                ambiguous=True,
            ) from None
        return ProviderAcceptance(
            provider_name=self.provider_name,
            provider_message_id=str(uuid.uuid5(uuid.NAMESPACE_URL, idempotency_key)),
            accepted_at=datetime.now(UTC),
        )


class AwsSesV2Client(Protocol):
    """Narrow synchronous boto3 boundary used by the async adapter."""

    def send_email(self, **kwargs: Any) -> dict[str, Any]: ...


class AwsSesEmailAdapter:
    """Amazon SES v2 adapter with no automatic retry of ambiguous sends."""

    provider_name = "aws-ses"
    supports_idempotency = False

    def __init__(
        self,
        *,
        client: AwsSesV2Client,
        from_address: str,
        configuration_set: str,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ):
        try:
            validated_sender = validate_email(from_address, check_deliverability=False)
            if validated_sender.ascii_email is None:
                raise EmailNotValidError("SES requires an ASCII mailbox")
            self.from_address = validated_sender.ascii_email
        except EmailNotValidError:
            raise ValueError("AWS SES sender address is invalid") from None
        if re.fullmatch(r"[A-Za-z0-9_-]{1,64}", configuration_set) is None:
            raise ValueError("AWS SES configuration set is invalid")
        self.client = client
        self.configuration_set = configuration_set
        self.clock = clock

    async def send(
        self,
        envelope: AeternaEmailEnvelope,
        idempotency_key: str,
    ) -> ProviderAcceptance:
        try:
            validated_recipient = validate_email(
                envelope.recipient, check_deliverability=False
            )
            if validated_recipient.ascii_email is None:
                raise EmailNotValidError("SES requires an ASCII mailbox")
            recipient = validated_recipient.ascii_email
        except EmailNotValidError:
            raise EmailDeliveryFailure(
                "aws-ses-envelope-invalid", retryable=False
            ) from None
        trace_key = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()
        tags = [{"Name": "aeterna-event", "Value": trace_key}]
        if not envelope.track_in_outbox:
            # Immediate account mail has no durable delivery row. This fixed tag
            # lets authenticated callbacks avoid an unmatched Outbox lookup.
            tags.append({"Name": "aeterna-delivery", "Value": "immediate"})
        try:
            response = await asyncio.to_thread(
                self.client.send_email,
                FromEmailAddress=self.from_address,
                Destination={"ToAddresses": [recipient]},
                Content={
                    "Simple": {
                        "Subject": {"Data": envelope.subject, "Charset": "UTF-8"},
                        "Body": {
                            "Text": {"Data": envelope.text_body, "Charset": "UTF-8"},
                            "Html": {"Data": envelope.html_body, "Charset": "UTF-8"},
                        },
                    }
                },
                ConfigurationSetName=self.configuration_set,
                EmailTags=tags,
            )
        except ClientError as exc:
            raise self._client_error(exc) from None
        except (
            NoCredentialsError,
            PartialCredentialsError,
            CredentialRetrievalError,
            ParamValidationError,
        ):
            raise EmailDeliveryFailure(
                "aws-ses-configuration-error", retryable=False
            ) from None
        except (EndpointConnectionError, ConnectTimeoutError):
            raise EmailDeliveryFailure(
                "aws-ses-connect-failed", retryable=True
            ) from None
        except (ReadTimeoutError, ConnectionClosedError):
            raise EmailDeliveryFailure(
                "aws-ses-outcome-ambiguous", retryable=False, ambiguous=True
            ) from None
        except BotoCoreError:
            raise EmailDeliveryFailure(
                "aws-ses-sdk-ambiguous", retryable=False, ambiguous=True
            ) from None

        message_id = response.get("MessageId")
        if (
            not isinstance(message_id, str)
            or not message_id
            or len(message_id.encode("utf-8")) > 255
            or any(
                ord(character) < 33 or ord(character) == 127 for character in message_id
            )
        ):
            raise EmailDeliveryFailure(
                "aws-ses-invalid-acceptance", retryable=False, ambiguous=True
            )
        accepted_at = self.clock()
        if accepted_at.tzinfo is None or accepted_at.utcoffset() is None:
            raise RuntimeError("AWS SES adapter clock must be timezone-aware")
        return ProviderAcceptance(
            provider_name=self.provider_name,
            provider_message_id=message_id,
            accepted_at=accepted_at.astimezone(UTC),
        )

    def _client_error(self, exc: ClientError) -> EmailDeliveryFailure:
        code = str(exc.response.get("Error", {}).get("Code", "Unknown"))
        if code in {
            "BadRequestException",
            "MailFromDomainNotVerifiedException",
            "MessageRejected",
            "NotFoundException",
            "AccountSuspendedException",
            "SendingPausedException",
        }:
            return EmailDeliveryFailure("aws-ses-request-rejected", retryable=False)
        if code in {"TooManyRequestsException", "LimitExceededException"}:
            return EmailDeliveryFailure("aws-ses-throttled", retryable=True)
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        if isinstance(status, int) and status < 500:
            return EmailDeliveryFailure("aws-ses-request-rejected", retryable=False)
        return EmailDeliveryFailure(
            "aws-ses-service-ambiguous", retryable=False, ambiguous=True
        )


class UnavailableProductionEmailAdapter:
    """Fail closed until a provider, regions, and data boundary are approved."""

    provider_name = "unavailable-production-provider"
    supports_idempotency = False

    def __init__(self, *, failure_code: str = "production-email-provider-unapproved"):
        self.failure_code = failure_code

    async def send(
        self,
        envelope: AeternaEmailEnvelope,
        idempotency_key: str,
    ) -> ProviderAcceptance:
        raise EmailDeliveryFailure(
            self.failure_code,
            retryable=False,
        )


def _aws_ses_settings_complete() -> bool:
    try:
        validated_sender = validate_email(
            settings.AWS_SES_FROM_ADDRESS, check_deliverability=False
        )
        if validated_sender.ascii_email is None:
            return False
    except EmailNotValidError:
        return False
    topic_match = re.fullmatch(
        r"arn:(aws|aws-us-gov|aws-cn):sns:([^:]+):[0-9]{12}:[A-Za-z0-9_-]{1,256}",
        settings.AWS_SES_SNS_TOPIC_ARN,
    )
    return bool(
        settings.AETERNA_EMAIL_PROVIDER == "aws-ses"
        and re.fullmatch(r"[a-z0-9-]+-[0-9]+", settings.AWS_SES_REGION)
        and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", settings.AWS_SES_CONFIGURATION_SET)
        and topic_match is not None
        and topic_match.group(2) == settings.AWS_SES_REGION
        and settings.AWS_SES_FROM_ADDRESS
    )


def validate_email_delivery_configuration() -> None:
    """Reject a partially enabled production or preview provider at startup."""

    if (
        settings.ENV in {"production", "preview"}
        and settings.AETERNA_EMAIL_PRODUCTION_ENABLED
    ):
        if not _aws_ses_settings_complete():
            raise RuntimeError(
                "Enabled AWS SES email configuration is incomplete or invalid"
            )


def get_aeterna_email_adapter() -> AeternaEmailAdapter:
    """Select only a completely configured and explicitly enabled boundary."""

    if settings.ENV in {"production", "preview"}:
        if settings.AETERNA_EMAIL_PRODUCTION_ENABLED and _aws_ses_settings_complete():
            try:
                client = boto3.client(
                    "sesv2",
                    region_name=settings.AWS_SES_REGION,
                    config=Config(
                        region_name=settings.AWS_SES_REGION,
                        signature_version="v4",
                        retries={"total_max_attempts": 1, "mode": "standard"},
                    ),
                )
            except Exception:
                # Resolve dependencies without exposing credential-chain failures
                # or aborting best-effort notices before the send boundary.
                return UnavailableProductionEmailAdapter(
                    failure_code="aws-ses-configuration-error"
                )
            return AwsSesEmailAdapter(
                client=client,
                from_address=settings.AWS_SES_FROM_ADDRESS,
                configuration_set=settings.AWS_SES_CONFIGURATION_SET,
            )
        return UnavailableProductionEmailAdapter()
    if settings.ENV == "development":
        return SmtpDevelopmentEmailAdapter()
    return UnavailableProductionEmailAdapter()
