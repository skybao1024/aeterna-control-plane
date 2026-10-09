"""Local-only contract tests for the AWS SES and signed SNS boundaries."""

import base64
import json
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

import pytest
from botocore.exceptions import (
    ClientError,
    CredentialRetrievalError,
    PartialCredentialsError,
    ReadTimeoutError,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from app.services.common.aeterna_aws_sns import (
    AwsSnsMessageVerifier,
    AwsSnsVerificationError,
)
from app.services.common.aeterna_email_adapter import (
    AeternaEmailEnvelope,
    AwsSesEmailAdapter,
    EmailDeliveryFailure,
    SmtpDevelopmentEmailAdapter,
    UnavailableProductionEmailAdapter,
    get_aeterna_email_adapter,
    validate_email_delivery_configuration,
)
from app.services.common.aeterna_notifier import get_aeterna_account_notifier
from app.services.common.email import get_email_service
from app.services.internal.aeterna_email_delivery import (
    get_aeterna_email_delivery_service,
)

NOW = datetime(2026, 9, 27, 12, tzinfo=UTC)
TOPIC_ARN = "arn:aws:sns:ap-southeast-1:123456789012:aeterna-ses-events"
CERTIFICATE_URL = (
    "https://sns.ap-southeast-1.amazonaws.com/" "SimpleNotificationService-test.pem"
)


class FakeSesClient:
    def __init__(self, response=None, error=None):
        self.response = {"MessageId": "ses-message-1"} if response is None else response
        self.error = error
        self.calls = []

    def send_email(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.response


@pytest.mark.parametrize("environment", ["production", "preview"])
def test_deployed_factory_requires_explicit_complete_aws_ses_enablement(
    monkeypatch, environment
):
    client = FakeSesClient()
    created = {}

    def create_client(service_name, **kwargs):
        created["service_name"] = service_name
        created.update(kwargs)
        return client

    settings = "app.services.common.aeterna_email_adapter.settings"
    monkeypatch.setattr(f"{settings}.ENV", environment)
    monkeypatch.setattr(f"{settings}.AETERNA_EMAIL_PROVIDER", "aws-ses")
    monkeypatch.setattr(f"{settings}.AETERNA_EMAIL_PRODUCTION_ENABLED", True)
    monkeypatch.setattr(f"{settings}.AWS_SES_REGION", "ap-southeast-1")
    monkeypatch.setattr(f"{settings}.AWS_SES_FROM_ADDRESS", "noreply@example.com")
    monkeypatch.setattr(f"{settings}.AWS_SES_CONFIGURATION_SET", "aeterna-events")
    monkeypatch.setattr(f"{settings}.AWS_SES_SNS_TOPIC_ARN", TOPIC_ARN)
    monkeypatch.setattr(
        "app.services.common.aeterna_email_adapter.boto3.client", create_client
    )

    validate_email_delivery_configuration()
    adapter = get_aeterna_email_adapter()
    assert isinstance(adapter, AwsSesEmailAdapter)
    for service in (get_email_service(), get_aeterna_email_delivery_service()):
        assert isinstance(service.adapter, AwsSesEmailAdapter)
        assert service.adapter.from_address == "noreply@example.com"
        assert service.adapter.configuration_set == "aeterna-events"
    assert created["service_name"] == "sesv2"
    assert created["region_name"] == "ap-southeast-1"
    assert created["config"].retries["total_max_attempts"] == 1
    assert set(created) == {"service_name", "region_name", "config"}


def configure_email_delivery(monkeypatch, *, environment, enabled, **overrides):
    values = {
        "ENV": environment,
        "AETERNA_EMAIL_PROVIDER": "aws-ses",
        "AETERNA_EMAIL_PRODUCTION_ENABLED": enabled,
        "AWS_SES_REGION": "ap-southeast-1",
        "AWS_SES_FROM_ADDRESS": "noreply@example.com",
        "AWS_SES_CONFIGURATION_SET": "aeterna-events",
        "AWS_SES_SNS_TOPIC_ARN": TOPIC_ARN,
        **overrides,
    }
    for name, value in values.items():
        monkeypatch.setattr(
            f"app.services.common.aeterna_email_adapter.settings.{name}", value
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("environment", ["production", "preview"])
async def test_disabled_production_gate_is_shared_by_account_and_outbox_mail(
    monkeypatch, environment
):
    configure_email_delivery(monkeypatch, environment=environment, enabled=False)
    created = []
    monkeypatch.setattr(
        "app.services.common.aeterna_email_adapter.boto3.client",
        lambda *args, **kwargs: created.append((args, kwargs)),
    )
    validate_email_delivery_configuration()
    account_service = get_email_service()
    outbox_service = get_aeterna_email_delivery_service()

    assert isinstance(account_service.adapter, UnavailableProductionEmailAdapter)
    assert isinstance(outbox_service.adapter, UnavailableProductionEmailAdapter)
    with pytest.raises(EmailDeliveryFailure) as exc_info:
        await account_service.send_verification_email(
            "owner@example.com", "Synthetic user", "12345678", 10
        )
    assert exc_info.value.code == "production-email-provider-unapproved"
    assert exc_info.value.retryable is False
    assert created == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [
        PartialCredentialsError(
            provider="synthetic-provider", cred_var="synthetic-missing-variable"
        ),
        CredentialRetrievalError(
            provider="synthetic-provider", error_msg="synthetic-sensitive-detail"
        ),
        RuntimeError("synthetic-sensitive-detail owner@example.com 12345678"),
    ],
)
async def test_ses_client_initialization_failure_resolves_redacted_send_boundary(
    monkeypatch, error, caplog
):
    configure_email_delivery(monkeypatch, environment="production", enabled=True)
    client_calls = []
    smtp_calls = []

    def create_client(*args, **kwargs):
        client_calls.append((args, kwargs))
        raise error

    async def send_smtp(*args, **kwargs):
        smtp_calls.append((args, kwargs))

    monkeypatch.setattr(
        "app.services.common.aeterna_email_adapter.boto3.client", create_client
    )
    monkeypatch.setattr(
        "app.services.common.aeterna_email_adapter.aiosmtplib.send", send_smtp
    )
    caplog.set_level("DEBUG")

    validate_email_delivery_configuration()
    account_service = get_email_service()
    account_notifier = get_aeterna_account_notifier()
    outbox_service = get_aeterna_email_delivery_service()
    assert isinstance(account_service.adapter, UnavailableProductionEmailAdapter)
    assert isinstance(outbox_service.adapter, UnavailableProductionEmailAdapter)
    sends = (
        (
            account_service.send_verification_email,
            ("owner@example.com", "Synthetic user", "12345678", 10),
        ),
        (
            account_notifier.send_challenge,
            ("owner@example.com", "12345678", 10),
        ),
        (
            account_notifier.send_security_notice,
            ("owner@example.com", "device-bound"),
        ),
        (
            outbox_service.adapter.send,
            (
                AeternaEmailEnvelope(
                    "contact@example.com", "Subject", "Body", "<p>Body</p>"
                ),
                "synthetic-event-key",
            ),
        ),
    )
    for send, args in sends:
        with pytest.raises(EmailDeliveryFailure) as exc_info:
            await send(*args)
        failure = exc_info.value
        assert failure.code == "aws-ses-configuration-error"
        assert failure.retryable is False
        assert failure.ambiguous is False
        assert str(failure) == "aws-ses-configuration-error"

    assert len(client_calls) == 3
    assert smtp_calls == []
    for sensitive in (
        "synthetic-sensitive-detail",
        "synthetic-provider",
        "synthetic-missing-variable",
        "owner@example.com",
        "12345678",
    ):
        assert sensitive not in caplog.text


@pytest.mark.parametrize("environment", ["production", "preview"])
@pytest.mark.parametrize(
    "overrides",
    [
        {"AETERNA_EMAIL_PROVIDER": "smtp"},
        {"AWS_SES_REGION": ""},
        {"AWS_SES_CONFIGURATION_SET": "invalid configuration set"},
        {"AWS_SES_SNS_TOPIC_ARN": "arn:aws:sns:eu-west-1:123456789012:aeterna-events"},
        {"AWS_SES_FROM_ADDRESS": "not-an-address"},
    ],
)
def test_enabled_deployed_configuration_rejects_partial_or_invalid_ses_settings(
    monkeypatch, environment, overrides
):
    configure_email_delivery(
        monkeypatch, environment=environment, enabled=True, **overrides
    )

    with pytest.raises(RuntimeError):
        validate_email_delivery_configuration()
    assert isinstance(get_aeterna_email_adapter(), UnavailableProductionEmailAdapter)


@pytest.mark.parametrize("environment", ["production", "preview"])
def test_disabled_deployed_configuration_does_not_require_ses_settings(
    monkeypatch, environment
):
    configure_email_delivery(
        monkeypatch,
        environment=environment,
        enabled=False,
        AETERNA_EMAIL_PROVIDER="disabled",
        AWS_SES_REGION="",
        AWS_SES_FROM_ADDRESS="",
        AWS_SES_CONFIGURATION_SET="",
        AWS_SES_SNS_TOPIC_ARN="",
    )

    validate_email_delivery_configuration()
    assert isinstance(get_aeterna_email_adapter(), UnavailableProductionEmailAdapter)


@pytest.mark.parametrize(
    "environment", ["development", "preview", "production", "test"]
)
def test_smtp_sink_is_selected_only_for_explicit_development(monkeypatch, environment):
    configure_email_delivery(monkeypatch, environment=environment, enabled=False)

    adapter = get_aeterna_email_adapter()

    expected = (
        SmtpDevelopmentEmailAdapter
        if environment == "development"
        else UnavailableProductionEmailAdapter
    )
    assert isinstance(adapter, expected)


@pytest.mark.parametrize("enabled", [False, True])
def test_unknown_environment_never_enables_any_transport(monkeypatch, enabled):
    configure_email_delivery(monkeypatch, environment="unknown", enabled=enabled)
    created = []
    monkeypatch.setattr(
        "app.services.common.aeterna_email_adapter.boto3.client",
        lambda *args, **kwargs: created.append((args, kwargs)),
    )

    assert isinstance(get_email_service().adapter, UnavailableProductionEmailAdapter)
    assert isinstance(
        get_aeterna_email_delivery_service().adapter, UnavailableProductionEmailAdapter
    )
    assert created == []


@pytest.mark.asyncio
@pytest.mark.parametrize("environment", ["preview", "production", "test"])
async def test_smtp_adapter_rejects_non_development_before_transport(
    monkeypatch, environment
):
    configure_email_delivery(monkeypatch, environment=environment, enabled=False)
    monkeypatch.setattr(
        "app.services.common.aeterna_email_adapter.settings.MAIL_HOST", "mailpit"
    )
    transport_calls = []

    async def send(*args, **kwargs):
        transport_calls.append((args, kwargs))

    monkeypatch.setattr(
        "app.services.common.aeterna_email_adapter.aiosmtplib.send", send
    )
    with pytest.raises(EmailDeliveryFailure) as exc_info:
        await SmtpDevelopmentEmailAdapter().send(
            AeternaEmailEnvelope("user@example.com", "Subject", "Body", "<p>Body</p>"),
            "synthetic-event-key",
        )

    assert exc_info.value.code == "development-smtp-environment-not-local"
    assert exc_info.value.retryable is False
    assert transport_calls == []


@pytest.mark.asyncio
async def test_aws_ses_adapter_uses_simple_content_and_stable_trace_tag():
    client = FakeSesClient()
    adapter = AwsSesEmailAdapter(
        client=client,
        from_address="noreply@example.com",
        configuration_set="aeterna-events",
        clock=lambda: NOW,
    )
    envelope = AeternaEmailEnvelope(
        recipient="contact@example.com",
        subject="Fixed subject",
        text_body="Plain text",
        html_body="<p>Escaped HTML</p>",
    )
    first = await adapter.send(envelope, "stable-event-key")
    second = await adapter.send(envelope, "stable-event-key")

    assert first.provider_message_id == "ses-message-1"
    assert second.accepted_at == NOW
    assert adapter.supports_idempotency is False
    request = client.calls[0]
    assert request["FromEmailAddress"] == "noreply@example.com"
    assert request["Destination"] == {"ToAddresses": ["contact@example.com"]}
    assert set(request["Content"]) == {"Simple"}
    assert "Raw" not in request["Content"]
    assert request["ConfigurationSetName"] == "aeterna-events"
    assert client.calls[0]["EmailTags"] == client.calls[1]["EmailTags"]
    assert len(request["EmailTags"][0]["Value"]) == 64
    assert [tag["Name"] for tag in request["EmailTags"]] == ["aeterna-event"]


@pytest.mark.asyncio
async def test_immediate_mail_uses_fixed_marker_without_exposing_message_data():
    client = FakeSesClient()
    adapter = AwsSesEmailAdapter(
        client=client,
        from_address="noreply@example.com",
        configuration_set="aeterna-events",
    )

    await adapter.send(
        AeternaEmailEnvelope(
            "owner@example.com",
            "Fixed subject",
            "12345678",
            "<p>12345678</p>",
            track_in_outbox=False,
        ),
        "synthetic-event-key",
    )

    tags = {tag["Name"]: tag["Value"] for tag in client.calls[0]["EmailTags"]}
    assert set(tags) == {"aeterna-event", "aeterna-delivery"}
    assert len(tags["aeterna-event"]) == 64
    assert tags["aeterna-delivery"] == "immediate"
    for sensitive in ("owner@example.com", "12345678", "synthetic-event-key"):
        assert sensitive not in repr(tags)


@pytest.mark.asyncio
async def test_aws_ses_adapter_classifies_throttling_without_claiming_idempotency():
    client = FakeSesClient(
        error=ClientError(
            {
                "Error": {"Code": "TooManyRequestsException", "Message": "masked"},
                "ResponseMetadata": {"HTTPStatusCode": 429},
            },
            "SendEmail",
        )
    )
    adapter = AwsSesEmailAdapter(
        client=client,
        from_address="noreply@example.com",
        configuration_set="aeterna-events",
    )
    with pytest.raises(EmailDeliveryFailure) as exc_info:
        await adapter.send(
            AeternaEmailEnvelope("a@example.com", "subject", "text", "<p>text</p>"),
            "stable-event-key",
        )
    assert exc_info.value.code == "aws-ses-throttled"
    assert exc_info.value.retryable is True
    assert exc_info.value.ambiguous is False
    assert adapter.supports_idempotency is False
    assert len(client.calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response,error,code",
    [
        (
            None,
            ReadTimeoutError(endpoint_url="https://synthetic-ses.example.com"),
            "aws-ses-outcome-ambiguous",
        ),
        ({}, None, "aws-ses-invalid-acceptance"),
        ({"MessageId": ""}, None, "aws-ses-invalid-acceptance"),
        ({"MessageId": "invalid\nmessage-id"}, None, "aws-ses-invalid-acceptance"),
    ],
)
async def test_aws_ses_ambiguous_results_are_redacted_and_never_retried(
    response, error, code
):
    client = FakeSesClient(response=response, error=error)
    adapter = AwsSesEmailAdapter(
        client=client,
        from_address="noreply@example.com",
        configuration_set="aeterna-events",
    )

    with pytest.raises(EmailDeliveryFailure) as exc_info:
        await adapter.send(
            AeternaEmailEnvelope(
                "user@example.com", "Synthetic subject", "12345678", "<p>12345678</p>"
            ),
            "synthetic-event-key",
        )

    assert exc_info.value.code == code
    assert exc_info.value.retryable is False
    assert exc_info.value.ambiguous is True
    assert len(client.calls) == 1
    for sensitive in ("user@example.com", "12345678", "synthetic-event-key"):
        assert sensitive not in str(exc_info.value)


@pytest.mark.asyncio
async def test_aws_ses_adapter_rejects_invalid_recipient_before_provider_call():
    client = FakeSesClient()
    adapter = AwsSesEmailAdapter(
        client=client,
        from_address="noreply@example.com",
        configuration_set="aeterna-events",
    )

    with pytest.raises(EmailDeliveryFailure) as exc_info:
        await adapter.send(
            AeternaEmailEnvelope("not-an-address", "subject", "text", "<p>text</p>"),
            "stable-event-key",
        )

    assert exc_info.value.code == "aws-ses-envelope-invalid"
    assert exc_info.value.retryable is False
    assert client.calls == []


def signing_material():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Amazon SNS Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "sns.amazonaws.com"),
        ]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )
    return private_key, certificate.public_bytes(serialization.Encoding.PEM)


def sns_body(event_type: str, private_key, **event_members) -> bytes:
    inner = {
        "eventType": event_type,
        "mail": {
            "messageId": "ses-message-1",
            "timestamp": "2026-09-27T12:00:00Z",
        },
        **event_members,
    }
    outer = {
        "Type": "Notification",
        "MessageId": "11111111-2222-4333-8444-555555555555",
        "TopicArn": TOPIC_ARN,
        "Message": json.dumps(inner, separators=(",", ":")),
        "Timestamp": "2026-09-27T12:00:01Z",
        "SignatureVersion": "2",
        "SigningCertURL": CERTIFICATE_URL,
    }
    fields = ["Message", "MessageId", "Timestamp", "TopicArn", "Type"]
    canonical = "".join(f"{field}\n{outer[field]}\n" for field in fields).encode()
    outer["Signature"] = base64.b64encode(
        private_key.sign(canonical, padding.PKCS1v15(), hashes.SHA256())
    ).decode()
    return json.dumps(outer, separators=(",", ":")).encode()


def confirmation_body(private_key, **overrides) -> bytes:
    token = "synthetic-confirmation-token"
    outer = {
        "Type": "SubscriptionConfirmation",
        "MessageId": "11111111-2222-4333-8444-555555555555",
        "TopicArn": TOPIC_ARN,
        "Message": "Confirm the synthetic subscription.",
        "Token": token,
        "SubscribeURL": "https://sns.ap-southeast-1.amazonaws.com/?"
        + urlencode(
            {"Action": "ConfirmSubscription", "TopicArn": TOPIC_ARN, "Token": token}
        ),
        "Timestamp": NOW.isoformat(),
        "SignatureVersion": "2",
        "SigningCertURL": CERTIFICATE_URL,
        **overrides,
    }
    fields = [
        "Message",
        "MessageId",
        "SubscribeURL",
        "Timestamp",
        "Token",
        "TopicArn",
        "Type",
    ]
    canonical = "".join(f"{field}\n{outer[field]}\n" for field in fields).encode()
    outer["Signature"] = base64.b64encode(
        private_key.sign(canonical, padding.PKCS1v15(), hashes.SHA256())
    ).decode()
    return json.dumps(outer).encode()


@pytest.mark.asyncio
async def test_confirmation_requires_separate_verification_and_hides_token():
    private_key, certificate = signing_material()

    async def load_certificate(url):
        assert url == CERTIFICATE_URL
        return certificate

    verifier = AwsSnsMessageVerifier(
        topic_arn=TOPIC_ARN, certificate_loader=load_certificate, clock=lambda: NOW
    )
    body = confirmation_body(private_key)
    with pytest.raises(AwsSnsVerificationError, match="type"):
        await verifier.verify_and_extract(body, "SubscriptionConfirmation")
    confirmation = await verifier.verify_subscription_confirmation(
        body, "SubscriptionConfirmation"
    )
    assert confirmation.token == "synthetic-confirmation-token"
    assert confirmation.topic_arn == TOPIC_ARN
    assert confirmation.token not in repr(confirmation)
    assert confirmation.subscribe_url not in repr(confirmation)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides",
    [
        {"TopicArn": TOPIC_ARN + "-other"},
        {"SignatureVersion": "1"},
        {"SubscribeURL": "https://example.com/confirmation"},
        {"SubscribeURL": "https://[malformed/confirmation"},
        {
            "SubscribeURL": "https://sns.ap-southeast-1.amazonaws.com/?Action=ConfirmSubscription"
        },
        {"Token": "different-synthetic-token"},
        {"Timestamp": (NOW - timedelta(minutes=16)).isoformat()},
        {"Timestamp": (NOW + timedelta(minutes=6)).isoformat()},
    ],
)
async def test_confirmation_rejects_wrong_topic_url_token_version_or_age(overrides):
    private_key, certificate = signing_material()

    async def load_certificate(_url):
        return certificate

    verifier = AwsSnsMessageVerifier(
        topic_arn=TOPIC_ARN, certificate_loader=load_certificate, clock=lambda: NOW
    )
    with pytest.raises(AwsSnsVerificationError):
        await verifier.verify_subscription_confirmation(
            confirmation_body(private_key, **overrides), "SubscriptionConfirmation"
        )


@pytest.mark.asyncio
async def test_confirmation_rejects_tampered_signed_fields():
    private_key, certificate = signing_material()

    async def load_certificate(_url):
        return certificate

    verifier = AwsSnsMessageVerifier(
        topic_arn=TOPIC_ARN, certificate_loader=load_certificate, clock=lambda: NOW
    )
    document = json.loads(confirmation_body(private_key))
    document["Token"] = "tampered-synthetic-token"
    with pytest.raises(AwsSnsVerificationError, match="signature"):
        await verifier.verify_subscription_confirmation(
            json.dumps(document).encode(), "SubscriptionConfirmation"
        )


@pytest.mark.asyncio
async def test_signed_sns_events_map_delivery_complaint_and_ignore_tracking():
    private_key, certificate = signing_material()
    certificate_loads = 0

    async def load_certificate(url):
        nonlocal certificate_loads
        certificate_loads += 1
        assert url == CERTIFICATE_URL
        return certificate

    verifier = AwsSnsMessageVerifier(
        topic_arn=TOPIC_ARN,
        certificate_loader=load_certificate,
        clock=lambda: NOW,
    )
    delivered = await verifier.verify_and_extract(
        sns_body(
            "Delivery",
            private_key,
            delivery={"timestamp": "2026-09-27T12:00:02Z"},
        ),
        "Notification",
    )
    assert delivered is not None
    assert delivered.callback_type == "delivered"
    assert delivered.provider_message_id == "ses-message-1"

    complaint = await verifier.verify_and_extract(
        sns_body(
            "Complaint",
            private_key,
            complaint={"timestamp": "2026-09-27T12:00:03Z"},
        ),
        "Notification",
    )
    assert complaint is not None
    assert complaint.callback_type == "complained"
    assert complaint.reason_code == "provider-complaint"

    assert (
        await verifier.verify_and_extract(sns_body("Open", private_key), "Notification")
        is None
    )
    assert (
        await verifier.verify_and_extract(
            sns_body("Click", private_key), "Notification"
        )
        is None
    )
    assert certificate_loads == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tags",
    [
        {"aeterna-delivery": ["immediate"]},
        {"aeterna-delivery": ["immediate"], "aeterna-event": ["synthetic-hash"]},
    ],
)
async def test_signed_immediate_mail_callback_is_ignored_by_outbox_verifier(tags):
    private_key, certificate = signing_material()

    async def load_certificate(_url):
        return certificate

    verifier = AwsSnsMessageVerifier(
        topic_arn=TOPIC_ARN, certificate_loader=load_certificate, clock=lambda: NOW
    )
    body = sns_body(
        "Delivery",
        private_key,
        mail={
            "messageId": "ses-message-1",
            "timestamp": "2026-09-27T12:00:00Z",
            "tags": tags,
        },
        delivery={"timestamp": "2026-09-27T12:00:02Z"},
    )

    assert await verifier.verify_and_extract(body, "Notification") is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mail_tags",
    [
        {},
        {"tags": {"aeterna-event": ["synthetic-hash"]}},
        {"tags": {"aeterna-delivery": ["unknown"]}},
        {"tags": {"aeterna-delivery": ["immediate", "other"]}},
        {"tags": {"aeterna-delivery": "immediate"}},
        {"tags": {"aeterna-delivery": None}},
        {"tags": ["immediate"]},
        {"tags": None},
    ],
)
async def test_missing_unknown_or_malformed_marker_preserves_signed_outbox_callback(
    mail_tags,
):
    private_key, certificate = signing_material()

    async def load_certificate(_url):
        return certificate

    verifier = AwsSnsMessageVerifier(
        topic_arn=TOPIC_ARN, certificate_loader=load_certificate, clock=lambda: NOW
    )
    body = sns_body(
        "Delivery",
        private_key,
        mail={
            "messageId": "ses-message-1",
            "timestamp": "2026-09-27T12:00:00Z",
            **mail_tags,
        },
        delivery={"timestamp": "2026-09-27T12:00:02Z"},
    )

    event = await verifier.verify_and_extract(body, "Notification")

    assert event is not None
    assert event.callback_type == "delivered"
    assert event.provider_message_id == "ses-message-1"


@pytest.mark.asyncio
async def test_unsigned_immediate_marker_cannot_suppress_outbox_callback():
    private_key, certificate = signing_material()

    async def load_certificate(_url):
        return certificate

    verifier = AwsSnsMessageVerifier(
        topic_arn=TOPIC_ARN, certificate_loader=load_certificate, clock=lambda: NOW
    )
    document = json.loads(
        sns_body(
            "Delivery",
            private_key,
            delivery={"timestamp": "2026-09-27T12:00:02Z"},
        )
    )
    message = json.loads(document["Message"])
    message["mail"]["tags"] = {"aeterna-delivery": ["immediate"]}
    document["Message"] = json.dumps(message, separators=(",", ":"))

    with pytest.raises(AwsSnsVerificationError, match="signature"):
        await verifier.verify_and_extract(json.dumps(document).encode(), "Notification")


@pytest.mark.asyncio
async def test_sns_verifier_rejects_tampering_and_untrusted_certificate_url():
    private_key, certificate = signing_material()

    async def load_certificate(_url):
        return certificate

    verifier = AwsSnsMessageVerifier(
        topic_arn=TOPIC_ARN,
        certificate_loader=load_certificate,
        clock=lambda: NOW,
    )
    document = json.loads(sns_body("Delivery", private_key))
    document["Message"] = document["Message"].replace("Delivery", "Complaint")
    with pytest.raises(AwsSnsVerificationError, match="signature"):
        await verifier.verify_and_extract(json.dumps(document).encode(), "Notification")

    document = json.loads(sns_body("Delivery", private_key))
    document["SigningCertURL"] = "https://example.com/certificate.pem"
    with pytest.raises(AwsSnsVerificationError, match="URL"):
        await verifier.verify_and_extract(json.dumps(document).encode(), "Notification")
