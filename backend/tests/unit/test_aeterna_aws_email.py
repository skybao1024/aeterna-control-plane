"""Local-only contract tests for the AWS SES and signed SNS boundaries."""

import base64
import json
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

import pytest
from botocore.exceptions import ClientError
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
    get_aeterna_email_adapter,
    validate_email_delivery_configuration,
)

NOW = datetime(2026, 9, 27, 12, tzinfo=UTC)
TOPIC_ARN = "arn:aws:sns:ap-southeast-1:123456789012:aeterna-ses-events"
CERTIFICATE_URL = (
    "https://sns.ap-southeast-1.amazonaws.com/" "SimpleNotificationService-test.pem"
)


class FakeSesClient:
    def __init__(self, response=None, error=None):
        self.response = response or {"MessageId": "ses-message-1"}
        self.error = error
        self.calls = []

    def send_email(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.response


def test_production_factory_requires_explicit_complete_aws_ses_enablement(
    monkeypatch,
):
    client = FakeSesClient()
    created = {}

    def create_client(service_name, **kwargs):
        created["service_name"] = service_name
        created.update(kwargs)
        return client

    settings = "app.services.common.aeterna_email_adapter.settings"
    monkeypatch.setattr(f"{settings}.ENV", "production")
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
    assert created["service_name"] == "sesv2"
    assert created["region_name"] == "ap-southeast-1"
    assert created["config"].retries["total_max_attempts"] == 1


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
