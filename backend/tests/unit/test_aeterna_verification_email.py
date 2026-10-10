"""Account and template mail share one constrained, local-tested provider boundary."""

import logging
from datetime import UTC, datetime

import pytest
from botocore.exceptions import ClientError, ReadTimeoutError
from jinja2 import TemplateNotFound

from app.services.common.aeterna_email_adapter import (
    AwsSesEmailAdapter,
    EmailDeliveryFailure,
)
from app.services.common.aeterna_notifier import EmailAeternaAccountNotifier
from app.services.common.email import EmailService, jinja_env

NOW = datetime(2026, 10, 9, 12, tzinfo=UTC)


class RecordingSesClient:
    def __init__(self, response=None, error=None):
        self.response = (
            {"MessageId": "synthetic-acceptance"} if response is None else response
        )
        self.error = error
        self.calls = []

    def send_email(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.response


def email_service(client):
    return EmailService(
        adapter=AwsSesEmailAdapter(
            client=client,
            from_address="noreply@example.com",
            configuration_set="aeterna-events",
            clock=lambda: NOW,
        )
    )


def test_verification_template_renders_supplied_lifetime() -> None:
    template = jinja_env.get_template("auth/verification.html")

    for minutes in (5, 10):
        rendered = template.render(
            first_name="Synthetic user",
            verification_code="12345678",
            expires_in_minutes=minutes,
        )
        assert f"{minutes} minutes" in rendered


@pytest.mark.asyncio
async def test_owner_notifier_challenge_and_security_notice_use_one_ses_boundary():
    client = RecordingSesClient()
    notifier = EmailAeternaAccountNotifier(email_service(client))

    assert await notifier.send_challenge("owner@example.com", "12345678", 10) is True
    assert (
        await notifier.send_security_notice("owner@example.com", "device-bound") is True
    )

    assert len(client.calls) == 2
    challenge, security = client.calls
    for request in client.calls:
        assert request["FromEmailAddress"] == "noreply@example.com"
        assert request["ConfigurationSetName"] == "aeterna-events"
        assert request["Destination"] == {"ToAddresses": ["owner@example.com"]}
        assert set(request["Content"]) == {"Simple"}
        assert len(request["EmailTags"][0]["Value"]) == 64
        tags = {tag["Name"]: tag["Value"] for tag in request["EmailTags"]}
        assert tags["aeterna-delivery"] == "immediate"

    content = challenge["Content"]["Simple"]
    assert content["Subject"]["Data"] == "Verify your Aeterna Relay email address"
    assert content["Body"]["Html"]["Data"] == jinja_env.get_template(
        "auth/verification.html"
    ).render(
        first_name="Aeterna Relay user",
        verification_code="12345678",
        expires_in_minutes=10,
    )
    text = " ".join(content["Body"]["Text"]["Data"].split())
    assert "12345678" in text
    assert "10 minutes" in text
    assert "Do not share this code" in text
    assert "box-sizing" not in text

    security_content = security["Content"]["Simple"]
    assert (
        security_content["Subject"]["Data"] == "Aeterna Relay account security notice"
    )
    assert "Event: device-bound" in security_content["Body"]["Text"]["Data"]


@pytest.mark.asyncio
async def test_password_reset_template_uses_ses_without_changing_rendered_html():
    client = RecordingSesClient()
    service = email_service(client)
    params = {
        "first_name": "Synthetic user",
        "reset_url": "https://example.com/reset?token=synthetic-token&source=email",
    }

    assert (
        await service.send_with_template(
            to_emails="user@example.com",
            template_name="auth/password-reset.html",
            template_params=params,
            subject="Reset your password",
        )
        is True
    )

    assert len(client.calls) == 1
    content = client.calls[0]["Content"]["Simple"]
    body = content["Body"]
    assert body["Html"]["Data"] == jinja_env.get_template(
        "auth/password-reset.html"
    ).render(**params)
    text = " ".join(body["Text"]["Data"].split())
    assert "Reset password" in text
    assert "30 minutes" in text
    assert params["reset_url"] in text
    assert "font-family" not in text
    assert "max-width" not in text


@pytest.mark.asyncio
@pytest.mark.parametrize("recipient", ["user@example.com", ["user@example.com"]])
async def test_single_recipient_html_produces_readable_plaintext_with_link(recipient):
    client = RecordingSesClient()
    html = (
        "<html><head><title>Hidden heading</title><style>Hidden CSS</style></head>"
        "<body><p>Hello &amp; welcome.</p>"
        '<a href="https://example.com/action?one=1&amp;two=2">Open action</a>'
        "</body></html>"
    )

    assert await email_service(client).send(recipient, "Fixed subject", html) is True

    assert len(client.calls) == 1
    request = client.calls[0]
    assert request["Destination"] == {"ToAddresses": ["user@example.com"]}
    body = request["Content"]["Simple"]["Body"]
    assert body["Html"]["Data"] == html
    text = body["Text"]["Data"]
    assert "Hello & welcome." in text
    assert "Open action" in text
    assert "https://example.com/action?one=1&two=2" in text
    assert "Hidden heading" not in text
    assert "Hidden CSS" not in text


@pytest.mark.asyncio
@pytest.mark.parametrize("recipients", [[], ["a@example.com", "b@example.com"]])
async def test_generic_mail_rejects_multiple_or_missing_recipients(recipients):
    client = RecordingSesClient()

    with pytest.raises(EmailDeliveryFailure) as exc_info:
        await email_service(client).send(recipients, "Fixed subject", "<p>Body</p>")

    assert exc_info.value.code == "email-recipient-count-invalid"
    assert exc_info.value.retryable is False
    assert client.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides",
    [{"from_email": "other@example.com"}, {"from_name": "Synthetic sender"}],
)
async def test_generic_mail_rejects_caller_sender_overrides(overrides):
    client = RecordingSesClient()

    with pytest.raises(EmailDeliveryFailure) as exc_info:
        await email_service(client).send(
            "user@example.com", "Fixed subject", "<p>Body</p>", **overrides
        )

    assert exc_info.value.code == "email-sender-override-forbidden"
    assert exc_info.value.retryable is False
    assert client.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("html", ["", "  \n\t"])
async def test_empty_html_does_not_call_provider(html):
    client = RecordingSesClient()

    assert (
        await email_service(client).send("user@example.com", "Subject", html) is False
    )
    assert client.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response,error,code,retryable,ambiguous",
    [
        (
            None,
            ReadTimeoutError(endpoint_url="https://synthetic-ses.example.com"),
            "aws-ses-outcome-ambiguous",
            False,
            True,
        ),
        ({}, None, "aws-ses-invalid-acceptance", False, True),
        (
            None,
            ClientError(
                {
                    "Error": {
                        "Code": "TooManyRequestsException",
                        "Message": "user@example.com 12345678 synthetic-provider-detail",
                    },
                    "ResponseMetadata": {"HTTPStatusCode": 429},
                },
                "SendEmail",
            ),
            "aws-ses-throttled",
            True,
            False,
        ),
    ],
)
async def test_generic_ses_failures_make_one_call_without_fallback_or_payload_logs(
    response, error, code, retryable, ambiguous, caplog
):
    client = RecordingSesClient(response=response, error=error)

    with caplog.at_level(logging.DEBUG, logger="email_service"):
        with pytest.raises(EmailDeliveryFailure) as exc_info:
            await email_service(client).send_verification_email(
                "user@example.com", "Synthetic user", "12345678", 10
            )

    failure = exc_info.value
    assert (failure.code, failure.retryable, failure.ambiguous) == (
        code,
        retryable,
        ambiguous,
    )
    assert len(client.calls) == 1
    for sensitive in ("user@example.com", "12345678", "synthetic-provider-detail"):
        assert sensitive not in caplog.text
        assert sensitive not in str(failure)


@pytest.mark.asyncio
async def test_classified_failure_is_preserved_without_provider_retry():
    failure = EmailDeliveryFailure("synthetic-redacted-failure", retryable=False)

    class FailingAdapter:
        provider_name = "synthetic-provider"
        supports_idempotency = False

        def __init__(self):
            self.calls = 0

        async def send(self, envelope, idempotency_key):
            self.calls += 1
            raise failure

    adapter = FailingAdapter()
    with pytest.raises(EmailDeliveryFailure) as exc_info:
        await EmailService(adapter=adapter).send(
            "user@example.com", "Fixed subject", "<p>Body</p>"
        )

    assert exc_info.value is failure
    assert adapter.calls == 1


@pytest.mark.asyncio
async def test_unexpected_provider_failure_is_ambiguous_and_redacted(caplog):
    detail = "user@example.com 12345678 synthetic-provider-detail"
    client = RecordingSesClient(error=RuntimeError(detail))

    with caplog.at_level(logging.DEBUG, logger="email_service"):
        with pytest.raises(EmailDeliveryFailure) as exc_info:
            await email_service(client).send_verification_email(
                "user@example.com", "Synthetic user", "12345678", 10
            )

    assert exc_info.value.code == "provider-failure-ambiguous"
    assert exc_info.value.retryable is False
    assert exc_info.value.ambiguous is True
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__suppress_context__ is True
    assert len(client.calls) == 1
    for sensitive in detail.split():
        assert sensitive not in str(exc_info.value)
        assert sensitive not in caplog.text


@pytest.mark.asyncio
async def test_missing_template_propagates_without_provider_call_or_payload_log(caplog):
    client = RecordingSesClient()
    template_name = "auth/synthetic-private-template.html"

    with caplog.at_level(logging.DEBUG, logger="email_service"):
        with pytest.raises(TemplateNotFound):
            await email_service(client).send_with_template(
                to_emails="user@example.com",
                template_name=template_name,
                template_params={"verification_code": "12345678"},
                subject="Fixed subject",
            )

    assert client.calls == []
    for sensitive in (template_name, "user@example.com", "12345678"):
        assert sensitive not in caplog.text
