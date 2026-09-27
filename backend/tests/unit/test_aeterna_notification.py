"""Boundary validation tests for Aeterna I12 notification schemas."""

import uuid

import pytest
from pydantic import ValidationError

from app.schemas.client.aeterna_notification import (
    ContactCreateRequest,
    NotificationTemplateRequest,
)
from app.services.common.aeterna_email_adapter import (
    UnavailableProductionEmailAdapter,
    get_aeterna_email_adapter,
)
from app.services.common.aeterna_security import InvalidEmail, normalize_email


def template_document(owner_message: str, contact_message: str, **extra):
    return {
        "protocol_version": 1,
        "signed": {
            "canonicalization": "jcs-rfc8785",
            "domain": "aeterna.notification-template.update.v1",
            "operation": "notification_template.update",
            "protocol_version": 1,
            "signature_version": 1,
            "request_id": str(uuid.uuid4()),
            "account_id": str(uuid.uuid4()),
            "authorizing_device_id": str(uuid.uuid4()),
            "owner_message": owner_message,
            "contact_message": contact_message,
            **extra,
        },
        "signature": "A" * 86,
    }


@pytest.mark.parametrize(
    "message",
    ["a" * 4097, "é" * 2049, "forbidden\u0000control"],
)
def test_notification_text_rejects_byte_overflow_and_controls(message):
    with pytest.raises(ValidationError):
        NotificationTemplateRequest.model_validate(template_document(message, "safe"))


def test_notification_schema_rejects_caller_controlled_email_headers():
    with pytest.raises(ValidationError):
        NotificationTemplateRequest.model_validate(
            template_document("safe", "safe", subject="Injected subject")
        )


def test_contact_schema_rejects_unknown_phone_and_sms_fields():
    document = {
        "protocol_version": 1,
        "signed": {
            "canonicalization": "jcs-rfc8785",
            "domain": "aeterna.contact.create.v1",
            "operation": "contact.create",
            "protocol_version": 1,
            "signature_version": 1,
            "request_id": str(uuid.uuid4()),
            "account_id": str(uuid.uuid4()),
            "authorizing_device_id": str(uuid.uuid4()),
            "email": "contact@example.com",
            "disclosure_mode": "CONFIRM_NOW",
            "phone": "+15555550100",
            "channel": "sms",
        },
        "signature": "A" * 86,
    }
    with pytest.raises(ValidationError):
        ContactCreateRequest.model_validate(document)


def test_email_normalization_rejects_header_injection():
    with pytest.raises(InvalidEmail):
        normalize_email("contact@example.com\r\nBcc: attacker@example.com")


def test_production_email_provider_is_fail_closed(monkeypatch):
    monkeypatch.setattr(
        "app.services.common.aeterna_email_adapter.settings.ENV", "production"
    )
    assert isinstance(get_aeterna_email_adapter(), UnavailableProductionEmailAdapter)
