"""Boundary validation tests for Aeterna I12 notification schemas."""

import uuid

import pytest
from pydantic import ValidationError

from app.schemas.client.aeterna_notification import (
    ContactCreateRequest,
    NotificationTemplateEditRequest,
    NotificationTemplateRequest,
    OwnerConfigurationRequest,
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


@pytest.mark.parametrize(
    "message", ["a" * 4097, "é" * 2049, "forbidden\u0000control", "e\u0301"]
)
def test_field_edit_rejects_overflow_control_and_non_nfc(message):
    document = template_document("", "")
    signed = document["signed"]
    signed.pop("owner_message")
    signed.pop("contact_message")
    signed.update(
        domain="aeterna.notification-template.edit.v1",
        operation="notification_template.edit",
        field="owner_message",
        expected_version=0,
        message=message,
    )
    with pytest.raises(ValidationError):
        NotificationTemplateEditRequest.model_validate(document)


@pytest.mark.parametrize(
    "ids",
    [
        ["00000000-0000-4000-8000-000000000001"] * 2,
        [str(uuid.uuid4()) for _ in range(11)],
    ],
)
def test_identity_read_rejects_duplicate_or_excessive_contact_ids(ids):
    document = template_document("", "")
    signed = document["signed"]
    signed.pop("owner_message")
    signed.pop("contact_message")
    signed.update(
        domain="aeterna.owner-configuration.read.v1",
        operation="owner_configuration.read",
        contact_ids=ids,
    )
    with pytest.raises(ValidationError):
        OwnerConfigurationRequest.model_validate(document)
