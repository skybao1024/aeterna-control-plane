"""Closed API schemas for Aeterna contacts and v1 email notifications."""

import unicodedata
from typing import Annotated, Literal, Optional

from pydantic import Field, model_validator

from app.schemas.client.aeterna_protocol import (
    Base64Url32,
    Base64Url64,
    ClosedModel,
    SignedHeader,
    Timestamp,
    UuidString,
)

DisclosureMode = Literal["CONFIRM_NOW", "PRIVATE_UNTIL_RELEASE"]
ConsentStatus = Literal["NOT_REQUESTED", "INVITED", "ACCEPTED", "DECLINED"]
DeliveryStatus = Literal[
    "queued",
    "sending",
    "retry_pending",
    "provider_accepted",
    "delivered",
    "bounced",
    "complained",
    "ambiguous",
    "failed",
    "cancelled",
]
BoundedMessage = Annotated[str, Field(max_length=4096)]


def _validate_message(value: str) -> str:
    if value != unicodedata.normalize("NFC", value):
        raise ValueError("notification text must use NFC normalization")
    if len(value.encode("utf-8")) > 4096:
        raise ValueError("notification text exceeds the 4096-byte limit")
    if any(
        unicodedata.category(character).startswith("C")
        and character not in {"\n", "\t"}
        for character in value
    ):
        raise ValueError("notification text contains a forbidden control character")
    return value


class ContactCreateSigned(SignedHeader):
    domain: Literal["aeterna.contact.create.v1"]
    operation: Literal["contact.create"]
    account_id: UuidString
    authorizing_device_id: UuidString
    email: Annotated[str, Field(min_length=3, max_length=254)]
    disclosure_mode: DisclosureMode


class ContactCreateRequest(ClosedModel):
    protocol_version: Literal[1]
    signed: ContactCreateSigned
    signature: Base64Url64


class ContactActionSigned(SignedHeader):
    domain: Literal[
        "aeterna.contact.invite.v1",
        "aeterna.contact.delete.v1",
        "aeterna.contact.status.v1",
        "aeterna.notification.test.v1",
    ]
    operation: Literal[
        "contact.invite",
        "contact.delete",
        "contact.status",
        "notification.test",
    ]
    account_id: UuidString
    authorizing_device_id: UuidString
    contact_id: UuidString

    @model_validator(mode="after")
    def validate_domain_operation_pair(self) -> "ContactActionSigned":
        expected = {
            "contact.invite": "aeterna.contact.invite.v1",
            "contact.delete": "aeterna.contact.delete.v1",
            "contact.status": "aeterna.contact.status.v1",
            "notification.test": "aeterna.notification.test.v1",
        }[self.operation]
        if self.domain != expected:
            raise ValueError("domain does not match operation")
        return self


class ContactActionRequest(ClosedModel):
    protocol_version: Literal[1]
    signed: ContactActionSigned
    signature: Base64Url64


class NotificationTemplateSigned(SignedHeader):
    domain: Literal["aeterna.notification-template.update.v1"]
    operation: Literal["notification_template.update"]
    account_id: UuidString
    authorizing_device_id: UuidString
    owner_message: BoundedMessage
    contact_message: BoundedMessage

    @model_validator(mode="after")
    def validate_messages(self) -> "NotificationTemplateSigned":
        self.owner_message = _validate_message(self.owner_message)
        self.contact_message = _validate_message(self.contact_message)
        return self


class NotificationTemplateRequest(ClosedModel):
    protocol_version: Literal[1]
    signed: NotificationTemplateSigned
    signature: Base64Url64


class ContactInvitationResponseRequest(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    token: Base64Url32
    decision: Literal["accept", "decline"]


class ContactData(ClosedModel):
    account_id: UuidString
    contact_id: UuidString
    disclosure_mode: DisclosureMode
    consent_status: ConsentStatus
    is_recovery_contact: bool
    deleted: bool
    last_delivery_status: Optional[DeliveryStatus] = None
    bounced_at: Optional[Timestamp] = None


class ContactResponse(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    data: ContactData


class InvitationResponseData(ClosedModel):
    processed: Literal[True]


class InvitationResponse(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    data: InvitationResponseData


class NotificationTemplateData(ClosedModel):
    account_id: UuidString
    version: Annotated[int, Field(ge=1)]


class NotificationTemplateResponse(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    data: NotificationTemplateData
