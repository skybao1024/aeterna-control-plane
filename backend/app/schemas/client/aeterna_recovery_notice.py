"""Closed signed read of the current released policy's email notice evidence."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.client.aeterna_protocol import (
    Base64Url64,
    ClosedModel,
    SignedHeader,
    Timestamp,
    UuidString,
)


class RecoveryNoticeSigned(SignedHeader):
    domain: Literal["aeterna.recovery-notice.read.v1"]
    operation: Literal["recovery_notice.read"]
    account_id: UuidString
    authorizing_device_id: UuidString
    contact_ids: Annotated[list[UuidString], Field(max_length=10)]

    @model_validator(mode="after")
    def validate_contact_ids(self) -> "RecoveryNoticeSigned":
        if len(set(self.contact_ids)) != len(self.contact_ids):
            raise ValueError("contact identifiers must be unique")
        return self


class RecoveryNoticeRequest(ClosedModel):
    protocol_version: Literal[1]
    signed: RecoveryNoticeSigned
    signature: Base64Url64


class RecoveryNoticeRecipient(ClosedModel):
    contact_id: UuidString
    email: Annotated[str, Field(min_length=3, max_length=254)]
    kind: Literal["release", "invitation"]
    status: Literal["pending", "submitted", "delivered", "failed", "unknown"]


class RecoveryNoticeData(BaseModel):
    # Nulls are explicit absence in this read-only response, never request fields.
    model_config = ConfigDict(extra="forbid")

    account_id: UuidString
    device_id: UuidString
    observed_at: Timestamp
    state: Literal[
        "NOT_CONFIGURED",
        "ACTIVE",
        "PRE_WARNING",
        "GRACE_PERIOD",
        "RELEASED",
        "DISABLED",
        "DELETED",
    ]
    epoch: Annotated[int, Field(strict=True, ge=1, le=2_147_483_647)] | None
    last_activity_at: Timestamp | None
    released_at: Timestamp | None
    recipients: Annotated[list[RecoveryNoticeRecipient], Field(max_length=10)]

    @model_validator(mode="after")
    def validate_release_scope(self) -> "RecoveryNoticeData":
        if self.state == "RELEASED":
            if any(
                value is None
                for value in (self.epoch, self.last_activity_at, self.released_at)
            ):
                raise ValueError("released notice requires exact policy timing")
        elif self.released_at is not None or self.recipients:
            raise ValueError("recipient notice evidence requires released policy")
        if len({value.contact_id for value in self.recipients}) != len(self.recipients):
            raise ValueError("recipient identifiers must be unique")
        return self


class RecoveryNoticeResponse(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    data: RecoveryNoticeData


class RecoveryNoticeResendSigned(SignedHeader):
    domain: Literal["aeterna.recovery-notice.resend.v1"]
    operation: Literal["recovery_notice.resend"]
    account_id: UuidString
    authorizing_device_id: UuidString
    contact_id: UuidString


class RecoveryNoticeResendRequest(ClosedModel):
    protocol_version: Literal[1]
    signed: RecoveryNoticeResendSigned
    signature: Base64Url64


class RecoveryNoticeResendData(ClosedModel):
    account_id: UuidString
    device_id: UuidString
    contact_id: UuidString
    observed_at: Timestamp
    kind: Literal["release", "invitation"]
    status: Literal["pending", "submitted", "delivered", "failed", "unknown"]
    retry_after_seconds: Annotated[int, Field(strict=True, ge=1, le=86_400)]


class RecoveryNoticeResendResponse(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    data: RecoveryNoticeResendData
