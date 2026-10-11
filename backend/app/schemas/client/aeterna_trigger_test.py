"""Closed schemas for isolated test operations; capabilities remain native-only."""

import re
from datetime import datetime
from typing import Annotated, Literal

from email_validator import EmailNotValidError, validate_email
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from app.schemas.client.aeterna_protocol import Base64Url32, Base64Url64, UuidString
from app.services.common.aeterna_security import decode_base64url

Code = Annotated[str, Field(pattern=r"^[0-9]{8}$", min_length=8, max_length=8)]


def validate_mailbox(value: str) -> str:
    if len(value.encode("utf-8")) > 254:
        raise ValueError("mailbox exceeds its encoded size limit")
    try:
        validate_email(value, check_deliverability=False, test_environment=True)
    except EmailNotValidError:
        raise ValueError("mailbox format is invalid") from None
    return value


Mailbox = Annotated[
    str, Field(min_length=3, max_length=254), AfterValidator(validate_mailbox)
]
RecipientId = Literal["owner"] | UuidString


class TestClosedModel(BaseModel):
    """Explicit null is allowed only where declared; unknown members are rejected."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    @model_validator(mode="before")
    @classmethod
    def reject_boolean_numeric_headers(cls, value):
        if isinstance(value, dict):
            for key in ("protocol_version", "signature_version"):
                if key in value and type(value[key]) is not int:
                    raise ValueError("protocol version must be an integer")
            if (
                "effects_acknowledged" in value
                and value["effects_acknowledged"] is not True
            ):
                raise ValueError("test effects require explicit boolean agreement")
        return value

    @model_validator(mode="after")
    def validate_encoding_and_times(self):
        encoded_fields = {
            "signature": 64,
            "notice_token": 32,
            "claim_token": 32,
            "wrapper_digest": 32,
            "source_srs": 32,
            "target_srs": 32,
        }
        time_fields = {
            "warning_at",
            "due_at",
            "release_at",
            "next_at",
            "expires_at",
            "observed_at",
            "claim_expires_at",
        }
        for key, size in encoded_fields.items():
            value = getattr(self, key, None)
            if value is not None:
                decode_base64url(value, size)
        for key in time_fields:
            value = getattr(self, key, None)
            if value is not None:
                if (
                    len(value) > 36
                    or re.fullmatch(
                        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z",
                        value,
                    )
                    is None
                ):
                    raise ValueError("timestamp must be bounded UTC RFC3339")
                try:
                    parsed = datetime.fromisoformat(value)
                except ValueError:
                    raise ValueError("timestamp is invalid") from None
                if parsed.tzinfo is None:
                    raise ValueError("timestamp must be aware UTC")
        return self


class TriggerTestHeader(TestClosedModel):
    canonicalization: Literal["jcs-rfc8785"]
    domain: str
    operation: str
    protocol_version: Literal[1]
    signature_version: Literal[1]
    request_id: UuidString
    account_id: UuidString
    device_id: UuidString

    @model_validator(mode="after")
    def validate_domain_operation_pair(self):
        operation = self.operation.removeprefix("trigger_test.")
        expected_domain = f"aeterna.trigger-test.{operation.replace('_', '-')}.v1"
        if (
            not self.operation.startswith("trigger_test.")
            or self.domain != expected_domain
        ):
            raise ValueError("domain does not match the test operation")
        return self


class TriggerTestReadSigned(TriggerTestHeader):
    operation: Literal["trigger_test.read"]
    session_id: UuidString | None


class TriggerTestCreateSigned(TriggerTestHeader):
    operation: Literal["trigger_test.create"]
    recipient_contact_id: UuidString | None
    include_recovery: bool = Field(strict=True)
    sample_vault_id: UuidString | None
    locale: Literal["en", "zh-CN"]
    effects_acknowledged: Literal[True]

    @model_validator(mode="after")
    def validate_sample_scope(self):
        if self.include_recovery != (self.sample_vault_id is not None):
            raise ValueError("sample identity must match the selected recovery scope")
        return self


class TriggerTestSessionSigned(TriggerTestHeader):
    operation: Literal[
        "trigger_test.provision",
        "trigger_test.warning_challenge",
        "trigger_test.activity",
        "trigger_test.stop",
        "trigger_test.retry",
    ]
    session_id: UuidString


class TriggerTestActivateSigned(TriggerTestHeader):
    operation: Literal["trigger_test.activate"]
    session_id: UuidString
    sample_vault_id: UuidString | None
    source_recovery_id: UuidString | None
    wrapper_digest: Base64Url32 | None

    @model_validator(mode="after")
    def validate_sample_scope(self):
        fields = (self.sample_vault_id, self.source_recovery_id, self.wrapper_digest)
        if not (all(value is None for value in fields) or all(fields)):
            raise ValueError("sample activation requires every exact binding or none")
        return self


class TriggerTestVerifySigned(TriggerTestHeader):
    operation: Literal["trigger_test.warning_verify", "trigger_test.recipient_verify"]
    session_id: UuidString
    challenge_id: UuidString
    code: Code


class TriggerTestRecipientChallengeSigned(TriggerTestHeader):
    operation: Literal["trigger_test.recipient_challenge"]
    session_id: UuidString
    notice_token: Base64Url32


class TriggerTestReleaseSigned(TriggerTestHeader):
    operation: Literal["trigger_test.release_secret"]
    session_id: UuidString
    sample_vault_id: UuidString
    source_recovery_id: UuidString
    claim_token: Base64Url32


class TriggerTestRotationSigned(TriggerTestHeader):
    operation: Literal["trigger_test.rotation_confirm"]
    session_id: UuidString
    sample_vault_id: UuidString
    target_recovery_id: UuidString
    wrapper_digest: Base64Url32
    generation: Annotated[int, Field(strict=True, ge=2, le=2)]
    claim_token: Base64Url32


SignedTestDocument = Annotated[
    TriggerTestReadSigned
    | TriggerTestCreateSigned
    | TriggerTestSessionSigned
    | TriggerTestActivateSigned
    | TriggerTestVerifySigned
    | TriggerTestRecipientChallengeSigned
    | TriggerTestReleaseSigned
    | TriggerTestRotationSigned,
    Field(discriminator="operation"),
]


class TriggerTestRequest(TestClosedModel):
    protocol_version: Literal[1]
    signed: SignedTestDocument
    signature: Base64Url64


class TriggerTestRecipient(TestClosedModel):
    id: RecipientId
    kind: Literal["owner", "contact"]
    email: Mailbox


class TriggerTestEvidence(TestClosedModel):
    key: Literal[
        "trigger", "warning", "notification", "recipient", "recovery", "activity"
    ]
    outcome: Literal["verified", "not_verified", "not_tested", "not_selected"]
    observed_at: str | None = Field(alias="observedAt")

    @model_validator(mode="after")
    def require_timestamp_for_verified_outcome(self):
        if self.outcome == "verified" and self.observed_at is None:
            raise ValueError(
                "verified test evidence requires its authoritative observation time"
            )
        return self


Transport = Literal["not_started", "pending", "accepted", "failed", "unknown"]


class TriggerTestSession(TestClosedModel):
    id: UuidString
    version: Annotated[int, Field(strict=True, ge=1, le=9_007_199_254_740_991)]
    stage: Literal[
        "preparing",
        "waiting",
        "warning",
        "grace",
        "released",
        "complete",
        "stopped",
        "expired",
    ]
    include_recovery: bool = Field(alias="includeRecovery", strict=True)
    recipient_id: RecipientId = Field(alias="recipientId")
    recipient_email: Mailbox = Field(alias="recipientEmail")
    warning_at: str | None = Field(alias="warningAt")
    due_at: str | None = Field(alias="dueAt")
    release_at: str | None = Field(alias="releaseAt")
    next_at: str | None = Field(alias="nextAt")
    expires_at: str = Field(alias="expiresAt")
    observed_at: str = Field(alias="observedAt")
    warning_transport: Transport = Field(alias="warningTransport")
    notification_transport: Transport = Field(alias="notificationTransport")
    warning_confirmed: bool = Field(alias="warningConfirmed", strict=True)
    recipient_verified: bool = Field(alias="recipientVerified", strict=True)
    sample_state: Literal[
        "absent", "prepared", "decrypted", "confirmation_pending", "protected"
    ] = Field(alias="sampleState")
    activity_stopped: bool = Field(alias="activityStopped", strict=True)
    evidence: list[TriggerTestEvidence] = Field(min_length=6, max_length=6)

    @model_validator(mode="after")
    def validate_evidence_keys(self):
        if {item.key for item in self.evidence} != {
            "trigger",
            "warning",
            "notification",
            "recipient",
            "recovery",
            "activity",
        }:
            raise ValueError(
                "test evidence must contain each selected outcome exactly once"
            )
        return self


class TriggerTestView(TestClosedModel):
    available: bool = Field(strict=True)
    sample_recovery_available: bool = Field(
        alias="sampleRecoveryAvailable", strict=True
    )
    owner_email: Mailbox | None = Field(alias="ownerEmail")
    recipients: list[TriggerTestRecipient] = Field(max_length=11)
    session: TriggerTestSession | None


class TriggerTestChallenge(TestClosedModel):
    id: UuidString
    expires_at: str = Field(alias="expiresAt")
    resend_after_seconds: Annotated[int, Field(strict=True, ge=0, le=60)] = Field(
        alias="resendAfterSeconds"
    )


class TriggerTestResponseData(TestClosedModel):
    view: TriggerTestView
    challenge: TriggerTestChallenge | None = None
    source_recovery_id: UuidString | None = None
    source_srs: Base64Url32 | None = None
    claim_token: Base64Url32 | None = None
    claim_expires_at: str | None = None
    target_recovery_id: UuidString | None = None
    target_srs: Base64Url32 | None = None


class TriggerTestResponse(TestClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    data: TriggerTestResponseData
