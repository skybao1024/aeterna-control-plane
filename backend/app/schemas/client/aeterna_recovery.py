"""Closed public schemas for delayed-recovery records and claims."""

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


class RecoveryRecordProvisionSigned(SignedHeader):
    domain: Literal["aeterna.recovery-record.provision.v1"]
    operation: Literal["recovery_record.provision"]
    account_id: UuidString
    device_id: UuidString
    vault_id: UuidString
    recovery_id: UuidString
    crypto_format_version: Literal[1]
    recovery_context_version: Literal[1]


class RecoveryRecordProvisionRequest(ClosedModel):
    protocol_version: Literal[1]
    signed: RecoveryRecordProvisionSigned
    signature: Base64Url64


class RecoveryRecordActionSigned(SignedHeader):
    domain: Literal[
        "aeterna.recovery-record.confirm.v1",
        "aeterna.recovery-record.abandon.v1",
    ]
    operation: Literal["recovery_record.confirm", "recovery_record.abandon"]
    account_id: UuidString
    device_id: UuidString
    vault_id: UuidString
    recovery_id: UuidString
    wrapper_digest: Optional[Base64Url32] = None

    @model_validator(mode="after")
    def validate_action(self) -> "RecoveryRecordActionSigned":
        expected = {
            "recovery_record.confirm": "aeterna.recovery-record.confirm.v1",
            "recovery_record.abandon": "aeterna.recovery-record.abandon.v1",
        }[self.operation]
        if self.domain != expected:
            raise ValueError("domain does not match operation")
        if (self.wrapper_digest is not None) != (
            self.operation == "recovery_record.confirm"
        ):
            raise ValueError("wrapper_digest does not match operation")
        return self


class RecoveryRecordActionRequest(ClosedModel):
    protocol_version: Literal[1]
    signed: RecoveryRecordActionSigned
    signature: Base64Url64


class RecoveryClaimStartRequest(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    claim_link_token: Base64Url32


class RecoveryClaimVerifyRequest(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    challenge_id: UuidString
    claim_link_token: Base64Url32
    code: Annotated[str, Field(min_length=8, max_length=8, pattern=r"^[0-9]{8}$")]


class RecoverySecretRequest(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    claim_token: Base64Url32
    device_id: UuidString
    recovery_id: UuidString
    vault_id: UuidString
    wrapper_digest: Base64Url32


class RecoveryRecordProvisionData(ClosedModel):
    account_id: UuidString
    device_id: UuidString
    expires_at: Timestamp
    kms_context_version: Literal[1]
    recovery_id: UuidString
    srs: Base64Url32
    state: Literal["pending_confirmation"]
    vault_id: UuidString


class RecoveryRecordProvisionResponse(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    data: RecoveryRecordProvisionData


class RecoveryRecordData(ClosedModel):
    account_id: UuidString
    device_id: UuidString
    recovery_id: UuidString
    state: Literal["pending_confirmation", "sealed", "abandoned", "expired"]
    updated_at: Timestamp
    vault_id: UuidString


class RecoveryRecordResponse(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    data: RecoveryRecordData


class RecoveryClaimStartData(ClosedModel):
    challenge_id: UuidString
    expires_in_seconds: Literal[600]
    resend_after_seconds: Literal[60]


class RecoveryClaimStartResponse(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    data: RecoveryClaimStartData


class RecoveryClaimData(ClosedModel):
    account_id: UuidString
    claim_token: Base64Url32
    device_id: UuidString
    expires_at: Timestamp
    recovery_id: UuidString
    scope: Literal["recovery.srs.read"]
    vault_id: UuidString
    wrapper_digest: Base64Url32


class RecoveryClaimVerifyResponse(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    data: RecoveryClaimData


class RecoverySecretData(ClosedModel):
    account_id: UuidString
    device_id: UuidString
    recovery_id: UuidString
    srs: Base64Url32
    vault_id: UuidString
    wrapper_digest: Base64Url32


class RecoverySecretResponse(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    data: RecoverySecretData
