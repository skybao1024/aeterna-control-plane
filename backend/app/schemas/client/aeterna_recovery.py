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
    state: Literal["pending_confirmation", "sealed", "abandoned", "expired", "revoked"]
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
    policy_epoch: Annotated[int, Field(ge=1)]
    recovery_generation: Annotated[int, Field(ge=1)]
    recovery_id: UuidString
    rekey_required: Literal[True]
    srs: Base64Url32
    vault_id: UuidString
    wrapper_digest: Base64Url32


class RecoverySecretResponse(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    data: RecoverySecretData


class OwnerRecoveryStartSigned(SignedHeader):
    domain: Literal["aeterna.owner-recovery.start.v1"]
    operation: Literal["owner_recovery.start"]
    account_id: UuidString
    device_id: UuidString
    policy_epoch: Annotated[int, Field(ge=1)]
    recovery_generation: Annotated[int, Field(ge=1)]
    recovery_id: UuidString
    vault_id: UuidString
    wrapper_digest: Base64Url32


class OwnerRecoveryStartRequest(ClosedModel):
    protocol_version: Literal[1]
    signed: OwnerRecoveryStartSigned
    signature: Base64Url64


class OwnerRecoveryVerifyRequest(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    owner_recovery_id: UuidString
    challenge_id: UuidString
    code: Annotated[str, Field(min_length=8, max_length=8, pattern=r"^[0-9]{8}$")]


class OwnerRecoveryActionSigned(SignedHeader):
    domain: Literal["aeterna.owner-recovery.action.v1"]
    operation: Literal["owner_recovery.action"]
    account_id: UuidString
    action: Literal["cancel", "release", "complete", "status"]
    device_id: UuidString
    owner_recovery_id: UuidString
    recovery_id: Optional[UuidString] = None
    vault_id: Optional[UuidString] = None
    wrapper_digest: Optional[Base64Url32] = None

    @model_validator(mode="after")
    def validate_action_binding(self) -> "OwnerRecoveryActionSigned":
        binding = (self.recovery_id, self.vault_id, self.wrapper_digest)
        needs_binding = self.action in {"release", "complete"}
        if needs_binding != all(value is not None for value in binding):
            raise ValueError("recovery binding does not match Owner action")
        if not needs_binding and any(value is not None for value in binding):
            raise ValueError("recovery binding does not match Owner action")
        return self


class OwnerRecoveryActionRequest(ClosedModel):
    protocol_version: Literal[1]
    signed: OwnerRecoveryActionSigned
    signature: Base64Url64


class OwnerRecoveryData(ClosedModel):
    account_id: UuidString
    challenge_id: UuidString
    cooldown_seconds: Literal[86400]
    device_id: UuidString
    expires_at: Timestamp
    owner_recovery_id: UuidString
    ready_at: Optional[Timestamp] = None
    rekey_required: bool
    state: Literal[
        "pending_email",
        "cooling_down",
        "ready",
        "material_released",
        "completed",
        "cancelled",
        "expired",
    ]


class OwnerRecoveryResponse(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    data: OwnerRecoveryData


class OwnerRecoverySecretData(ClosedModel):
    account_id: UuidString
    device_id: UuidString
    owner_recovery_id: UuidString
    policy_epoch: Annotated[int, Field(ge=1)]
    recovery_generation: Annotated[int, Field(ge=1)]
    recovery_id: UuidString
    rekey_required: bool
    srs: Base64Url32
    vault_id: UuidString
    wrapper_digest: Base64Url32


class OwnerRecoverySecretResponse(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    data: OwnerRecoverySecretData


class RecoveryRotationProvisionSigned(SignedHeader):
    domain: Literal["aeterna.recovery-rotation.provision.v1"]
    operation: Literal["recovery_rotation.provision"]
    account_id: UuidString
    device_id: UuidString
    kind: Literal["erc_rotation", "post_compromise"]
    owner_recovery_id: Optional[UuidString] = None
    recovery_id: UuidString
    rotation_id: UuidString
    source_generation: Annotated[int, Field(ge=1)]
    source_policy_epoch: Annotated[int, Field(ge=1)]
    target_generation: Annotated[int, Field(ge=2)]
    target_policy_epoch: Annotated[int, Field(ge=1)]
    vault_id: UuidString

    @model_validator(mode="after")
    def validate_rotation(self) -> "RecoveryRotationProvisionSigned":
        if self.target_generation != self.source_generation + 1:
            raise ValueError("target_generation must increment by one")
        post_compromise = self.kind == "post_compromise"
        if (self.owner_recovery_id is not None) != post_compromise:
            raise ValueError("owner_recovery_id does not match rotation kind")
        expected_epoch = self.source_policy_epoch + (1 if post_compromise else 0)
        if self.target_policy_epoch != expected_epoch:
            raise ValueError("target_policy_epoch does not match rotation kind")
        return self


class RecoveryRotationProvisionRequest(ClosedModel):
    protocol_version: Literal[1]
    signed: RecoveryRotationProvisionSigned
    signature: Base64Url64


class RecoveryRotationConfirmSigned(SignedHeader):
    domain: Literal["aeterna.recovery-rotation.confirm.v1"]
    operation: Literal["recovery_rotation.confirm"]
    account_id: UuidString
    device_id: UuidString
    recovery_id: UuidString
    rotation_id: UuidString
    target_generation: Annotated[int, Field(ge=2)]
    target_policy_epoch: Annotated[int, Field(ge=1)]
    vault_id: UuidString
    wrapper_digest: Base64Url32


class RecoveryRotationConfirmRequest(ClosedModel):
    protocol_version: Literal[1]
    signed: RecoveryRotationConfirmSigned
    signature: Base64Url64


class RecoveryRotationProvisionData(ClosedModel):
    account_id: UuidString
    device_id: UuidString
    expires_at: Timestamp
    recovery_id: UuidString
    rotation_id: UuidString
    srs: Base64Url32
    target_generation: Annotated[int, Field(ge=2)]
    target_policy_epoch: Annotated[int, Field(ge=1)]
    vault_id: UuidString


class RecoveryRotationProvisionResponse(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    data: RecoveryRotationProvisionData


class RecoveryRotationDeviceData(ClosedModel):
    device_id: UuidString
    device_label: Optional[Annotated[str, Field(min_length=1, max_length=64)]] = None
    state: Literal["pending", "not_enrolled", "complete", "excluded"]
    updated_at: Timestamp


class RecoveryRotationData(ClosedModel):
    account_id: UuidString
    complete: bool
    devices: Annotated[list[RecoveryRotationDeviceData], Field(max_length=32)]
    kind: Literal["erc_rotation", "post_compromise"]
    rotation_id: UuidString
    state: Literal["preparing", "active", "complete", "cancelled"]
    target_generation: Annotated[int, Field(ge=2)]
    target_policy_epoch: Annotated[int, Field(ge=1)]


class RecoveryRotationResponse(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    data: RecoveryRotationData
