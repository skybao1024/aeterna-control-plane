"""Closed, device-signed recipient recovery and local custody contracts."""

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
from app.schemas.client.aeterna_recovery import RecoveryClaimData, RecoverySecretData


class RecipientRecoverySourceSigned(SignedHeader):
    account_id: UuidString
    device_id: UuidString
    vault_id: UuidString
    recovery_id: UuidString
    wrapper_digest: Base64Url32
    rotation_id: UuidString


class RecipientRecoverySecretSigned(RecipientRecoverySourceSigned):
    domain: Literal["aeterna.recipient-recovery.secret.v1"]
    operation: Literal["recipient_recovery.secret"]


class RecipientRecoverySecretRequest(ClosedModel):
    protocol_version: Literal[1]
    claim_token: Base64Url32 = Field(repr=False)
    signed: RecipientRecoverySecretSigned
    signature: Base64Url64


class RecipientRecoveryProvisionSigned(RecipientRecoverySourceSigned):
    domain: Literal["aeterna.recipient-recovery.provision.v1"]
    operation: Literal["recipient_recovery.provision"]
    target_recovery_id: UuidString
    erc_commitment: Base64Url32


class RecipientRecoveryProvisionRequest(ClosedModel):
    protocol_version: Literal[1]
    claim_token: Base64Url32 = Field(repr=False)
    signed: RecipientRecoveryProvisionSigned
    signature: Base64Url64


class RecipientRecoveryPrepareSigned(RecipientRecoveryProvisionSigned):
    domain: Literal["aeterna.recipient-recovery.prepare.v1"]
    operation: Literal["recipient_recovery.prepare"]
    target_wrapper_digest: Base64Url32


class RecipientRecoveryPrepareRequest(ClosedModel):
    protocol_version: Literal[1]
    claim_token: Base64Url32 = Field(repr=False)
    signed: RecipientRecoveryPrepareSigned
    signature: Base64Url64


class RecipientRecoveryConfirmSigned(RecipientRecoveryPrepareSigned):
    domain: Literal["aeterna.recipient-recovery.confirm.v1"]
    operation: Literal["recipient_recovery.confirm"]


class RecipientRecoveryConfirmRequest(ClosedModel):
    protocol_version: Literal[1]
    claim_token: Base64Url32 = Field(repr=False)
    signed: RecipientRecoveryConfirmSigned
    signature: Base64Url64


class RecipientRecoveryAbandonSigned(RecipientRecoverySourceSigned):
    domain: Literal["aeterna.recipient-recovery.abandon.v1"]
    operation: Literal["recipient_recovery.abandon"]


class RecipientRecoveryAbandonRequest(ClosedModel):
    protocol_version: Literal[1]
    claim_token: Base64Url32 = Field(repr=False)
    signed: RecipientRecoveryAbandonSigned
    signature: Base64Url64


class RecipientRecoveryClaimData(RecoveryClaimData):
    scope: Literal["recovery.recipient.rotate"]
    claim_token: Base64Url32 = Field(repr=False)


class RecipientRecoveryClaimResponse(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    data: RecipientRecoveryClaimData


class RecipientRecoverySecretData(RecoverySecretData):
    rotation_id: UuidString
    state: Literal["reserved"]
    srs: Base64Url32 = Field(repr=False)


class RecipientRecoverySecretResponse(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    data: RecipientRecoverySecretData


class RecipientRecoveryTargetData(ClosedModel):
    account_id: UuidString
    device_id: UuidString
    vault_id: UuidString
    rotation_id: UuidString
    source_recovery_id: UuidString
    source_wrapper_digest: Base64Url32
    source_policy_epoch: int = Field(ge=1)
    source_generation: int = Field(ge=1)
    target_recovery_id: UuidString
    target_policy_epoch: int = Field(ge=1)
    target_generation: Literal[1]
    erc_commitment: Base64Url32
    binding_kind: Literal["recipient_successor"]


class RecipientRecoveryProvisionData(RecipientRecoveryTargetData):
    state: Literal["provisioned"]
    srs: Base64Url32 = Field(repr=False)


class RecipientRecoveryProvisionResponse(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    data: RecipientRecoveryProvisionData


class RecipientRecoveryData(RecipientRecoveryTargetData):
    target_wrapper_digest: Base64Url32
    state: Literal["prepared", "complete"]
    protection_active: Literal[False]
    account_management_transferred: bool
    management_email: Optional[Annotated[str, Field(min_length=3, max_length=254)]] = (
        Field(...)
    )
    updated_at: Timestamp

    @model_validator(mode="before")
    @classmethod
    def reject_explicit_nulls(cls, value):
        if isinstance(value, dict) and any(
            item is None and key != "management_email" for key, item in value.items()
        ):
            raise ValueError("protocol members cannot be null")
        return value

    @model_validator(mode="after")
    def validate_management_state(self):
        completed = self.state == "complete"
        if (
            self.account_management_transferred != completed
            or (self.management_email is not None) != completed
        ):
            raise ValueError("management authority must match completion")
        return self


class RecipientRecoveryResponse(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    data: RecipientRecoveryData


class RecipientRecoveryAbandonData(ClosedModel):
    rotation_id: UuidString
    state: Literal["abandoned"]
    updated_at: Timestamp


class RecipientRecoveryAbandonResponse(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    data: RecipientRecoveryAbandonData


class RecoveryCustodyChallengeSigned(SignedHeader):
    domain: Literal["aeterna.recovery-custody.challenge.v1"]
    operation: Literal["recovery_custody.challenge"]
    account_id: UuidString
    device_id: UuidString
    vault_id: UuidString
    recovery_id: UuidString
    wrapper_digest: Base64Url32


class RecoveryCustodyChallengeRequest(ClosedModel):
    protocol_version: Literal[1]
    signed: RecoveryCustodyChallengeSigned
    signature: Base64Url64


class RecoveryCustodyChallengeData(ClosedModel):
    challenge_id: UuidString
    challenge: Base64Url32
    expires_at: Timestamp


class RecoveryCustodyChallengeResponse(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    data: RecoveryCustodyChallengeData


class RecoveryCustodyVerifySigned(SignedHeader):
    domain: Literal["aeterna.recovery-custody.verify.v1"]
    operation: Literal["recovery_custody.verify"]
    challenge_id: UuidString
    challenge: Base64Url32
    account_id: UuidString
    device_id: UuidString
    vault_id: UuidString
    recovery_id: UuidString
    wrapper_digest: Base64Url32
    erc_commitment: Base64Url32


class RecoveryCustodyVerifyRequest(ClosedModel):
    protocol_version: Literal[1]
    signed: RecoveryCustodyVerifySigned
    signature: Base64Url64


class RecoveryCustodyVerifyData(ClosedModel):
    verified: Literal[True]


class RecoveryCustodyVerifyResponse(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    data: RecoveryCustodyVerifyData
