"""Closed public schemas for Owner policy and recovery setup visibility."""

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

InactivityDays = Annotated[int, Field(strict=True, ge=14, le=365)]
WarningDays = Annotated[int, Field(strict=True, ge=3, le=30)]
GraceDays = Annotated[int, Field(strict=True, ge=3, le=24855)]


class PolicyConfigureSigned(SignedHeader):
    domain: Literal["aeterna.policy.configure.v1"]
    operation: Literal["policy.configure"]
    account_id: UuidString
    device_id: UuidString
    inactivity_days: InactivityDays
    warning_days: WarningDays
    grace_days: GraceDays

    @model_validator(mode="after")
    def validate_windows(self) -> "PolicyConfigureSigned":
        if self.warning_days >= self.inactivity_days:
            raise ValueError("warning window must be shorter than inactivity window")
        return self


class PolicyConfigureRequest(ClosedModel):
    protocol_version: Literal[1]
    signed: PolicyConfigureSigned
    signature: Base64Url64


class SetupStatusSigned(SignedHeader):
    domain: Literal["aeterna.setup.status.v1"]
    operation: Literal["setup.status"]
    account_id: UuidString
    device_id: UuidString
    vault_id: Optional[UuidString] = None


class SetupStatusRequest(ClosedModel):
    protocol_version: Literal[1]
    signed: SetupStatusSigned
    signature: Base64Url64


class PolicySnapshot(ClosedModel):
    epoch: Annotated[int, Field(strict=True, ge=1)]
    generation: Annotated[int, Field(strict=True, ge=1)]
    state: Literal[
        "ACTIVE", "PRE_WARNING", "GRACE_PERIOD", "RELEASED", "DISABLED", "DELETED"
    ]
    inactivity_days: InactivityDays
    warning_days: WarningDays
    grace_days: GraceDays
    due_at: Timestamp
    version: Annotated[int, Field(strict=True, ge=0)]


class PolicyConfigureData(ClosedModel):
    account_id: UuidString
    observed_at: Timestamp
    policy: PolicySnapshot


class PolicyConfigureResponse(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    data: PolicyConfigureData


class DeviceSetupState(ClosedModel):
    device_id: UuidString
    label: Optional[Annotated[str, Field(max_length=64)]] = None
    state: Literal["not_enrolled", "pending", "complete"]


class LocalRecoveryRecord(ClosedModel):
    recovery_id: UuidString
    vault_id: UuidString
    state: Literal["pending_confirmation", "sealed", "expired"]
    expires_at: Timestamp
    wrapper_digest: Optional[Base64Url32] = None

    @model_validator(mode="after")
    def validate_digest(self) -> "LocalRecoveryRecord":
        if (self.wrapper_digest is not None) != (self.state == "sealed"):
            raise ValueError("wrapper digest must match sealed state")
        return self


class SetupStatusData(ClosedModel):
    account_id: UuidString
    device_id: UuidString
    observed_at: Timestamp
    policy: Optional[PolicySnapshot] = None
    devices: list[DeviceSetupState]
    erc_committed: bool
    local_record: Optional[LocalRecoveryRecord] = None


class SetupStatusResponse(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    data: SetupStatusData
