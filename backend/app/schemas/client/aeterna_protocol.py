"""Closed Pydantic models generated from the Aeterna v1 public contract."""

from typing import Annotated, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

UuidString = Annotated[
    str,
    Field(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
]
Base64Url32 = Annotated[
    str, Field(min_length=43, max_length=43, pattern=r"^[A-Za-z0-9_-]{43}$")
]
Base64Url64 = Annotated[
    str, Field(min_length=86, max_length=86, pattern=r"^[A-Za-z0-9_-]{86}$")
]
HeartbeatSequence = Annotated[int, Field(strict=True, ge=1, le=9_007_199_254_740_991)]
Timestamp = Annotated[str, Field(pattern=r"Z$")]
ChallengePurpose = Literal[
    "account_onboarding",
    "device_binding",
    "device_binding_cancellation",
    "device_binding_delayed_confirmation",
]


class ClosedModel(BaseModel):
    """Base type that rejects unsigned and unknown protocol members."""

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="before")
    @classmethod
    def reject_explicit_nulls(cls, value):
        if isinstance(value, dict) and any(item is None for item in value.values()):
            raise ValueError("protocol members cannot be null")
        return value


class AccountChallengeRequest(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    email: Annotated[str, Field(min_length=3, max_length=254)]
    purpose: ChallengePurpose
    account_id: Optional[UuidString] = None
    binding_id: Optional[UuidString] = None

    @model_validator(mode="after")
    def validate_binding_scope(self) -> "AccountChallengeRequest":
        binding_scoped = self.purpose in {
            "device_binding_cancellation",
            "device_binding_delayed_confirmation",
        }
        if self.account_id is not None and self.purpose != "device_binding":
            raise ValueError("account_id requires device_binding purpose")
        if binding_scoped != (self.binding_id is not None):
            raise ValueError("binding_id does not match the challenge purpose")
        return self


class AccountChallengeVerificationRequest(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    challenge_id: UuidString
    code: Annotated[str, Field(min_length=8, max_length=8, pattern=r"^[0-9]{8}$")]


class SignedHeader(ClosedModel):
    canonicalization: Literal["jcs-rfc8785"]
    domain: str
    operation: str
    protocol_version: Literal[1]
    signature_version: Literal[1]
    request_id: UuidString


class DeviceBindingRequestSigned(SignedHeader):
    domain: Literal["aeterna.device-binding.request.v1"]
    operation: Literal["device_binding.request"]
    binding_grant_id: UuidString
    device_id: UuidString
    public_key: Base64Url32
    device_label: Optional[Annotated[str, Field(min_length=1, max_length=64)]] = None


class DeviceBindingRequest(ClosedModel):
    protocol_version: Literal[1]
    signed: DeviceBindingRequestSigned
    signature: Base64Url64


class DeviceBindingApprovalSigned(SignedHeader):
    domain: Literal["aeterna.device-binding.approval.v1"]
    operation: Literal["device_binding.approval"]
    account_id: UuidString
    binding_id: UuidString
    approving_device_id: UuidString
    device_id: UuidString
    public_key: Base64Url32
    challenge: Base64Url32


class DeviceBindingApprovalRequest(ClosedModel):
    protocol_version: Literal[1]
    signed: DeviceBindingApprovalSigned
    signature: Base64Url64


class DeviceBindingStatusSigned(SignedHeader):
    domain: Literal["aeterna.device-binding.status.v1"]
    operation: Literal["device_binding.status"]
    account_id: UuidString
    device_id: UuidString
    public_key: Base64Url32


class DeviceBindingStatusRequest(ClosedModel):
    protocol_version: Literal[1]
    signed: DeviceBindingStatusSigned
    signature: Base64Url64


class DeviceBindingConfirmationSigned(SignedHeader):
    domain: Literal["aeterna.device-binding.request.v1"]
    operation: Literal[
        "device_binding.delayed_confirmation", "device_binding.cancellation"
    ]
    account_id: UuidString
    binding_grant_id: UuidString
    binding_id: UuidString
    device_id: UuidString
    public_key: Base64Url32
    challenge: Base64Url32


class DeviceBindingDelayedConfirmationRequest(ClosedModel):
    protocol_version: Literal[1]
    signed: DeviceBindingConfirmationSigned
    signature: Base64Url64

    @model_validator(mode="after")
    def validate_operation(self) -> "DeviceBindingDelayedConfirmationRequest":
        if self.signed.operation != "device_binding.delayed_confirmation":
            raise ValueError("operation does not match endpoint")
        return self


class DeviceBindingCancellationRequest(ClosedModel):
    protocol_version: Literal[1]
    signed: DeviceBindingConfirmationSigned
    signature: Base64Url64

    @model_validator(mode="after")
    def validate_operation(self) -> "DeviceBindingCancellationRequest":
        if self.signed.operation != "device_binding.cancellation":
            raise ValueError("operation does not match endpoint")
        return self


class HeartbeatSigned(SignedHeader):
    account_id: UuidString
    device_id: UuidString
    domain: Literal["aeterna.heartbeat.submit.v1"]
    operation: Literal["heartbeat.submit"]
    sequence: HeartbeatSequence


class HeartbeatRequest(ClosedModel):
    protocol_version: Literal[1]
    signed: HeartbeatSigned
    signature: Base64Url64


class DeviceStatusChangeSigned(SignedHeader):
    account_id: UuidString
    action: Literal["mark_lost", "revoke"]
    authorizing_device_id: UuidString
    domain: Literal["aeterna.device-status.change.v1"]
    operation: Literal["device_status.change"]
    target_device_id: UuidString


class DeviceStatusChangeRequest(ClosedModel):
    protocol_version: Literal[1]
    signed: DeviceStatusChangeSigned
    signature: Base64Url64


class AccountChallengeData(ClosedModel):
    challenge_id: UuidString
    expires_in_seconds: Literal[600]
    resend_after_seconds: Literal[60]


class AccountChallengeResponse(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    data: AccountChallengeData


class AccountChallengeVerificationData(ClosedModel):
    account_id: UuidString
    binding_grant_id: UuidString
    binding_grant_token: Base64Url32
    expires_at: Timestamp
    purpose: ChallengePurpose
    binding_id: Optional[UuidString] = None


class AccountChallengeVerificationResponse(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    data: AccountChallengeVerificationData


class DeviceBindingData(ClosedModel):
    account_id: UuidString
    binding_id: UuidString
    device_id: UuidString
    state: Literal["active", "pending", "cancelled", "expired"]
    challenge: Optional[Base64Url32] = None
    not_before: Optional[Timestamp] = None
    expires_at: Optional[Timestamp] = None


class DeviceBindingResponse(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    data: DeviceBindingData


class DeviceBindingStatusData(ClosedModel):
    account_id: UuidString
    binding_id: UuidString
    device_id: UuidString
    state: Literal[
        "active", "pending", "cancelled", "expired", "dormant", "lost", "revoked"
    ]
    observed_at: Timestamp
    challenge: Optional[Base64Url32] = None
    not_before: Optional[Timestamp] = None
    expires_at: Optional[Timestamp] = None
    active_device_count: Optional[Annotated[int, Field(strict=True, ge=0, le=32)]] = (
        None
    )


class DeviceBindingStatusResponse(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    data: DeviceBindingStatusData


class HeartbeatData(ClosedModel):
    accepted_at: Timestamp
    accepted_sequence: HeartbeatSequence
    account_id: UuidString
    device_id: UuidString
    next_heartbeat_not_before: Timestamp


class HeartbeatResponse(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    data: HeartbeatData


class DeviceStatusChangeData(ClosedModel):
    account_id: UuidString
    changed_at: Timestamp
    device_id: UuidString
    status: Literal["lost", "revoked"]


class DeviceStatusChangeResponse(ClosedModel):
    protocol_version: Literal[1]
    request_id: UuidString
    data: DeviceStatusChangeData


class ProtocolErrorBody(ClosedModel):
    code: Annotated[
        str,
        Field(
            min_length=3,
            max_length=64,
            pattern=r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$",
        ),
    ]
    retry_after_seconds: Optional[Annotated[int, Field(ge=1, le=86_400)]] = None
    supported_protocol_versions: Optional[
        Annotated[list[int], Field(min_length=1, max_length=4)]
    ] = None


class ProtocolErrorResponse(ClosedModel):
    protocol_version: Literal[1]
    request_id: Optional[UuidString] = None
    error: ProtocolErrorBody
