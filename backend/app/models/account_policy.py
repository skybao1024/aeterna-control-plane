"""Internal account-policy and transactional Outbox persistence models."""

import uuid
from enum import Enum

from sqlalchemy import (
    JSON,
    TIMESTAMP,
    CheckConstraint,
    Column,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID

from .base import BaseModel


class AccountPolicyState(str, Enum):
    """Server-authoritative account-policy states."""

    ACTIVE = "ACTIVE"
    PRE_WARNING = "PRE_WARNING"
    GRACE_PERIOD = "GRACE_PERIOD"
    RELEASED = "RELEASED"
    DISABLED = "DISABLED"
    DELETED = "DELETED"


class AccountPolicy(BaseModel):
    """Server-authoritative timing and state for one internal policy."""

    __tablename__ = "account_policies"
    __table_args__ = (
        CheckConstraint(
            "state IN ('ACTIVE', 'PRE_WARNING', 'GRACE_PERIOD', 'RELEASED', "
            "'DISABLED', 'DELETED')",
            name="ck_account_policies_state",
        ),
        CheckConstraint(
            "version >= 0",
            name="ck_account_policies_version_nonnegative",
        ),
        CheckConstraint(
            "inactivity_window_seconds >= 1209600 "
            "AND inactivity_window_seconds <= 31536000",
            name="ck_account_policies_inactivity_window_range",
        ),
        CheckConstraint(
            "warning_window_seconds >= 259200 "
            "AND warning_window_seconds <= 2592000 "
            "AND warning_window_seconds < inactivity_window_seconds",
            name="ck_account_policies_warning_window_range",
        ),
        CheckConstraint(
            "grace_window_seconds >= 259200",
            name="ck_account_policies_grace_window_minimum",
        ),
        UniqueConstraint("account_id", name="uq_account_policies_account_id"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    account_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_accounts.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    state = Column(String(24), nullable=False, default=AccountPolicyState.ACTIVE.value)
    version = Column(Integer, nullable=False, default=0)
    inactivity_window_seconds = Column(Integer, nullable=False)
    warning_window_seconds = Column(Integer, nullable=False)
    grace_window_seconds = Column(Integer, nullable=False)
    last_activity_at = Column(TIMESTAMP(timezone=True), nullable=False)
    due_at = Column(TIMESTAMP(timezone=True), nullable=False)
    state_changed_at = Column(TIMESTAMP(timezone=True), nullable=False)
    warning_started_at = Column(TIMESTAMP(timezone=True), nullable=True)
    owner_warning_proven_at = Column(TIMESTAMP(timezone=True), nullable=True)
    grace_started_at = Column(TIMESTAMP(timezone=True), nullable=True)
    released_at = Column(TIMESTAMP(timezone=True), nullable=True)


class AccountPolicyOutboxEvent(BaseModel):
    """A policy event and optional notification intent committed atomically."""

    __tablename__ = "account_policy_outbox_events"
    __table_args__ = (
        UniqueConstraint(
            "idempotency_key",
            name="uq_account_policy_outbox_events_idempotency_key",
        ),
        UniqueConstraint(
            "delivery_idempotency_key",
            name="uq_account_policy_outbox_events_delivery_idempotency_key",
        ),
        CheckConstraint(
            "status IN ('pending', 'queued', 'acknowledged', 'cancelled')",
            name="ck_account_policy_outbox_events_status",
        ),
        CheckConstraint(
            "(notification_type IS NULL) = (delivery_idempotency_key IS NULL)",
            name="ck_account_policy_outbox_events_notification_delivery_pair",
        ),
        CheckConstraint(
            "attempt_count >= 0",
            name="ck_account_policy_outbox_events_attempt_count_nonnegative",
        ),
        Index(
            "ix_account_policy_outbox_events_delivery_scan",
            "status",
            "scheduled_at",
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    account_policy_id = Column(
        UUID(as_uuid=True),
        ForeignKey("account_policies.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_type = Column(String(64), nullable=False)
    idempotency_key = Column(String(255), nullable=False)
    from_state = Column(String(24), nullable=False)
    to_state = Column(String(24), nullable=False)
    policy_version = Column(Integer, nullable=False)
    payload = Column(JSON, nullable=False)
    scheduled_at = Column(TIMESTAMP(timezone=True), nullable=False)
    status = Column(String(16), nullable=False, default="pending")
    notification_type = Column(String(64), nullable=True)
    delivery_idempotency_key = Column(String(255), nullable=True)
    attempt_count = Column(Integer, nullable=False, default=0)
    queued_at = Column(TIMESTAMP(timezone=True), nullable=True)
    acknowledged_at = Column(TIMESTAMP(timezone=True), nullable=True)
    cancelled_at = Column(TIMESTAMP(timezone=True), nullable=True)


class AccountPolicyOutboxAttempt(BaseModel):
    """One idempotent queue preparation using the event's stable delivery key."""

    __tablename__ = "account_policy_outbox_attempts"
    __table_args__ = (
        UniqueConstraint(
            "task_idempotency_key",
            name="uq_account_policy_outbox_attempts_task_idempotency_key",
        ),
        CheckConstraint(
            "status = 'prepared'",
            name="ck_account_policy_outbox_attempts_status",
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    outbox_event_id = Column(
        UUID(as_uuid=True),
        ForeignKey("account_policy_outbox_events.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    task_idempotency_key = Column(String(255), nullable=False)
    delivery_idempotency_key = Column(String(255), nullable=False)
    attempt_number = Column(Integer, nullable=False)
    status = Column(String(16), nullable=False, default="prepared")
    prepared_at = Column(TIMESTAMP(timezone=True), nullable=False)


class AccountPolicyOutboxCallback(BaseModel):
    """An idempotent internal dispatch callback that is not delivery proof."""

    __tablename__ = "account_policy_outbox_callbacks"
    __table_args__ = (
        UniqueConstraint(
            "idempotency_key",
            name="uq_account_policy_outbox_callbacks_idempotency_key",
        ),
        CheckConstraint(
            "outcome IN ('dispatch-accepted', 'dispatch-failed')",
            name="ck_account_policy_outbox_callbacks_outcome",
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    outbox_event_id = Column(
        UUID(as_uuid=True),
        ForeignKey("account_policy_outbox_events.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    idempotency_key = Column(String(255), nullable=False)
    outcome = Column(String(32), nullable=False)
    received_at = Column(TIMESTAMP(timezone=True), nullable=False)
