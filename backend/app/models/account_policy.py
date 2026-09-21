"""Internal account-policy and transactional Outbox persistence models."""

import uuid
from enum import Enum

from sqlalchemy import (
    JSON,
    TIMESTAMP,
    CheckConstraint,
    Column,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID

from .base import BaseModel


class AccountPolicyState(str, Enum):
    """Account-policy states exercised by the I03 internal prototype."""

    ACTIVE = "ACTIVE"
    PRE_WARNING = "PRE_WARNING"
    GRACE_PERIOD = "GRACE_PERIOD"
    RELEASED = "RELEASED"


class AccountPolicy(BaseModel):
    """Server-authoritative timing and state for one internal policy."""

    __tablename__ = "account_policies"
    __table_args__ = (
        CheckConstraint(
            "state IN ('ACTIVE', 'PRE_WARNING', 'GRACE_PERIOD', 'RELEASED')",
            name="ck_account_policies_state",
        ),
        CheckConstraint(
            "inactivity_window_seconds > 0",
            name="ck_account_policies_inactivity_window_positive",
        ),
        CheckConstraint(
            "warning_window_seconds > 0 "
            "AND warning_window_seconds < inactivity_window_seconds",
            name="ck_account_policies_warning_window_valid",
        ),
        CheckConstraint(
            "grace_window_seconds > 0",
            name="ck_account_policies_grace_window_positive",
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
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
    """A structural policy event committed with its corresponding mutation."""

    __tablename__ = "account_policy_outbox_events"
    __table_args__ = (
        UniqueConstraint(
            "idempotency_key",
            name="uq_account_policy_outbox_events_idempotency_key",
        ),
        CheckConstraint(
            "status IN ('pending', 'processed')",
            name="ck_account_policy_outbox_events_status",
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
