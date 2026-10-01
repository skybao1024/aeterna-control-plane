"""Bounded M05 fixture actions, inside Docker from /app.

Usage: python -m scripts.m05_acceptance_control ACTION ACCOUNT_UUID.
No secrets, tokens, addresses, or email bodies are emitted. Warning proof is
explicitly synthetic; local SMTP acceptance is not proof of human receipt.
"""

import argparse
import asyncio
import json
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select

from app.db.base import get_session_local
from app.models.account_policy import AccountPolicy, AccountPolicyOutboxEvent
from app.models.aeterna_identity import AeternaAccountChallenge
from app.models.aeterna_notification import AeternaEmailOutboxEvent
from app.services.client.aeterna_notification import AeternaNotificationService
from app.services.client.aeterna_recovery import AeternaRecoveryService
from app.services.internal.account_policy_outbox import (
    AccountPolicyOutboxService,
    OutboxCallbackOutcome,
)
from app.services.internal.account_policy_transition import (
    AccountPolicyTransitionService,
)
from app.services.internal.aeterna_email_delivery import AeternaEmailDeliveryService
from scripts.m05_acceptance_runtime import CLOCK_PATH, clock, require_isolated_fixture


def set_offset(value):
    if not 0 <= value <= 60 * 86400:
        raise RuntimeError("M05 fixture clock is out of bounds")
    CLOCK_PATH.write_text(str(value))
    CLOCK_PATH.chmod(0o600)


async def run(action, account_id):
    require_isolated_fixture()
    if action in {"guard", "reset-clock", "advance-minute"}:
        if action == "reset-clock":
            set_offset(0)
        elif action == "advance-minute":
            value = float(CLOCK_PATH.read_text()) if CLOCK_PATH.exists() else 0
            set_offset(value + 61)
        print(json.dumps({"fixture": "isolated-m05", "action": action}))
        return

    factory = get_session_local()
    if action == "begin-run":
        async with factory() as db:
            latest = await db.scalar(
                select(func.max(AeternaAccountChallenge.resend_after))
            )
        set_offset(
            max(0, (latest - datetime.now(UTC)).total_seconds() + 2) if latest else 0
        )
        print(json.dumps({"fixture": "isolated-m05", "action": action}))
        return
    policy_service = AccountPolicyTransitionService(clock=clock)
    recovery = AeternaRecoveryService(clock=clock)
    notification = AeternaNotificationService(clock=clock)
    delivery = AeternaEmailDeliveryService(clock=clock)
    outbox = AccountPolicyOutboxService(clock=clock)
    async with factory() as db:
        policy = await db.scalar(
            select(AccountPolicy).where(
                AccountPolicy.account_id == account_id,
                AccountPolicy.retired_at.is_(None),
            )
        )
    if action in {"warning", "grace", "release", "proof"} and policy is None:
        raise RuntimeError("M05 fixture policy is missing")
    if action in {"warning", "grace", "release"}:
        if action == "warning":
            target = policy.due_at - timedelta(seconds=policy.warning_window_seconds)
        elif action == "grace":
            target = policy.due_at
        else:
            target = max(policy.grace_started_at, policy.owner_warning_proven_at)
            target += timedelta(seconds=policy.grace_window_seconds)
        set_offset(max(0, (target - datetime.now(UTC)).total_seconds() + 2))
        async with factory() as db:
            await policy_service.run_scheduler(db, policy.id, str(uuid.uuid4()))
    if action == "proof":
        if policy.warning_started_at is None:
            raise RuntimeError("M05 fixture warning has not started")
        async with factory() as db:
            evidence = await db.scalar(
                select(AeternaEmailOutboxEvent.id)
                .join(
                    AccountPolicyOutboxEvent,
                    AeternaEmailOutboxEvent.source_policy_outbox_id
                    == AccountPolicyOutboxEvent.id,
                )
                .where(
                    AeternaEmailOutboxEvent.account_id == account_id,
                    AeternaEmailOutboxEvent.event_type == "owner-pre-warning",
                    AeternaEmailOutboxEvent.status == "provider_accepted",
                    AccountPolicyOutboxEvent.account_policy_id == policy.id,
                    AccountPolicyOutboxEvent.scheduled_at >= policy.warning_started_at,
                )
                .order_by(AeternaEmailOutboxEvent.created_at.desc())
            )
            if evidence is None:
                raise RuntimeError("M05 fixture has no local SMTP warning evidence")
        async with factory() as db:
            await policy_service.confirm_owner_warning(
                db, policy.id, "m05-synthetic-proof-" + str(evidence)
            )

    async with factory() as db:
        events = list(
            await db.scalars(
                select(AccountPolicyOutboxEvent.id)
                .join(AccountPolicy)
                .where(
                    AccountPolicy.account_id == account_id,
                    AccountPolicyOutboxEvent.notification_type.is_not(None),
                    AccountPolicyOutboxEvent.status.in_({"pending", "queued"}),
                )
            )
        )
    for event_id in events:
        async with factory() as db:
            await outbox.prepare_delivery(db, event_id, str(uuid.uuid4()))
        async with factory() as db:
            await notification.materialize_policy_event(db, event_id)
        async with factory() as db:
            await outbox.record_callback(
                db, event_id, str(uuid.uuid4()), OutboxCallbackOutcome.DISPATCH_ACCEPTED
            )
    if policy is not None:
        async with factory() as db:
            policy = await db.get(AccountPolicy, policy.id)
            if policy.state == "RELEASED":
                await recovery.materialize_released_account(db, account_id)
    async with factory() as db:
        emails = list(
            await db.scalars(
                select(AeternaEmailOutboxEvent.id).where(
                    AeternaEmailOutboxEvent.account_id == account_id,
                    AeternaEmailOutboxEvent.status.in_({"queued", "retry_pending"}),
                    AeternaEmailOutboxEvent.next_attempt_at <= clock(),
                )
            )
        )
    for event_id in emails:
        async with factory() as db:
            result = await delivery.dispatch_event(db, event_id)
        if result.status != "provider_accepted":
            raise RuntimeError("M05 local SMTP delivery was not accepted")
    print(json.dumps({"fixture": "isolated-m05", "action": action}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=[
            "guard",
            "begin-run",
            "reset-clock",
            "advance-minute",
            "pump",
            "warning",
            "grace",
            "release",
            "proof",
        ],
    )
    parser.add_argument("account_id", type=uuid.UUID)
    args = parser.parse_args()
    try:
        asyncio.run(run(args.action, args.account_id))
    except Exception as error:
        raise SystemExit(
            "M05 isolated fixture action failed: " + type(error).__name__
        ) from None
