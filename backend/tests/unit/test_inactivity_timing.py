"""Timing boundaries must behave identically for production and trigger tests."""

from datetime import UTC, datetime, timedelta

import pytest

from app.services.internal.inactivity_timing import due_inactivity_transition

BASELINE = datetime(2026, 10, 11, 12, tzinfo=UTC)


def evaluate(state, elapsed, *, grace_start=None, warning_proof=None):
    return due_inactivity_transition(
        state=state,
        now=BASELINE + timedelta(seconds=elapsed),
        due_at=BASELINE + timedelta(seconds=120),
        warning_window_seconds=60,
        grace_window_seconds=60,
        grace_started_at=grace_start,
        owner_warning_proven_at=warning_proof,
    )


def test_delayed_scheduler_does_not_skip_warning():
    decision = evaluate("ACTIVE", 3600)
    assert decision.target_state == "PRE_WARNING"
    assert decision.timestamp_field == "warning_started_at"
    assert evaluate("ACTIVE", 59) is None


def test_warning_proof_does_not_start_grace_before_inactivity_threshold():
    proof = BASELINE + timedelta(seconds=60)
    assert evaluate("PRE_WARNING", 119, warning_proof=proof) is None
    decision = evaluate("PRE_WARNING", 120, warning_proof=proof)
    assert decision.target_state == "GRACE_PERIOD"
    assert decision.timestamp_field == "grace_started_at"


def test_release_waits_for_mailbox_proof_and_a_full_actual_grace_interval():
    grace = BASELINE + timedelta(seconds=240)
    assert evaluate("GRACE_PERIOD", 3600, grace_start=grace) is None
    proof = BASELINE + timedelta(seconds=300)
    assert evaluate("GRACE_PERIOD", 359, grace_start=grace, warning_proof=proof) is None
    decision = evaluate("GRACE_PERIOD", 360, grace_start=grace, warning_proof=proof)
    assert decision.target_state == "RELEASED"


def test_missing_grace_baseline_is_rejected_when_release_is_considered():
    with pytest.raises(ValueError, match="GRACE_PERIOD requires grace_started_at"):
        evaluate("GRACE_PERIOD", 180, warning_proof=BASELINE)


@pytest.mark.parametrize(
    "state", ["RELEASED", "DISABLED", "DELETED", "STOPPED", "EXPIRED"]
)
def test_terminal_states_never_resume(state):
    assert evaluate(state, 3600, warning_proof=BASELINE) is None
