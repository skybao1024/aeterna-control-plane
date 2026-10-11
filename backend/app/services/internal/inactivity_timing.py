"""Authoritative timing decisions shared by normal and isolated test policies."""

from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass(frozen=True, slots=True)
class DueInactivityTransition:
    """A single due transition; persistence and authorization remain caller-owned."""

    target_state: str
    timestamp_field: str


def due_inactivity_transition(
    *,
    state: str,
    now: datetime,
    due_at: datetime,
    warning_window_seconds: int,
    grace_window_seconds: int,
    grace_started_at: datetime | None,
    owner_warning_proven_at: datetime | None,
) -> DueInactivityTransition | None:
    """Never skip warning or a full grace interval, even after delayed scheduling."""

    if state == "ACTIVE":
        if now >= due_at - timedelta(seconds=warning_window_seconds):
            return DueInactivityTransition("PRE_WARNING", "warning_started_at")
    elif state == "PRE_WARNING":
        if now >= due_at:
            return DueInactivityTransition("GRACE_PERIOD", "grace_started_at")
    elif state == "GRACE_PERIOD" and owner_warning_proven_at is not None:
        if grace_started_at is None:
            raise ValueError("GRACE_PERIOD requires grace_started_at")
        release_at = max(grace_started_at, owner_warning_proven_at) + timedelta(
            seconds=grace_window_seconds
        )
        if now >= release_at:
            return DueInactivityTransition("RELEASED", "released_at")
    return None
