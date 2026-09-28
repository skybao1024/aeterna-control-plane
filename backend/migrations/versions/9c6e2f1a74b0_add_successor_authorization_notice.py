"""add successor authorization notice

Revision ID: 9c6e2f1a74b0
Revises: 8b5d1e0f63a9
Create Date: 2026-09-27
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "9c6e2f1a74b0"
down_revision: Union[str, None] = "8b5d1e0f63a9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

OLD_EVENT_TYPES = (
    "event_type IN ('owner-pre-warning', 'owner-grace-period-started', "
    "'owner-warning-required', 'owner-release-authorized', "
    "'contact-invitation', 'contact-test', 'recovery-claim-link', "
    "'recovery-otp', 'recovery-claimed-owner', 'recovery-claimed-contact', "
    "'owner-recovery-otp', 'owner-recovery-cooling-down', "
    "'owner-recovery-cancelled', 'owner-recovery-material-released')"
)
NEW_EVENT_TYPES = OLD_EVENT_TYPES[:-1] + ", 'owner-recovery-successor-authorized')"


def upgrade() -> None:
    op.drop_constraint(
        "ck_aeterna_email_outbox_events_event_type",
        "aeterna_email_outbox_events",
        type_="check",
    )
    op.create_check_constraint(
        "ck_aeterna_email_outbox_events_event_type",
        "aeterna_email_outbox_events",
        NEW_EVENT_TYPES,
    )


def downgrade() -> None:
    count = (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT count(*) FROM aeterna_email_outbox_events "
                "WHERE event_type = 'owner-recovery-successor-authorized'"
            )
        )
        .scalar_one()
    )
    if count:
        raise RuntimeError(
            "Downgrade refused: successor authorization notices must be retained"
        )
    op.drop_constraint(
        "ck_aeterna_email_outbox_events_event_type",
        "aeterna_email_outbox_events",
        type_="check",
    )
    op.create_check_constraint(
        "ck_aeterna_email_outbox_events_event_type",
        "aeterna_email_outbox_events",
        OLD_EVENT_TYPES,
    )
