"""Persist a closed notification locale without changing legacy contact consent."""

import sqlalchemy as sa
from alembic import op

revision = "2ea8c943d6b1"
down_revision = "3acbf214b906"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "aeterna_contacts",
        sa.Column(
            "notification_locale", sa.String(16), nullable=False, server_default="en"
        ),
    )
    op.create_check_constraint(
        "ck_aeterna_contacts_notification_locale",
        "aeterna_contacts",
        "notification_locale IN ('en', 'zh-CN')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_aeterna_contacts_notification_locale", "aeterna_contacts", type_="check"
    )
    op.drop_column("aeterna_contacts", "notification_locale")
