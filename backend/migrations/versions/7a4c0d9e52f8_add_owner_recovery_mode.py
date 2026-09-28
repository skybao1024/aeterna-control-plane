"""add owner recovery mode

Revision ID: 7a4c0d9e52f8
Revises: 6f2a9c8d41e7
Create Date: 2026-09-27
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "7a4c0d9e52f8"
down_revision: Union[str, None] = "6f2a9c8d41e7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "aeterna_owner_recovery_requests",
        sa.Column(
            "rekey_required", sa.Boolean(), server_default="false", nullable=False
        ),
    )


def downgrade() -> None:
    op.drop_column("aeterna_owner_recovery_requests", "rekey_required")
