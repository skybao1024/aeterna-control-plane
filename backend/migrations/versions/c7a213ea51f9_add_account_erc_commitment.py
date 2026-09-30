"""Store only an account-bound commitment for shared recovery entropy."""

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "c7a213ea51f9"
down_revision: Union[str, None] = "b28a413c96d2"
branch_labels: Union[str, None] = None
depends_on: Union[str, None] = None


def upgrade() -> None:
    op.add_column(
        "aeterna_accounts", sa.Column("erc_commitment", sa.LargeBinary(), nullable=True)
    )
    op.add_column(
        "aeterna_accounts",
        sa.Column("erc_commitment_epoch", sa.Integer(), nullable=True),
    )
    op.add_column(
        "aeterna_accounts",
        sa.Column("erc_commitment_generation", sa.Integer(), nullable=True),
    )
    op.create_check_constraint(
        "ck_aeterna_accounts_erc_commitment",
        "aeterna_accounts",
        "(erc_commitment IS NULL AND erc_commitment_epoch IS NULL "
        "AND erc_commitment_generation IS NULL) OR "
        "(octet_length(erc_commitment) = 32 AND erc_commitment_epoch > 0 "
        "AND erc_commitment_generation > 0)",
    )
    op.add_column(
        "aeterna_recovery_records",
        sa.Column("erc_commitment", sa.LargeBinary(), nullable=True),
    )
    op.create_check_constraint(
        "ck_aeterna_recovery_records_erc_commitment_length",
        "aeterna_recovery_records",
        "erc_commitment IS NULL OR octet_length(erc_commitment) = 32",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_aeterna_recovery_records_erc_commitment_length",
        "aeterna_recovery_records",
        type_="check",
    )
    op.drop_column("aeterna_recovery_records", "erc_commitment")
    op.drop_constraint(
        "ck_aeterna_accounts_erc_commitment", "aeterna_accounts", type_="check"
    )
    op.drop_column("aeterna_accounts", "erc_commitment_generation")
    op.drop_column("aeterna_accounts", "erc_commitment_epoch")
    op.drop_column("aeterna_accounts", "erc_commitment")
