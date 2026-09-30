"""Require complete account commitment metadata or none of it."""

from typing import Union

from alembic import op

revision: str = "d81b53aa672e"
down_revision: Union[str, None] = "c7a213ea51f9"
branch_labels: Union[str, None] = None
depends_on: Union[str, None] = None


def upgrade() -> None:
    op.drop_constraint(
        "ck_aeterna_accounts_erc_commitment", "aeterna_accounts", type_="check"
    )
    op.create_check_constraint(
        "ck_aeterna_accounts_erc_commitment",
        "aeterna_accounts",
        "(erc_commitment IS NULL AND erc_commitment_epoch IS NULL "
        "AND erc_commitment_generation IS NULL) OR "
        "(erc_commitment IS NOT NULL AND erc_commitment_epoch IS NOT NULL "
        "AND erc_commitment_generation IS NOT NULL "
        "AND octet_length(erc_commitment) = 32 AND erc_commitment_epoch > 0 "
        "AND erc_commitment_generation > 0)",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_aeterna_accounts_erc_commitment", "aeterna_accounts", type_="check"
    )
    op.create_check_constraint(
        "ck_aeterna_accounts_erc_commitment",
        "aeterna_accounts",
        "(erc_commitment IS NULL AND erc_commitment_epoch IS NULL "
        "AND erc_commitment_generation IS NULL) OR "
        "(octet_length(erc_commitment) = 32 AND erc_commitment_epoch > 0 "
        "AND erc_commitment_generation > 0)",
    )
