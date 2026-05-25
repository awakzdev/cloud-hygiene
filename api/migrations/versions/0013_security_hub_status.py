"""Add Security Hub status table.

Revision ID: 0013
Revises: 0012
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "security_hub_statuses",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("account_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("aws_accounts.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("region", sa.String(40), nullable=False),
        sa.Column("hub_arn", sa.String(512), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.UniqueConstraint("account_id", "region"),
    )


def downgrade() -> None:
    op.drop_table("security_hub_statuses")
