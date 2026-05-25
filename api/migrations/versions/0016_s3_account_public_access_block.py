"""Add S3 account public access block table.

Revision ID: 0016
Revises: 0015
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "s3_account_public_access_blocks",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("account_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("aws_accounts.id", ondelete="CASCADE"), nullable=False, unique=True, index=True),
        sa.Column("block_public_acls", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("ignore_public_acls", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("block_public_policy", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("restrict_public_buckets", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("all_blocked", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )


def downgrade() -> None:
    op.drop_table("s3_account_public_access_blocks")
