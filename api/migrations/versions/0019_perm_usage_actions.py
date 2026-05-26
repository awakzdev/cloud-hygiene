"""Add actions_json to iam_perm_usage for action-level last-accessed data.

Revision ID: 0019
Revises: 0018
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "iam_perm_usage",
        sa.Column("actions_json", postgresql.JSONB(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("iam_perm_usage", "actions_json")
