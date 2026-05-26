"""Add has_codeowners and protected_envs to repos.

Revision ID: 0020
Revises: 0019
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("repos", sa.Column("has_codeowners", sa.Boolean(), nullable=True))
    op.add_column("repos", sa.Column("protected_envs", postgresql.JSONB(), nullable=True))


def downgrade() -> None:
    op.drop_column("repos", "protected_envs")
    op.drop_column("repos", "has_codeowners")
