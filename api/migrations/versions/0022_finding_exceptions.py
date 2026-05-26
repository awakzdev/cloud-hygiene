"""Add exception fields to findings.

Revision ID: 0022
Revises: 0021
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("exception_reason", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("exception_approved_by", sa.String(320), nullable=True))
    op.add_column("findings", sa.Column("exception_expires_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "exception_expires_at")
    op.drop_column("findings", "exception_approved_by")
    op.drop_column("findings", "exception_reason")
