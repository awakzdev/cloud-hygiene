"""add settings jsonb to orgs

Revision ID: 0005
Revises: 0004
Create Date: 2026-05-24
"""
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE orgs ADD COLUMN IF NOT EXISTS settings JSONB NOT NULL DEFAULT '{}'")


def downgrade() -> None:
    op.execute("ALTER TABLE orgs DROP COLUMN IF EXISTS settings")
