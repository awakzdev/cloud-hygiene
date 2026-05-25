"""Add composite index on findings(org_id, status, risk_score)

Revision ID: 0009
Revises: 0008
"""
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_findings_org_status_score",
        "findings",
        ["org_id", "status", "risk_score"],
        postgresql_ops={"risk_score": "DESC"},
    )


def downgrade() -> None:
    op.drop_index("ix_findings_org_status_score", table_name="findings")
