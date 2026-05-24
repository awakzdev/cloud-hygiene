"""add s3_buckets and kms_keys tables

Revision ID: 0006
Revises: 0005
Create Date: 2026-05-24
"""
from alembic import op
import sqlalchemy as sa

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "s3_buckets",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("account_id", sa.dialects.postgresql.UUID(as_uuid=True), sa.ForeignKey("aws_accounts.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("arn", sa.String(512), nullable=False),
        sa.Column("logging_enabled", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("encrypted", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("kms_encrypted", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("versioning_enabled", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("public_access_blocked", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("https_only", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("account_id", "arn"),
    )

    op.create_table(
        "kms_keys",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("account_id", sa.dialects.postgresql.UUID(as_uuid=True), sa.ForeignKey("aws_accounts.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("key_id", sa.String(64), nullable=False),
        sa.Column("arn", sa.String(512), nullable=False),
        sa.Column("alias", sa.String(256), nullable=True),
        sa.Column("rotation_enabled", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("has_wildcard_principal", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("key_state", sa.String(40), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("account_id", "arn"),
    )


def downgrade() -> None:
    op.drop_table("kms_keys")
    op.drop_table("s3_buckets")
