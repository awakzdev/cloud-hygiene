"""Add EC2 instances, EBS defaults, IAM password policy, Access Analyzer, Config Recorder tables.
Also extend security_groups with vpc_id, is_default, has_any_inbound/outbound_rules.

Revision ID: 0012
Revises: 0011
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── EC2 instances ─────────────────────────────────────────────────────────
    op.create_table(
        "ec2_instances",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("account_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("aws_accounts.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("instance_id", sa.String(64), nullable=False),
        sa.Column("region", sa.String(40), nullable=False),
        sa.Column("instance_type", sa.String(64), nullable=True),
        sa.Column("state", sa.String(20), nullable=False, server_default="unknown"),
        sa.Column("imdsv2_required", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("vpc_id", sa.String(64), nullable=True),
        sa.Column("subnet_id", sa.String(64), nullable=True),
        sa.Column("security_group_ids", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("tags", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.UniqueConstraint("account_id", "region", "instance_id"),
    )

    # ── EBS encryption defaults ───────────────────────────────────────────────
    op.create_table(
        "ebs_encryption_defaults",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("account_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("aws_accounts.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("region", sa.String(40), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.UniqueConstraint("account_id", "region"),
    )

    # ── IAM password policy (one per account) ─────────────────────────────────
    op.create_table(
        "iam_password_policies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("account_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("aws_accounts.id", ondelete="CASCADE"), nullable=False, unique=True, index=True),
        sa.Column("exists", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("min_length", sa.Integer(), nullable=True),
        sa.Column("require_uppercase", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("require_lowercase", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("require_numbers", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("require_symbols", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("max_age", sa.Integer(), nullable=True),
        sa.Column("password_reuse_prevention", sa.Integer(), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )

    # ── Access Analyzer (per region) ──────────────────────────────────────────
    op.create_table(
        "access_analyzers",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("account_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("aws_accounts.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("region", sa.String(40), nullable=False),
        sa.Column("analyzer_name", sa.String(256), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="none"),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.UniqueConstraint("account_id", "region"),
    )

    # ── Config Recorder (per region) ─────────────────────────────────────────
    op.create_table(
        "config_recorders",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("account_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("aws_accounts.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("region", sa.String(40), nullable=False),
        sa.Column("recorder_name", sa.String(256), nullable=True),
        sa.Column("recording", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("delivery_channel_exists", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.UniqueConstraint("account_id", "region"),
    )

    # ── Extend security_groups ────────────────────────────────────────────────
    op.add_column("security_groups", sa.Column("vpc_id", sa.String(64), nullable=True))
    op.add_column("security_groups", sa.Column("is_default", sa.Boolean(), nullable=False, server_default="false"))
    op.add_column("security_groups", sa.Column("has_any_inbound_rules", sa.Boolean(), nullable=False, server_default="false"))
    op.add_column("security_groups", sa.Column("has_any_outbound_rules", sa.Boolean(), nullable=False, server_default="false"))


def downgrade() -> None:
    op.drop_column("security_groups", "has_any_outbound_rules")
    op.drop_column("security_groups", "has_any_inbound_rules")
    op.drop_column("security_groups", "is_default")
    op.drop_column("security_groups", "vpc_id")
    op.drop_table("config_recorders")
    op.drop_table("access_analyzers")
    op.drop_table("iam_password_policies")
    op.drop_table("ebs_encryption_defaults")
    op.drop_table("ec2_instances")
