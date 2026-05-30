"""Per-module remediation flags (replace single enable_remediation_automation)."""

from alembic import op
import sqlalchemy as sa

revision = "0038"
down_revision = "0037"
branch_labels = None
depends_on = None

_MODULE_ENABLE_COLS = [
    "enable_remediation_sg",
    "enable_remediation_s3",
    "enable_remediation_iam_keys",
    "enable_remediation_iam_policy",
    "enable_remediation_cloudtrail",
]
_MODULE_DEPLOYED_COLS = [
    "remediation_sg_deployed",
    "remediation_s3_deployed",
    "remediation_iam_keys_deployed",
    "remediation_iam_policy_deployed",
    "remediation_cloudtrail_deployed",
]


def upgrade() -> None:
    for col in _MODULE_ENABLE_COLS:
        op.add_column(
            "aws_accounts",
            sa.Column(col, sa.Boolean(), nullable=False, server_default=sa.false()),
        )
    for col in _MODULE_DEPLOYED_COLS:
        op.add_column(
            "aws_accounts",
            sa.Column(col, sa.Boolean(), nullable=False, server_default=sa.false()),
        )

    op.execute(
        """
        UPDATE aws_accounts
        SET enable_remediation_sg = enable_remediation_automation,
            remediation_sg_deployed = remediation_automation_deployed
        """
    )

    op.drop_column("aws_accounts", "remediation_automation_deployed")
    op.drop_column("aws_accounts", "enable_remediation_automation")


def downgrade() -> None:
    op.add_column(
        "aws_accounts",
        sa.Column("enable_remediation_automation", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "aws_accounts",
        sa.Column("remediation_automation_deployed", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.execute(
        """
        UPDATE aws_accounts
        SET enable_remediation_automation = enable_remediation_sg,
            remediation_automation_deployed = remediation_sg_deployed
        """
    )
    for col in reversed(_MODULE_DEPLOYED_COLS):
        op.drop_column("aws_accounts", col)
    for col in reversed(_MODULE_ENABLE_COLS):
        op.drop_column("aws_accounts", col)
