"""Add SSM parameter remediation module flags."""

from alembic import op
import sqlalchemy as sa

revision = "0040_ssm_remediation_module"
down_revision = "0039_cfn_stack_name"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "aws_accounts",
        sa.Column("enable_remediation_ssm_parameters", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "aws_accounts",
        sa.Column("remediation_ssm_parameters_deployed", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("aws_accounts", "remediation_ssm_parameters_deployed")
    op.drop_column("aws_accounts", "enable_remediation_ssm_parameters")
