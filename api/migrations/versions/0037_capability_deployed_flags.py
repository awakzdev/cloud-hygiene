"""Track optional capabilities only after AWS deployment is verified."""

from alembic import op
import sqlalchemy as sa

revision = "0037"
down_revision = "0036"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "aws_accounts",
        sa.Column(
            "advanced_policy_generation_deployed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column(
        "aws_accounts",
        sa.Column(
            "remediation_automation_deployed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    op.drop_column("aws_accounts", "remediation_automation_deployed")
    op.drop_column("aws_accounts", "advanced_policy_generation_deployed")
