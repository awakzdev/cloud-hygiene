"""Account connection options — optional advanced policy gen and remediation stacks."""

from alembic import op
import sqlalchemy as sa

revision = "0036"
down_revision = "0035"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "aws_accounts",
        sa.Column(
            "enable_advanced_policy_generation",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column(
        "aws_accounts",
        sa.Column(
            "enable_remediation_automation",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    op.drop_column("aws_accounts", "enable_remediation_automation")
    op.drop_column("aws_accounts", "enable_advanced_policy_generation")
