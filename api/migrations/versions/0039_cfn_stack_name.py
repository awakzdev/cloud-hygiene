"""Per-account CloudFormation stack name (VigilAccountConnector; legacy VigilReadOnly)."""

from alembic import op
import sqlalchemy as sa

revision = "0039"
down_revision = "0038"
branch_labels = None
depends_on = None

CFN_STACK_LEGACY = "VigilReadOnly"
CFN_STACK_CURRENT = "VigilAccountConnector"


def upgrade() -> None:
    op.add_column(
        "aws_accounts",
        sa.Column(
            "cfn_stack_name",
            sa.String(64),
            nullable=False,
            server_default=CFN_STACK_LEGACY,
        ),
    )
    # Existing rows keep legacy stack name for CloudFormation update URLs.
    op.execute(
        f"UPDATE aws_accounts SET cfn_stack_name = '{CFN_STACK_LEGACY}'"
    )
    op.alter_column("aws_accounts", "cfn_stack_name", server_default=CFN_STACK_CURRENT)


def downgrade() -> None:
    op.drop_column("aws_accounts", "cfn_stack_name")
