from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks.base import FindingDraft, score
from app.models import AwsAccount
from app.models.resources import SecurityHubStatus

CHECK_ID = "aws.securityhub.not_enabled"


def run(db: Session, account_id) -> list[FindingDraft]:
    acc = db.get(AwsAccount, account_id)
    if not acc:
        return []

    disabled = db.scalars(
        select(SecurityHubStatus).where(
            SecurityHubStatus.account_id == account_id,
            SecurityHubStatus.enabled == False,  # noqa: E712
        )
    ).all()

    if not disabled:
        return []

    regions = sorted(s.region for s in disabled)

    return [
        FindingDraft(
            check_id=CHECK_ID,
            resource_arn=f"arn:aws:securityhub::{acc.account_id or 'unknown'}:account",
            title="Security Hub is not enabled",
            severity="medium",
            risk_score=score("medium"),
            evidence={
                "disabled_regions": regions,
                "region_count": len(regions),
            },
        )
    ]
