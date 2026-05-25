from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks.base import FindingDraft, score
from app.models import AwsAccount
from app.models.resources import AccessAnalyzer

CHECK_ID = "aws.access_analyzer.not_enabled"


def run(db: Session, account_id) -> list[FindingDraft]:
    acc = db.get(AwsAccount, account_id)
    if not acc:
        return []

    disabled = db.scalars(
        select(AccessAnalyzer).where(
            AccessAnalyzer.account_id == account_id,
            AccessAnalyzer.status != "ACTIVE",
        )
    ).all()

    if not disabled:
        return []

    regions = sorted(d.region for d in disabled)

    return [
        FindingDraft(
            check_id=CHECK_ID,
            resource_arn=f"arn:aws:access-analyzer::{acc.account_id or 'unknown'}:account",
            title="IAM Access Analyzer is not enabled",
            severity="medium",
            risk_score=score("medium"),
            evidence={
                "disabled_regions": regions,
                "region_count": len(regions),
            },
        )
    ]
