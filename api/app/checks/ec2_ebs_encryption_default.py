from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks.base import FindingDraft, score
from app.models import AwsAccount
from app.models.resources import EbsEncryptionDefault

CHECK_ID = "ec2.ebs.encryption_not_default"


def run(db: Session, account_id) -> list[FindingDraft]:
    acc = db.get(AwsAccount, account_id)
    if not acc:
        return []

    disabled = db.scalars(
        select(EbsEncryptionDefault).where(
            EbsEncryptionDefault.account_id == account_id,
            EbsEncryptionDefault.enabled == False,  # noqa: E712
        )
    ).all()

    if not disabled:
        return []

    regions = sorted(d.region for d in disabled)

    return [
        FindingDraft(
            check_id=CHECK_ID,
            resource_arn=f"arn:aws:ec2::{acc.account_id or 'unknown'}:ebs-encryption-default",
            title="EBS encryption by default is not enabled",
            severity="medium",
            risk_score=score("medium"),
            evidence={
                "disabled_regions": regions,
                "region_count": len(regions),
            },
        )
    ]
