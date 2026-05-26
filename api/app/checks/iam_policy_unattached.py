from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks.base import FindingDraft, score
from app.models.iam import IamPolicy

CHECK_ID = "iam.policy.unattached"


def run(db: Session, account_id) -> list[FindingDraft]:
    policies = db.scalars(
        select(IamPolicy).where(
            IamPolicy.account_id == account_id,
            IamPolicy.attachment_count == 0,
        )
    ).all()

    return [
        FindingDraft(
            check_id=CHECK_ID,
            resource_arn=p.arn,
            title=f"Customer-managed policy `{p.name}` is not attached to anything",
            severity="low",
            risk_score=score("low"),
            evidence={
                "policy_arn": p.arn,
                "policy_name": p.name,
                "attachment_count": p.attachment_count,
            },
        )
        for p in policies
    ]
