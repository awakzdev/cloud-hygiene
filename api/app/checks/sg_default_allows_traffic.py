from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks.base import FindingDraft, score
from app.models import AwsAccount
from app.models.resources import SecurityGroup

CHECK_ID = "ec2.security_group.default_allows_traffic"


def run(db: Session, account_id) -> list[FindingDraft]:
    acc = db.get(AwsAccount, account_id)
    if not acc:
        return []

    violating = db.scalars(
        select(SecurityGroup).where(
            SecurityGroup.account_id == account_id,
            SecurityGroup.is_default == True,  # noqa: E712
            (SecurityGroup.has_any_inbound_rules == True) | (SecurityGroup.has_any_outbound_rules == True),  # noqa: E712
        )
    ).all()

    return [
        FindingDraft(
            check_id=CHECK_ID,
            resource_arn=f"arn:aws:ec2:{sg.region}:{acc.account_id or 'unknown'}:security-group/{sg.group_id}",
            title=f"Default security group in {sg.vpc_id or sg.region} allows traffic",
            severity="medium",
            risk_score=score("medium"),
            evidence={
                "group_id": sg.group_id,
                "vpc_id": sg.vpc_id,
                "region": sg.region,
                "has_inbound_rules": sg.has_any_inbound_rules,
                "has_outbound_rules": sg.has_any_outbound_rules,
            },
        )
        for sg in violating
    ]
