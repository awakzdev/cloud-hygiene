from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks.base import FindingDraft, score
from app.models import AwsAccount
from app.models.resources import Ec2Instance

CHECK_ID = "ec2.instance.imdsv2_not_required"


def run(db: Session, account_id) -> list[FindingDraft]:
    acc = db.get(AwsAccount, account_id)
    if not acc:
        return []

    instances = db.scalars(
        select(Ec2Instance).where(
            Ec2Instance.account_id == account_id,
            Ec2Instance.imdsv2_required == False,  # noqa: E712
            Ec2Instance.state == "running",
        )
    ).all()

    return [
        FindingDraft(
            check_id=CHECK_ID,
            resource_arn=f"arn:aws:ec2:{i.region}:{acc.account_id or 'unknown'}:instance/{i.instance_id}",
            title=f"Instance `{i.instance_id}` does not require IMDSv2",
            severity="medium",
            risk_score=score("medium"),
            evidence={
                "instance_id": i.instance_id,
                "region": i.region,
                "instance_type": i.instance_type,
                "state": i.state,
            },
        )
        for i in instances
    ]
