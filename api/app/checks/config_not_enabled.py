from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks.base import FindingDraft, score
from app.models import AwsAccount
from app.models.resources import ConfigRecorder

CHECK_ID = "aws.config.not_enabled"


def run(db: Session, account_id) -> list[FindingDraft]:
    acc = db.get(AwsAccount, account_id)
    if not acc:
        return []

    not_recording = db.scalars(
        select(ConfigRecorder).where(
            ConfigRecorder.account_id == account_id,
            (ConfigRecorder.recording == False) | (ConfigRecorder.delivery_channel_exists == False),  # noqa: E712
        )
    ).all()

    if not not_recording:
        return []

    regions = sorted(r.region for r in not_recording)

    return [
        FindingDraft(
            check_id=CHECK_ID,
            resource_arn=f"arn:aws:config::{acc.account_id or 'unknown'}:account",
            title="AWS Config is not fully enabled",
            severity="low",
            risk_score=score("low"),
            evidence={
                "affected_regions": regions,
                "region_count": len(regions),
            },
        )
    ]
