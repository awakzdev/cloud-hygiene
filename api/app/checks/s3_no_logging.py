from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks.base import FindingDraft, score
from app.models.resources import S3Bucket

CHECK_ID = "s3.bucket.no_logging"


def run(db: Session, account_id) -> list[FindingDraft]:
    rows = db.scalars(
        select(S3Bucket).where(
            S3Bucket.account_id == account_id,
            S3Bucket.logging_enabled == False,  # noqa: E712
        )
    ).all()
    return [
        FindingDraft(
            check_id=CHECK_ID,
            resource_arn=b.arn,
            title=f"S3 bucket `{b.name}` has access logging disabled",
            severity="low",
            risk_score=score("low"),
            evidence={"bucket_name": b.name},
        )
        for b in rows
    ]
