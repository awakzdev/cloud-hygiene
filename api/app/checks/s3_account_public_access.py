from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks.base import FindingDraft, score
from app.models import AwsAccount
from app.models.resources import S3AccountPublicAccessBlock

CHECK_ID = "s3.account.public_access_not_blocked"


def run(db: Session, account_id) -> list[FindingDraft]:
    acc = db.get(AwsAccount, account_id)
    if not acc:
        return []

    cfg = db.scalars(
        select(S3AccountPublicAccessBlock).where(
            S3AccountPublicAccessBlock.account_id == account_id,
            S3AccountPublicAccessBlock.all_blocked == False,  # noqa: E712
        )
    ).first()

    if not cfg:
        return []

    return [
        FindingDraft(
            check_id=CHECK_ID,
            resource_arn=f"arn:aws:s3:::{acc.account_id or 'unknown'}:account-public-access-block",
            title="S3 account-level Block Public Access is not fully enabled",
            severity="high",
            risk_score=score("high"),
            evidence={
                "block_public_acls": cfg.block_public_acls,
                "ignore_public_acls": cfg.ignore_public_acls,
                "block_public_policy": cfg.block_public_policy,
                "restrict_public_buckets": cfg.restrict_public_buckets,
            },
        )
    ]
