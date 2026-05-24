from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks.base import FindingDraft, score
from app.models.resources import KmsKey

CHECK_ID = "kms.key.no_rotation"


def run(db: Session, account_id) -> list[FindingDraft]:
    rows = db.scalars(
        select(KmsKey).where(
            KmsKey.account_id == account_id,
            KmsKey.rotation_enabled == False,  # noqa: E712
        )
    ).all()
    return [
        FindingDraft(
            check_id=CHECK_ID,
            resource_arn=k.arn,
            title=f"KMS key `{k.alias or k.key_id}` does not have automatic rotation enabled",
            severity="medium",
            risk_score=score("medium"),
            evidence={"key_id": k.key_id, "alias": k.alias},
        )
        for k in rows
    ]
