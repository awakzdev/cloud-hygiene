from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks.base import FindingDraft, score
from app.models import IamAccessKey

CHECK_ID = "iam.access_key.unused_45d"
THRESHOLD_DAYS = 45


def run(db: Session, account_id) -> list[FindingDraft]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=THRESHOLD_DAYS)
    rows = db.scalars(
        select(IamAccessKey).where(IamAccessKey.account_id == account_id, IamAccessKey.status == "Active")
    ).all()
    out: list[FindingDraft] = []
    for k in rows:
        ref = k.last_used or k.created
        if ref and ref >= cutoff:
            continue
        days = _days_since(ref)
        out.append(
            FindingDraft(
                check_id=CHECK_ID,
                resource_arn=f"{k.user_arn}#{k.key_id}",
                title=f"Access key `{k.key_id[-4:]}...` on `{_uname(k.user_arn)}` unused 45+ days",
                severity="high",
                risk_score=score("high", age_days=days or THRESHOLD_DAYS),
                evidence={
                    "user_arn": k.user_arn,
                    "key_id": k.key_id,
                    "created": k.created.isoformat() if k.created else None,
                    "last_used": k.last_used.isoformat() if k.last_used else None,
                    "threshold_days": THRESHOLD_DAYS,
                    "days_unused": days,
                    "cis_control": "1.11",
                },
            )
        )
    return out


def _days_since(ts) -> int | None:
    if not ts:
        return None
    return (datetime.now(timezone.utc) - ts).days


def _uname(arn: str) -> str:
    return arn.split("/")[-1] if "/" in arn else arn
