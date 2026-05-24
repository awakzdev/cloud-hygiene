from __future__ import annotations

from sqlalchemy.orm import Session

from app.checks.base import FindingDraft, score
from app.core.aws import assume_role
from app.models import AwsAccount

CHECK_ID = "iam.root.has_access_keys"


def run(db: Session, account_id) -> list[FindingDraft]:
    acc = db.get(AwsAccount, account_id)
    if not acc:
        return []
    try:
        sess = assume_role(acc.role_arn, acc.external_id, session_name="vigil-root-check")
        summary = sess.client("iam").get_account_summary()["SummaryMap"]
    except Exception:  # noqa: BLE001
        return []

    if not summary.get("AccountAccessKeysPresent", 0):
        return []

    return [FindingDraft(
        check_id=CHECK_ID,
        resource_arn=f"arn:aws:iam::{acc.account_id}:root",
        title="Root account has active access keys",
        severity="critical",
        risk_score=score("critical"),
        evidence={"account_id": acc.account_id},
    )]
