from __future__ import annotations

from sqlalchemy.orm import Session

from app.checks.base import FindingDraft, score
from app.core.aws import assume_role
from app.models import AwsAccount

CHECK_ID = "iam.root.no_mfa"


def run(db: Session, account_id) -> list[FindingDraft]:
    acc = db.get(AwsAccount, account_id)
    if not acc:
        return []
    try:
        sess = assume_role(acc.role_arn, acc.external_id, session_name="vigil-root-mfa")
        summary = sess.client("iam").get_account_summary()["SummaryMap"]
    except Exception:  # noqa: BLE001
        return []

    if summary.get("AccountMFAEnabled", 0):
        return []

    return [FindingDraft(
        check_id=CHECK_ID,
        resource_arn=f"arn:aws:iam::{acc.account_id}:root",
        title="Root account does not have MFA enabled",
        severity="critical",
        risk_score=score("critical"),
        evidence={"account_id": acc.account_id},
    )]
