from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks.base import FindingDraft, score
from app.models import AwsAccount
from app.models.resources import IamPasswordPolicy

CHECK_ID = "iam.account.password_policy_weak"

_MIN_LENGTH = 14
_MAX_AGE = 90
_MIN_REUSE_PREVENTION = 5


def run(db: Session, account_id) -> list[FindingDraft]:
    acc = db.get(AwsAccount, account_id)
    if not acc:
        return []

    pol = db.scalar(
        select(IamPasswordPolicy).where(IamPasswordPolicy.account_id == account_id)
    )

    if pol is None:
        return []

    failures: list[str] = []

    if not pol.exists:
        failures.append("no password policy set")
    else:
        if pol.min_length is None or pol.min_length < _MIN_LENGTH:
            failures.append(f"minimum length is {pol.min_length or 0} (required: {_MIN_LENGTH})")
        if not pol.require_uppercase:
            failures.append("uppercase characters not required")
        if not pol.require_lowercase:
            failures.append("lowercase characters not required")
        if not pol.require_numbers:
            failures.append("numbers not required")
        if not pol.require_symbols:
            failures.append("symbols not required")
        if pol.max_age is None or pol.max_age == 0 or pol.max_age > _MAX_AGE:
            failures.append(f"password expiry is {pol.max_age or 'never'} days (required: ≤{_MAX_AGE})")
        if pol.password_reuse_prevention is None or pol.password_reuse_prevention < _MIN_REUSE_PREVENTION:
            failures.append(f"password reuse prevention is {pol.password_reuse_prevention or 0} (required: ≥{_MIN_REUSE_PREVENTION})")

    if not failures:
        return []

    return [
        FindingDraft(
            check_id=CHECK_ID,
            resource_arn=f"arn:aws:iam::{acc.account_id or 'unknown'}:account-password-policy",
            title="IAM account password policy does not meet requirements",
            severity="medium",
            risk_score=score("medium"),
            evidence={
                "failures": failures,
                "min_length": pol.min_length,
                "require_uppercase": pol.require_uppercase,
                "require_lowercase": pol.require_lowercase,
                "require_numbers": pol.require_numbers,
                "require_symbols": pol.require_symbols,
                "max_age_days": pol.max_age,
                "password_reuse_prevention": pol.password_reuse_prevention,
                "policy_exists": pol.exists,
            },
        )
    ]
