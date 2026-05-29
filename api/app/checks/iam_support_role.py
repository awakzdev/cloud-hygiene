"""CIS 1.16 — account should have a role that can manage AWS Support cases."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks.base import FindingDraft, score
from app.models import AwsAccount, IamRole

CHECK_ID = "iam.account.no_support_role"
_SUPPORT_POLICY_MARKERS = ("AWSSupportAccess", "arn:aws:iam::aws:policy/AWSSupportAccess")


def _role_has_support_access(role: IamRole) -> bool:
    for pol in role.attached_policies or []:
        arn = (pol.get("policy_arn") or "").strip()
        name = (pol.get("policy_name") or "").strip()
        if any(m in arn or m == name for m in _SUPPORT_POLICY_MARKERS):
            return True
    for _pname, doc in (role.inline_policies or {}).items():
        for stmt in doc.get("Statement", []) if isinstance(doc, dict) else []:
            if not isinstance(stmt, dict):
                continue
            for action in stmt.get("Action", []) if isinstance(stmt.get("Action"), list) else [stmt.get("Action")]:
                if action and "support:" in str(action).lower():
                    return True
    return False


def run(db: Session, account_id) -> list[FindingDraft]:
    acc = db.get(AwsAccount, account_id)
    if not acc:
        return []

    roles = db.scalars(select(IamRole).where(IamRole.account_id == account_id)).all()
    support_roles = [r.name for r in roles if _role_has_support_access(r)]
    if support_roles:
        return []

    return [
        FindingDraft(
            check_id=CHECK_ID,
            resource_arn=f"arn:aws:iam::{acc.account_id or 'unknown'}:account/support-role",
            title="No IAM role with AWSSupportAccess for AWS Support",
            severity="low",
            risk_score=score("low"),
            evidence={
                "roles_scanned": len(roles),
                "hint": "Attach managed policy AWSSupportAccess to a dedicated support role",
            },
        )
    ]
