"""Check: role granted services it hasn't used in 90 days."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks.base import FindingDraft, score
from app.models import IamPermUsage, IamRole

CHECK_ID = "iam.role.unused_services_90d"
THRESHOLD_DAYS = 90


def _removable_statements(inline_policies: dict, unused_set: set[str]) -> list[dict]:
    """Find inline policy statements whose actions map to unused services."""
    out = []
    for policy_name, doc in (inline_policies or {}).items():
        stmts = doc.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        for stmt in stmts:
            if stmt.get("Effect", "Allow") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            if any(a == "*" for a in actions):
                matching = ["* (action wildcard — narrow to used API calls)"]
            else:
                matching = [
                    a for a in actions
                    if a.split(":")[0].lower() in unused_set
                ]
            if not matching:
                continue
            resources = stmt.get("Resource", ["*"])
            if isinstance(resources, str):
                resources = [resources]
            out.append({
                "policy": policy_name,
                "sid": stmt.get("Sid", ""),
                "actions": matching,
                "resources": resources,
            })
    return out


def run(db: Session, account_id) -> list[FindingDraft]:
    roles = db.scalars(select(IamRole).where(IamRole.account_id == account_id)).all()
    cutoff = datetime.now(timezone.utc) - timedelta(days=THRESHOLD_DAYS)
    out: list[FindingDraft] = []

    for r in roles:
        if "/aws-service-role/" in r.arn:
            continue

        usages = db.scalars(
            select(IamPermUsage).where(
                IamPermUsage.account_id == account_id,
                IamPermUsage.principal_arn == r.arn,
            )
        ).all()

        if not usages:
            continue  # no data yet — collector hasn't run or no policies

        unused = sorted(
            u.service for u in usages
            if u.last_authenticated is None or u.last_authenticated < cutoff
        )

        if not unused:
            continue

        total = len(usages)
        age_days = 90 + max(
            (
                (datetime.now(timezone.utc) - u.last_authenticated).days - 90
                for u in usages
                if u.last_authenticated is not None and u.last_authenticated < cutoff
            ),
            default=0,
        )

        unused_set = set(unused)
        removable = _removable_statements(r.inline_policies or {}, unused_set)

        out.append(
            FindingDraft(
                check_id=CHECK_ID,
                resource_arn=r.arn,
                title=f"Role `{r.name}` has {len(unused)}/{total} granted services unused for 90+ days",
                severity="medium",
                risk_score=score("medium", age_days=age_days),
                evidence={
                    "unused_services": unused,
                    "total_granted_services": total,
                    "threshold_days": THRESHOLD_DAYS,
                    "removable_statements": removable,
                },
            )
        )

    return out
