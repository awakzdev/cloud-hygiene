"""Check: role grants actions that have no recorded usage in 90 days (action-level)."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks.base import FindingDraft, score
from app.models import IamPermUsage, IamRole

CHECK_ID = "iam.perm.granted_vs_used"
THRESHOLD_DAYS = 90

# Prefixes we consider read-only/low-risk — skip from the unused calculation
_SAFE_PREFIXES = re.compile(
    r"^(Describe|List|Get|Head|View|Scan|Search|Query|Lookup|Read|Show)",
    re.IGNORECASE,
)


def _extract_granted_actions(role: IamRole) -> dict[str, list[str]]:
    """Return {service: [action, ...]} for all Allow actions in role policies."""
    granted: dict[str, list[str]] = {}

    def _add(action: str) -> None:
        if ":" not in action:
            return
        svc, act = action.split(":", 1)
        svc = svc.lower()
        if act == "*":
            return  # wildcard_action check handles this
        if _SAFE_PREFIXES.match(act):
            return  # read-only, low risk
        granted.setdefault(svc, []).append(action)

    def _walk(doc: dict) -> None:
        stmts = doc.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        for stmt in stmts:
            if stmt.get("Effect", "Allow") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            for a in actions:
                _add(a)

    for doc in (role.inline_policies or {}).values():
        _walk(doc)
    for pol in (role.attached_policies or []):
        doc = pol.get("document") or {}
        _walk(doc)

    return granted


def run(db: Session, account_id) -> list[FindingDraft]:
    roles = db.scalars(select(IamRole).where(IamRole.account_id == account_id)).all()
    cutoff = datetime.now(timezone.utc) - timedelta(days=THRESHOLD_DAYS)
    out: list[FindingDraft] = []

    for r in roles:
        if "/aws-service-role/" in r.arn:
            continue

        granted = _extract_granted_actions(r)
        if not granted:
            continue

        usages = db.scalars(
            select(IamPermUsage).where(
                IamPermUsage.account_id == account_id,
                IamPermUsage.principal_arn == r.arn,
            )
        ).all()

        # Build set of action names used in the last 90 days (ACTION_LEVEL data)
        used_actions: set[str] = set()
        for u in usages:
            if u.last_authenticated and u.last_authenticated >= cutoff:
                for a in (u.actions_json or []):
                    used_actions.add(a.lower())

        # If no action-level data at all, skip — collector may not have run yet
        if not any(u.actions_json for u in usages):
            continue

        # Find write actions granted but never observed
        unused: list[str] = []
        for svc_actions in granted.values():
            for action in svc_actions:
                if action.lower() not in used_actions:
                    unused.append(action)

        if not unused:
            continue

        total_granted = sum(len(v) for v in granted.values())
        unused_pct = int(100 * len(unused) / total_granted) if total_granted else 0

        # Only flag if ≥40% of granted write actions are unused
        if unused_pct < 40:
            continue

        out.append(FindingDraft(
            check_id=CHECK_ID,
            resource_arn=r.arn,
            title=f"Role `{r.name}` has {len(unused)} write actions granted but never used",
            severity="medium",
            risk_score=score("medium"),
            evidence={
                "role_name": r.name,
                "total_granted_write_actions": total_granted,
                "unused_write_actions": unused[:30],  # cap for readability
                "unused_pct": unused_pct,
                "note": "Only write/mutating actions counted — read-only actions excluded",
            },
        ))

    return out
