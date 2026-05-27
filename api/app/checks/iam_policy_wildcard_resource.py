from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks.base import FindingDraft, score
from app.models import AwsAccount
from app.models.iam import IamRole

CHECK_ID = "iam.policy.wildcard_resource"

# Vigil collector + IAM credential report APIs — read-only, require Resource: *
_SAFE_ACTIONS_ON_ANY_RESOURCE = {
    "iam:generateservicelastaccesseddetails",
    "iam:getservicelastaccesseddetails",
}

# Read-only prefixes safe to ignore on Resource: *
_SAFE_PREFIXES = {
    "Describe", "List", "Get", "Head", "View", "Scan",
    "Search", "Query", "Lookup", "Read", "Show",
}

_DANGEROUS_SERVICES = {
    "iam", "sts", "kms", "s3", "secretsmanager", "ssm",
    "lambda", "ec2", "rds", "dynamodb", "cloudtrail",
    "logs", "events", "sns", "sqs",
}


def _is_dangerous_action(action: str) -> bool:
    """Return True if this action on Resource:* is worth flagging."""
    action = action.strip()
    if action.lower() in _SAFE_ACTIONS_ON_ANY_RESOURCE:
        return False
    if action == "*":
        return False  # already caught by wildcard_action check
    if ":" not in action:
        return True
    service, verb = action.split(":", 1)
    if verb == "*":
        return service.lower() in _DANGEROUS_SERVICES
    # flag if verb is not a safe read prefix
    return not any(verb.startswith(p) for p in _SAFE_PREFIXES)


def _wildcard_resource_statements(doc: dict) -> list[dict]:
    """Return Allow statements that have Resource:* with dangerous actions."""
    flagged = []
    for stmt in doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        if "*" not in resources:
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        dangerous = [a for a in actions if _is_dangerous_action(a)]
        if dangerous:
            flagged.append({
                "sid": stmt.get("Sid", ""),
                "actions": dangerous,
                "resource": "*",
            })
    return flagged


def run(db: Session, account_id) -> list[FindingDraft]:
    acc = db.get(AwsAccount, account_id)
    vigil_role_arn = (acc.role_arn or "").lower() if acc else ""

    roles = db.scalars(select(IamRole).where(IamRole.account_id == account_id)).all()
    out: list[FindingDraft] = []
    for r in roles:
        if "/aws-service-role/" in r.arn:
            continue
        if vigil_role_arn and r.arn.lower() == vigil_role_arn:
            continue  # Vigil CFN scan role — intentionally broad read-only

        hits: list[dict] = []

        for pname, doc in (r.inline_policies or {}).items():
            stmts = _wildcard_resource_statements(doc)
            if stmts:
                hits.append({"policy": pname, "type": "inline", "statements": stmts})

        for pol in (r.attached_policies or []):
            if pol.get("policy_type") == "aws_managed":
                continue
            stmts = _wildcard_resource_statements({"Statement": pol.get("statements", [])})
            if stmts:
                hits.append({"policy": pol["policy_name"], "type": "customer_managed", "statements": stmts})

        if not hits:
            continue

        flat_policies = [
            {
                "policy": h["policy"],
                "type": h["type"],
                "dangerous_actions": ", ".join(
                    a for stmt in h["statements"] for a in stmt["actions"]
                ),
            }
            for h in hits
        ]
        out.append(FindingDraft(
            check_id=CHECK_ID,
            resource_arn=r.arn,
            title=f"Role `{r.name}` grants dangerous actions on Resource: *",
            severity="high",
            risk_score=score("high", admin=True),
            evidence={
                "role_arn": r.arn,
                "policy_names": [h["policy"] for h in hits],
                "policies": flat_policies,
            },
        ))
    return out
