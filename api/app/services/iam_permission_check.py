"""Check IAM role policies for required actions (no resource mutations)."""
from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError


def iam_action_matches(pattern: str, action: str) -> bool:
    """Match IAM action strings including * wildcards."""
    pat = pattern.strip().lower()
    act = action.strip().lower()
    if pat == "*" or pat == act:
        return True
    if "*" not in pat:
        return False
    if pat.endswith("*"):
        return act.startswith(pat[:-1])
    if pat.startswith("*"):
        return act.endswith(pat[1:])
    return False


def _normalize_actions(value: str | list[str] | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def statements_allow_action(statements: list[dict[str, Any]], action: str) -> bool:
    """True if any Allow statement grants action and no Deny blocks it."""
    denied = False
    allowed = False
    for stmt in statements:
        effect = stmt.get("Effect")
        actions = _normalize_actions(stmt.get("Action"))
        not_actions = _normalize_actions(stmt.get("NotAction"))
        if effect == "Deny":
            if any(iam_action_matches(p, action) for p in actions):
                denied = True
            if not_actions and not any(iam_action_matches(p, action) for p in not_actions):
                denied = True
        elif effect == "Allow":
            if any(iam_action_matches(p, action) for p in actions):
                allowed = True
            if not_actions and not any(iam_action_matches(p, action) for p in not_actions):
                allowed = True
    return allowed and not denied


def _policy_document(doc: Any) -> dict[str, Any]:
    if isinstance(doc, str):
        return json.loads(doc)
    return doc


def load_role_policy_documents(iam_client, role_name: str) -> list[dict[str, Any]]:
    """Inline + attached managed policy documents for a role."""
    documents: list[dict[str, Any]] = []
    try:
        inline_names = iam_client.list_role_policies(RoleName=role_name).get("PolicyNames") or []
        for name in inline_names:
            raw = iam_client.get_role_policy(RoleName=role_name, PolicyName=name).get("PolicyDocument")
            if raw:
                documents.append(_policy_document(raw))
        attached = iam_client.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies") or []
        for item in attached:
            arn = item.get("PolicyArn")
            if not arn:
                continue
            meta = iam_client.get_policy(PolicyArn=arn)["Policy"]
            version_id = meta["DefaultVersionId"]
            raw = iam_client.get_policy_version(PolicyArn=arn, VersionId=version_id)["PolicyVersion"].get(
                "Document"
            )
            if raw:
                documents.append(_policy_document(raw))
    except ClientError:
        return []
    return documents


def check_role_actions(iam_client, role_name: str, actions: tuple[str, ...]) -> dict[str, bool]:
    documents = load_role_policy_documents(iam_client, role_name)
    statements: list[dict[str, Any]] = []
    for doc in documents:
        statements.extend(doc.get("Statement") or [])
    return {action: statements_allow_action(statements, action) for action in actions}
