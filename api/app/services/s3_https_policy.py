"""Merge DenyInsecureTransport into an S3 bucket policy document."""
from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

DENY_INSECURE_TRANSPORT_SID = "DenyInsecureTransport"


def deny_insecure_transport_statement(bucket_name: str) -> dict[str, Any]:
    return {
        "Sid": DENY_INSECURE_TRANSPORT_SID,
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": [
            f"arn:aws:s3:::{bucket_name}",
            f"arn:aws:s3:::{bucket_name}/*",
        ],
        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
    }


def _normalize_statements(policy: dict[str, Any]) -> list[dict[str, Any]]:
    raw = policy.get("Statement")
    if raw is None:
        return []
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, list):
        return [s for s in raw if isinstance(s, dict)]
    return []


def policy_has_https_deny(policy: dict[str, Any] | None) -> bool:
    if not policy:
        return False
    for stmt in _normalize_statements(policy):
        if stmt.get("Sid") == DENY_INSECURE_TRANSPORT_SID:
            return True
        cond = stmt.get("Condition")
        if not isinstance(cond, dict):
            continue
        bool_cond = cond.get("Bool")
        if not isinstance(bool_cond, dict):
            continue
        if stmt.get("Effect") == "Deny" and bool_cond.get("aws:SecureTransport") == "false":
            return True
    return False


def merge_deny_insecure_transport(
    policy: dict[str, Any] | None,
    bucket_name: str,
) -> tuple[dict[str, Any], bool]:
    """Return (merged_policy, statement_added)."""
    if policy_has_https_deny(policy):
        doc = policy or {"Version": "2012-10-17", "Statement": []}
        version = doc.get("Version") or "2012-10-17"
        return {"Version": version, "Statement": _normalize_statements(doc)}, False

    stmt = deny_insecure_transport_statement(bucket_name)
    if policy is None:
        return {"Version": "2012-10-17", "Statement": [stmt]}, True

    version = policy.get("Version") or "2012-10-17"
    statements = _normalize_statements(policy)
    return {"Version": version, "Statement": [*statements, stmt]}, True


def fetch_live_bucket_policy(s3_client, bucket_name: str) -> tuple[dict[str, Any] | None, bool]:
    """Return (policy_doc or None, had_policy). Raises ClientError on access errors."""
    try:
        policy_str = s3_client.get_bucket_policy(Bucket=bucket_name).get("Policy", "")
        if not policy_str:
            return None, False
        return json.loads(policy_str), True
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "NoSuchBucketPolicy":
            return None, False
        raise


def build_https_policy_suggestion(
    s3_client,
    bucket_name: str,
) -> dict[str, Any]:
    original, had_policy = fetch_live_bucket_policy(s3_client, bucket_name)
    merged, statement_added = merge_deny_insecure_transport(original, bucket_name)
    return {
        "bucket_name": bucket_name,
        "had_policy": had_policy,
        "already_has_https_deny": not statement_added,
        "original_policy": original,
        "merged_policy": merged,
        "statement_added": statement_added,
    }
