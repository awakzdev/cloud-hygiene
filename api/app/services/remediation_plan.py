"""Signed remediation plans for customer-hosted automation (read-only Vigil → customer executor)."""
from __future__ import annotations

import hashlib
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from app.core.config import get_settings
from app.models import Finding
from app.services.pack_signing import sign_payload

PLAN_SCHEMA = "vigil_remediation_plan/v2"
SG_CHECKS = frozenset(
    {
        "ec2.security_group.unrestricted_ssh",
        "ec2.security_group.unrestricted_rdp",
    }
)
SSM_CHECKS = frozenset({"ssm.parameter.plaintext_secret"})


def _region_from_arn(arn: str | None) -> str | None:
    parts = (arn or "").split(":")
    if len(parts) > 3 and parts[0] == "arn" and parts[3]:
        return parts[3]
    return None


def _resource_region(finding: Finding) -> str:
    ev = finding.evidence or {}
    if isinstance(ev.get("region"), str) and ev["region"]:
        return ev["region"]
    arn_region = _region_from_arn(finding.resource_arn)
    if arn_region:
        return arn_region
    return "us-east-1"


def _supported_action(check_id: str) -> str | None:
    if check_id in SG_CHECKS:
        return "revoke_public_ingress"
    if check_id == "s3.bucket.public_access_not_blocked":
        return "put_public_access_block"
    if check_id in SSM_CHECKS:
        return "migrate_ssm_string_to_secure_string"
    return None


def _seal_remediation_plan(body: dict[str, Any]) -> dict[str, Any]:
    """Attach content_sha256 and optional signature over the canonical JSON body."""
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    body["content_sha256"] = hashlib.sha256(canonical.encode()).hexdigest()
    sig = sign_payload(canonical.encode())
    if sig:
        body["signature"] = sig
    return body


def build_remediation_plan_body(
    finding: Finding,
    *,
    mode: str = "customer_ssm",
    delivery: str = "ssm_automation",
) -> dict[str, Any]:
    """Unsigned plan body (preview). Seal with _seal_remediation_plan before dispatch."""
    settings = get_settings()
    plan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    ttl = max(5, int(settings.REMEDIATION_PLAN_TTL_MINUTES))
    expires = now + timedelta(minutes=ttl)
    resource_region = _resource_region(finding)
    ev = finding.evidence or {}

    return {
        "plan_id": plan_id,
        "schema": PLAN_SCHEMA,
        "created_at": now.isoformat(),
        "expires_at": expires.isoformat(),
        "finding_id": str(finding.id),
        "check_id": finding.check_id,
        "resource_arn": finding.resource_arn,
        "resource_region": resource_region,
        "automation_region": settings.REMEDIATION_AUTOMATION_REGION,
        "evidence": ev,
        "title": finding.title,
        "severity": finding.severity,
        "supported_action": _supported_action(finding.check_id),
        "exact_match_rules": list(ev.get("exposing_rules") or []),
        "execution": {
            "runner_type": "ssm",
            "mode": mode,
            "delivery": delivery,
            "document_name": settings.REMEDIATION_SSM_DOCUMENT_NAME,
            "note": (
                "Start the customer-owned SSM Automation document in automation_region. "
                "The document executes AWS APIs in resource_region."
            ),
        },
        "steps": _steps_for_check(finding),
        "rollback_hint": "Revert via CloudFormation stack change set or restore prior policy version in IAM.",
    }


def build_remediation_plan(
    finding: Finding,
    *,
    mode: str = "customer_ssm",
    delivery: str = "ssm_automation",
) -> dict[str, Any]:
    """Emit a remediation plan the customer automation can validate and execute (preview, no approval)."""
    return _seal_remediation_plan(build_remediation_plan_body(finding, mode=mode, delivery=delivery))


def build_approved_remediation_plan(
    finding: Finding,
    *,
    approved_by: str,
    mode: str = "customer_ssm",
    delivery: str = "ssm_automation",
) -> dict[str, Any]:
    """Signed plan including approval block — use only when dispatching approved automation."""
    body = build_remediation_plan_body(finding, mode=mode, delivery=delivery)
    now = datetime.now(timezone.utc)
    body["approval"] = {
        "approval_token": secrets.token_urlsafe(32),
        "approved_by": approved_by,
        "approved_at": now.isoformat(),
    }
    return _seal_remediation_plan(body)


def _steps_for_check(finding: Finding) -> list[dict[str, str]]:
    cid = finding.check_id
    if cid.startswith("s3."):
        return [
            {"action": "review", "detail": "Apply bucket policy / encryption from Finding drawer generated policy"},
            {"action": "execute", "detail": "Use customer automation only when an SSM document exists for this check"},
        ]
    if cid.startswith("iam."):
        return [
            {"action": "review", "detail": "Use generated least-privilege policy or detach unused policy"},
            {"action": "execute", "detail": "Use customer automation only when an SSM document exists for this check"},
        ]
    if cid in SG_CHECKS:
        return [
            {"action": "review", "detail": "Confirm exposing_rules in plan match the ingress you intend to remove"},
            {"action": "execute", "detail": "Start the SSM Automation document, or use Console/CLI"},
        ]
    if cid in SSM_CHECKS:
        return [
            {"action": "review", "detail": "Confirm the parameter name is a secret and applications can read SecureString values"},
            {"action": "execute", "detail": "SSM Automation rewrites the same parameter name as SecureString with overwrite"},
        ]
    return [
        {"action": "review", "detail": "Follow Console/CLI remediation in Vigil finding drawer"},
        {"action": "execute", "detail": "Optional: wire customer automation when plan type is supported"},
    ]
