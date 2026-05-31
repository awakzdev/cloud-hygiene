"""Verify customer-account SSM remediation automation (read-only)."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from app.core.config import get_settings
from app.core.aws import assume_role
from app.models import AwsAccount

DOCUMENT_NAME = "Vigil-RemediationPlanExecutor"


def check_remediation_runner(acc: AwsAccount) -> dict[str, Any]:
    """
    Inspect the customer-owned SSM Automation document in the remediation region.
    """
    settings = get_settings()
    automation_region = settings.REMEDIATION_AUTOMATION_REGION
    document_name = settings.REMEDIATION_SSM_DOCUMENT_NAME or DOCUMENT_NAME

    out: dict[str, Any] = {
        "automation_region": automation_region,
        "document": {"name": document_name, "exists": False, "status": None},
        "ready": False,
        "rule": {"name": document_name, "exists": False, "state": None},
        "lambda": {"name": None, "exists": False},
        "schema_discovery": {"enabled": None, "note": "Not used by SSM Automation"},
        "blockers": [],
        "warnings": [],
        "hints": [],
    }

    if not acc.role_arn:
        out["blockers"].append("AWS account role not verified — connect account first")
        return out

    try:
        sess = assume_role(
            acc.role_arn,
            acc.external_id,
            session_name="vigil-remediation-check",
            aws_account=acc,
            purpose="remediation_runner_status",
        )
    except Exception as exc:  # noqa: BLE001
        out["blockers"].append(f"Cannot assume role: {exc}")
        return out

    ssm = sess.client("ssm", region_name=automation_region)
    try:
        doc = ssm.describe_document(Name=document_name)
        status = (doc.get("Document") or {}).get("Status")
        out["document"]["exists"] = True
        out["document"]["status"] = status
        out["rule"]["exists"] = True
        out["rule"]["state"] = status
        if status not in (None, "Active"):
            out["blockers"].append(f"SSM document {document_name} exists but Status={status}")
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") in ("InvalidDocument", "InvalidDocumentOperation"):
            out["blockers"].append(
                f"SSM Automation document {document_name} not found in {automation_region} — deploy vigil-remediation-ssm.yaml"
            )
        else:
            out["blockers"].append(f"Cannot describe SSM document: {e}")

    out["ready"] = not out["blockers"] and out["document"].get("exists")
    if out["ready"]:
        out["hints"] = [
            f"SSM Automation is ready in {automation_region}. Prepare a plan, then start automation.",
            "Re-scan after remediation so the next plan matches live resources.",
        ]
    else:
        out["hints"] = [
            "Deploy: aws cloudformation deploy --region "
            f"{automation_region} --template-file infra/cfn/vigil-remediation-ssm.yaml "
            "--capabilities CAPABILITY_NAMED_IAM",
            f"Set REMEDIATION_AUTOMATION_REGION={automation_region} in Vigil .env to match the SSM document region.",
        ]
    return out
