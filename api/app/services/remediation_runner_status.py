"""Verify customer-account SSM remediation automation (read-only)."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from app.core.config import get_settings
from app.core.aws import assume_role
from app.models import AwsAccount
from app.services.iam_permission_check import (
    check_actions_on_documents,
    connector_can_start_document_automation,
)
from app.services.remediation_plan import (
    automation_home_region,
    resolve_automation_region,
)

DOCUMENT_NAME = "Vigil-RemediationPlanExecutor"

# Connector role (VigilScannerRole) — not the remediation execution role.
CONNECTOR_SSM_START_ACTIONS = (
    "ssm:DescribeDocument",
    "ssm:StartAutomationExecution",
    "ssm:GetAutomationExecution",
)


def connector_ssm_start_blockers(scanner_policy_documents: list[dict]) -> list[str]:
    """Blockers when the connector role cannot describe/start SSM from the API."""
    if not scanner_policy_documents:
        return [
            "Cannot read VigilScannerRole policies — update VigilAccountConnector with SSM remediation enabled"
        ]
    granted = check_actions_on_documents(scanner_policy_documents, CONNECTOR_SSM_START_ACTIONS)
    missing = [action for action, ok in granted.items() if not ok]
    if not missing:
        return []
    return [
        "VigilScannerRole cannot start SSM Automation "
        f"(missing {', '.join(missing)}). "
        "Update the VigilAccountConnector stack with remediation modules enabled "
        "(e.g. EnableIamAccessKeyRemediation=Yes), then Verify capabilities on Accounts."
    ]


def check_remediation_runner(
    acc: AwsAccount,
    *,
    check_id: str | None = None,
    resource_region: str | None = None,
    session: Any | None = None,
    scanner_policy_documents: list[dict] | None = None,
) -> dict[str, Any]:
    """Inspect SSM Automation readiness in the remediation region (connector can describe/start)."""
    from app.services.ssm_remediation_catalog import runbook_for_check

    settings = get_settings()
    automation_region = resolve_automation_region(check_id, resource_region)
    runbook = runbook_for_check(check_id) if check_id else None
    document_name = (
        runbook.document_name
        if runbook
        else (settings.REMEDIATION_SSM_DOCUMENT_NAME or DOCUMENT_NAME)
    )

    out: dict[str, Any] = {
        "automation_region": automation_region,
        "resource_region": resource_region,
        "document": {"name": document_name, "exists": False, "status": None},
        "ready": False,
        "rule": {"name": document_name, "exists": False, "state": None},
        "lambda": {"name": None, "exists": False, "deprecated": True},
        "schema_discovery": {"enabled": None, "note": "SSM Automation only — no Lambda runner"},
        "blockers": [],
        "warnings": [],
        "hints": [],
    }

    if not acc.role_arn:
        out["blockers"].append("AWS account role not verified — connect account first")
        return out

    sess = session
    if sess is None:
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
            if runbook and runbook.owner == "vigil":
                home = automation_home_region()
                out["blockers"].append(
                    f"Custom Vigil automation document {document_name} is not deployed in the "
                    f"automation home region {home}. Deploy vigil-remediation-ssm.yaml there once; "
                    "PlanJson carries resource_region for changes in the target region."
                )
            else:
                out["blockers"].append(
                    f"AWS runbook {document_name} is not available in {automation_region} "
                    "(resource region). AWS-owned documents are regional."
                )
        else:
            out["blockers"].append(f"Cannot describe SSM document: {e}")

    if scanner_policy_documents is not None:
        out["blockers"].extend(connector_ssm_start_blockers(scanner_policy_documents))
        if (
            runbook
            and runbook.owner == "vigil"
            and out["document"].get("exists")
            and not connector_can_start_document_automation(scanner_policy_documents, document_name)
        ):
            out["blockers"].append(
                "VigilSsmRemediationStart allows StartAutomationExecution on automation-definition only. "
                f"Update VigilAccountConnector (latest vigil-core-scanner.yaml) so IAM also allows "
                f"ssm:StartAutomationExecution on document/{document_name} in {automation_region}."
            )

    out["ready"] = not out["blockers"] and out["document"].get("exists")
    if runbook and runbook.owner == "aws":
        out["warnings"].append(
            f"AWS-owned runbook {document_name} — no Vigil custom document required."
        )
    elif runbook and runbook.owner == "vigil":
        home = automation_home_region()
        out["hints"].append(
            f"Custom Vigil document: deploy vigil-remediation-ssm.yaml once in {home} "
            f"(REMEDIATION_AUTOMATION_REGION). Target resource region: {resource_region or 'n/a'}."
        )

    if out["ready"]:
        out["hints"] = [
            *out["hints"],
            f"SSM remediation ready in {automation_region}. Approve on the finding, then start automation.",
            "Re-scan after remediation so the next plan matches live resources.",
        ]
    else:
        out["hints"] = [
            *out["hints"],
            "Update the Vigil connector stack (vigil-stack / core scanner) with SSM remediation modules enabled.",
            f"Connector needs ssm:DescribeDocument and ssm:StartAutomationExecution in {automation_region}.",
            (
                f"Set REMEDIATION_AUTOMATION_REGION={settings.REMEDIATION_AUTOMATION_REGION} "
                f"to match where Vigil-RemediationPlanExecutor is deployed."
                if runbook and runbook.owner == "vigil"
                else f"AWS-owned runbook must exist in the resource region ({automation_region})."
            ),
        ]
    return out
