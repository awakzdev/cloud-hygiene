"""Poll SSM Automation execution status and persist terminal outcomes."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.core.aws import assume_role
from app.models.aws_account import AwsAccount
from app.models.remediation_execution import RemediationExecution

_SUCCESS_SSM = frozenset({"Success", "CompletedWithSuccess"})
_TERMINAL_SSM = _SUCCESS_SSM | frozenset(
    {"Failed", "TimedOut", "Cancelled", "Cancelling", "CompletedWithFailure", "Exited"}
)


def _automation_execution_body(resp: dict[str, Any]) -> dict[str, Any]:
    """Boto3 nests fields under AutomationExecution; accept flat mocks in tests."""
    body = resp.get("AutomationExecution")
    return body if isinstance(body, dict) else resp


def _parse_plan_result(outputs: dict[str, Any] | None) -> dict[str, Any] | None:
    if not outputs:
        return None
    for key in ("ExecutePlan", "executePlan"):
        raw = outputs.get(key)
        if not raw:
            continue
        text = raw[0] if isinstance(raw, list) and raw else raw
        if not isinstance(text, str):
            continue
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            continue
    return None


def sync_remediation_execution_from_ssm(
    db: Session,
    *,
    row: RemediationExecution,
    account: AwsAccount,
) -> RemediationExecution:
    """If execution is running, refresh status from ssm:GetAutomationExecution."""
    if row.status != "running":
        return row
    meta = row.result_json if isinstance(row.result_json, dict) else {}
    exec_id = meta.get("automation_execution_id")
    region = meta.get("region")
    if not exec_id or not region:
        return row

    try:
        sess = assume_role(
            account.role_arn,
            account.external_id,
            session_name="vigil-remediation-status",
            aws_account=account,
            purpose="sync_remediation_execution",
        )
        resp = sess.client("ssm", region_name=region).get_automation_execution(
            AutomationExecutionId=exec_id,
        )
    except Exception:  # noqa: BLE001
        return row

    ae = _automation_execution_body(resp)
    ssm_status = ae.get("AutomationExecutionStatus") or ""
    if ssm_status not in _TERMINAL_SSM:
        return row

    now = datetime.now(timezone.utc)
    outputs = ae.get("Outputs") or {}
    plan_result = _parse_plan_result(outputs)
    merged_result = {**meta, "ssm_status": ssm_status, "ssm_outputs": outputs}
    if plan_result:
        merged_result["plan_result"] = plan_result

    if ssm_status in _SUCCESS_SSM:
        ok = plan_result.get("ok", True) if plan_result else True
        row.status = "success" if ok else "failed"
        row.error = None if ok else str(plan_result.get("error") or "automation_step_failed")[:2000]
        row.result_json = merged_result
        row.completed_at = now
    else:
        row.status = "failed"
        row.error = (
            ae.get("FailureMessage")
            or (plan_result or {}).get("error")
            or ssm_status
            or "automation_failed"
        )[:2000]
        row.result_json = merged_result
        row.completed_at = now

    db.commit()
    db.refresh(row)
    return row
