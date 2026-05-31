"""Persist remediation plan dispatch + optional execution completion callbacks."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.models.remediation_execution import RemediationExecution


def record_dispatch(
    db: Session,
    *,
    plan: dict[str, Any],
    org_id: uuid.UUID,
    finding_id: uuid.UUID,
    account_id: uuid.UUID,
) -> RemediationExecution:
    plan_id = plan["plan_id"]
    row = db.get(RemediationExecution, plan_id)
    if not row:
        row = RemediationExecution(
            plan_id=plan_id,
            org_id=org_id,
            finding_id=finding_id,
            account_id=account_id,
            check_id=plan.get("check_id", ""),
            plan_json=plan,
            content_sha256=plan.get("content_sha256"),
            status="dispatched",
        )
        db.add(row)
    else:
        row.plan_json = plan
        row.content_sha256 = plan.get("content_sha256")
        row.status = "dispatched"
        row.dispatched_at = datetime.now(timezone.utc)
        row.completed_at = None
        row.result_json = None
        row.error = None
    db.commit()
    db.refresh(row)
    return row


def record_execution_result(
    db: Session,
    *,
    plan_id: str,
    content_sha256: str,
    result: dict[str, Any],
) -> RemediationExecution | None:
    row = db.get(RemediationExecution, plan_id)
    if not row:
        return None
    if row.content_sha256 and row.content_sha256 != content_sha256:
        return None
    ok = bool(result.get("ok"))
    row.status = "success" if ok else "failed"
    row.result_json = result
    row.error = None if ok else str(result.get("error") or result.get("hint") or "failed")
    row.completed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(row)
    return row


def record_automation_start(
    db: Session,
    *,
    plan_id: str,
    automation_execution_id: str,
    document_name: str,
    region: str,
) -> RemediationExecution | None:
    row = db.get(RemediationExecution, plan_id)
    if not row:
        return None
    row.status = "running"
    row.result_json = {
        "automation_execution_id": automation_execution_id,
        "document_name": document_name,
        "region": region,
    }
    row.error = None
    db.commit()
    db.refresh(row)
    return row
