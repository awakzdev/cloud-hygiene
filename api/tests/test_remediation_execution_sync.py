"""SSM automation status sync for remediation executions."""
from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

from app.services.remediation_execution_sync import sync_remediation_execution_from_ssm


def _row(*, status: str = "running", result_json: dict | None = None):
    row = MagicMock()
    row.status = status
    row.result_json = result_json or {
        "automation_execution_id": "exec-abc",
        "region": "us-east-1",
    }
    row.plan_id = "plan-1"
    return row


def test_skips_when_not_running():
    db = MagicMock()
    row = _row(status="success")
    out = sync_remediation_execution_from_ssm(db, row=row, account=MagicMock())
    assert out is row
    db.commit.assert_not_called()


def test_marks_success_from_ssm():
    db = MagicMock()
    row = _row()
    account = MagicMock(role_arn="arn:aws:iam::1:role/VigilReadOnly", external_id="ext")

    mock_ssm = MagicMock()
    mock_ssm.get_automation_execution.return_value = {
        "AutomationExecution": {
            "AutomationExecutionStatus": "Success",
            "Outputs": {
                "ExecutePlan": [
                    '{"ok": true, "action": "revoke_exact_ingress", "revoked": 1}',
                ],
            },
        },
    }
    mock_sess = MagicMock()
    mock_sess.client.return_value = mock_ssm

    with patch("app.services.remediation_execution_sync.assume_role", return_value=mock_sess):
        sync_remediation_execution_from_ssm(db, row=row, account=account)

    assert row.status == "success"
    assert row.completed_at is not None
    assert row.error is None
    db.commit.assert_called_once()


def test_marks_failed_when_step_returns_ok_false():
    db = MagicMock()
    row = _row()
    account = MagicMock(role_arn="arn:aws:iam::1:role/VigilReadOnly", external_id="ext")

    mock_ssm = MagicMock()
    mock_ssm.get_automation_execution.return_value = {
        "AutomationExecution": {
            "AutomationExecutionStatus": "Success",
            "Outputs": {"ExecutePlan": ['{"ok": false, "error": "stale_plan"}']},
        },
    }
    mock_sess = MagicMock()
    mock_sess.client.return_value = mock_ssm

    with patch("app.services.remediation_execution_sync.assume_role", return_value=mock_sess):
        sync_remediation_execution_from_ssm(db, row=row, account=account)

    assert row.status == "failed"
    assert "stale_plan" in row.error


def test_marks_success_from_completed_with_success_status():
    db = MagicMock()
    row = _row()
    account = MagicMock(role_arn="arn:aws:iam::1:role/x", external_id="ext")

    mock_ssm = MagicMock()
    mock_ssm.get_automation_execution.return_value = {
        "AutomationExecution": {
            "AutomationExecutionStatus": "CompletedWithSuccess",
            "Outputs": {"ExecutePlan": ['{"ok": true}']},
        },
    }
    mock_sess = MagicMock()
    mock_sess.client.return_value = mock_ssm

    with patch("app.services.remediation_execution_sync.assume_role", return_value=mock_sess):
        sync_remediation_execution_from_ssm(db, row=row, account=account)

    assert row.status == "success"


def test_leaves_running_when_ssm_still_in_progress():
    db = MagicMock()
    row = _row()
    account = MagicMock(role_arn="arn:aws:iam::1:role/x", external_id="ext")

    mock_ssm = MagicMock()
    mock_ssm.get_automation_execution.return_value = {
        "AutomationExecution": {"AutomationExecutionStatus": "InProgress"},
    }
    mock_sess = MagicMock()
    mock_sess.client.return_value = mock_ssm

    with patch("app.services.remediation_execution_sync.assume_role", return_value=mock_sess):
        out = sync_remediation_execution_from_ssm(db, row=row, account=account)

    assert out.status == "running"
    db.commit.assert_not_called()
