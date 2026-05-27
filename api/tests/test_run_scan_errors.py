"""Tests for the early-bailout paths of run_scan + check-error isolation.

Full scan flow is exercised by integration; here we just verify:
- invalid account UUID returns a clean error without raising
- account-not-found returns a clean error without raising
- per-check exceptions are recorded in stats but the scan still succeeds
"""
from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch


def test_run_scan_invalid_account_id_returns_clean_error():
    from app.worker import tasks

    fake_db = MagicMock()
    with patch.object(tasks, "SessionLocal", return_value=fake_db):
        result = tasks.run_scan("not-a-uuid")

    assert result["ok"] is False
    assert "invalid account id" in result["error"]
    fake_db.close.assert_called()


def test_run_scan_account_not_found_returns_clean_error():
    from app.worker import tasks

    fake_db = MagicMock()
    fake_db.get.return_value = None
    with patch.object(tasks, "SessionLocal", return_value=fake_db):
        result = tasks.run_scan(str(uuid.uuid4()))

    assert result["ok"] is False
    assert "account not found" in result["error"]
    fake_db.close.assert_called()


def test_run_scan_check_failure_does_not_kill_scan(monkeypatch):
    """If a single check raises, the scan should still complete and record
    the failure under stats.check_errors (not flip the whole run to 'error')."""
    from app.worker import tasks

    # Stub: account exists, collectors return empty stats, one check raises,
    # the others succeed, persist returns (0, 0), snapshots returns 0.
    fake_acc = MagicMock()
    fake_acc.id = uuid.uuid4()
    fake_acc.org_id = uuid.uuid4()
    fake_acc.role_arn = "arn:role"
    fake_acc.external_id = "ext"

    fake_run = MagicMock()
    fake_run.id = uuid.uuid4()
    fake_run.stats = {}

    fake_db = MagicMock()
    # Two .get calls: 1) AwsAccount, 2) Org
    fake_db.get.side_effect = [fake_acc, None]

    # Stub every collector. collect_iam/vpc/ec2 must return dicts; the rest
    # return ints (matching production signatures).
    dict_collectors = {"collect_iam", "collect_vpc", "collect_ec2"}
    int_collectors = {
        "collect_s3_account_public_access_block",
        "collect_s3",
        "collect_kms",
        "collect_cloudtrail",
        "collect_cloudtrail_events",
        "collect_guardduty",
        "collect_rds",
        "collect_access_analyzer",
        "collect_config_service",
        "collect_securityhub",
    }
    for name in dict_collectors:
        monkeypatch.setattr(tasks, name, lambda *a, **kw: {})
    for name in int_collectors:
        monkeypatch.setattr(tasks, name, lambda *a, **kw: 0)

    good_check = MagicMock()
    good_check.CHECK_ID = "test.good"
    good_check.run.return_value = []

    bad_check = MagicMock()
    bad_check.CHECK_ID = "test.bad"
    bad_check.run.side_effect = RuntimeError("synthetic check failure")

    monkeypatch.setattr(tasks, "ALL_CHECKS", [good_check, bad_check])
    monkeypatch.setattr(tasks, "persist_findings", lambda *a, **kw: (0, 0))
    monkeypatch.setattr(tasks, "_write_evidence_snapshots", lambda db, acc, run: 0)
    monkeypatch.setattr(tasks, "ScanRun", lambda **kw: fake_run)
    monkeypatch.setattr(tasks.collect_perm_usage_task, "delay", lambda *a, **kw: None)

    with patch.object(tasks, "SessionLocal", return_value=fake_db):
        result = tasks.run_scan(str(fake_acc.id))

    assert result["ok"] is True
    # The scan completed; the failing check is recorded in stats.check_errors
    assert fake_run.status == "ok"
    assert "check_errors" in fake_run.stats
    assert any(e["check_id"] == "test.bad" for e in fake_run.stats["check_errors"])
