from datetime import datetime, timezone

from app.services.control_audit_block import build_control_audit_block


def _ctrl(*, description="Disable stale credentials", title="CIS 1.11", guidance="Deactivate unused keys."):
    c = type("Control", (), {})()
    c.description = description
    c.title = title
    c.guidance = guidance
    c.id = "ctrl-1"
    c.control_id = "1.11"
    return c


def _cr(status="fail", finding_count=2):
    return {
        "status": status,
        "finding_count": finding_count,
        "supporting_open_count": 0,
        "exception_count": 0,
        "snapshots_included": 1,
        "snapshots": [{}],
        "snapshots_total": 1,
    }


def _block(check_ids):
    now = datetime(2026, 5, 1, tzinfo=timezone.utc)
    since = datetime(2026, 2, 1, tzinfo=timezone.utc)
    return build_control_audit_block(
        _ctrl(), _cr(), check_ids, since=since, end=now, evidence_sources=["IAM"]
    )


def test_audit_block_always_states_read_only_ownership():
    block = _block(["iam.user.no_mfa"])
    ro = block["remediation_ownership"]
    assert "read-only" in ro
    assert "never writes to your AWS account" in ro


def test_credential_control_calls_out_manual_disable_no_one_click():
    # CIS 1.11 maps to inactive users + unused keys — must spell out the manual, no-one-click boundary.
    block = _block(["iam.user.credentials_unused_45d", "iam.access_key.unused_45d"])
    ro = block["remediation_ownership"]
    assert "CIS 1.11" in ro
    assert "manual step" in ro
    assert "no one-click disable or delete" in ro


def test_non_credential_control_omits_one_click_caveat():
    block = _block(["s3.bucket.public"])
    ro = block["remediation_ownership"]
    assert "one-click" not in ro
    assert "read-only" in ro
