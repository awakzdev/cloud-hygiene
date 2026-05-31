from datetime import datetime, timezone

from app.models import Finding
from app.services.remediation_dispatch import build_remediation_dispatch
from app.services.remediation_plan import PLAN_SCHEMA, build_remediation_plan
import uuid


def _sg_finding(**ev) -> Finding:
    now = datetime.now(timezone.utc)
    base_ev = {"group_id": "sg-abc", "group_name": "test", "region": "us-east-2", "exposing_rules": [
        {"protocol": "tcp", "from_port": 3389, "to_port": 3389, "cidr": "0.0.0.0/0", "match_reason": "port_in_range"},
    ]}
    base_ev.update(ev)
    return Finding(
        id=uuid.uuid4(),
        org_id=uuid.uuid4(),
        account_id=uuid.uuid4(),
        check_id="ec2.security_group.unrestricted_rdp",
        resource_arn="arn:aws:ec2:us-east-2:123456789012:security-group/sg-abc",
        title="RDP open",
        severity="high",
        risk_score=80,
        status="open",
        evidence=base_ev,
        first_seen=now,
        last_seen=now,
    )


def test_remediation_plan_v2_fields():
    f = _sg_finding()
    plan = build_remediation_plan(f)
    assert plan["schema"] == PLAN_SCHEMA
    assert plan["resource_region"] == "us-east-2"
    assert plan["automation_region"]
    assert plan["exact_match_rules"]
    assert plan["expires_at"]
    assert plan["content_sha256"]


def test_dispatch_includes_approval_block():
    f = _sg_finding()
    out = build_remediation_dispatch(f, approved_by="user-abc")
    plan = out["plan"]
    assert "approval" in plan
    assert plan["approval"]["approved_by"] == "user-abc"
    assert plan["approval"]["approval_token"]
    assert plan["approval"]["approved_at"]


def test_preview_plan_has_no_approval():
    f = _sg_finding()
    plan = build_remediation_plan(f)
    assert "approval" not in plan


def test_dispatch_uses_ssm_automation_region_not_resource_region():
    f = _sg_finding()
    out = build_remediation_dispatch(f, approved_by="user-abc")
    region = out["automation_region"]
    assert region
    assert out["resource_region"] == "us-east-2"
    assert out["plan"]["execution"]["runner_type"] == "ssm"
    cli = out["cli"]["start_automation"]
    assert "ssm start-automation-execution" in cli
    assert f"--region {region}" in cli or f"--region '{region}'" in cli
    if region != "us-east-2":
        assert "--region us-east-2" not in cli


def test_sg_iac_no_terraform():
    from unittest.mock import MagicMock

    from app.services.iac_snippets import build_iac_remediation

    f = _sg_finding()
    db = MagicMock()
    db.scalar.return_value = None
    db.scalars.return_value.all.return_value = []
    out = build_iac_remediation(db, f, f.org_id)
    assert out["terraform"] is None
    assert out["iac_status"] == "automation_only"
    assert out["apply_paths"]["terraform_generic"] is False
    assert out["apply_paths"]["customer_automation"] is True


def test_ssm_plan_uses_arn_region_and_enables_automation():
    from unittest.mock import MagicMock

    from app.services.iac_snippets import build_iac_remediation

    now = datetime.now(timezone.utc)
    f = Finding(
        id=uuid.uuid4(),
        org_id=uuid.uuid4(),
        account_id=uuid.uuid4(),
        check_id="ssm.parameter.plaintext_secret",
        resource_arn="arn:aws:ssm:eu-west-1:123456789012:parameter/prod/db/password",
        title="Plaintext parameter",
        severity="high",
        risk_score=90,
        status="open",
        evidence={"parameter_name": "/prod/db/password", "parameter_type": "String"},
        first_seen=now,
        last_seen=now,
    )

    plan = build_remediation_plan(f)
    assert plan["resource_region"] == "eu-west-1"
    assert plan["supported_action"] == "migrate_ssm_string_to_secure_string"

    db = MagicMock()
    db.scalar.return_value = None
    db.scalars.return_value.all.return_value = []
    out = build_iac_remediation(db, f, f.org_id)
    assert out["apply_paths"]["customer_automation"] is True
