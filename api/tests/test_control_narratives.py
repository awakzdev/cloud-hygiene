"""Tests for structured control narratives."""
import json
from pathlib import Path

from app.data.control_narratives import narrative_detail_for, narrative_for, scope_limitations_for

_MAPPINGS_PATH = Path(__file__).resolve().parents[1] / "data" / "control_mappings.json"


def test_narrative_detail_includes_short_and_refs():
    detail = narrative_detail_for("soc2", "CC6.1", ["iam.user.no_mfa", "iam.user.credentials_unused_45d"])
    assert detail["short_answer"]
    assert detail["long_answer"] == narrative_for("soc2", "CC6.1")
    assert len(detail["evidence_refs"]) >= 2
    assert not any("Physical access" in g for g in detail["known_gaps"])


def test_physical_scope_limitation_is_pack_level_not_cc61():
    soc2_limits = scope_limitations_for("soc2")
    assert any("Physical security" in line for line in soc2_limits)
    detail = narrative_detail_for("soc2", "CC6.1", ["iam.user.no_mfa"])
    assert not any("physical" in g.lower() for g in detail["known_gaps"])


def test_read_only_posture_is_first_scope_limitation_every_framework():
    for fw in ("soc2", "cis_aws_l1", "iso27001"):
        limits = scope_limitations_for(fw)
        assert limits, f"{fw} has no scope limitations"
        assert "read-only" in limits[0].lower()
        assert "never disables" in limits[0] and "modifies any resource" in limits[0]


def test_cis_narrative_lookup():
    detail = narrative_detail_for("cis_aws_l1", "1.10", ["iam.user.no_mfa"])
    assert detail["long_answer"]
    assert "MFA" in detail["short_answer"] or "MFA" in (detail["long_answer"] or "")


def test_every_mapped_control_has_narrative():
    raw = json.loads(_MAPPINGS_PATH.read_text())
    missing: list[str] = []
    for entry in raw:
        fw = entry["framework"]
        cid = entry["control_id"]
        if not narrative_for(fw, cid):
            missing.append(f"{fw}:{cid}")
    assert not missing, f"missing narratives: {missing[:10]}"
