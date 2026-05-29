"""Tests for structured control narratives."""
import json
from pathlib import Path

from app.data.control_narratives import narrative_detail_for, narrative_for

_MAPPINGS_PATH = Path(__file__).resolve().parents[1] / "data" / "control_mappings.json"


def test_narrative_detail_includes_short_and_refs():
    detail = narrative_detail_for("soc2", "CC6.1", ["iam.user.no_mfa", "iam.user.inactive_90d"])
    assert detail["short_answer"]
    assert detail["long_answer"] == narrative_for("soc2", "CC6.1")
    assert len(detail["evidence_refs"]) >= 2


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
