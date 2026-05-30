from app.services.check_controls import check_control_bundle, primary_control_for_check


def test_primary_framework_priority_soc2_first():
    primary = primary_control_for_check("iam.root.no_mfa")
    assert primary is not None
    assert primary["framework"] == "soc2"
    assert primary["control_id"] == "CC6.6"


def test_bundle_includes_reference_url():
    bundle = check_control_bundle("iam.root.no_mfa")
    assert bundle["primary"]["reference_url"]
    url = bundle["primary"]["reference_url"]
    assert "ctfassets.net" in url or "aicpa" in url
    assert len(bundle["controls"]) >= 2


def test_cis_reference_security_hub():
    bundle = check_control_bundle("iam.root.no_mfa")
    cis = next((c for c in bundle["controls"] if c["framework"] == "cis_aws_l1"), None)
    assert cis is not None
    assert cis["control_id"] == "1.5"
    assert "iam-9" in cis["reference_url"]


def test_iso_reference_27002_obp():
    bundle = check_control_bundle("iam.root.no_mfa")
    iso_rows = [c for c in bundle["controls"] if c["framework"] == "iso27001"]
    assert iso_rows
    for row in iso_rows:
        assert "27002" in row["reference_url"]


def test_legacy_unused_access_key_maps_like_45d():
    legacy = check_control_bundle("iam.access_key.unused_90d")
    current = check_control_bundle("iam.access_key.unused_45d")
    assert legacy["check_id"] == "iam.access_key.unused_90d"
    assert len(legacy["controls"]) == len(current["controls"]) >= 1
    assert {c["framework"] for c in legacy["controls"]} == {c["framework"] for c in current["controls"]}
