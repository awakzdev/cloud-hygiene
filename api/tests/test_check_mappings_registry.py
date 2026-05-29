"""CI guard: core benchmark checks must appear in control_mappings.json."""
from app.checks.optional_checks import OPTIONAL_CHECK_IDS
from app.checks.registry import ALL_CHECKS
from app.services.check_coverage import tier_for_check
from app.services.check_frameworks import frameworks_for_check


def _all_check_ids() -> list[str]:
    return sorted({mod.CHECK_ID for mod in ALL_CHECKS})


def test_optional_checks_are_unmapped():
    for check_id in OPTIONAL_CHECK_IDS:
        assert frameworks_for_check(check_id) == [], f"{check_id} must stay unmapped"


def test_core_checks_have_framework_mapping():
    missing = []
    for check_id in _all_check_ids():
        if check_id in OPTIONAL_CHECK_IDS:
            continue
        if tier_for_check(check_id) != "core":
            continue
        if not frameworks_for_check(check_id):
            missing.append(check_id)
    assert not missing, f"core checks missing framework mapping: {missing}"


def test_registry_check_ids_are_unique():
    ids = [mod.CHECK_ID for mod in ALL_CHECKS]
    assert len(ids) == len(set(ids))
