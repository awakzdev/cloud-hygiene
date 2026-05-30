"""Map Vigil check_id → compliance controls (framework priority: SOC 2 → CIS → ISO)."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.data.control_narratives import narrative_for
from app.services.control_reference_urls import reference_url

_MAPPINGS_PATH = Path(__file__).parent.parent.parent / "data" / "control_mappings.json"

FRAMEWORK_PRIORITY = ("soc2", "cis_aws_l1", "iso27001")

# Open findings may still use pre-consolidation check_ids (90d); mappings use 45d only.
CHECK_CONTROL_ALIASES: dict[str, str] = {
    "iam.access_key.unused_90d": "iam.access_key.unused_45d",
    "iam.user.inactive_90d": "iam.user.credentials_unused_45d",
}


def resolve_check_id_for_controls(check_id: str) -> str:
    return CHECK_CONTROL_ALIASES.get(check_id, check_id)


@lru_cache(maxsize=1)
def _mapping_entries() -> list[dict[str, Any]]:
    return json.loads(_MAPPINGS_PATH.read_text())


def _priority_index(framework: str) -> int:
    try:
        return FRAMEWORK_PRIORITY.index(framework)
    except ValueError:
        return len(FRAMEWORK_PRIORITY)


def controls_for_check(check_id: str) -> list[dict[str, Any]]:
    """All control rows that include this check, sorted by framework priority."""
    mapped_id = resolve_check_id_for_controls(check_id)
    rows: list[dict[str, Any]] = []
    for entry in _mapping_entries():
        if mapped_id not in entry.get("checks", []):
            continue
        fw = entry["framework"]
        cid = entry["control_id"]
        url, url_label, ref_note = reference_url(fw, cid)
        rows.append(
            {
                "framework": fw,
                "control_id": cid,
                "title": entry.get("title", ""),
                "description": entry.get("description", ""),
                "guidance": entry.get("guidance"),
                "narrative": narrative_for(fw, cid),
                "reference_url": url,
                "reference_label": url_label,
                "reference_note": ref_note,
            }
        )
    rows.sort(key=lambda r: (_priority_index(r["framework"]), r["control_id"]))
    return rows


def primary_control_for_check(check_id: str) -> dict[str, Any] | None:
    rows = controls_for_check(check_id)
    return rows[0] if rows else None


def check_control_bundle(check_id: str) -> dict[str, Any]:
    rows = controls_for_check(check_id)
    primary = rows[0] if rows else None
    return {
        "check_id": check_id,
        "framework_priority": list(FRAMEWORK_PRIORITY),
        "primary": primary,
        "controls": rows,
        "frameworks": [r["framework"] for r in rows],
    }
