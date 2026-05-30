"""Reverse index: check_id → compliance frameworks (from control_mappings.json)."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from app.services.check_controls import resolve_check_id_for_controls

_MAPPINGS_PATH = Path(__file__).parent.parent.parent / "data" / "control_mappings.json"

FRAMEWORK_LABELS: dict[str, str] = {
    "soc2": "SOC 2",
    "cis_aws_l1": "CIS AWS L1",
    "iso27001": "ISO 27001",
}


@lru_cache(maxsize=1)
def check_framework_map() -> dict[str, list[str]]:
    raw = json.loads(_MAPPINGS_PATH.read_text())
    out: dict[str, set[str]] = {}
    for entry in raw:
        fw = entry["framework"]
        for check_id in entry.get("checks", []):
            out.setdefault(check_id, set()).add(fw)
    return {k: sorted(v) for k, v in sorted(out.items())}


def frameworks_for_check(check_id: str) -> list[str]:
    mapped = resolve_check_id_for_controls(check_id)
    return check_framework_map().get(mapped, [])


def framework_catalog() -> list[dict[str, str]]:
    return [{"id": fid, "label": FRAMEWORK_LABELS[fid]} for fid in FRAMEWORK_LABELS]
