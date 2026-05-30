"""Structured auditor-facing control narrative blocks (v2 audit template)."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from app.models.control import Control
from app.services.check_evidence import evidence_class_label, evidence_class_for_check

# Checks whose remediation is "deactivate / delete a credential" (CIS 1.11 and neighbours).
# Vigil flags these but never performs the change — see _remediation_ownership.
_CREDENTIAL_LIFECYCLE_CHECKS = frozenset({
    "iam.user.inactive_90d",
    "iam.user.credentials_unused_45d",
    "iam.access_key.unused_90d",
    "iam.access_key.unused_45d",
    "iam.access_key.no_rotation_90d",
    "iam.access_key.multiple_active",
    "iam.role.unassumed_90d",
})


def _remediation_ownership(check_ids: list[str]) -> str:
    base = (
        "Vigil is read-only and never writes to your AWS account. It detects and reports; your "
        "team performs any disable, delete, rotate, or policy change in your own environment. "
        "Vigil re-verifies on the next scan and updates this control automatically."
    )
    if any(cid in _CREDENTIAL_LIFECYCLE_CHECKS for cid in check_ids):
        base += (
            " For this control (e.g. CIS 1.11 — stale/unused credentials), deactivating or deleting "
            "the flagged users and access keys is a manual step. Vigil provides console and CLI "
            "remediation guidance per finding but intentionally offers no one-click disable or delete, "
            "preserving the read-only trust boundary auditors expect of an evidence platform."
        )
    return base


def build_control_audit_block(
    ctrl: Control,
    cr: dict[str, Any],
    check_ids: list[str],
    *,
    since: datetime,
    end: datetime,
    evidence_sources: list[str],
) -> dict[str, Any]:
    status = cr.get("status", "no_data")
    open_count = cr.get("finding_count", 0)
    supporting_open = cr.get("supporting_open_count", 0)
    exceptions = cr.get("exception_count", 0)

    tested_lines = []
    for cid in check_ids:
        ec = evidence_class_for_check(cid)
        tested_lines.append(f"{cid} ({evidence_class_label(ec)})")

    if status == "pass":
        current = f"PASS — no open benchmark findings ({exceptions} approved exception(s))" if exceptions else "PASS — no open benchmark findings"
        next_step = "Continue monitoring; no benchmark remediation required."
    elif status == "fail":
        current = f"FAIL — {open_count} open benchmark finding(s)"
        if supporting_open:
            current += f"; {supporting_open} supporting finding(s) do not change pass/fail"
        next_step = "Remediate open findings or document approved exceptions with expiry."
    else:
        current = "NO DATA — no automated checks mapped or insufficient scan data in period"
        next_step = "Run scans across the audit period or supply manual attestation."

    return {
        "objective": (ctrl.description or ctrl.title or "").strip(),
        "what_vigil_tested": tested_lines,
        "evidence_collected": {
            "sources": evidence_sources,
            "period_start": since.isoformat(),
            "period_end": end.isoformat(),
            "snapshots_included": cr.get("snapshots_included", len(cr.get("snapshots", []))),
            "snapshots_total": cr.get("snapshots_total", 0),
        },
        "current_result": {
            "status": status,
            "open_benchmark_findings": open_count,
            "supporting_open_findings": supporting_open,
            "approved_exceptions": exceptions,
            "summary": current,
        },
        "why_it_matters": (ctrl.guidance or "").strip() or None,
        "what_vigil_does_not_prove": (
            "Company policies, HR attestations, vendor risk questionnaires, "
            "and incident-response runbooks are outside automated technical collection."
        ),
        "remediation_ownership": _remediation_ownership(check_ids),
        "recommended_next_step": next_step,
    }
