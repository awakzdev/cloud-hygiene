"""Assemble a ZIP evidence pack for a given framework + account + time period."""
from __future__ import annotations

import csv
import io
import json
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Finding, EvidenceSnapshot
from app.models.control import Control, CheckControl
from app.models.aws_account import AwsAccount
from app.services.pdf_report import build_pdf


def _control_status(
    open_findings: list[Finding],
    check_ids: list[str],
) -> tuple[str, list[Finding]]:
    """Return (pass|fail|partial|no_data, matching_findings)."""
    if not check_ids:
        return "no_data", []
    hits = [f for f in open_findings if f.check_id in check_ids]
    if hits:
        return "fail", hits
    return "pass", []


def build_evidence_pack(
    db: Session,
    org_id: uuid.UUID,
    account_id: uuid.UUID,
    framework: str,
    period_days: int = 90,
) -> bytes:
    acc = db.get(AwsAccount, account_id)
    if not acc or str(acc.org_id) != str(org_id):
        raise ValueError("account not found")

    since = datetime.now(timezone.utc) - timedelta(days=period_days)

    controls = db.scalars(
        select(Control).where(Control.framework == framework).order_by(Control.control_id)
    ).all()

    check_map: dict[uuid.UUID, list[str]] = {}
    for c in controls:
        links = db.scalars(
            select(CheckControl.check_id).where(CheckControl.control_id == c.id)
        ).all()
        check_map[c.id] = list(links)

    open_findings = db.scalars(
        select(Finding).where(
            Finding.account_id == account_id,
            Finding.status == "open",
        )
    ).all()

    snapshots = db.scalars(
        select(EvidenceSnapshot).where(
            EvidenceSnapshot.account_id == account_id,
            EvidenceSnapshot.taken_at >= since,
        ).order_by(EvidenceSnapshot.taken_at.desc())
    ).all()

    snap_by_type: dict[str, list[dict[str, Any]]] = {}
    for s in snapshots:
        snap_by_type.setdefault(s.entity_type, []).append(
            {"entity_id": s.entity_id, "taken_at": s.taken_at.isoformat(), "data": s.payload_json}
        )

    control_results: list[dict[str, Any]] = []
    for ctrl in controls:
        status, hits = _control_status(open_findings, check_map[ctrl.id])
        relevant_types = _entity_types_for_checks(check_map[ctrl.id])
        snaps = []
        for t in relevant_types:
            snaps.extend(snap_by_type.get(t, []))

        control_results.append(
            {
                "control_id": ctrl.control_id,
                "title": ctrl.title,
                "description": ctrl.description,
                "guidance": ctrl.guidance or "",
                "status": status,
                "finding_count": len(hits),
                "findings": [_finding_dict(f) for f in hits],
                "snapshots": snaps[:50],
            }
        )

    buf = io.BytesIO()
    generated_at = datetime.now(timezone.utc)

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        readme = _build_readme(acc, framework, period_days, generated_at, control_results)
        zf.writestr("README.txt", readme)

        index_csv = _build_index_csv(control_results)
        zf.writestr("INDEX.csv", index_csv)

        for cr in control_results:
            folder = f"controls/{cr['control_id']}/"
            zf.writestr(folder + "summary.json", json.dumps({
                "control_id": cr["control_id"],
                "title": cr["title"],
                "framework": framework,
                "status": cr["status"],
                "finding_count": cr["finding_count"],
                "description": cr["description"],
                "guidance": cr["guidance"],
                "generated_at": generated_at.isoformat(),
            }, indent=2))
            zf.writestr(folder + "findings.json", json.dumps(cr["findings"], indent=2, default=str))
            zf.writestr(folder + "snapshots.json", json.dumps(cr["snapshots"], indent=2, default=str))

        pdf_bytes = build_pdf(acc, framework, period_days, generated_at, control_results)
        zf.writestr("report.pdf", pdf_bytes)

    return buf.getvalue()


def _entity_types_for_checks(check_ids: list[str]) -> list[str]:
    types = set()
    for cid in check_ids:
        if cid.startswith("iam.root"):
            types.add("account_summary")
        elif cid.startswith("iam.user"):
            types.add("iam_user")
        elif cid.startswith("iam.access_key"):
            types.add("iam_access_key")
        elif cid.startswith("iam.role"):
            types.add("iam_role")
        elif cid.startswith("s3."):
            types.add("s3_bucket")
        elif cid.startswith("kms."):
            types.add("kms_key")
    return list(types)


def _finding_dict(f: Finding) -> dict[str, Any]:
    return {
        "id": str(f.id),
        "check_id": f.check_id,
        "resource_arn": f.resource_arn,
        "title": f.title,
        "severity": f.severity,
        "risk_score": f.risk_score,
        "status": f.status,
        "first_seen": f.first_seen.isoformat(),
        "last_seen": f.last_seen.isoformat(),
        "evidence": f.evidence,
    }


def _build_readme(
    acc: AwsAccount,
    framework: str,
    period_days: int,
    generated_at: datetime,
    results: list[dict[str, Any]],
) -> str:
    passed = sum(1 for r in results if r["status"] == "pass")
    failed = sum(1 for r in results if r["status"] == "fail")
    no_data = sum(1 for r in results if r["status"] == "no_data")
    lines = [
        "VIGIL — COMPLIANCE EVIDENCE PACK",
        "=" * 50,
        f"Account:     {acc.label} ({acc.account_id or 'unknown'})",
        f"Framework:   {framework.upper().replace('_', ' ')}",
        f"Period:      {period_days} days",
        f"Generated:   {generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "SUMMARY",
        "-" * 30,
        f"PASS:     {passed}",
        f"FAIL:     {failed}",
        f"NO DATA:  {no_data}",
        f"TOTAL:    {len(results)}",
        "",
        "CONTENTS",
        "-" * 30,
        "INDEX.csv          — control ID, status, finding count",
        "controls/[ID]/     — per-control folder",
        "  summary.json     — control metadata and pass/fail status",
        "  findings.json    — open findings mapped to this control",
        "  snapshots.json   — raw collected evidence (last 50 entries)",
        "report.pdf         — formatted summary report",
        "",
        "NOTE: Evidence in snapshots.json is raw API data collected by",
        "Vigil during scans. Each entry includes a taken_at timestamp.",
        "Auditors may request specific date-range exports to confirm a",
        "control was in effect on a sampled date.",
    ]
    return "\n".join(lines)


def _build_index_csv(results: list[dict[str, Any]]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["control_id", "title", "status", "finding_count"])
    for r in results:
        writer.writerow([r["control_id"], r["title"], r["status"], r["finding_count"]])
    return buf.getvalue()
