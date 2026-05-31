"""Compliance history: scan-level posture summaries (not per-finding evidence feed)."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Finding, ScanRun
from app.models.cloudtrail import CloudTrailEvent
from app.models.control import Control, CheckControl
from app.services.compliance_timeline import _control_status_at
from app.services.finding_history import (
    finding_open_for_control,
    finding_state_at,
    load_events_by_finding,
)
from app.services.timeline_filters import COMPLIANCE_EVENT_SOURCES

def _control_catalog(db: Session, framework: str) -> list[tuple[Control, list[str]]]:
    controls = db.scalars(
        select(Control).where(Control.framework == framework).order_by(Control.control_id)
    ).all()
    out: list[tuple[Control, list[str]]] = []
    for ctrl in controls:
        check_ids = list(
            db.scalars(select(CheckControl.check_id).where(CheckControl.control_id == ctrl.id)).all()
        )
        out.append((ctrl, check_ids))
    return out


def _snapshot_at(
    *,
    catalog: list[tuple[Control, list[str]]],
    findings: list[Finding],
    events_by_finding: dict,
    scan_runs: list[ScanRun],
    as_of: datetime,
) -> dict[str, dict[str, Any]]:
    has_scan = any(
        (r.finished_at or r.started_at) <= as_of and r.status == "ok" for r in scan_runs
    )
    out: dict[str, dict[str, Any]] = {}
    for ctrl, check_ids in catalog:
        mapped = [f for f in findings if f.check_id in check_ids]
        status = _control_status_at(check_ids, mapped, as_of, has_scan, events_by_finding)
        open_count = sum(
            1
            for f in mapped
            if finding_open_for_control(
                f, finding_state_at(f, as_of, events_by_finding.get(f.id))
            )
        )
        out[ctrl.control_id] = {
            "status": status,
            "title": ctrl.title,
            "open_finding_count": open_count,
        }
    return out


def _counts(snap: dict[str, dict[str, Any]]) -> dict[str, int]:
    return {
        "controls_passed": sum(1 for v in snap.values() if v["status"] == "pass"),
        "controls_failed": sum(1 for v in snap.values() if v["status"] == "fail"),
        "controls_no_data": sum(1 for v in snap.values() if v["status"] == "no_data"),
        "controls_total": len(snap),
    }


def _posture_score(counts: dict[str, int]) -> int | None:
    scored = counts["controls_passed"] + counts["controls_failed"]
    if scored == 0:
        return None
    return round(100 * counts["controls_passed"] / scored)


def _scan_control_diff(
    prev: dict[str, dict[str, Any]],
    curr: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Control-level pass/fail transitions only (no finding rows — use Findings for detail)."""
    newly_failed: list[dict[str, Any]] = []
    newly_passed: list[dict[str, Any]] = []
    for cid, cur in curr.items():
        prev_status = prev.get(cid, {}).get("status", "no_data")
        cur_status = cur["status"]
        base = {
            "control_id": cid,
            "title": cur["title"],
            "open_finding_count": cur.get("open_finding_count", 0),
        }
        if prev_status != "fail" and cur_status == "fail":
            newly_failed.append(base)
        elif prev_status == "fail" and cur_status == "pass":
            newly_passed.append(base)
    newly_failed.sort(key=lambda c: c.get("open_finding_count", 0), reverse=True)
    newly_passed.sort(key=lambda c: c.get("open_finding_count", 0), reverse=True)
    return newly_failed, newly_passed


def _snapshot_summary(
    counts: dict[str, int],
    score: int | None,
    *,
    findings_opened: int,
    findings_resolved: int,
) -> dict[str, Any]:
    return {
        "posture_score": score,
        "controls_passed": counts["controls_passed"],
        "controls_failed": counts["controls_failed"],
        "controls_no_data": counts["controls_no_data"],
        "findings_opened": findings_opened,
        "findings_resolved": findings_resolved,
    }


def _open_findings_count(
    findings: list[Finding],
    events_by_finding: dict,
    as_of: datetime,
) -> int:
    n = 0
    for f in findings:
        state = finding_state_at(f, as_of, events_by_finding.get(f.id))
        if finding_open_for_control(f, state):
            n += 1
    return n


def _infra_event_counts_by_day(
    db: Session,
    account_id: uuid.UUID,
    since: datetime,
) -> dict[str, int]:
    day_col = func.date(CloudTrailEvent.event_time)
    rows = db.execute(
        select(day_col, func.count())
        .where(
            CloudTrailEvent.account_id == account_id,
            CloudTrailEvent.event_time >= since,
            CloudTrailEvent.event_source.in_(tuple(COMPLIANCE_EVENT_SOURCES)),
        )
        .group_by(day_col)
    ).all()
    return {str(row[0]): int(row[1]) for row in rows}


def _attach_infra_counts(events: list[dict[str, Any]], counts: dict[str, int]) -> None:
    for evt in events:
        day = evt["timestamp"][:10]
        evt["infrastructure_events_count"] = counts.get(day, 0)


def _period_summary(events: list[dict[str, Any]]) -> dict[str, int]:
    controls_regressed = 0
    controls_improved = 0
    for e in events:
        if e.get("type") == "baseline_established":
            continue
        controls_regressed += len(e.get("diff", {}).get("newly_failed", []))
        controls_improved += len(e.get("diff", {}).get("newly_passed", []))
    return {
        "compliance_changes": len(events),
        "controls_regressed": controls_regressed,
        "controls_improved": controls_improved,
        "evidence_snapshots": len(events),
    }


def _scan_cadence(scan_runs: list[ScanRun], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    posture_days: dict[str, int] = {}
    for evt in events:
        day = evt["timestamp"][:10]
        posture_days[day] = posture_days.get(day, 0) + 1

    days: dict[str, int] = {}
    for run in scan_runs:
        ts = run.finished_at or run.started_at
        day = ts.date().isoformat()
        days[day] = days.get(day, 0) + 1

    return [
        {
            "date": day,
            "scan_count": count,
            "posture_change_count": posture_days.get(day, 0),
        }
        for day, count in sorted(days.items())
    ]


def _top_change(
    *,
    newly_failed: list[dict[str, Any]],
    newly_passed: list[dict[str, Any]],
    score_before: int | None,
    score_after: int | None,
    baseline: bool = False,
) -> dict[str, Any]:
    if baseline:
        return {
            "control_id": None,
            "title": "Initial compliance baseline",
            "direction": "baseline",
            "label": "Initial compliance baseline",
        }
    if score_before is None and score_after is not None:
        return {
            "control_id": None,
            "title": "Initial compliance baseline",
            "direction": "baseline",
            "label": "Initial compliance baseline",
        }
    if newly_passed and (not newly_failed or len(newly_passed) >= len(newly_failed)):
        c = newly_passed[0]
        return {
            "control_id": c["control_id"],
            "title": c["title"],
            "direction": "improved",
            "label": f"{c['control_id']} improved",
        }
    if newly_failed:
        c = newly_failed[0]
        return {
            "control_id": c["control_id"],
            "title": c["title"],
            "direction": "regressed",
            "label": f"{c['control_id']} regressed",
        }
    if score_before is not None and score_after is not None and score_after != score_before:
        verb = "improved" if score_after > score_before else "regressed"
        return {
            "control_id": None,
            "title": "Posture shift",
            "direction": verb,
            "label": f"Score {verb} ({score_before}% → {score_after}%)",
        }
    return {
        "control_id": None,
        "title": "Controls updated",
        "direction": "changed",
        "label": "Control status changed",
    }


def _event_type(
    *,
    newly_failed: list[dict[str, Any]],
    newly_passed: list[dict[str, Any]],
    score_before: int | None,
    score_after: int | None,
) -> str:
    if score_before is not None and score_after is not None:
        if score_after < score_before and not newly_passed:
            return "compliance_regressed"
        if score_after > score_before and not newly_failed:
            return "compliance_improved"
    if len(newly_failed) > len(newly_passed):
        return "compliance_regressed"
    if len(newly_passed) > len(newly_failed):
        return "compliance_improved"
    return "scan_with_changes"


def build_compliance_scan_timeline(
    db: Session,
    account_id: uuid.UUID,
    framework: str,
    days: int = 90,
    limit: int = 40,
) -> dict[str, Any]:
    """One history entry per scan that changed compliance posture (plus baseline)."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    catalog = _control_catalog(db, framework)
    if not catalog:
        return {
            "framework": framework,
            "period_days": days,
            "events": [],
            "period_summary": {
                "compliance_changes": 0,
                "controls_regressed": 0,
                "controls_improved": 0,
                "evidence_snapshots": 0,
            },
            "current_summary": None,
            "current_posture_score": None,
            "total_failing": 0,
            "scan_count": 0,
            "scan_cadence": [],
        }

    findings = list(db.scalars(select(Finding).where(Finding.account_id == account_id)).all())
    events_by_finding = load_events_by_finding(db, [f.id for f in findings])

    scan_runs = db.scalars(
        select(ScanRun)
        .where(
            ScanRun.account_id == account_id,
            ScanRun.started_at >= since,
            ScanRun.status == "ok",
        )
        .order_by(ScanRun.started_at.asc())
    ).all()

    events: list[dict[str, Any]] = []
    prev_snap: dict[str, dict[str, Any]] | None = None
    last_snap: dict[str, dict[str, Any]] | None = None

    for run in scan_runs:
        ts = run.finished_at or run.started_at
        snap = _snapshot_at(
            catalog=catalog,
            findings=findings,
            events_by_finding=events_by_finding,
            scan_runs=scan_runs,
            as_of=ts,
        )
        last_snap = snap
        curr_counts = _counts(snap)
        score_after = _posture_score(curr_counts)

        if prev_snap is None:
            baseline_failed = [
                {
                    "control_id": cid,
                    "title": v["title"],
                    "open_finding_count": v.get("open_finding_count", 0),
                }
                for cid, v in sorted(snap.items())
                if v["status"] == "fail"
            ]
            baseline_failed.sort(key=lambda c: c.get("open_finding_count", 0), reverse=True)
            findings_discovered = _open_findings_count(findings, events_by_finding, ts)
            events.append(
                {
                    "type": "baseline_established",
                    "timestamp": ts.isoformat(),
                    "scan_run_id": str(run.id),
                    "framework": framework,
                    "posture_before": None,
                    "posture_after": score_after,
                    "controls_failed_before": None,
                    "controls_failed_after": curr_counts["controls_failed"],
                    "controls_passed_before": None,
                    "controls_passed_after": curr_counts["controls_passed"],
                    "new_failures_count": curr_counts["controls_failed"],
                    "resolved_count": 0,
                    "findings_opened": run.findings_opened,
                    "findings_resolved": run.findings_resolved,
                    "findings_discovered": findings_discovered,
                    "snapshot": _snapshot_summary(
                        curr_counts,
                        score_after,
                        findings_opened=run.findings_opened,
                        findings_resolved=run.findings_resolved,
                    ),
                    "top_change": _top_change(
                        newly_failed=baseline_failed,
                        newly_passed=[],
                        score_before=None,
                        score_after=score_after,
                        baseline=True,
                    ),
                    "diff": {
                        "newly_failed": baseline_failed,
                        "newly_passed": [],
                    },
                }
            )
            prev_snap = snap
            continue

        prev_counts = _counts(prev_snap)
        score_before = _posture_score(prev_counts)
        newly_failed, newly_passed = _scan_control_diff(prev_snap, snap)

        if not newly_failed and not newly_passed:
            prev_snap = snap
            continue

        evt_type = _event_type(
            newly_failed=newly_failed,
            newly_passed=newly_passed,
            score_before=score_before,
            score_after=score_after,
        )

        events.append(
            {
                "type": evt_type,
                "timestamp": ts.isoformat(),
                "scan_run_id": str(run.id),
                "framework": framework,
                "posture_before": score_before,
                "posture_after": score_after,
                "controls_failed_before": prev_counts["controls_failed"],
                "controls_failed_after": curr_counts["controls_failed"],
                "controls_passed_before": prev_counts["controls_passed"],
                "controls_passed_after": curr_counts["controls_passed"],
                "new_failures_count": len(newly_failed),
                "resolved_count": len(newly_passed),
                "findings_opened": run.findings_opened,
                "findings_resolved": run.findings_resolved,
                "snapshot": _snapshot_summary(
                    curr_counts,
                    score_after,
                    findings_opened=run.findings_opened,
                    findings_resolved=run.findings_resolved,
                ),
                "top_change": _top_change(
                    newly_failed=newly_failed,
                    newly_passed=newly_passed,
                    score_before=score_before,
                    score_after=score_after,
                ),
                "diff": {
                    "newly_failed": newly_failed,
                    "newly_passed": newly_passed,
                },
            }
        )
        prev_snap = snap

    events.reverse()
    events = events[:limit]

    infra_counts = _infra_event_counts_by_day(db, account_id, since)
    _attach_infra_counts(events, infra_counts)

    current_summary = None
    current_posture_score = None
    total_failing = 0
    if last_snap:
        current_summary = _counts(last_snap)
        current_posture_score = _posture_score(current_summary)
        total_failing = current_summary["controls_failed"]

    return {
        "framework": framework,
        "period_days": days,
        "events": events,
        "period_summary": _period_summary(events),
        "current_summary": current_summary,
        "current_posture_score": current_posture_score,
        "total_failing": total_failing,
        "scan_count": len(scan_runs),
        "scan_cadence": _scan_cadence(scan_runs, events),
    }
