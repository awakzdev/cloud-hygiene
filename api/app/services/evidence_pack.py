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
from app.models.cloudtrail import CloudTrailEvent
from app.models.control import Control, CheckControl
from app.models.aws_account import AwsAccount
from app.models.github import IdentityProvider, IdentityUser, PullRequest, Repo, RepoProtection
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
            Finding.status.in_(["open", "excepted"]),
        )
    ).all()

    snapshots = db.scalars(
        select(EvidenceSnapshot).where(
            EvidenceSnapshot.account_id == account_id,
            EvidenceSnapshot.taken_at >= since,
        ).order_by(EvidenceSnapshot.taken_at.desc())
    ).all()

    generated_at = datetime.now(timezone.utc)

    snap_by_type: dict[str, list[dict[str, Any]]] = {}
    for s in snapshots:
        snap_by_type.setdefault(s.entity_type, []).append(
            {"entity_id": s.entity_id, "taken_at": s.taken_at.isoformat(), "data": s.payload_json}
        )

    # Identity evidence (GitHub / GitLab) — keyed by provider type
    identity_snaps = _build_identity_snapshots(db, acc.org_id, generated_at)
    snap_by_type.update(identity_snaps)

    # CloudTrail change events — used for CC8.1 change management evidence
    snap_by_type["cloudtrail_event"] = _build_cloudtrail_event_snapshots(db, account_id, since)
    control_results: list[dict[str, Any]] = []
    for ctrl in controls:
        status, hits = _control_status(open_findings, check_map[ctrl.id])
        relevant_types = _entity_types_for_checks(check_map[ctrl.id])
        snaps = []
        for t in relevant_types:
            snaps.extend(snap_by_type.get(t, []))

        # When no snapshots exist (e.g. resource was never present — CloudTrail not enabled),
        # synthesize entries from finding evidence so auditors see account state rather than [].
        if not snaps and hits:
            snaps = [
                {
                    "entity_id": f.resource_arn,
                    "taken_at": generated_at.isoformat(),
                    "data": {**(f.evidence or {}), "_synthetic": True, "note": "Resource absent — no collected snapshot. Evidence derived from finding."},
                }
                for f in hits[:50]
            ]

        exceptions = [_finding_dict(f) for f in hits if f.status == "excepted"]
        control_results.append(
            {
                "control_id": ctrl.control_id,
                "title": ctrl.title,
                "description": ctrl.description,
                "guidance": ctrl.guidance or "",
                "status": status,
                "finding_count": len([f for f in hits if f.status == "open"]),
                "exception_count": len(exceptions),
                "findings": [_finding_dict(f) for f in hits if f.status == "open"],
                "exceptions": exceptions,
                "snapshots": snaps[:50],
            }
        )

    buf = io.BytesIO()
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
        elif cid.startswith("s3.account."):
            types.add("s3_account_public_access_block")
        elif cid.startswith("s3."):
            types.add("s3_bucket")
        elif cid.startswith("kms."):
            types.add("kms_key")
        elif cid.startswith("cloudtrail."):
            types.add("cloudtrail_trail")
        elif cid.startswith("guardduty."):
            types.add("guardduty_detector")
        elif cid.startswith("aws.access_analyzer"):
            types.add("access_analyzer")
        elif cid.startswith("aws.config"):
            types.add("config_recorder")
        elif cid.startswith("aws.securityhub"):
            types.add("security_hub")
        elif cid.startswith("vpc."):
            types.add("vpc")
        elif cid.startswith("ec2.security_group"):
            types.add("security_group")
        elif cid.startswith("ec2.instance"):
            types.add("ec2_instance")
        elif cid.startswith("ec2.ebs"):
            types.add("ebs_volume")
            types.add("ebs_encryption_default")
        elif cid.startswith("rds."):
            types.add("rds_instance")
        elif cid.startswith("github."):
            types.add("github_identity")
            types.add("cloudtrail_event")
        elif cid.startswith("gitlab."):
            types.add("gitlab_identity")
            types.add("cloudtrail_event")
    return list(types)


def _build_identity_snapshots(
    db: Session,
    org_id: uuid.UUID,
    generated_at: datetime,
) -> dict[str, list[dict[str, Any]]]:
    """Build evidence snapshots from identity tables for GitHub and GitLab providers."""
    result: dict[str, list[dict[str, Any]]] = {}
    providers = db.scalars(
        select(IdentityProvider).where(IdentityProvider.org_id == org_id)
    ).all()

    for provider in providers:
        ptype = provider.type  # "github" or "gitlab"
        snap_key = f"{ptype}_identity"
        snaps: list[dict[str, Any]] = []

        users = db.scalars(
            select(IdentityUser).where(IdentityUser.provider_id == provider.id)
        ).all()
        for u in users:
            snaps.append({
                "entity_id": u.external_id,
                "taken_at": u.snapshot_taken_at.isoformat(),
                "data": {
                    "type": "identity_user",
                    "provider": ptype,
                    "external_id": u.external_id,
                    "name": u.name,
                    "email": u.email,
                    "mfa_enabled": u.mfa_enabled,
                    "status": u.status,
                    "last_active_at": u.last_active_at.isoformat() if u.last_active_at else None,
                },
            })

        repos = db.scalars(
            select(Repo).where(Repo.provider_id == provider.id)
        ).all()
        for repo in repos:
            protection = db.scalars(
                select(RepoProtection).where(RepoProtection.repo_id == repo.id)
            ).first()
            prs = db.scalars(
                select(PullRequest)
                .where(PullRequest.repo_id == repo.id)
                .order_by(PullRequest.merged_at.desc())
                .limit(10)
            ).all()
            snaps.append({
                "entity_id": repo.name,
                "taken_at": repo.snapshot_taken_at.isoformat(),
                "data": {
                    "type": "repo",
                    "provider": ptype,
                    "name": repo.name,
                    "default_branch": repo.default_branch,
                    "has_codeowners": repo.has_codeowners,
                    "protected_envs": repo.protected_envs,
                    "branch_protection": {
                        "required_reviews": protection.required_reviews if protection else None,
                        "dismiss_stale": protection.dismiss_stale if protection else None,
                        "require_code_owners": protection.require_code_owners if protection else None,
                        "allow_force_push": protection.allow_force_push if protection else None,
                    } if protection else None,
                    "recent_prs": [
                        {
                            "number": pr.number,
                            "author": pr.author,
                            "merged_by": pr.merged_by,
                            "merged_at": pr.merged_at.isoformat() if pr.merged_at else None,
                            "approval_count": pr.approval_count,
                            "required_review_count": pr.required_review_count,
                            "self_merge": pr.self_merge,
                        }
                        for pr in prs
                    ],
                },
            })

        result[snap_key] = snaps
    return result


def _build_cloudtrail_event_snapshots(
    db: Session,
    account_id: uuid.UUID,
    since: datetime,
) -> list[dict[str, Any]]:
    """Return significant CloudTrail write events as evidence snapshots for CC8.1."""
    events = db.scalars(
        select(CloudTrailEvent)
        .where(CloudTrailEvent.account_id == account_id, CloudTrailEvent.event_time >= since)
        .order_by(CloudTrailEvent.event_time.desc())
        .limit(200)
    ).all()
    return [
        {
            "entity_id": evt.event_id,
            "taken_at": evt.event_time.isoformat(),
            "data": {
                "type": "cloudtrail_event",
                "event_name": evt.event_name,
                "event_source": evt.event_source,
                "event_time": evt.event_time.isoformat(),
                "actor": evt.actor,
                "source_ip": evt.source_ip,
                "resources": evt.resources or [],
            },
        }
        for evt in events
    ]


def _finding_dict(f: Finding) -> dict[str, Any]:
    d: dict[str, Any] = {
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
    if f.status == "excepted":
        d["exception"] = {
            "reason": f.exception_reason,
            "approved_by": f.exception_approved_by,
            "expires_at": f.exception_expires_at.isoformat() if f.exception_expires_at else None,
        }
    return d


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
        "VIGIL - COMPLIANCE EVIDENCE PACK",
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
        "INDEX.csv          - control ID, status, finding count",
        "controls/[ID]/     - per-control folder",
        "  summary.json     - control metadata and pass/fail status",
        "  findings.json    - open findings mapped to this control",
        "  snapshots.json   - raw collected evidence (last 50 entries)",
        "report.pdf         - formatted summary report",
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
