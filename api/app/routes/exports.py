import hashlib
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.security import current_principal
from app.models import AwsAccount, EvidenceExport
from app.services.evidence_coverage import parse_as_of
from app.services.evidence_pack import build_evidence_pack


def _parse_vault_retain_until(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None

router = APIRouter()

FRAMEWORKS = {"soc2", "cis_aws_l1", "iso27001"}


@router.get("/evidence-pack")
def download_evidence_pack(
    framework: str = Query(...),
    account_id: str = Query(...),
    period: int = Query(default=90, ge=7, le=365),
    as_of: str | None = Query(default=None, description="End of audit period (YYYY-MM-DD). Defaults to today UTC."),
    p=Depends(current_principal),
    db: Session = Depends(get_db),
):
    if framework not in FRAMEWORKS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"framework must be one of {sorted(FRAMEWORKS)}")

    acc = db.get(AwsAccount, uuid.UUID(account_id))
    if not acc or str(acc.org_id) != p["org_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")

    try:
        pack = build_evidence_pack(
            db=db,
            org_id=uuid.UUID(p["org_id"]),
            account_id=acc.id,
            framework=framework,
            period_days=period,
            as_of=parse_as_of(as_of),
        )
    except Exception as exc:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, str(exc)) from exc

    zip_bytes = pack.zip_bytes
    vault = pack.vault_upload if pack.vault_upload and pack.vault_upload.get("status") == "uploaded" else None
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    filename = f"vigil-evidence-{framework}-{ts}.zip"
    zip_sha256 = hashlib.sha256(zip_bytes).hexdigest()
    as_of_dt = parse_as_of(as_of)
    db.add(
        EvidenceExport(
            org_id=uuid.UUID(p["org_id"]),
            account_id=acc.id,
            framework=framework,
            period_days=period,
            as_of=as_of_dt.date() if as_of_dt else None,
            zip_sha256=zip_sha256,
            file_size_bytes=len(zip_bytes),
            report_id=pack.report_id,
            vault_s3_uri=vault.get("s3_uri") if vault else None,
            vault_version_id=vault.get("version_id") if vault else None,
            vault_object_lock_mode=vault.get("object_lock_mode") if vault else None,
            vault_retain_until=_parse_vault_retain_until(vault.get("retention_until") if vault else None),
            created_by=uuid.UUID(p["sub"]) if p.get("sub") else None,
        )
    )
    db.commit()
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Content-SHA256": zip_sha256,
            "X-Vigil-Pack-SHA256": zip_sha256,
        },
    )


@router.get("/sample-evidence-pack")
def download_sample_evidence_pack(framework: str = Query(default="soc2")):
    """Public demo endpoint — returns a pre-built sample evidence pack with synthetic data.
    No auth required. Useful for landing page / trial onboarding."""
    import io, json, zipfile, csv as _csv
    from datetime import timedelta

    if framework not in FRAMEWORKS:
        framework = "soc2"

    now = datetime.now(timezone.utc)
    ts_str = now.strftime("%Y-%m-%d")

    sample_controls = [
        ("CC6.1", "Logical and Physical Access Controls", "MFA enforced for all console users", "pass", 0, 0),
        ("CC6.2", "Logical Access Restrictions", "No dormant identities beyond 90 days", "pass", 0, 0),
        ("CC6.3", "Access Reviews", "No roles with wildcard Action grants", "fail", 2, 0),
        ("CC6.6", "Least Privilege", "Roles granted only services they use", "fail", 1, 1),
        ("CC7.1", "Change Management", "Branch protection and required reviews on all repos", "pass", 0, 0),
        ("CC7.2", "Monitoring Controls", "CloudTrail enabled and log validation active", "fail", 1, 0),
    ] if framework == "soc2" else [
        ("CIS 1.5", "Ensure MFA is enabled for root account", "Root MFA check", "pass", 0, 0),
        ("CIS 1.10", "Ensure MFA is enabled for IAM users", "IAM user MFA check", "fail", 3, 0),
        ("CIS 1.16", "Ensure IAM policies are not attached to users", "IAM policy attachment check", "pass", 0, 0),
        ("CIS 2.1", "Ensure CloudTrail is enabled", "CloudTrail multi-region", "pass", 0, 0),
        ("CIS 2.2", "Ensure CloudTrail log file validation", "Log validation check", "fail", 1, 0),
        ("CIS 3.1", "Ensure log metric filter for root account usage", "Root usage", "pass", 0, 0),
    ]

    sample_findings = [
        {
            "id": "f1000000-0000-0000-0000-000000000001",
            "check_id": "iam.role.wildcard_action",
            "resource_arn": "arn:aws:iam::123456789012:role/dev-unrestricted",
            "title": "Role dev-unrestricted has Action: * in inline policy",
            "severity": "high",
            "risk_score": 85,
            "status": "open",
            "first_seen": (now - timedelta(days=14)).isoformat(),
            "last_seen": now.isoformat(),
            "evidence": {"role_name": "dev-unrestricted", "policy_names": ["DevInlinePolicy"]},
        },
        {
            "id": "f1000000-0000-0000-0000-000000000002",
            "check_id": "iam.role.wildcard_action",
            "resource_arn": "arn:aws:iam::123456789012:role/ci-runner",
            "title": "Role ci-runner has Action: * in inline policy",
            "severity": "high",
            "risk_score": 80,
            "status": "open",
            "first_seen": (now - timedelta(days=30)).isoformat(),
            "last_seen": now.isoformat(),
            "evidence": {"role_name": "ci-runner", "policy_names": ["CIInlinePolicy"]},
        },
        {
            "id": "f1000000-0000-0000-0000-000000000003",
            "check_id": "iam.perm.granted_vs_used",
            "resource_arn": "arn:aws:iam::123456789012:role/legacy-batch",
            "title": "Role legacy-batch has 72% unused granted write actions",
            "severity": "medium",
            "risk_score": 55,
            "status": "excepted",
            "first_seen": (now - timedelta(days=60)).isoformat(),
            "last_seen": now.isoformat(),
            "evidence": {"role_name": "legacy-batch", "unused_pct": 72},
            "exception": {
                "reason": "Legacy batch job scheduled for decommission Q3 2026. Risk accepted.",
                "approved_by": "Alice Smith (CTO)",
                "expires_at": (now + timedelta(days=90)).isoformat(),
            },
        },
        {
            "id": "f1000000-0000-0000-0000-000000000004",
            "check_id": "cloudtrail.trail.no_log_validation",
            "resource_arn": "arn:aws:cloudtrail:us-east-1:123456789012:trail/management-events",
            "title": "CloudTrail trail management-events has log file validation disabled",
            "severity": "medium",
            "risk_score": 45,
            "status": "open",
            "first_seen": (now - timedelta(days=7)).isoformat(),
            "last_seen": now.isoformat(),
            "evidence": {"trail_name": "management-events", "region": "us-east-1"},
        },
    ]
    finding_by_check: dict[str, list[dict]] = {}
    for f in sample_findings:
        finding_by_check.setdefault(f["check_id"], []).append(f)

    check_to_control: dict[str, list[str]] = {
        "iam.role.wildcard_action": ["CC6.3", "CIS 1.16"],
        "iam.perm.granted_vs_used": ["CC6.6"],
        "cloudtrail.trail.no_log_validation": ["CC7.2", "CIS 2.2"],
        "iam.user.no_mfa": ["CC6.1", "CIS 1.10"],
        "iam.user.credentials_unused_45d": ["CC6.2"],
        "github.repo.no_branch_protection": ["CC7.1"],
    }

    control_results: list[dict] = []
    for ctrl_id, title, desc, ctrl_status, open_ct, exc_ct in sample_controls:
        checks_for_ctrl = [c for c, ctrls in check_to_control.items() if ctrl_id in ctrls]
        open_findings = [f for c in checks_for_ctrl for f in finding_by_check.get(c, []) if f["status"] == "open"]
        ev_status = "complete" if ctrl_status == "pass" else ("partial" if open_findings else "missing")
        reason = (
            f"{open_ct} open finding(s) mapped to this control require remediation or documented exception."
            if ctrl_status == "fail"
            else "No open findings mapped to this control."
        )
        control_results.append({
            "control_id": ctrl_id,
            "title": title,
            "description": desc,
            "guidance": "",
            "status": ctrl_status,
            "evidence_status": ev_status,
            "finding_count": open_ct,
            "findings": open_findings,
            "review_reason": reason,
        })

    from types import SimpleNamespace
    from app.services.pdf_report import build_pdf

    sample_acc = SimpleNamespace(label="ACME Corp Demo", account_id="123456789012")
    since = now - timedelta(days=90)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        pdf_bytes = build_pdf(
            sample_acc,
            framework,
            90,
            now,
            control_results,
            since=since,
            evidence_sources=["AWS IAM", "AWS CloudTrail", "AWS Config", "GitHub"],
            report_id="SAMPLE000001",
        )
        zf.writestr("report.pdf", pdf_bytes)

        # README
        passed = sum(1 for _, _, _, s, _, _ in sample_controls if s == "pass")
        failed = sum(1 for _, _, _, s, _, _ in sample_controls if s == "fail")
        period_start = (now - timedelta(days=90)).date()
        readme_lines = [
            "VIGIL - SAMPLE COMPLIANCE EVIDENCE PACK (v2)",
            "=" * 50,
            "NOTICE: This is a synthetic sample pack with demo data.",
            "        Connect your AWS/GitHub account to generate real evidence.",
            "",
            f"Account:     ACME Corp Demo (123456789012)",
            f"Framework:   {framework.upper().replace('_', ' ')}",
            f"Generated:   {now.strftime('%Y-%m-%d %H:%M UTC')}",
            f"Period:      {period_start} to {now.date()} (90 days)",
            "",
            f"Controls:    {passed} passed / {failed} failed",
            "",
            "START HERE",
            "-" * 40,
            "1. Read report.pdf for the auditor-facing summary.",
            "2. Open INDEX.csv for pass/fail per control.",
            "3. Drill into controls/[ID]/ for findings and exceptions.",
            "4. timeline.csv shows when findings opened or were excepted.",
            "",
            "CONTENTS",
            "-" * 40,
            "README.txt             - this file",
            "report.pdf             - formatted summary report",
            "INDEX.csv              - control status table",
            "control_status.csv     - same as INDEX.csv",
            "timeline.csv           - sample audit-period events",
            "source_manifest.json   - collection metadata",
            "check_evidence_classes.json - benchmark vs supporting vs hygiene per check",
            "controls/              - per-control evidence folders",
            "",
            "Download from the Vigil login page or connect your account for real evidence.",
        ]
        zf.writestr("README.txt", "\n".join(readme_lines))

        # INDEX.csv + control_status.csv
        idx_buf = io.StringIO()
        idx_w = _csv.writer(idx_buf)
        idx_w.writerow(["control_id", "title", "status", "open_findings", "exceptions", "status_note"])
        for ctrl_id, title, _, ctrl_status, open_ct, exc_ct in sample_controls:
            if ctrl_status == "pass" and exc_ct:
                note = f"PASS with {exc_ct} approved exception(s)"
            elif ctrl_status == "pass":
                note = "PASS — no open findings"
            elif exc_ct:
                note = f"FAIL — {open_ct} open, {exc_ct} exception(s)"
            else:
                note = f"FAIL — {open_ct} open finding(s)"
            idx_w.writerow([ctrl_id, title, ctrl_status, open_ct, exc_ct, note])
        index_csv = idx_buf.getvalue()
        zf.writestr("INDEX.csv", index_csv)
        zf.writestr("control_status.csv", index_csv)

        # timeline.csv
        tl_buf = io.StringIO()
        tl_w = _csv.writer(tl_buf)
        tl_w.writerow(["timestamp", "event_type", "control_id", "check_id", "resource_arn", "detail"])
        tl_w.writerow([
            (now - timedelta(days=60)).isoformat(),
            "finding_first_seen",
            "",
            "iam.perm.granted_vs_used",
            "arn:aws:iam::123456789012:role/legacy-batch",
            "Role legacy-batch has 72% unused granted write actions",
        ])
        tl_w.writerow([
            (now - timedelta(days=59)).isoformat(),
            "exception_active",
            "",
            "iam.perm.granted_vs_used",
            "arn:aws:iam::123456789012:role/legacy-batch",
            "Exception approved by Alice Smith (CTO) until " + (now + timedelta(days=90)).date().isoformat(),
        ])
        tl_w.writerow([
            (now - timedelta(days=14)).isoformat(),
            "finding_first_seen",
            "",
            "iam.role.wildcard_action",
            "arn:aws:iam::123456789012:role/dev-unrestricted",
            "Role dev-unrestricted has Action: * in inline policy",
        ])
        tl_w.writerow([now.isoformat(), "scan_completed", "", "", "", "Scan ok; opened=2 resolved=0"])
        zf.writestr("timeline.csv", tl_buf.getvalue())

        manifest = {
            "pack_version": "2.0",
            "sample": True,
            "generated_at": now.isoformat(),
            "framework": framework,
            "audit_period": {"days": 90, "start": (now - timedelta(days=90)).isoformat(), "end": now.isoformat()},
            "integrations": [
                {"type": "aws", "account_label": "ACME Corp Demo", "account_id": "123456789012", "status": "connected"},
                {"type": "github", "status": "connected"},
            ],
            "collection_summary": {
                "scan_runs_in_period": 12,
                "successful_scans": 12,
                "evidence_snapshots_in_period": 847,
                "snapshot_types": {"iam_user": 24, "iam_role": 18, "s3_bucket": 6, "github_identity": 42},
            },
            "artifacts": {
                "report.pdf": "Executive summary (included in this sample pack)",
                "INDEX.csv": "Control status table",
                "timeline.csv": "Audit-period events",
            },
        }
        zf.writestr("source_manifest.json", json.dumps(manifest, indent=2))

        from app.services.check_evidence import all_evidence_classes

        zf.writestr("check_evidence_classes.json", json.dumps(all_evidence_classes(), indent=2))

        zf.writestr(
            "iam_history.json",
            json.dumps(
                {
                    "as_of": now.isoformat(),
                    "source": "evidence_snapshots",
                    "sample": True,
                    "snapshot_count": 3,
                    "summary": {"iam_user": 2, "iam_role": 1},
                    "entities": {
                        "iam_user": [
                            {
                                "entity_id": "arn:aws:iam::123456789012:user/alice",
                                "taken_at": (now - timedelta(days=7)).isoformat(),
                                "data": {"username": "alice", "mfa_enabled": True},
                            }
                        ],
                    },
                },
                indent=2,
            ),
        )
        zf.writestr(
            "vault_upload_plan.json",
            json.dumps(
                {
                    "status": "planned",
                    "sample": True,
                    "s3_uri": "s3://your-audit-vault-bucket/vigil-evidence/orgs/…/packs/SAMPLE000001.zip",
                    "note": "Enable EVIDENCE_VAULT_ENABLED + EVIDENCE_VAULT_S3_URI on the server for real WORM uploads.",
                },
                indent=2,
            ),
        )

        # Per-control folders
        for ctrl_id, title, desc, ctrl_status, _, _ in sample_controls:
            checks_for_ctrl = [c for c, ctrls in check_to_control.items() if ctrl_id in ctrls]
            open_findings = [f for c in checks_for_ctrl for f in finding_by_check.get(c, []) if f["status"] == "open"]
            exceptions = [f for c in checks_for_ctrl for f in finding_by_check.get(c, []) if f["status"] == "excepted"]
            exc_narratives = []
            for ex in exceptions:
                exc = ex.get("exception") or {}
                exc_narratives.append(
                    f"Finding '{ex['title']}' — exception approved by {exc.get('approved_by', 'unknown')}"
                    + (f" until {exc['expires_at'][:10]}" if exc.get("expires_at") else "")
                    + f". Reason: {exc.get('reason', '')}"
                )
            if ctrl_status == "pass" and exceptions:
                status_note = f"PASS with {len(exceptions)} approved exception(s)"
            elif ctrl_status == "pass":
                status_note = "PASS — no open findings"
            elif exceptions:
                status_note = f"FAIL — {len(open_findings)} open, {len(exceptions)} exception(s)"
            else:
                status_note = f"FAIL — {len(open_findings)} open finding(s)"
            summary = {
                "control_id": ctrl_id,
                "title": title,
                "description": desc,
                "status": ctrl_status,
                "status_note": status_note,
                "open_findings": len(open_findings),
                "exceptions": len(exceptions),
                "exception_narratives": exc_narratives,
                "generated_at": now.isoformat(),
                "account": "ACME Corp Demo (123456789012)",
                "framework": framework,
                "note": "Sample data — connect your account for real evidence",
            }
            prefix = f"controls/{ctrl_id}/"
            zf.writestr(prefix + "summary.json", json.dumps(summary, indent=2))
            zf.writestr(prefix + "findings.json", json.dumps(open_findings, indent=2))
            zf.writestr(prefix + "exceptions.json", json.dumps(exceptions, indent=2))

    ts = now.strftime("%Y-%m-%d")
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="vigil-sample-{framework}-{ts}.zip"'},
    )


@router.get("/findings.csv")
def export_findings_csv(
    status_filter: str | None = Query(default="open", alias="status"),
    account_id: str | None = Query(default=None),
    p=Depends(current_principal),
    db: Session = Depends(get_db),
):
    import csv, io
    from sqlalchemy import select
    from app.models import Finding
    from app.models.org import Org
    from app.services.check_settings import hidden_check_ids

    org = db.get(Org, uuid.UUID(p["org_id"]))
    hidden = hidden_check_ids(org.settings if org else {})

    q = select(Finding).where(Finding.org_id == uuid.UUID(p["org_id"]))
    if hidden:
        q = q.where(Finding.check_id.notin_(hidden))
    if status_filter and status_filter != "all":
        q = q.where(Finding.status == status_filter)
    if account_id:
        acc = db.get(AwsAccount, uuid.UUID(account_id))
        if acc and str(acc.org_id) == p["org_id"]:
            q = q.where(Finding.account_id == acc.id)
    q = q.order_by(Finding.risk_score.desc())
    rows = db.scalars(q).all()

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([
        "id", "check_id", "resource_arn", "title", "severity", "risk_score", "status",
        "first_seen", "last_seen", "exception_reason", "exception_approved_by", "exception_expires_at",
    ])
    for f in rows:
        w.writerow([
            str(f.id), f.check_id, f.resource_arn, f.title, f.severity, f.risk_score, f.status,
            f.first_seen.isoformat(), f.last_seen.isoformat(),
            f.exception_reason or "",
            f.exception_approved_by or "",
            f.exception_expires_at.isoformat() if f.exception_expires_at else "",
        ])

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return Response(
        content=buf.getvalue().encode(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="vigil-findings-{ts}.csv"'},
    )
