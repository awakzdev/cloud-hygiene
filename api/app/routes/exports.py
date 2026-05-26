import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.security import current_principal
from app.models import AwsAccount
from app.services.evidence_pack import build_evidence_pack

router = APIRouter()

FRAMEWORKS = {"soc2", "cis_aws_l1"}


@router.get("/evidence-pack")
def download_evidence_pack(
    framework: str = Query(...),
    account_id: str = Query(...),
    period: int = Query(default=90, ge=7, le=365),
    p=Depends(current_principal),
    db: Session = Depends(get_db),
):
    if framework not in FRAMEWORKS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"framework must be one of {sorted(FRAMEWORKS)}")

    acc = db.get(AwsAccount, uuid.UUID(account_id))
    if not acc or str(acc.org_id) != p["org_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")

    try:
        zip_bytes = build_evidence_pack(
            db=db,
            org_id=uuid.UUID(p["org_id"]),
            account_id=acc.id,
            framework=framework,
            period_days=period,
        )
    except Exception as exc:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, str(exc)) from exc

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    filename = f"vigil-evidence-{framework}-{ts}.zip"
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
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
        "iam.user.inactive_90d": ["CC6.2"],
        "github.repo.no_branch_protection": ["CC7.1"],
    }

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # README
        passed = sum(1 for _, _, _, s, _, _ in sample_controls if s == "pass")
        failed = sum(1 for _, _, _, s, _, _ in sample_controls if s == "fail")
        readme_lines = [
            "VIGIL - SAMPLE COMPLIANCE EVIDENCE PACK",
            "=" * 50,
            "NOTICE: This is a synthetic sample pack with demo data.",
            "        Connect your AWS/GitHub account to generate real evidence.",
            "",
            f"Account:     ACME Corp Demo (123456789012)",
            f"Framework:   {framework.upper().replace('_', ' ')}",
            f"Generated:   {now.isoformat()}",
            f"Period:      {(now - timedelta(days=90)).date()} to {now.date()} (90 days)",
            "",
            f"Controls:    {passed} passed / {failed} failed",
            "",
            "CONTENTS",
            "-" * 40,
            "README.txt             - this file",
            "INDEX.csv              - control ID, status, finding count",
            "controls/              - per-control evidence folder",
            "  <CTRL-ID>/",
            "    summary.json       - control metadata and status",
            "    findings.json      - open findings for this control",
            "    exceptions.json    - approved exceptions with approver + reason",
            "",
            "Download at vigil.sh/sample or connect your account for real evidence.",
        ]
        zf.writestr("README.txt", "\n".join(readme_lines))

        # INDEX.csv
        idx_buf = io.StringIO()
        idx_w = _csv.writer(idx_buf)
        idx_w.writerow(["control_id", "title", "status", "open_findings", "exceptions"])
        for ctrl_id, title, _, ctrl_status, open_ct, exc_ct in sample_controls:
            idx_w.writerow([ctrl_id, title, ctrl_status, open_ct, exc_ct])
        zf.writestr("INDEX.csv", idx_buf.getvalue())

        # Per-control folders
        for ctrl_id, title, desc, ctrl_status, _, _ in sample_controls:
            checks_for_ctrl = [c for c, ctrls in check_to_control.items() if ctrl_id in ctrls]
            open_findings = [f for c in checks_for_ctrl for f in finding_by_check.get(c, []) if f["status"] == "open"]
            exceptions = [f for c in checks_for_ctrl for f in finding_by_check.get(c, []) if f["status"] == "excepted"]
            summary = {
                "control_id": ctrl_id,
                "title": title,
                "description": desc,
                "status": ctrl_status,
                "open_findings": len(open_findings),
                "exceptions": len(exceptions),
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

    q = select(Finding).where(Finding.org_id == uuid.UUID(p["org_id"]))
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
    w.writerow(["id", "check_id", "resource_arn", "title", "severity", "risk_score", "status", "first_seen", "last_seen"])
    for f in rows:
        w.writerow([str(f.id), f.check_id, f.resource_arn, f.title, f.severity, f.risk_score, f.status, f.first_seen.isoformat(), f.last_seen.isoformat()])

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return Response(
        content=buf.getvalue().encode(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="vigil-findings-{ts}.csv"'},
    )
