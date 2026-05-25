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
