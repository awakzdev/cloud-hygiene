import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.security import current_principal
from app.models import Finding, AwsAccount, EvidenceSnapshot
from app.models.control import Control, CheckControl

router = APIRouter()

FRAMEWORKS = {"soc2", "cis_aws_l1"}


class ControlOut(BaseModel):
    id: str
    framework: str
    control_id: str
    title: str
    description: str
    guidance: str | None
    check_ids: list[str]
    status: str          # pass | fail | no_data
    finding_count: int
    open_finding_ids: list[str]


@router.get("", response_model=list[ControlOut])
def list_controls(
    framework: str = Query(...),
    account_id: str | None = Query(default=None),
    p=Depends(current_principal),
    db: Session = Depends(get_db),
):
    if framework not in FRAMEWORKS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"framework must be one of {sorted(FRAMEWORKS)}")

    controls = db.scalars(
        select(Control).where(Control.framework == framework).order_by(Control.control_id)
    ).all()

    # Resolve account for this org
    acc_id: uuid.UUID | None = None
    if account_id:
        acc = db.get(AwsAccount, uuid.UUID(account_id))
        if not acc or str(acc.org_id) != p["org_id"]:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")
        acc_id = acc.id
    else:
        # Use first connected account
        acc = db.scalars(
            select(AwsAccount).where(
                AwsAccount.org_id == uuid.UUID(p["org_id"]),
                AwsAccount.status == "connected",
            )
        ).first()
        if acc:
            acc_id = acc.id

    open_findings: list[Finding] = []
    if acc_id:
        open_findings = db.scalars(
            select(Finding).where(
                Finding.account_id == acc_id,
                Finding.status == "open",
            )
        ).all()

    open_by_check: dict[str, list[Finding]] = {}
    for f in open_findings:
        open_by_check.setdefault(f.check_id, []).append(f)

    result = []
    for ctrl in controls:
        check_ids = list(
            db.scalars(
                select(CheckControl.check_id).where(CheckControl.control_id == ctrl.id)
            ).all()
        )

        hits: list[Finding] = []
        for cid in check_ids:
            hits.extend(open_by_check.get(cid, []))

        if not check_ids:
            ctrl_status = "no_data"
        elif hits:
            ctrl_status = "fail"
        else:
            ctrl_status = "pass" if acc_id else "no_data"

        result.append(
            ControlOut(
                id=str(ctrl.id),
                framework=ctrl.framework,
                control_id=ctrl.control_id,
                title=ctrl.title,
                description=ctrl.description,
                guidance=ctrl.guidance,
                check_ids=check_ids,
                status=ctrl_status,
                finding_count=len(hits),
                open_finding_ids=[str(f.id) for f in hits],
            )
        )

    return result


@router.get("/{control_id}/evidence")
def control_evidence(
    control_id: str,
    account_id: str = Query(...),
    period: int = Query(default=90, ge=7, le=365),
    p=Depends(current_principal),
    db: Session = Depends(get_db),
):
    """Return recent evidence snapshots relevant to a specific control."""
    ctrl = db.scalars(
        select(Control).where(Control.control_id == control_id)
    ).first()
    if not ctrl:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "control not found")

    acc = db.get(AwsAccount, uuid.UUID(account_id))
    if not acc or str(acc.org_id) != p["org_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")

    check_ids = list(
        db.scalars(select(CheckControl.check_id).where(CheckControl.control_id == ctrl.id)).all()
    )

    entity_types = _entity_types_for_check_ids(check_ids)
    since = datetime.now(timezone.utc) - timedelta(days=period)

    q = select(EvidenceSnapshot).where(
        EvidenceSnapshot.account_id == acc.id,
        EvidenceSnapshot.taken_at >= since,
    )
    if entity_types:
        q = q.where(EvidenceSnapshot.entity_type.in_(entity_types))
    q = q.order_by(EvidenceSnapshot.taken_at.desc()).limit(200)

    snaps = db.scalars(q).all()
    return {
        "control_id": ctrl.control_id,
        "title": ctrl.title,
        "check_ids": check_ids,
        "period_days": period,
        "snapshot_count": len(snaps),
        "snapshots": [
            {
                "id": str(s.id),
                "entity_type": s.entity_type,
                "entity_id": s.entity_id,
                "taken_at": s.taken_at.isoformat(),
                "data": s.payload_json,
            }
            for s in snaps
        ],
    }


def _entity_types_for_check_ids(check_ids: list[str]) -> list[str]:
    types: set[str] = set()
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
