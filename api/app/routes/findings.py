import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.security import current_principal
from app.models import Finding, FindingEvent, AwsAccount

router = APIRouter()


class FindingOut(BaseModel):
    id: str
    check_id: str
    resource_arn: str
    title: str
    severity: str
    risk_score: int
    status: str
    evidence: dict
    first_seen: datetime
    last_seen: datetime

    class Config:
        from_attributes = True


class SnoozeIn(BaseModel):
    days: int = 30
    note: str | None = None


class ResolveIn(BaseModel):
    note: str | None = None


def _to_out(f: Finding) -> FindingOut:
    return FindingOut(
        id=str(f.id),
        check_id=f.check_id,
        resource_arn=f.resource_arn,
        title=f.title,
        severity=f.severity,
        risk_score=f.risk_score,
        status=f.status,
        evidence=f.evidence,
        first_seen=f.first_seen,
        last_seen=f.last_seen,
    )


@router.get("", response_model=list[FindingOut])
def list_findings(
    status_filter: str | None = Query(default="open", alias="status"),
    severity: str | None = None,
    check_id: str | None = None,
    p=Depends(current_principal),
    db: Session = Depends(get_db),
):
    q = select(Finding).where(Finding.org_id == uuid.UUID(p["org_id"]))
    if status_filter and status_filter != "all":
        q = q.where(Finding.status == status_filter)
    if severity:
        q = q.where(Finding.severity == severity)
    if check_id:
        q = q.where(Finding.check_id == check_id)
    q = q.order_by(Finding.risk_score.desc(), Finding.first_seen.desc())
    rows = db.scalars(q).all()
    return [_to_out(f) for f in rows]


def _get_owned(db: Session, p, finding_id: str) -> Finding:
    f = db.get(Finding, uuid.UUID(finding_id))
    if not f or str(f.org_id) != p["org_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    return f


@router.post("/{finding_id}/snooze", response_model=FindingOut)
def snooze(finding_id: str, body: SnoozeIn, p=Depends(current_principal), db: Session = Depends(get_db)):
    f = _get_owned(db, p, finding_id)
    f.status = "snoozed"
    f.snooze_until = datetime.now(timezone.utc) + timedelta(days=body.days)
    db.add(FindingEvent(id=uuid.uuid4(), finding_id=f.id, action="snoozed", actor=p["sub"], note=body.note))
    db.commit()
    return _to_out(f)


@router.post("/{finding_id}/resolve", response_model=FindingOut)
def resolve(finding_id: str, body: ResolveIn, p=Depends(current_principal), db: Session = Depends(get_db)):
    f = _get_owned(db, p, finding_id)
    f.status = "resolved"
    f.resolved_at = datetime.now(timezone.utc)
    db.add(FindingEvent(id=uuid.uuid4(), finding_id=f.id, action="resolved", actor=p["sub"], note=body.note))
    db.commit()
    return _to_out(f)


@router.post("/{finding_id}/ignore", response_model=FindingOut)
def ignore(finding_id: str, p=Depends(current_principal), db: Session = Depends(get_db)):
    f = _get_owned(db, p, finding_id)
    f.status = "ignored"
    db.add(FindingEvent(id=uuid.uuid4(), finding_id=f.id, action="ignored", actor=p["sub"]))
    db.commit()
    return _to_out(f)


@router.post("/{finding_id}/recheck")
def recheck(finding_id: str, p=Depends(current_principal), db: Session = Depends(get_db)):
    from app.worker.tasks import recheck_finding
    f = _get_owned(db, p, finding_id)
    acc = db.get(AwsAccount, f.account_id)
    if not acc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")
    recheck_finding.delay(str(acc.id), f.check_id)
    return {"queued": True, "check_id": f.check_id}
