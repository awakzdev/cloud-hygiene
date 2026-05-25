import base64
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select, func
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


class FindingPage(BaseModel):
    items: list[FindingOut]
    total: int
    next_cursor: str | None


def _encode_cursor(risk_score: int, id: uuid.UUID) -> str:
    return base64.urlsafe_b64encode(f"{risk_score}:{id}".encode()).decode()


def _decode_cursor(cursor: str) -> tuple[int, uuid.UUID]:
    raw = base64.urlsafe_b64decode(cursor.encode()).decode()
    score_s, id_s = raw.split(":", 1)
    return int(score_s), uuid.UUID(id_s)


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


@router.get("", response_model=FindingPage)
def list_findings(
    status_filter: str | None = Query(default="open", alias="status"),
    severity: str | None = None,
    check_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    cursor: str | None = Query(default=None),
    p=Depends(current_principal),
    db: Session = Depends(get_db),
):
    org_id = uuid.UUID(p["org_id"])
    base_q = select(Finding).where(Finding.org_id == org_id)
    if status_filter and status_filter != "all":
        base_q = base_q.where(Finding.status == status_filter)
    if severity:
        base_q = base_q.where(Finding.severity == severity)
    if check_id:
        base_q = base_q.where(Finding.check_id == check_id)

    total = db.scalar(select(func.count()).select_from(base_q.subquery()))

    q = base_q.order_by(Finding.risk_score.desc(), Finding.id.desc())
    if cursor:
        try:
            cur_score, cur_id = _decode_cursor(cursor)
            q = q.where(
                (Finding.risk_score < cur_score)
                | ((Finding.risk_score == cur_score) & (Finding.id < cur_id))
            )
        except Exception:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid cursor")

    rows = db.scalars(q.limit(limit + 1)).all()
    has_more = len(rows) > limit
    items = rows[:limit]
    next_cursor = _encode_cursor(items[-1].risk_score, items[-1].id) if has_more and items else None

    return FindingPage(items=[_to_out(f) for f in items], total=total, next_cursor=next_cursor)


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
