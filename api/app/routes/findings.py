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
from app.models.org import Org
from app.services.check_settings import hidden_check_ids

router = APIRouter()


class FindingOut(BaseModel):
    id: str
    account_id: str
    check_id: str
    resource_arn: str
    title: str
    severity: str
    risk_score: int
    status: str
    evidence: dict
    first_seen: datetime
    last_seen: datetime
    exception_reason: str | None = None
    exception_approved_by: str | None = None
    exception_expires_at: datetime | None = None

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
    verified: bool = False


class ExceptionIn(BaseModel):
    reason: str
    approved_by: str
    expires_at: datetime | None = None


def _to_out(f: Finding) -> FindingOut:
    return FindingOut(
        id=str(f.id),
        account_id=str(f.account_id),
        check_id=f.check_id,
        resource_arn=f.resource_arn,
        title=f.title,
        severity=f.severity,
        risk_score=f.risk_score,
        status=f.status,
        evidence=f.evidence,
        first_seen=f.first_seen,
        last_seen=f.last_seen,
        exception_reason=f.exception_reason,
        exception_approved_by=f.exception_approved_by,
        exception_expires_at=f.exception_expires_at,
    )


@router.get("", response_model=FindingPage)
def list_findings(
    status_filter: str | None = Query(default="open", alias="status"),
    severity: str | None = None,
    check_id: str | None = None,
    account_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    cursor: str | None = Query(default=None),
    p=Depends(current_principal),
    db: Session = Depends(get_db),
):
    org_id = uuid.UUID(p["org_id"])
    org = db.get(Org, org_id)
    hidden = hidden_check_ids(org.settings if org else {})

    base_q = select(Finding).where(Finding.org_id == org_id)
    if hidden:
        base_q = base_q.where(Finding.check_id.notin_(hidden))
    if status_filter and status_filter != "all":
        base_q = base_q.where(Finding.status == status_filter)
    if severity:
        base_q = base_q.where(Finding.severity == severity)
    if check_id:
        base_q = base_q.where(Finding.check_id == check_id)
    if account_id:
        base_q = base_q.where(Finding.account_id == uuid.UUID(account_id))

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
    if not body.verified:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Confirm verification before resolving (re-scan or manual check)",
        )
    f = _get_owned(db, p, finding_id)
    f.status = "resolved"
    f.resolved_at = datetime.now(timezone.utc)
    db.add(FindingEvent(id=uuid.uuid4(), finding_id=f.id, action="resolved", actor=p["sub"], note=body.note))
    db.commit()
    return _to_out(f)


@router.post("/{finding_id}/reopen", response_model=FindingOut)
def reopen(finding_id: str, p=Depends(current_principal), db: Session = Depends(get_db)):
    f = _get_owned(db, p, finding_id)
    if f.status not in ("resolved", "ignored"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "only resolved or ignored findings can be reopened")
    f.status = "open"
    f.resolved_at = None
    f.snooze_until = None
    db.add(FindingEvent(id=uuid.uuid4(), finding_id=f.id, action="reopened", actor=p["sub"]))
    db.commit()
    return _to_out(f)


@router.post("/{finding_id}/ignore", response_model=FindingOut)
def ignore(finding_id: str, p=Depends(current_principal), db: Session = Depends(get_db)):
    f = _get_owned(db, p, finding_id)
    f.status = "ignored"
    db.add(FindingEvent(id=uuid.uuid4(), finding_id=f.id, action="ignored", actor=p["sub"]))
    db.commit()
    return _to_out(f)


@router.post("/{finding_id}/exception", response_model=FindingOut)
def create_exception(finding_id: str, body: ExceptionIn, p=Depends(current_principal), db: Session = Depends(get_db)):
    f = _get_owned(db, p, finding_id)
    f.status = "excepted"
    f.exception_reason = body.reason
    f.exception_approved_by = body.approved_by
    f.exception_expires_at = body.expires_at
    db.add(FindingEvent(
        id=uuid.uuid4(),
        finding_id=f.id,
        action="excepted",
        actor=p["sub"],
        note=f"Approved by {body.approved_by}: {body.reason}",
    ))
    db.commit()
    return _to_out(f)


@router.get("/{finding_id}/remediation-plan")
def remediation_plan(finding_id: str, p=Depends(current_principal), db: Session = Depends(get_db)):
    """Customer-hosted remediation plan preview (no execution)."""
    from app.services.remediation_plan import build_remediation_plan

    f = _get_owned(db, p, finding_id)
    return build_remediation_plan(f)


@router.get("/{finding_id}/iac-snippets")
def iac_snippets(finding_id: str, p=Depends(current_principal), db: Session = Depends(get_db)):
    """Deterministic Terraform / CLI snippets (Phase 1 — not automatic PR)."""
    from app.services.iac_snippets import build_iac_remediation

    f = _get_owned(db, p, finding_id)
    return build_iac_remediation(db, f, uuid.UUID(p["org_id"]))


class TerraformPrIn(BaseModel):
    repo_full_name: str
    file_path: str = "vigil/remediation.tf"
    base_branch: str | None = None


@router.post("/{finding_id}/iac/terraform-pr")
def create_terraform_pr_route(
    finding_id: str,
    body: TerraformPrIn,
    p=Depends(current_principal),
    db: Session = Depends(get_db),
):
    """Open a GitHub PR with repo-aware HCL patch + terraform validate."""
    from app.services.terraform_pr import build_terraform_pr

    f = _get_owned(db, p, finding_id)
    try:
        return build_terraform_pr(
            db,
            finding=f,
            org_id=uuid.UUID(p["org_id"]),
            repo_full_name=body.repo_full_name,
            file_path=body.file_path,
            base_branch=body.base_branch,
        )
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e


class TerraformRepoScanIn(BaseModel):
    repo_full_name: str
    base_branch: str | None = None


@router.post("/{finding_id}/iac/repo-scan")
def terraform_repo_scan(
    finding_id: str,
    body: TerraformRepoScanIn,
    p=Depends(current_principal),
    db: Session = Depends(get_db),
):
    """Scan connected repo .tf/.hcl for resources matching this finding."""
    from app.services.terraform_pr import scan_repo_for_finding

    f = _get_owned(db, p, finding_id)
    try:
        return scan_repo_for_finding(
            db,
            finding=f,
            org_id=uuid.UUID(p["org_id"]),
            repo_full_name=body.repo_full_name,
            base_branch=body.base_branch,
        )
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e


@router.get("/{finding_id}/remediation-execution")
def get_remediation_execution(finding_id: str, p=Depends(current_principal), db: Session = Depends(get_db)):
    """Latest execution record for a finding (by most recent dispatch)."""
    from sqlalchemy import select

    from app.models.remediation_execution import RemediationExecution

    f = _get_owned(db, p, finding_id)
    row = db.scalar(
        select(RemediationExecution)
        .where(RemediationExecution.finding_id == f.id)
        .order_by(RemediationExecution.dispatched_at.desc())
        .limit(1)
    )
    if not row:
        return {"status": "none"}
    return {
        "plan_id": row.plan_id,
        "status": row.status,
        "dispatched_at": row.dispatched_at.isoformat() if row.dispatched_at else None,
        "completed_at": row.completed_at.isoformat() if row.completed_at else None,
        "result": row.result_json,
        "error": row.error,
    }


@router.post("/{finding_id}/remediation/dispatch")
def remediation_dispatch(finding_id: str, p=Depends(current_principal), db: Session = Depends(get_db)):
    """Approve and start customer-hosted SSM Automation when scoped permissions are enabled."""
    from app.services.remediation_dispatch import build_remediation_dispatch

    f = _get_owned(db, p, finding_id)
    approved_by = p.get("sub") or p.get("email") or "unknown"
    return build_remediation_dispatch(
        f,
        approved_by=str(approved_by),
        db=db,
        org_id=uuid.UUID(p["org_id"]),
    )


@router.post("/{finding_id}/recheck")
def recheck(finding_id: str, p=Depends(current_principal), db: Session = Depends(get_db)):
    from app.worker.tasks import recheck_finding
    f = _get_owned(db, p, finding_id)
    acc = db.get(AwsAccount, f.account_id)
    if not acc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")
    recheck_finding.delay(str(acc.id), f.check_id)
    return {"queued": True, "check_id": f.check_id}
