import copy
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.aws import verify_account
from app.core.config import get_settings
from app.core.db import get_db
from app.core.security import current_principal
from app.models import AwsAccount, IamPermUsage, IamRole, ScanRun
from app.models.org import Org

router = APIRouter()
settings = get_settings()

CFN_TEMPLATE_URL = (
    "https://amzn-demo-cloud-hygiene.s3.amazonaws.com/hygiene-readonly-role.yaml"
)


class AccountIn(BaseModel):
    label: str = "AWS Account"


class AccountOut(BaseModel):
    id: str
    label: str
    account_id: str | None
    status: str
    external_id: str
    cfn_launch_url: str | None = None


class VerifyIn(BaseModel):
    role_arn: str


def _launch_url(external_id: str) -> str:
    params = {
        "templateURL": CFN_TEMPLATE_URL,
        "stackName": "VigilReadOnly",
        "param_ExternalId": external_id,
        "param_HygieneAccountPrincipal": settings.TRUST_PRINCIPAL_ARN,
    }
    qs = "&".join(f"{k}={quote(v, safe='')}" for k, v in params.items())
    return f"https://console.aws.amazon.com/cloudformation/home#/stacks/create/review?{qs}"


@router.post("", response_model=AccountOut, status_code=status.HTTP_201_CREATED)
def create_account(body: AccountIn, p=Depends(current_principal), db: Session = Depends(get_db)):
    if not db.get(Org, uuid.UUID(p["org_id"])):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "session expired — please sign in again")
    # MVP: one account per org
    existing = db.scalar(select(AwsAccount).where(AwsAccount.org_id == uuid.UUID(p["org_id"])))
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT, "account already exists for this org")

    ext = secrets.token_urlsafe(24)
    acc = AwsAccount(
        id=uuid.uuid4(),
        org_id=uuid.UUID(p["org_id"]),
        label=body.label,
        external_id=ext,
    )
    db.add(acc)
    db.commit()
    return AccountOut(
        id=str(acc.id),
        label=acc.label,
        account_id=acc.account_id,
        status=acc.status,
        external_id=ext,
        cfn_launch_url=_launch_url(ext),
    )


@router.get("", response_model=list[AccountOut])
def list_accounts(p=Depends(current_principal), db: Session = Depends(get_db)):
    rows = db.scalars(select(AwsAccount).where(AwsAccount.org_id == uuid.UUID(p["org_id"]))).all()
    return [
        AccountOut(
            id=str(a.id),
            label=a.label,
            account_id=a.account_id,
            status=a.status,
            external_id=a.external_id,
            cfn_launch_url=_launch_url(a.external_id),
        )
        for a in rows
    ]


@router.post("/{account_id}/verify", response_model=AccountOut)
def verify(account_id: str, body: VerifyIn, p=Depends(current_principal), db: Session = Depends(get_db)):
    acc = db.get(AwsAccount, uuid.UUID(account_id))
    if not acc or str(acc.org_id) != p["org_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")
    ok, aws_account_id, alias, err = verify_account(body.role_arn, acc.external_id)
    if not ok:
        acc.status = "error"
        acc.last_error = err
        db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"assume role failed: {err}")
    acc.role_arn = body.role_arn
    acc.account_id = aws_account_id
    acc.label = alias or aws_account_id or acc.label
    acc.status = "connected"
    acc.last_error = None
    db.commit()
    return AccountOut(
        id=str(acc.id),
        label=acc.label,
        account_id=acc.account_id,
        status=acc.status,
        external_id=acc.external_id,
        cfn_launch_url=_launch_url(acc.external_id),
    )


@router.post("/{account_id}/scan")
def trigger_scan(account_id: str, p=Depends(current_principal), db: Session = Depends(get_db)):
    from app.worker.tasks import run_scan
    acc = db.get(AwsAccount, uuid.UUID(account_id))
    if not acc or str(acc.org_id) != p["org_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")
    if acc.status != "connected":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "account not connected")
    job = run_scan.delay(str(acc.id))
    return {"job_id": job.id}


class ScanRunOut(BaseModel):
    id: str
    status: str
    started_at: str
    finished_at: str | None
    error: str | None
    findings_opened: int
    findings_resolved: int


@router.get("/{account_id}/scan-runs/latest", response_model=ScanRunOut | None)
def latest_scan_run(account_id: str, p=Depends(current_principal), db: Session = Depends(get_db)):
    acc = db.get(AwsAccount, uuid.UUID(account_id))
    if not acc or str(acc.org_id) != p["org_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")
    run = db.scalar(
        select(ScanRun)
        .where(ScanRun.account_id == acc.id)
        .order_by(ScanRun.started_at.desc())
        .limit(1)
    )
    if not run:
        return None
    return ScanRunOut(
        id=str(run.id),
        status=run.status,
        started_at=run.started_at.isoformat(),
        finished_at=run.finished_at.isoformat() if run.finished_at else None,
        error=run.error,
        findings_opened=run.findings_opened or 0,
        findings_resolved=run.findings_resolved or 0,
    )


def _clean_policy_doc(doc: dict, unused_set: set[str]) -> tuple[dict, int]:
    """Return (cleaned_doc, removed_statement_count)."""
    doc = copy.deepcopy(doc)
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]

    new_stmts = []
    removed = 0
    for stmt in stmts:
        if stmt.get("Effect", "Allow") != "Allow":
            new_stmts.append(stmt)
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        kept = [a for a in actions if a == "*" or a.split(":")[0].lower() not in unused_set]
        if not kept:
            removed += 1
            continue
        stmt["Action"] = kept if len(kept) > 1 else kept[0]
        new_stmts.append(stmt)

    doc["Statement"] = new_stmts
    return doc, removed


@router.get("/{account_id}/roles/generated-policy")
def generate_role_policy(
    account_id: str,
    role_arn: str,
    threshold_days: int = 90,
    p=Depends(current_principal),
    db: Session = Depends(get_db),
):
    acc = db.get(AwsAccount, uuid.UUID(account_id))
    if not acc or str(acc.org_id) != p["org_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")

    role = db.scalar(
        select(IamRole).where(IamRole.account_id == acc.id, IamRole.arn == role_arn)
    )
    if not role:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "role not found — run a scan first")

    usages = db.scalars(
        select(IamPermUsage).where(
            IamPermUsage.account_id == acc.id,
            IamPermUsage.principal_arn == role_arn,
        )
    ).all()

    cutoff = datetime.now(timezone.utc) - timedelta(days=threshold_days)
    unused_set = {
        u.service for u in usages
        if u.last_authenticated is None or u.last_authenticated < cutoff
    }
    used_set = {
        u.service for u in usages
        if u.last_authenticated is not None and u.last_authenticated >= cutoff
    }

    inline = role.inline_policies or {}
    if not inline:
        return {
            "role_arn": role_arn,
            "has_inline_policies": False,
            "unused_services": sorted(unused_set),
            "used_services": sorted(used_set),
            "note": "Role has no inline policies. Permissions come from attached managed policies — review with list-attached-role-policies.",
        }

    cleaned_policies: dict = {}
    total_removed = 0
    for policy_name, doc in inline.items():
        cleaned, removed = _clean_policy_doc(doc, unused_set)
        cleaned_policies[policy_name] = cleaned
        total_removed += removed

    return {
        "role_arn": role_arn,
        "has_inline_policies": True,
        "unused_services": sorted(unused_set),
        "used_services": sorted(used_set),
        "threshold_days": threshold_days,
        "statements_removed": total_removed,
        "original_policies": inline,
        "cleaned_policies": cleaned_policies,
    }
