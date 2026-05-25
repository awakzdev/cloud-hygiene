"""Org-level settings: check enable/disable + notification config."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.security import current_principal
from app.models.org import Org, User
from app.models import AwsAccount, Finding

router = APIRouter()

DEFAULT_SETTINGS: dict = {
    "checks": {},
    "notifications": {
        "email_digest_enabled": False,
        "digest_email": None,
    },
}


def _merged(stored: dict) -> dict:
    merged = {**DEFAULT_SETTINGS}
    merged["checks"] = {**stored.get("checks", {})}
    merged["notifications"] = {**DEFAULT_SETTINGS["notifications"], **stored.get("notifications", {})}
    return merged


class CheckSettingIn(BaseModel):
    enabled: bool


class NotificationsIn(BaseModel):
    email_digest_enabled: bool = False
    digest_email: str | None = None


class SettingsPatch(BaseModel):
    checks: dict[str, CheckSettingIn] | None = None
    notifications: NotificationsIn | None = None


class SettingsOut(BaseModel):
    checks: dict
    notifications: dict


def _get_org(p, db: Session) -> Org:
    org = db.get(Org, uuid.UUID(p["org_id"]))
    if not org:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "org not found")
    return org


@router.get("", response_model=SettingsOut)
def get_settings(p=Depends(current_principal), db: Session = Depends(get_db)):
    org = _get_org(p, db)
    return _merged(org.settings or {})


@router.patch("", response_model=SettingsOut)
def patch_settings(body: SettingsPatch, p=Depends(current_principal), db: Session = Depends(get_db)):
    org = _get_org(p, db)
    current = dict(org.settings or {})

    if body.checks is not None:
        checks = dict(current.get("checks", {}))
        for check_id, cfg in body.checks.items():
            checks[check_id] = {"enabled": cfg.enabled}
        current["checks"] = checks

    if body.notifications is not None:
        current["notifications"] = body.notifications.model_dump()

    org.settings = current
    db.add(org)
    db.commit()
    db.refresh(org)
    return _merged(org.settings)


@router.post("/test-digest", status_code=200)
def test_digest(p=Depends(current_principal), db: Session = Depends(get_db)):
    """Fire a digest email immediately to the configured address (or current user)."""
    from app.services.digest import send_digest
    from datetime import datetime, timedelta, timezone

    org = _get_org(p, db)
    org_settings = org.settings or {}
    digest_email = org_settings.get("notifications", {}).get("digest_email")

    if not digest_email:
        user = db.get(User, uuid.UUID(p["sub"]))
        if not user or not user.email:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "No recipient email configured")
        digest_email = user.email

    acc = db.scalars(
        select(AwsAccount).where(
            AwsAccount.org_id == org.id,
            AwsAccount.status == "connected",
        )
    ).first()

    if not acc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No connected AWS account")

    since = datetime.now(timezone.utc) - timedelta(days=7)

    open_findings = db.scalars(
        select(Finding).where(
            Finding.account_id == acc.id,
            Finding.status == "open",
        ).order_by(Finding.risk_score.desc())
    ).all()

    new_this_week = db.scalars(
        select(Finding).where(
            Finding.account_id == acc.id,
            Finding.first_seen >= since,
        )
    ).all()

    from sqlalchemy import func as sa_func
    resolved_count = db.scalar(
        select(sa_func.count()).select_from(
            select(Finding).where(
                Finding.account_id == acc.id,
                Finding.status == "resolved",
                Finding.last_seen >= since,
            ).subquery()
        )
    ) or 0

    ok = send_digest(
        to=digest_email,
        org_name=org.name if hasattr(org, "name") else str(org.id),
        account_label=acc.label,
        open_findings=[
            {"title": f.title, "severity": f.severity, "risk_score": f.risk_score, "resource_arn": f.resource_arn, "check_id": f.check_id}
            for f in open_findings
        ],
        new_this_week=[{"title": f.title, "severity": f.severity} for f in new_this_week],
        resolved_this_week=resolved_count,
    )

    if not ok:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Failed to send email — check RESEND_API_KEY")

    return {"sent_to": digest_email}
