"""Org-level settings: notifications + automated scan schedule."""
from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.security import current_principal
from app.models.org import Org, User
from app.models import AwsAccount, Finding
from app.services.scan_schedule import (
    DEFAULT_SCANNING,
    get_scanning_settings,
    max_interval_for_plan,
    min_custom_hours_for_plan,
    next_scan_at,
    validate_scanning,
)

router = APIRouter()

DEFAULT_SETTINGS: dict = {
    "checks": {},
    "scanning": dict(DEFAULT_SCANNING),
    "notifications": {
        "email_digest_enabled": False,
        "digest_email": None,
        "slack_webhook_url": None,
        "scan_failure_email_enabled": True,
    },
}


def _merged(stored: dict) -> dict:
    merged = {**DEFAULT_SETTINGS}
    merged["checks"] = {**stored.get("checks", {})}
    merged["scanning"] = get_scanning_settings(stored)
    merged["notifications"] = {**DEFAULT_SETTINGS["notifications"], **stored.get("notifications", {})}
    return merged


class CheckSettingIn(BaseModel):
    enabled: bool


class NotificationsIn(BaseModel):
    email_digest_enabled: bool = False
    digest_email: str | None = None
    slack_webhook_url: str | None = None
    scan_failure_email_enabled: bool = True


class ScanningIn(BaseModel):
    enabled: bool = True
    interval: Literal["daily", "weekly", "custom", "manual"] = "daily"
    custom_hours: int | None = None

    @field_validator("interval")
    @classmethod
    def normalize_interval(cls, v: str) -> str:
        if v not in ("daily", "weekly", "custom", "manual"):
            raise ValueError("interval must be daily, weekly, custom, or manual")
        return v


class ScanStatusOut(BaseModel):
    account_connected: bool
    last_scan_at: str | None
    next_scan_at: str | None
    max_interval: Literal["daily", "weekly"]
    min_custom_hours: int


class SettingsPatch(BaseModel):
    checks: dict[str, CheckSettingIn] | None = None
    scanning: ScanningIn | None = None
    notifications: NotificationsIn | None = None


class SettingsOut(BaseModel):
    checks: dict
    scanning: dict
    notifications: dict
    scan_status: ScanStatusOut


def _get_org(p, db: Session) -> Org:
    org = db.get(Org, uuid.UUID(p["org_id"]))
    if not org:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "org not found")
    return org


def _scan_status(org: Org, db: Session) -> ScanStatusOut:
    acc = db.scalars(
        select(AwsAccount).where(
            AwsAccount.org_id == org.id,
            AwsAccount.status == "connected",
        )
    ).first()
    scanning = get_scanning_settings(org.settings or {})
    last = acc.last_scan_at if acc else None
    nxt = next_scan_at(last, scanning) if acc else None
    return ScanStatusOut(
        account_connected=acc is not None,
        last_scan_at=last.isoformat() if last else None,
        next_scan_at=nxt.isoformat() if nxt else None,
        max_interval=max_interval_for_plan(org.plan),
        min_custom_hours=min_custom_hours_for_plan(org.plan),
    )


@router.get("", response_model=SettingsOut)
def get_settings(p=Depends(current_principal), db: Session = Depends(get_db)):
    org = _get_org(p, db)
    merged = _merged(org.settings or {})
    return SettingsOut(**merged, scan_status=_scan_status(org, db))


@router.patch("", response_model=SettingsOut)
def patch_settings(body: SettingsPatch, p=Depends(current_principal), db: Session = Depends(get_db)):
    org = _get_org(p, db)
    current = dict(org.settings or {})

    if body.checks is not None:
        checks = dict(current.get("checks", {}))
        for check_id, cfg in body.checks.items():
            checks[check_id] = {"enabled": cfg.enabled}
        current["checks"] = checks

    if body.scanning is not None:
        payload = {
            "enabled": body.scanning.enabled,
            "interval": body.scanning.interval,
            "custom_hours": body.scanning.custom_hours,
        }
        try:
            validate_scanning(payload, org.plan)
        except ValueError as e:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e
        interval = body.scanning.interval
        enabled = body.scanning.enabled and interval != "manual"
        stored = {"enabled": enabled, "interval": interval}
        if interval == "custom":
            stored["custom_hours"] = body.scanning.custom_hours
        current["scanning"] = stored

    if body.notifications is not None:
        current["notifications"] = body.notifications.model_dump()

    org.settings = current
    db.add(org)
    db.commit()
    db.refresh(org)
    merged = _merged(org.settings)
    return SettingsOut(**merged, scan_status=_scan_status(org, db))


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


class SlackTestBody(BaseModel):
    url: str | None = None


@router.post("/test-slack", status_code=200)
def test_slack(body: SlackTestBody = SlackTestBody(), p=Depends(current_principal), db: Session = Depends(get_db)):
    """POST a test message to the configured Slack webhook URL."""
    import httpx

    org = _get_org(p, db)
    webhook_url = body.url or (org.settings or {}).get("notifications", {}).get("slack_webhook_url")
    if not webhook_url:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No Slack webhook URL configured")

    try:
        resp = httpx.post(
            webhook_url,
            json={"text": ":white_check_mark: *Vigil* — Slack notifications are working."},
            timeout=10,
        )
        if resp.status_code != 200:
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"Slack returned {resp.status_code}: {resp.text}")
    except httpx.RequestError as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"Slack request failed: {e}")

    return {"ok": True}
