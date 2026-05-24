"""Org-level settings: check enable/disable + notification config."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.security import current_principal
from app.models.org import Org

router = APIRouter()

# Default settings — all checks enabled, no notifications wired
DEFAULT_SETTINGS: dict = {
    "checks": {},
    "notifications": {
        "slack_enabled": False,
        "slack_webhook_url": None,
        "email_digest_enabled": False,
        "email_digest_address": None,
        "email_digest_frequency": "weekly",
    },
}


def _merged(stored: dict) -> dict:
    """Merge stored settings over defaults so missing keys get defaults."""
    merged = {**DEFAULT_SETTINGS}
    merged["checks"] = {**stored.get("checks", {})}
    merged["notifications"] = {**DEFAULT_SETTINGS["notifications"], **stored.get("notifications", {})}
    return merged


class CheckSettingIn(BaseModel):
    enabled: bool


class NotificationsIn(BaseModel):
    slack_enabled: bool = False
    slack_webhook_url: str | None = None
    email_digest_enabled: bool = False
    email_digest_address: str | None = None
    email_digest_frequency: str = "weekly"


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
