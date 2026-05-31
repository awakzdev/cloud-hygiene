"""Unauthenticated public endpoints (token-based actions only)."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Header, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.models.org import Org
from app.services.remediation_execution_store import record_execution_result

router = APIRouter()


class RemediationExecutionIn(BaseModel):
    plan_id: str
    content_sha256: str
    result: dict


@router.post("/remediation-execution")
def remediation_execution_webhook(
    body: RemediationExecutionIn,
    x_vigil_content_sha256: str | None = Header(default=None, alias="X-Vigil-Content-Sha256"),
    db: Session = Depends(get_db),
):
    """Execution callback: record outcome keyed by plan_id (verified via content_sha256)."""
    if not x_vigil_content_sha256 or x_vigil_content_sha256 != body.content_sha256:
        raise HTTPException(status_code=401, detail="content_sha256 header mismatch")
    row = record_execution_result(
        db,
        plan_id=body.plan_id,
        content_sha256=body.content_sha256,
        result=body.result,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Unknown plan_id or checksum mismatch")
    return {"status": "recorded", "plan_id": row.plan_id, "execution_status": row.status}


def _find_org_by_digest_token(db: Session, token: str) -> Org | None:
    if not token or len(token) < 16:
        return None
    for org in db.scalars(select(Org)).all():
        notifications = (org.settings or {}).get("notifications") or {}
        if notifications.get("digest_unsubscribe_token") == token:
            return org
    return None


@router.get("/digest/unsubscribe", response_class=HTMLResponse)
def unsubscribe_digest(
    token: str = Query(..., min_length=16),
    db: Session = Depends(get_db),
):
    """One-click weekly digest unsubscribe via signed URL token in email."""
    org = _find_org_by_digest_token(db, token)
    if not org:
        raise HTTPException(status_code=404, detail="Invalid or expired unsubscribe link")

    settings = dict(org.settings or {})
    notifications = dict(settings.get("notifications") or {})
    notifications["email_digest_enabled"] = False
    settings["notifications"] = notifications
    org.settings = settings
    db.add(org)
    db.commit()

    return HTMLResponse(
        """<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Unsubscribed — Vigil</title>
<style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1.5rem;color:#18181b}
h1{font-size:1.25rem}p{color:#52525b;line-height:1.5}</style></head>
<body>
<h1>Weekly digest turned off</h1>
<p>You will no longer receive Vigil weekly security digests for this organization.
Re-enable anytime under Settings → Notifications.</p>
</body></html>"""
    )
