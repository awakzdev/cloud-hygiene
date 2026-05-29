"""Digest notification helpers."""
from __future__ import annotations

import secrets


def ensure_digest_unsubscribe_token(notifications: dict) -> dict:
    out = dict(notifications)
    if out.get("email_digest_enabled") and not out.get("digest_unsubscribe_token"):
        out["digest_unsubscribe_token"] = secrets.token_urlsafe(32)
    return out


def digest_unsubscribe_token_for_org(org) -> str | None:
    notifications = (org.settings or {}).get("notifications") or {}
    return notifications.get("digest_unsubscribe_token")


def persist_digest_unsubscribe_token(db, org) -> str | None:
    """Ensure token exists when digest is enabled; persist if newly created."""
    settings = dict(org.settings or {})
    notifications = ensure_digest_unsubscribe_token(dict(settings.get("notifications") or {}))
    if notifications != settings.get("notifications"):
        settings["notifications"] = notifications
        org.settings = settings
        db.add(org)
        db.commit()
        db.refresh(org)
    return notifications.get("digest_unsubscribe_token")
