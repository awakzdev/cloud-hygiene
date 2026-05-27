"""Helpers for IAM service/action last-accessed data."""
from __future__ import annotations

from datetime import datetime, timezone

from app.models import IamPermUsage


def _parse_dt(value) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    return None


def _normalize_action(action: str, service: str) -> str:
    if ":" in action:
        return action
    svc = (service or "").lower()
    return f"{svc}:{action}" if svc else action


def used_actions_from_usages(usages: list[IamPermUsage], cutoff: datetime) -> list[str]:
    """Return distinct action names used on or after cutoff (preserves AWS casing)."""
    seen: dict[str, str] = {}
    for u in usages:
        for entry in u.actions_json or []:
            if isinstance(entry, str):
                if u.last_authenticated and u.last_authenticated >= cutoff:
                    action = _normalize_action(entry, u.service)
                    key = action.lower()
                    seen.setdefault(key, action)
                continue
            if not isinstance(entry, dict):
                continue
            action = entry.get("action")
            if not action:
                continue
            action = _normalize_action(action, u.service)
            la = _parse_dt(entry.get("last_authenticated"))
            if la is None or la < cutoff:
                continue
            key = action.lower()
            seen.setdefault(key, action)
    return sorted(seen.values(), key=str.lower)


def used_services_from_usages(usages: list[IamPermUsage], cutoff: datetime) -> set[str]:
    return {
        u.service for u in usages
        if u.last_authenticated is not None and u.last_authenticated >= cutoff
    }


def unused_services_from_usages(usages: list[IamPermUsage], cutoff: datetime) -> set[str]:
    return {
        u.service for u in usages
        if u.last_authenticated is None or u.last_authenticated < cutoff
    }
