"""Per-org automated scan scheduling."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AwsAccount, ScanRun

ScanInterval = Literal["daily", "weekly", "custom", "manual"]

DEFAULT_SCANNING: dict = {
    "enabled": True,
    "interval": "daily",
    "custom_hours": None,
}

_INTERVAL_HOURS: dict[str, int] = {
    "daily": 24,
    "weekly": 24 * 7,
}

MIN_CUSTOM_HOURS_PAID = 6
MAX_CUSTOM_HOURS = 24 * 30
MIN_CUSTOM_HOURS_FREE = 24 * 7


def min_custom_hours_for_plan(plan: str) -> int:
    if plan == "free":
        return MIN_CUSTOM_HOURS_FREE
    return MIN_CUSTOM_HOURS_PAID


def get_scanning_settings(org_settings: dict | None) -> dict:
    stored = (org_settings or {}).get("scanning") or {}
    interval = stored.get("interval", DEFAULT_SCANNING["interval"])
    if interval not in (*_INTERVAL_HOURS.keys(), "custom", "manual"):
        interval = DEFAULT_SCANNING["interval"]
    enabled = stored.get("enabled", DEFAULT_SCANNING["enabled"])
    if interval == "manual":
        enabled = False
    result: dict = {"enabled": bool(enabled), "interval": interval}
    if interval == "custom":
        raw = stored.get("custom_hours", 24)
        try:
            result["custom_hours"] = int(raw)
        except (TypeError, ValueError):
            result["custom_hours"] = 24
    else:
        result["custom_hours"] = None
    return result


def max_interval_for_plan(plan: str) -> Literal["daily", "weekly"]:
    if plan == "free":
        return "weekly"
    return "daily"


def interval_hours(scanning: dict) -> int | None:
    if not scanning.get("enabled", True):
        return None
    interval = scanning.get("interval", "daily")
    if interval == "manual":
        return None
    if interval == "custom":
        return int(scanning.get("custom_hours") or 24)
    return _INTERVAL_HOURS.get(interval)


def validate_scanning(scanning: dict, plan: str) -> None:
    enabled = scanning.get("enabled", True)
    interval = scanning.get("interval", "daily")
    if not enabled or interval == "manual":
        return
    if interval == "custom":
        hours = scanning.get("custom_hours")
        if not isinstance(hours, int):
            raise ValueError("custom_hours is required for custom scan interval")
        if hours < min_custom_hours_for_plan(plan) or hours > MAX_CUSTOM_HOURS:
            raise ValueError(
                f"custom_hours must be between {min_custom_hours_for_plan(plan)} and {MAX_CUSTOM_HOURS}"
            )
        return
    if interval not in ("daily", "weekly"):
        raise ValueError("interval must be daily, weekly, custom, or manual")
    allowed = max_interval_for_plan(plan)
    if interval == "daily" and allowed == "weekly":
        raise ValueError("Daily automated scans require a paid plan")


def effective_interval(scanning: dict) -> ScanInterval:
    if not scanning.get("enabled", True):
        return "manual"
    interval = scanning.get("interval", "daily")
    if interval == "manual":
        return "manual"
    return interval  # type: ignore[return-value]


def is_scan_due(
    last_scan_at: datetime | None,
    scanning: dict,
    now: datetime | None = None,
) -> bool:
    hours = interval_hours(scanning)
    if hours is None:
        return False
    now = now or datetime.now(timezone.utc)
    if last_scan_at is None:
        return True
    if last_scan_at.tzinfo is None:
        last_scan_at = last_scan_at.replace(tzinfo=timezone.utc)
    return (now - last_scan_at) >= timedelta(hours=hours)


def next_scan_at(
    last_scan_at: datetime | None,
    scanning: dict,
    now: datetime | None = None,
) -> datetime | None:
    hours = interval_hours(scanning)
    if hours is None:
        return None
    now = now or datetime.now(timezone.utc)
    if last_scan_at is None:
        return now
    if last_scan_at.tzinfo is None:
        last_scan_at = last_scan_at.replace(tzinfo=timezone.utc)
    return last_scan_at + timedelta(hours=hours)


def has_running_scan(db: Session, account_id, *, max_age_minutes: int = 30) -> bool:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=max_age_minutes)
    row = db.scalar(
        select(ScanRun.id)
        .where(ScanRun.account_id == account_id)
        .where(ScanRun.status == "running")
        .where(ScanRun.started_at >= cutoff)
        .limit(1)
    )
    return row is not None


def should_queue_automated_scan(
    acc: AwsAccount,
    scanning: dict,
    db: Session,
    now: datetime | None = None,
) -> bool:
    if acc.status != "connected":
        return False
    if not is_scan_due(acc.last_scan_at, scanning, now):
        return False
    if has_running_scan(db, acc.id):
        return False
    return True
