from datetime import datetime, timedelta, timezone

import pytest

from app.services.scan_schedule import (
    get_scanning_settings,
    interval_hours,
    is_scan_due,
    max_interval_for_plan,
    min_custom_hours_for_plan,
    next_scan_at,
    validate_scanning,
)


def test_default_scanning_settings():
    assert get_scanning_settings({}) == {
        "enabled": True,
        "interval": "daily",
        "custom_hours": None,
    }


def test_manual_interval_disables():
    assert get_scanning_settings({"scanning": {"enabled": True, "interval": "manual"}}) == {
        "enabled": False,
        "interval": "manual",
        "custom_hours": None,
    }


def test_custom_interval_settings():
    assert get_scanning_settings({"scanning": {"enabled": True, "interval": "custom", "custom_hours": 48}}) == {
        "enabled": True,
        "interval": "custom",
        "custom_hours": 48,
    }


def test_interval_hours_custom():
    assert interval_hours({"enabled": True, "interval": "custom", "custom_hours": 12}) == 12


def test_is_scan_due_never_scanned():
    scanning = {"enabled": True, "interval": "daily", "custom_hours": None}
    assert is_scan_due(None, scanning)


def test_is_scan_due_daily_not_yet():
    scanning = {"enabled": True, "interval": "daily", "custom_hours": None}
    now = datetime(2026, 5, 27, 12, 0, tzinfo=timezone.utc)
    last = now - timedelta(hours=12)
    assert not is_scan_due(last, scanning, now)


def test_is_scan_due_daily_yes():
    scanning = {"enabled": True, "interval": "daily", "custom_hours": None}
    now = datetime(2026, 5, 27, 12, 0, tzinfo=timezone.utc)
    last = now - timedelta(hours=25)
    assert is_scan_due(last, scanning, now)


def test_is_scan_due_custom():
    scanning = {"enabled": True, "interval": "custom", "custom_hours": 48}
    now = datetime(2026, 5, 27, 12, 0, tzinfo=timezone.utc)
    last = now - timedelta(hours=49)
    assert is_scan_due(last, scanning, now)


def test_is_scan_due_manual_never():
    scanning = {"enabled": False, "interval": "daily", "custom_hours": None}
    assert not is_scan_due(None, scanning)


def test_next_scan_at_manual():
    assert next_scan_at(None, {"enabled": False, "interval": "daily", "custom_hours": None}) is None


def test_plan_gating():
    assert max_interval_for_plan("free") == "weekly"
    assert max_interval_for_plan("trial") == "daily"
    assert min_custom_hours_for_plan("free") == 168
    assert min_custom_hours_for_plan("trial") == 6


def test_validate_daily_on_free_raises():
    with pytest.raises(ValueError, match="paid plan"):
        validate_scanning({"enabled": True, "interval": "daily", "custom_hours": None}, "free")


def test_validate_weekly_on_free_ok():
    validate_scanning({"enabled": True, "interval": "weekly", "custom_hours": None}, "free")


def test_validate_custom_too_short_on_free():
    with pytest.raises(ValueError, match="custom_hours"):
        validate_scanning({"enabled": True, "interval": "custom", "custom_hours": 24}, "free")


def test_validate_custom_ok_on_trial():
    validate_scanning({"enabled": True, "interval": "custom", "custom_hours": 12}, "trial")
