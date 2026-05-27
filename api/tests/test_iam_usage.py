from datetime import datetime, timezone

from app.core.iam_usage import used_actions_from_usages


def _usage(*, service="ec2", last_auth=None, actions_json=None):
    u = type("Usage", (), {})()
    u.service = service
    u.last_authenticated = last_auth
    u.actions_json = actions_json
    return u


def test_used_actions_from_dict_entries_respects_cutoff():
    cutoff = datetime(2026, 1, 1, tzinfo=timezone.utc)
    usages = [
        _usage(
            actions_json=[
                {"action": "ec2:DescribeInstances", "last_authenticated": "2026-02-01T00:00:00+00:00"},
                {"action": "ec2:RunInstances", "last_authenticated": "2025-12-01T00:00:00+00:00"},
            ],
        ),
    ]

    actions = used_actions_from_usages(usages, cutoff)

    assert actions == ["ec2:DescribeInstances"]


def test_used_actions_normalizes_service_prefix():
    cutoff = datetime(2026, 1, 1, tzinfo=timezone.utc)
    usages = [
        _usage(
            service="ec2",
            actions_json=[
                {"action": "DescribeInstances", "last_authenticated": "2026-02-01T00:00:00+00:00"},
            ],
        ),
    ]

    actions = used_actions_from_usages(usages, cutoff)

    assert actions == ["ec2:DescribeInstances"]


def test_used_actions_from_legacy_strings_uses_service_window():
    cutoff = datetime(2026, 1, 1, tzinfo=timezone.utc)
    recent = datetime(2026, 2, 1, tzinfo=timezone.utc)
    stale = datetime(2025, 12, 1, tzinfo=timezone.utc)
    usages = [
        _usage(last_auth=recent, actions_json=["ec2:DescribeInstances"]),
        _usage(last_auth=stale, actions_json=["s3:GetObject"]),
    ]

    actions = used_actions_from_usages(usages, cutoff)

    assert actions == ["ec2:DescribeInstances"]
