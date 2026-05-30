from datetime import datetime, timezone

from app.core.iam_usage import (
    augment_used_actions_with_granted_for_service_only,
    remove_service_wildcards_when_specific_actions_exist,
    used_actions_from_usages,
)


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


def test_augment_preserves_granted_actions_for_service_only_usage():
    cutoff = datetime(2026, 1, 1, tzinfo=timezone.utc)
    recent = datetime(2026, 2, 1, tzinfo=timezone.utc)
    usages = [
        _usage(
            service="ec2",
            last_auth=recent,
            actions_json=[
                {"action": "ec2:DescribeInstances", "last_authenticated": "2026-02-01T00:00:00+00:00"},
            ],
        ),
        _usage(service="dynamodb", last_auth=recent, actions_json=None),
    ]
    granted = ["ec2:*", "dynamodb:PutItem", "dynamodb:GetItem", "s3:*"]

    actions, warnings = augment_used_actions_with_granted_for_service_only(
        used_actions_from_usages(usages, cutoff),
        usages,
        cutoff,
        granted,
    )

    assert "ec2:DescribeInstances" in actions
    assert "dynamodb:PutItem" in actions
    assert "dynamodb:GetItem" in actions
    assert "dynamodb:*" not in actions
    assert not any("dynamodb" in w for w in warnings)


def test_augment_preserves_service_scoped_wildcard_under_star_grant():
    # Regression: a used service granted only via "*" must not be silently dropped.
    # It is preserved as "<svc>:*" (narrower than "*") with a warning, never removed.
    cutoff = datetime(2026, 1, 1, tzinfo=timezone.utc)
    recent = datetime(2026, 2, 1, tzinfo=timezone.utc)
    usages = [_usage(service="dynamodb", last_auth=recent, actions_json=None)]

    actions, warnings = augment_used_actions_with_granted_for_service_only(
        [], usages, cutoff, ["*"]
    )

    assert actions == ["dynamodb:*"]
    assert any("dynamodb" in w for w in warnings)


def test_augment_preserves_service_scoped_wildcard_under_service_wildcard_grant():
    # The DynamoDB report: service used, only service-level evidence, granted via "dynamodb:*".
    # Must keep DynamoDB (as dynamodb:*) so the workload is not broken.
    cutoff = datetime(2026, 1, 1, tzinfo=timezone.utc)
    recent = datetime(2026, 2, 1, tzinfo=timezone.utc)
    usages = [
        _usage(
            service="ec2",
            last_auth=recent,
            actions_json=[
                {"action": "ec2:DescribeInstances", "last_authenticated": "2026-02-01T00:00:00+00:00"},
            ],
        ),
        _usage(service="dynamodb", last_auth=recent, actions_json=None),
    ]
    granted = ["ec2:*", "dynamodb:*"]

    actions, warnings = augment_used_actions_with_granted_for_service_only(
        used_actions_from_usages(usages, cutoff),
        usages,
        cutoff,
        granted,
    )

    assert "dynamodb:*" in actions
    assert "ec2:DescribeInstances" in actions
    assert any("dynamodb" in w for w in warnings)


def test_augment_warns_when_used_service_has_no_matching_grant():
    cutoff = datetime(2026, 1, 1, tzinfo=timezone.utc)
    recent = datetime(2026, 2, 1, tzinfo=timezone.utc)
    usages = [_usage(service="dynamodb", last_auth=recent, actions_json=None)]

    actions, warnings = augment_used_actions_with_granted_for_service_only(
        [], usages, cutoff, ["s3:GetObject"]
    )

    assert actions == []
    assert any("dynamodb" in w and "no matching grant" in w for w in warnings)


def test_remove_service_wildcard_when_cloudtrail_actions_exist():
    actions = [
        "cloudfront:*",
        "dynamodb:*",
        "cloudfront:GetDistribution",
        "cloudfront:ListTagsForResource",
        "dynamodb:GetItem",
        "dynamodb:PutItem",
    ]
    cleaned = remove_service_wildcards_when_specific_actions_exist(actions)
    assert "cloudfront:*" not in cleaned
    assert "dynamodb:*" not in cleaned
    assert "cloudfront:GetDistribution" in cleaned
    assert "dynamodb:GetItem" in cleaned


def test_augment_does_not_add_wildcard_when_actions_already_merged_from_cloudtrail():
    cutoff = datetime(2026, 1, 1, tzinfo=timezone.utc)
    recent = datetime(2026, 2, 1, tzinfo=timezone.utc)
    usages = [_usage(service="cloudfront", last_auth=recent, actions_json=None)]

    actions, warnings = augment_used_actions_with_granted_for_service_only(
        ["cloudfront:GetDistribution", "cloudfront:TagResource"],
        usages,
        cutoff,
        ["*"],
    )

    assert "cloudfront:*" not in actions
    assert not any("Preserved as" in w for w in warnings)
