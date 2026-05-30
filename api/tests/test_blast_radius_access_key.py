"""Blast-radius handler for IAM access key findings."""
from __future__ import annotations

import uuid
from unittest.mock import MagicMock

from app.routes.accounts import blast_radius


def _access_key(
    *,
    key_id: str = "AKIAEXAMPLE",
    user_arn: str = "arn:aws:iam::123456789012:user/jane",
    last_used=None,
):
    key = MagicMock()
    key.key_id = key_id
    key.user_arn = user_arn
    key.last_used = last_used
    key.last_used_service = None
    key.last_used_region = None
    key.status = "Active"
    return key


def test_blast_radius_access_key_composite_resource_arn():
    """iam.access_key.unused_90d stores resource_arn as {user_arn}#{key_id}."""
    acc_id = uuid.uuid4()
    org_id = uuid.uuid4()
    acc = MagicMock()
    acc.id = acc_id
    acc.org_id = org_id

    target = _access_key()
    other = _access_key(key_id="AKIAOTHER")

    db = MagicMock()
    db.get.return_value = acc
    db.scalars.return_value.all.return_value = [target, other]

    result = blast_radius(
        str(acc_id),
        f"{target.user_arn}#{target.key_id}",
        "iam.access_key.unused_90d",
        p={"org_id": str(org_id)},
        db=db,
    )

    assert result["resource_type"] == "iam_access_key"
    assert len(result["keys"]) == 1
    assert result["keys"][0]["key_id"] == "AKIAEXAMPLE"


def test_blast_radius_access_key_user_arn_only():
    """iam.access_key.no_rotation_90d and multiple_active use user_arn only."""
    acc_id = uuid.uuid4()
    org_id = uuid.uuid4()
    acc = MagicMock()
    acc.id = acc_id
    acc.org_id = org_id

    keys = [_access_key(key_id="AKIAONE"), _access_key(key_id="AKIATWO")]

    db = MagicMock()
    db.get.return_value = acc
    db.scalars.return_value.all.return_value = keys

    result = blast_radius(
        str(acc_id),
        "arn:aws:iam::123456789012:user/jane",
        "iam.access_key.no_rotation_90d",
        p={"org_id": str(org_id)},
        db=db,
    )

    assert result["resource_type"] == "iam_access_key"
    assert len(result["keys"]) == 2
