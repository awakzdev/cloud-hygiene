"""Retired 90d findings superseded by CIS 45d checks."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

from app.services.finding_supersession import (
    RETIRED_FINDING_CHECKS,
    resolve_retired_for_resource,
    resolve_retired_superseded,
)


def _open_finding(*, check_id: str, resource_arn: str = "arn:aws:iam::1:user/u#AKIAKEY"):
    f = MagicMock()
    f.id = uuid.uuid4()
    f.account_id = uuid.uuid4()
    f.check_id = check_id
    f.resource_arn = resource_arn
    f.status = "open"
    return f


def test_retired_access_key_90d_in_set():
    assert "iam.access_key.unused_90d" in RETIRED_FINDING_CHECKS


def test_resolve_retired_when_45d_check_ran():
    db = MagicMock()
    legacy = _open_finding(check_id="iam.access_key.unused_90d")
    db.scalars.return_value.all.return_value = [legacy]
    now = datetime.now(timezone.utc)
    account_id = legacy.account_id

    n = resolve_retired_superseded(
        db,
        account_id=account_id,
        now=now,
        check_ids_run={"iam.access_key.unused_45d"},
    )

    assert n == 1
    assert legacy.status == "resolved"
    assert legacy.resolved_at == now
    db.add.assert_called()


def test_skips_when_canonical_not_in_run():
    db = MagicMock()
    n = resolve_retired_superseded(
        db,
        account_id=uuid.uuid4(),
        now=datetime.now(timezone.utc),
        check_ids_run={"s3.bucket.public_read"},
    )
    assert n == 0
    db.scalars.assert_not_called()


def test_resolve_sibling_on_manual_canonical_resolve():
    db = MagicMock()
    canonical = _open_finding(check_id="iam.access_key.unused_45d")
    legacy = _open_finding(check_id="iam.access_key.unused_90d", resource_arn=canonical.resource_arn)
    db.scalars.return_value.all.return_value = [legacy]
    now = datetime.now(timezone.utc)

    n = resolve_retired_for_resource(db, canonical=canonical, now=now, actor="user@example.com")

    assert n == 1
    assert legacy.status == "resolved"
