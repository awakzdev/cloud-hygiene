"""Tests for generated-policy advanced auto-enable and metadata."""
from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

from app.routes.accounts import _policy_generation_meta
from app.services.policy_generation_messages import POLICY_GEN_NO_JOB_NOTE


def test_policy_generation_meta_medium_note_without_cloudtrail_job():
    db = MagicMock()
    db.scalars.return_value.all.return_value = []

    meta = _policy_generation_meta(
        db,
        uuid.uuid4(),
        threshold_days=90,
        advanced=True,
        advanced_requested=False,
        has_action_data=True,
        aa={"available": False, "reason": "no_generation", "note": POLICY_GEN_NO_JOB_NOTE},
    )

    assert meta["confidence"] == "medium"
    assert "Start CloudTrail analysis" in meta["confidence_note"]
    assert meta["advanced_requested"] is False
    assert meta["advanced_effective"] is True
    assert meta["advanced_available"] is True
    assert meta["access_analyzer"]["reason"] == "no_generation"


@patch("app.routes.accounts._resolve_advanced_policy_generation")
def test_use_advanced_auto_enabled_when_deployed(mock_resolve):
    from app.routes.accounts import generate_role_policy

    mock_resolve.return_value = {"available": False, "reason": "no_generation", "note": "none yet"}

    acc = MagicMock()
    acc.id = uuid.uuid4()
    acc.org_id = uuid.uuid4()
    acc.enable_advanced_policy_generation = False
    acc.advanced_policy_generation_deployed = True
    acc.role_arn = "arn:aws:iam::123456789012:role/VigilScannerRole"
    acc.external_id = "ext"

    role = MagicMock()
    role.inline_policies = {}

    db = MagicMock()
    db.get.return_value = acc
    db.scalar.return_value = role
    db.scalars.return_value.all.return_value = []

    principal = {"org_id": str(acc.org_id)}

    generate_role_policy(
        account_id=str(acc.id),
        role_arn="arn:aws:iam::123456789012:role/CCLabAdminRole",
        threshold_days=90,
        advanced=False,
        p=principal,
        db=db,
    )

    mock_resolve.assert_called_once()
