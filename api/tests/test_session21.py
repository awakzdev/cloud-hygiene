"""Session 21: identity blast-radius helpers."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

from app.services.blast_radius_identity import _parse_identity_arn, blast_radius_identity


def test_parse_identity_arn_github_user():
    ptype, first, second = _parse_identity_arn("github://acme-corp/alice")
    assert ptype == "github"
    assert first == "acme-corp"
    assert second == "alice"


def test_parse_identity_arn_github_org():
    ptype, first, second = _parse_identity_arn("github://org/acme-corp")
    assert ptype == "github"
    assert first == "org"
    assert second == "acme-corp"


def test_blast_radius_identity_no_provider():
    acc = MagicMock()
    acc.org_id = uuid.uuid4()
    db = MagicMock()
    db.scalars.return_value.all.return_value = []

    out = blast_radius_identity(
        db,
        acc,
        "github.org.mfa_not_enforced",
        "github://org/acme",
        now=datetime.now(timezone.utc),
    )
    assert out["resource_type"] == "identity_provider"
    assert "No identity provider" in out["warnings"][0]
