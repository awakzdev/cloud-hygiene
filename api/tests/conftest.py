"""Shared fixtures for Vigil tests."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest


def make_account(
    role_arn: str = "arn:aws:iam::123456789012:role/VigilScannerRole",
    external_id: str = "test-external-id",
    account_id: str = "123456789012",
) -> MagicMock:
    acc = MagicMock()
    acc.id = uuid.uuid4()
    acc.org_id = uuid.uuid4()
    acc.account_id = account_id
    acc.role_arn = role_arn
    acc.external_id = external_id
    acc.status = "connected"
    return acc


def now() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def account():
    return make_account()


@pytest.fixture
def mock_db():
    """SQLAlchemy Session mock. Configure .scalars().all() per test."""
    db = MagicMock()
    # default: get() returns None, scalars().all() returns []
    db.get.return_value = None
    db.scalars.return_value.all.return_value = []
    db.scalars.return_value.first.return_value = None
    return db
