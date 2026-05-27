"""Tests for sts:AssumeRole audit logging in app.core.aws.

Verifies that every assume_role call writes a row to assume_role_audit
with the right fields — success path, ClientError path, generic Exception
path. Uses an in-memory mock for boto3's STS client and a MagicMock for
the DB session.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError


@pytest.fixture
def stub_aws_account():
    acc = MagicMock()
    acc.id = uuid.uuid4()
    acc.org_id = uuid.uuid4()
    return acc


def _patched_session(rows: list) -> MagicMock:
    """Return a fake SessionLocal() whose .add captures into `rows`."""
    db = MagicMock()
    db.add.side_effect = lambda obj: rows.append(obj)
    return db


def test_assume_role_logs_success(stub_aws_account):
    """Happy path: sts.assume_role returns creds, audit row is written with success=True."""
    from app.core import aws as awsmod

    sts_client = MagicMock()
    sts_client.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "AKIA...",
            "SecretAccessKey": "secret",
            "SessionToken": "token",
            "Expiration": datetime.now(timezone.utc),
        }
    }

    rows: list = []
    with patch.object(awsmod.settings, "DEV_MODE", False), \
         patch.object(awsmod.boto3, "client", return_value=sts_client), \
         patch("app.core.aws.SessionLocal", lambda: _patched_session(rows)) if False else patch("app.core.db.SessionLocal", lambda: _patched_session(rows)), \
         patch.object(awsmod.boto3, "Session", return_value=MagicMock()):
        awsmod.assume_role(
            "arn:aws:iam::123:role/x",
            "ext-id",
            session_name="vigil-test",
            aws_account=stub_aws_account,
            purpose="unit_test",
        )

    assert len(rows) == 1
    row = rows[0]
    assert row.success is True
    assert row.role_arn == "arn:aws:iam::123:role/x"
    assert row.session_name == "vigil-test"
    assert row.purpose == "unit_test"
    assert row.aws_account_id == stub_aws_account.id
    assert row.org_id == stub_aws_account.org_id
    assert row.error_code is None
    assert row.error_message is None


def test_assume_role_logs_client_error(stub_aws_account):
    """ClientError path: audit row stores error_code + error_message; exception re-raises."""
    from app.core import aws as awsmod

    sts_client = MagicMock()
    sts_client.assume_role.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "User is not authorized"}},
        "AssumeRole",
    )

    rows: list = []
    with patch.object(awsmod.settings, "DEV_MODE", False), \
         patch.object(awsmod.boto3, "client", return_value=sts_client), \
         patch("app.core.db.SessionLocal", lambda: _patched_session(rows)):
        with pytest.raises(ClientError):
            awsmod.assume_role(
                "arn:aws:iam::123:role/x",
                "ext-id",
                session_name="vigil-test",
                aws_account=stub_aws_account,
                purpose="unit_test",
            )

    assert len(rows) == 1
    row = rows[0]
    assert row.success is False
    assert row.error_code == "AccessDenied"
    assert "not authorized" in row.error_message
    assert row.aws_account_id == stub_aws_account.id


def test_assume_role_logs_generic_exception(stub_aws_account):
    """Non-ClientError path: error_code falls back to the exception class name."""
    from app.core import aws as awsmod

    sts_client = MagicMock()
    sts_client.assume_role.side_effect = TimeoutError("STS endpoint timed out")

    rows: list = []
    with patch.object(awsmod.settings, "DEV_MODE", False), \
         patch.object(awsmod.boto3, "client", return_value=sts_client), \
         patch("app.core.db.SessionLocal", lambda: _patched_session(rows)):
        with pytest.raises(TimeoutError):
            awsmod.assume_role(
                "arn:aws:iam::123:role/x",
                "ext-id",
                session_name="vigil-test",
                aws_account=stub_aws_account,
                purpose="unit_test",
            )

    assert len(rows) == 1
    row = rows[0]
    assert row.success is False
    assert row.error_code == "TimeoutError"
    assert "timed out" in row.error_message


def test_assume_role_audit_failure_is_swallowed(stub_aws_account):
    """If the audit write itself blows up, the caller should still get its session.

    Otherwise a broken audit table would take down every scan.
    """
    from app.core import aws as awsmod

    sts_client = MagicMock()
    sts_client.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "AKIA...",
            "SecretAccessKey": "secret",
            "SessionToken": "token",
            "Expiration": datetime.now(timezone.utc),
        }
    }

    def _broken_session():
        raise RuntimeError("DB is on fire")

    with patch.object(awsmod.settings, "DEV_MODE", False), \
         patch.object(awsmod.boto3, "client", return_value=sts_client), \
         patch("app.core.db.SessionLocal", _broken_session), \
         patch.object(awsmod.boto3, "Session", return_value=MagicMock()) as boto_sess:
        result = awsmod.assume_role(
            "arn:aws:iam::123:role/x",
            "ext-id",
            session_name="vigil-test",
            aws_account=stub_aws_account,
        )

    # Caller still got a boto3.Session — audit failure didn't propagate
    assert result is boto_sess.return_value
