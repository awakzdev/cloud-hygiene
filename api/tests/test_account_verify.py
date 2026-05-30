"""Role verify must not demote an established connected account on failure."""

from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.routes.accounts import _heal_established_account_after_failed_reverify, verify


@pytest.fixture
def connected_acc():
    acc = MagicMock()
    acc.id = uuid4()
    acc.org_id = uuid4()
    acc.status = "connected"
    acc.role_arn = "arn:aws:iam::123456789012:role/VigilReadOnlyScannerRole"
    acc.account_id = "123456789012"
    acc.external_id = "ext-1"
    acc.last_error = None
    return acc


def test_heal_error_with_role_and_account_id():
    acc = MagicMock(status="error", account_id="123", role_arn="arn:aws:iam::123:role/X")
    assert _heal_established_account_after_failed_reverify(acc) is True
    assert acc.status == "connected"


@patch("app.routes.accounts.verify_account", return_value=(False, None, None, "AccessDenied"))
def test_verify_failure_keeps_connected_status(mock_verify, connected_acc):
    db = MagicMock()
    db.get.return_value = connected_acc
    bad_arn = "arn:aws:iam::999999999999:role/VigilReadOnlyss"
    body = MagicMock(role_arn=bad_arn)

    with pytest.raises(HTTPException):
        verify(str(connected_acc.id), body, p={"org_id": str(connected_acc.org_id)}, db=db)

    assert connected_acc.status == "connected"
    assert connected_acc.role_arn == "arn:aws:iam::123456789012:role/VigilReadOnlyScannerRole"
    assert connected_acc.last_error is None
    assert body.role_arn != connected_acc.role_arn
    db.commit.assert_called()


@patch("app.core.aws.assume_role")
def test_verify_account_requires_real_assume_role(mock_assume):
    from botocore.exceptions import ClientError

    from app.core.aws import verify_account

    mock_assume.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "not authorized"}},
        "AssumeRole",
    )
    ok, account_id, alias, err = verify_account(
        "arn:aws:iam::123456789012:role/VigilReadOnlysss",
        "ext-1",
    )
    assert ok is False
    assert account_id is None
    assert alias is None
    assert err is not None
    mock_assume.assert_called_once()
    assert mock_assume.call_args.kwargs["strict"] is True


@patch("app.worker.tasks.run_scan.delay")
@patch("app.routes.accounts.apply_capability_verification", return_value={})
@patch("app.routes.accounts.verify_account", return_value=(True, "123456789012", "MyAcct", None))
def test_verify_role_update_does_not_auto_scan(mock_verify, mock_apply, mock_delay, connected_acc):
    db = MagicMock()
    db.get.return_value = connected_acc
    body = MagicMock(role_arn="arn:aws:iam::123456789012:role/VigilReadOnlyScannerRole")

    from app.routes.accounts import verify

    verify(str(connected_acc.id), body, p={"org_id": str(connected_acc.org_id)}, db=db)

    mock_delay.assert_not_called()


@patch("app.worker.tasks.run_scan.delay")
@patch("app.routes.accounts.apply_capability_verification", return_value={})
@patch("app.routes.accounts.verify_account", return_value=(True, "123456789012", "MyAcct", None))
def test_verify_first_connect_still_auto_scans(mock_verify, mock_apply, mock_delay):
    acc = MagicMock()
    acc.id = uuid4()
    acc.org_id = uuid4()
    acc.status = "pending"
    acc.role_arn = None
    acc.account_id = None
    acc.external_id = "ext-1"
    acc.last_error = None
    acc.label = "New"

    db = MagicMock()
    db.get.return_value = acc
    body = MagicMock(role_arn="arn:aws:iam::123456789012:role/VigilReadOnlyScannerRole")

    from app.routes.accounts import verify

    verify(str(acc.id), body, p={"org_id": str(acc.org_id)}, db=db)

    mock_delay.assert_called_once_with(str(acc.id))
