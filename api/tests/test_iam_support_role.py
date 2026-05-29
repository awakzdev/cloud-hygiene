import uuid
from unittest.mock import MagicMock

from app.checks.iam_support_role import CHECK_ID, run


def _role(name: str, attached=None, inline=None):
    r = MagicMock()
    r.name = name
    r.attached_policies = attached or []
    r.inline_policies = inline or {}
    return r


def test_passes_when_support_role_exists(mock_db):
    acc_id = uuid.uuid4()
    acc = MagicMock()
    acc.account_id = "123456789012"
    mock_db.get.return_value = acc
    mock_db.scalars.return_value.all.return_value = [
        _role("SupportRole", attached=[{"policy_arn": "arn:aws:iam::aws:policy/AWSSupportAccess"}]),
    ]
    assert run(mock_db, acc_id) == []


def test_fails_when_no_support_role(mock_db):
    acc_id = uuid.uuid4()
    acc = MagicMock()
    acc.account_id = "123456789012"
    mock_db.get.return_value = acc
    mock_db.scalars.return_value.all.return_value = [_role("OtherRole", attached=[])]
    out = run(mock_db, acc_id)
    assert len(out) == 1
    assert out[0].check_id == CHECK_ID
