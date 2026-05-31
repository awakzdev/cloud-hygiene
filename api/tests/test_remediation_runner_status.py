from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

from app.services.remediation_runner_status import check_remediation_runner


def test_no_role_arn_blocker():
    acc = MagicMock()
    acc.role_arn = None
    out = check_remediation_runner(acc)
    assert out["ready"] is False
    assert any("role" in b.lower() for b in out["blockers"])


@patch("app.services.remediation_runner_status.assume_role")
def test_ssm_document_missing_blocker(mock_assume):
    acc = MagicMock()
    acc.role_arn = "arn:aws:iam::123:role/x"
    acc.external_id = "ext"

    ssm = MagicMock()

    sess = MagicMock()

    def client_factory(svc, **kwargs):
        return {"ssm": ssm}[svc]

    sess.client.side_effect = client_factory
    mock_assume.return_value = sess

    ssm.describe_document.side_effect = ClientError(
        {"Error": {"Code": "InvalidDocument", "Message": "missing"}},
        "DescribeDocument",
    )

    out = check_remediation_runner(acc)
    assert out["ready"] is False
    assert any("SSM Automation document" in b for b in out["blockers"])


@patch("app.services.remediation_runner_status.assume_role")
def test_ssm_document_ready(mock_assume):
    acc = MagicMock()
    acc.role_arn = "arn:aws:iam::123:role/x"
    acc.external_id = "ext"

    ssm = MagicMock()
    sess = MagicMock()
    sess.client.return_value = ssm
    mock_assume.return_value = sess
    ssm.describe_document.return_value = {"Document": {"Status": "Active"}}

    out = check_remediation_runner(acc)
    assert out["ready"] is True
    assert out["document"]["exists"] is True
