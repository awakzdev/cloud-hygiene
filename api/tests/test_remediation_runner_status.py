from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

from app.services.remediation_runner_status import (
    CONNECTOR_SSM_START_ACTIONS,
    check_remediation_runner,
    connector_ssm_start_blockers,
)


def _scanner_policy_with_ssm_start():
    return [
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": list(CONNECTOR_SSM_START_ACTIONS) + ["iam:PassRole"],
                    "Resource": "*",
                }
            ]
        }
    ]


def test_connector_ssm_start_blockers_when_missing():
    docs = [{"Statement": [{"Effect": "Allow", "Action": "ssm:DescribeDocument", "Resource": "*"}]}]
    blockers = connector_ssm_start_blockers(docs)
    assert len(blockers) == 1
    assert "StartAutomationExecution" in blockers[0]


def test_connector_ssm_start_blockers_when_granted():
    assert connector_ssm_start_blockers(_scanner_policy_with_ssm_start()) == []


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

    out = check_remediation_runner(
        acc,
        check_id="ec2.security_group.unrestricted_rdp",
        resource_region="us-east-2",
    )
    assert out["ready"] is False
    assert out["automation_region"] == "us-east-1"
    assert any("Custom Vigil automation document" in b for b in out["blockers"])


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

    out = check_remediation_runner(acc, scanner_policy_documents=_scanner_policy_with_ssm_start())
    assert out["ready"] is True
    assert out["document"]["exists"] is True


@patch("app.services.remediation_runner_status.assume_role")
def test_ssm_ready_false_when_start_only_on_automation_definition(mock_assume):
    acc = MagicMock()
    acc.role_arn = "arn:aws:iam::123:role/x"
    acc.external_id = "ext"

    ssm = MagicMock()
    sess = MagicMock()
    sess.client.return_value = ssm
    mock_assume.return_value = sess
    ssm.describe_document.return_value = {"Document": {"Status": "Active"}}

    docs_bad = [
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["ssm:DescribeDocument", "ssm:GetDocument"],
                    "Resource": "arn:aws:ssm:*:123456789012:document/Vigil-RemediationPlanExecutor",
                },
                {
                    "Effect": "Allow",
                    "Action": list(CONNECTOR_SSM_START_ACTIONS),
                    "Resource": [
                        "arn:aws:ssm:*:123456789012:automation-definition/Vigil-RemediationPlanExecutor:*",
                        "arn:aws:ssm:*:123456789012:automation-execution/*",
                    ],
                },
            ]
        }
    ]
    out = check_remediation_runner(
        acc,
        check_id="iam.access_key.unused_45d",
        scanner_policy_documents=docs_bad,
    )
    assert out["ready"] is False
    assert any("document/" in b for b in out["blockers"])


@patch("app.services.remediation_runner_status.assume_role")
def test_ssm_ready_false_when_connector_cannot_start(mock_assume):
    acc = MagicMock()
    acc.role_arn = "arn:aws:iam::123:role/x"
    acc.external_id = "ext"

    ssm = MagicMock()
    sess = MagicMock()
    sess.client.return_value = ssm
    mock_assume.return_value = sess
    ssm.describe_document.return_value = {"Document": {"Status": "Active"}}

    docs = [{"Statement": [{"Effect": "Allow", "Action": "ssm:DescribeDocument", "Resource": "*"}]}]
    out = check_remediation_runner(acc, scanner_policy_documents=docs)
    assert out["ready"] is False
    assert any("StartAutomationExecution" in b for b in out["blockers"])
