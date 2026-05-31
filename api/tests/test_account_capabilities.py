"""Optional capability deployment verification."""

from unittest.mock import MagicMock, patch

from app.data.remediation_modules import REMEDIATION_MODULES
from app.services.account_capabilities import (
    apply_capability_verification,
    build_capability_verification_context,
    verify_advanced_policy_generation,
    verify_remediation_module,
    verify_ssm_remediation,
)


def _ctx(*, runner_ready=False, session_error=None, remediation_documents=None):
    runner_status = {"ready": runner_ready, "blockers": [] if runner_ready else ["missing doc"]}
    return MagicMock(
        session_error=session_error,
        account_id="123456789012",
        remediation_documents=remediation_documents or [],
        remediation_inline_policy_names=set(),
        remediation_attached_policy_names=set(),
        runner_status=runner_status,
    )


@patch("app.services.account_capabilities.cloudtrail_monitor_role_exists", return_value=False)
@patch(
    "app.services.account_capabilities.cloudtrail_monitor_role_name",
    return_value="VigilScannerRoleAccessAnalyzerMonitor",
)
@patch("app.services.account_capabilities.check_actions_on_documents")
@patch("app.services.account_capabilities.build_capability_verification_context")
def test_verify_advanced_inspects_role_even_when_not_enabled(
    mock_ctx_build, mock_check, _mock_name, _mock_exists
):
    mock_ctx_build.return_value = MagicMock(
        session_error=None,
        scanner_documents=[{"Statement": []}],
    )
    mock_check.return_value = {
        a: False
        for a in (
            "iam:GenerateServiceLastAccessedDetails",
            "access-analyzer:StartPolicyGeneration",
            "access-analyzer:CancelPolicyGeneration",
            "access-analyzer:GetGeneratedPolicy",
        )
    }
    acc = MagicMock(
        enable_advanced_policy_generation=False,
        role_arn="arn:aws:iam::123456789012:role/VigilScannerRole",
        external_id="ext",
    )
    out = verify_advanced_policy_generation(acc)
    assert out["deployed"] is False
    assert out["status"] == "not_requested"
    mock_check.assert_called_once()


@patch("app.services.account_capabilities.cloudtrail_monitor_role_exists", return_value=True)
@patch(
    "app.services.account_capabilities.cloudtrail_monitor_role_name",
    return_value="VigilScannerRoleAccessAnalyzerMonitor",
)
@patch("app.services.account_capabilities.check_actions_on_documents")
@patch("app.services.account_capabilities.build_capability_verification_context")
def test_verify_advanced_all_granted(mock_ctx_build, mock_check, _mock_name, _mock_exists):
    mock_ctx_build.return_value = MagicMock(
        session_error=None,
        scanner_documents=[{"Statement": []}],
        session=MagicMock(),
    )
    mock_check.return_value = {a: True for a in (
        "iam:GenerateServiceLastAccessedDetails",
        "access-analyzer:StartPolicyGeneration",
        "access-analyzer:CancelPolicyGeneration",
        "access-analyzer:GetGeneratedPolicy",
        "access-analyzer:ListPolicyGenerations",
        "iam:PassRole",
    )}
    acc = MagicMock(
        enable_advanced_policy_generation=True,
        role_arn="arn:aws:iam::123456789012:role/VigilScannerRole",
        external_id="ext",
    )
    out = verify_advanced_policy_generation(acc)
    assert out["deployed"] is True
    assert out["status"] == "ready"
    assert out["error"] is None
    assert out["granted_count"] == 6


@patch("app.services.account_capabilities.verify_remediation_module")
@patch("app.services.account_capabilities.verify_advanced_policy_generation")
def test_apply_clears_deployed_when_iam_missing(mock_adv, mock_rem):
    mock_adv.return_value = {"deployed": False, "requested": False, "status": "not_requested", "error": None}
    mock_rem.return_value = {"deployed": False, "requested": False, "status": "not_requested", "error": None}
    acc = MagicMock(
        enable_advanced_policy_generation=False,
        enable_remediation_sg=False,
        enable_remediation_s3=False,
        enable_remediation_iam_keys=False,
        enable_remediation_iam_policy=False,
        enable_remediation_cloudtrail=False,
        advanced_policy_generation_deployed=True,
        remediation_sg_deployed=True,
    )
    apply_capability_verification(acc)
    assert acc.advanced_policy_generation_deployed is False
    assert acc.remediation_sg_deployed is False


@patch("app.services.account_capabilities.verify_remediation_module")
@patch("app.services.account_capabilities.verify_advanced_policy_generation")
def test_apply_syncs_enable_when_iam_has_advanced(mock_adv, mock_rem):
    mock_adv.return_value = {
        "deployed": True,
        "requested": True,
        "status": "ready",
        "error": None,
    }
    mock_rem.return_value = {"deployed": False, "requested": False, "status": "not_requested", "error": None}
    acc = MagicMock(
        enable_advanced_policy_generation=False,
        enable_remediation_sg=False,
        enable_remediation_s3=False,
        enable_remediation_iam_keys=False,
        enable_remediation_iam_policy=False,
        enable_remediation_cloudtrail=False,
        advanced_policy_generation_deployed=False,
        remediation_sg_deployed=False,
    )
    apply_capability_verification(acc)
    assert acc.advanced_policy_generation_deployed is True
    assert acc.enable_advanced_policy_generation is True


@patch("app.services.account_capabilities.check_remediation_runner")
@patch("app.services.account_capabilities.load_role_policy_names", return_value=(set(), set()))
@patch("app.services.account_capabilities.load_role_policy_documents", return_value=[])
@patch("app.services.account_capabilities.assume_role")
def test_apply_assumes_role_once(mock_assume, mock_load_docs, mock_load_names, mock_runner):
    mock_sess = MagicMock()
    mock_assume.return_value = mock_sess
    mock_sess.client.return_value.get_caller_identity.return_value = {"Account": "123456789012"}
    mock_runner.return_value = {"ready": True, "blockers": []}

    acc = MagicMock(
        role_arn="arn:aws:iam::123456789012:role/VigilScannerRole",
        external_id="ext",
        enable_advanced_policy_generation=True,
        advanced_policy_generation_deployed=False,
    )
    for spec in REMEDIATION_MODULES:
        setattr(acc, spec.enable_column, True)
        setattr(acc, spec.deployed_column, False)

    apply_capability_verification(acc)

    assert mock_assume.call_count == 1
    assert mock_load_docs.call_count == 2
    assert mock_runner.call_count == 1
    mock_runner.assert_called_once()
    assert mock_runner.call_args.kwargs.get("session") is mock_sess
    assert mock_runner.call_args.kwargs.get("scanner_policy_documents") == []


@patch("app.services.account_capabilities.check_remediation_runner")
@patch("app.services.account_capabilities.load_role_policy_names", return_value=(set(), set()))
@patch("app.services.account_capabilities.load_role_policy_documents", return_value=[])
@patch("app.services.account_capabilities.assume_role")
def test_build_context_single_runner_check(mock_assume, mock_load_docs, mock_load_names, mock_runner):
    mock_sess = MagicMock()
    mock_assume.return_value = mock_sess
    mock_sess.client.return_value.get_caller_identity.return_value = {"Account": "123456789012"}
    mock_runner.return_value = {"ready": False, "blockers": ["missing doc"]}

    acc = MagicMock(
        role_arn="arn:aws:iam::123456789012:role/VigilScannerRole",
        external_id="ext",
    )
    ctx = build_capability_verification_context(acc)
    assert ctx.session is mock_sess
    assert mock_assume.call_count == 1
    assert mock_runner.call_count == 1


@patch("app.services.account_capabilities.check_actions_on_documents")
def test_remediation_module_ready_via_ssm_without_executor_role_perms(mock_check):
    mock_check.return_value = {a: False for spec in REMEDIATION_MODULES for a in spec.permissions}
    acc = MagicMock(enable_remediation_sg=True)
    ctx = _ctx(runner_ready=True)

    out = verify_remediation_module(acc, REMEDIATION_MODULES[0], ctx)

    assert out["deployed"] is True
    assert out["via_ssm"] is True
    assert out["status"] == "ready"
    assert out["error"] is None


@patch("app.services.account_capabilities.check_actions_on_documents")
def test_remediation_module_ssm_not_ready_reports_blockers_not_iam_list(mock_check):
    mock_check.return_value = {a: False for a in REMEDIATION_MODULES[0].permissions}
    acc = MagicMock(enable_remediation_sg=True)
    ctx = _ctx(runner_ready=False)

    out = verify_remediation_module(acc, REMEDIATION_MODULES[0], ctx)

    assert out["deployed"] is False
    assert out["error"] == "missing doc"
    assert "Missing permissions:" not in (out["error"] or "")


def test_verify_ssm_remediation_aggregate():
    acc = MagicMock(
        enable_remediation_sg=True,
        enable_remediation_s3=False,
        enable_remediation_iam_keys=False,
        enable_remediation_iam_policy=False,
        enable_remediation_ssm_parameters=False,
        enable_remediation_cloudtrail=False,
    )
    ready_ctx = _ctx(runner_ready=True)
    out = verify_ssm_remediation(acc, ready_ctx)
    assert out["requested"] is True
    assert out["ready"] is True
    assert out["status"] == "ready"
    assert out["error"] is None

    blocked_ctx = _ctx(runner_ready=False)
    blocked = verify_ssm_remediation(acc, blocked_ctx)
    assert blocked["ready"] is False
    assert blocked["error"] == "missing doc"


@patch("app.services.account_capabilities.verify_ssm_remediation")
@patch("app.services.account_capabilities.verify_remediation_module")
@patch("app.services.account_capabilities.verify_advanced_policy_generation")
def test_apply_includes_ssm_remediation_aggregate(mock_adv, mock_rem, mock_ssm):
    mock_adv.return_value = {"deployed": False, "requested": False, "status": "not_requested", "error": None}
    mock_rem.return_value = {"deployed": True, "requested": True, "status": "ready", "error": None}
    mock_ssm.return_value = {"deployed": True, "ready": True, "requested": True, "status": "ready", "error": None}
    acc = MagicMock(
        enable_advanced_policy_generation=False,
        enable_remediation_sg=True,
        enable_remediation_s3=False,
        enable_remediation_iam_keys=False,
        enable_remediation_iam_policy=False,
        enable_remediation_ssm_parameters=False,
        enable_remediation_cloudtrail=False,
        advanced_policy_generation_deployed=False,
        remediation_sg_deployed=False,
    )
    results = apply_capability_verification(acc)
    assert "ssm_remediation" in results
    assert results["ssm_remediation"]["ready"] is True
