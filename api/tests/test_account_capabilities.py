"""Optional capability deployment verification."""

from unittest.mock import MagicMock, patch

from app.services.account_capabilities import (
    apply_capability_verification,
    verify_advanced_policy_generation,
)


@patch("app.services.account_capabilities.check_role_actions")
@patch("app.services.account_capabilities.assume_role")
def test_verify_advanced_inspects_role_even_when_not_enabled(mock_assume, mock_check):
    mock_sess = MagicMock()
    mock_assume.return_value = mock_sess
    mock_check.return_value = {a: False for a in (
        "iam:GenerateServiceLastAccessedDetails",
        "access-analyzer:StartPolicyGeneration",
        "access-analyzer:CancelPolicyGeneration",
        "access-analyzer:GetGeneratedPolicy",
    )}
    acc = MagicMock(
        enable_advanced_policy_generation=False,
        role_arn="arn:aws:iam::123456789012:role/VigilScannerRole",
        external_id="ext",
    )
    out = verify_advanced_policy_generation(acc)
    assert out["deployed"] is False
    assert out["status"] == "not_requested"
    mock_check.assert_called_once()


@patch("app.services.account_capabilities.check_role_actions")
@patch("app.services.account_capabilities.assume_role")
@patch("app.services.account_capabilities.verify_account")
def test_verify_advanced_assumes_derived_role(mock_verify, mock_assume, mock_check):
    mock_verify.return_value = (True, "123456789012", None, None)
    mock_sess = MagicMock()
    mock_assume.return_value = mock_sess
    mock_check.return_value = {a: True for a in (
        "iam:GenerateServiceLastAccessedDetails",
        "access-analyzer:StartPolicyGeneration",
        "access-analyzer:CancelPolicyGeneration",
        "access-analyzer:GetGeneratedPolicy",
        "access-analyzer:ListPolicyGenerations",
    )}
    acc = MagicMock(
        enable_advanced_policy_generation=True,
        role_arn="arn:aws:iam::123456789012:role/VigilReadOnlyScannerRole",
        external_id="ext",
    )
    out = verify_advanced_policy_generation(acc)
    assert out["deployed"] is True
    assert out["status"] == "ready"
    assert out["error"] is None
    assert out["granted_count"] == 5


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
