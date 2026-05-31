"""CFN launch URLs reflect account connection options (parent stack + nested children)."""

from unittest.mock import MagicMock

from app.core.config import get_settings
from app.data.remediation_modules import REMEDIATION_MODULES
from app.routes.accounts import (
    _account_out,
    _cli_command,
    _display_cfn_stack_name,
    _launch_url,
    _remediation_launch_url,
    _update_cli_command,
    _update_launch_url,
)

settings = get_settings()

_MODULES_OFF = {
    "security_groups": False,
    "s3_public_access": False,
    "iam_access_keys": False,
    "iam_policies": False,
    "ssm_parameters": False,
    "cloudtrail_logging": False,
}


def test_launch_url_new_stack_name():
    url = _launch_url(
        "ext-abc",
        stack_name=settings.CFN_STACK_NAME,
        enable_advanced_policy_generation=False,
        remediation_modules=_MODULES_OFF,
    )
    assert f"stackName={settings.CFN_STACK_NAME}" in url
    assert "param_EnableSecurityGroupRemediation=No" in url


def test_launch_url_legacy_stack_name():
    url = _update_launch_url(
        "ext-abc",
        stack_name=settings.CFN_STACK_NAME_LEGACY,
        enable_advanced_policy_generation=True,
        remediation_modules={**_MODULES_OFF, "security_groups": True},
    )
    assert f"stackName={settings.CFN_STACK_NAME_LEGACY}" in url
    assert "param_EnableSecurityGroupRemediation=Yes" in url


def test_cli_uses_stack_name():
    cli = _cli_command(
        "ext-abc",
        stack_name=settings.CFN_STACK_NAME,
        enable_advanced_policy_generation=False,
        remediation_modules=_MODULES_OFF,
    )
    assert f"--stack-name {settings.CFN_STACK_NAME}" in cli


def test_update_cli_uses_update_stack():
    cli = _update_cli_command(
        "ext-abc",
        stack_name=settings.CFN_STACK_NAME_LEGACY,
        enable_advanced_policy_generation=True,
        remediation_modules=_MODULES_OFF,
    )
    assert "aws cloudformation update-stack" in cli
    assert f"--stack-name {settings.CFN_STACK_NAME_LEGACY}" in cli


def test_remediation_launch_url_legacy_helper():
    url = _remediation_launch_url()
    assert "VigilRemediationSSM" in url


def _mock_account(*, status: str, cfn_stack_name: str) -> MagicMock:
    acc = MagicMock()
    acc.id = "00000000-0000-0000-0000-000000000001"
    acc.label = "Test"
    acc.account_id = None
    acc.status = status
    acc.external_id = "ext-abc"
    acc.role_arn = None
    acc.last_error = None
    acc.enable_advanced_policy_generation = False
    acc.advanced_policy_generation_deployed = False
    acc.cfn_stack_name = cfn_stack_name
    acc.last_scan_at = None
    for spec in REMEDIATION_MODULES:
        setattr(acc, spec.enable_column, False)
        setattr(acc, spec.deployed_column, False)
    return acc


def test_display_stack_name_pending_legacy():
    acc = _mock_account(status="pending", cfn_stack_name=settings.CFN_STACK_NAME_LEGACY)
    assert _display_cfn_stack_name(acc) == settings.CFN_STACK_NAME


def test_display_stack_name_connected_legacy():
    acc = _mock_account(status="connected", cfn_stack_name=settings.CFN_STACK_NAME_LEGACY)
    assert _display_cfn_stack_name(acc) == settings.CFN_STACK_NAME_LEGACY


def test_account_out_launch_uses_current_even_when_db_legacy():
    acc = _mock_account(status="pending", cfn_stack_name=settings.CFN_STACK_NAME_LEGACY)
    out = _account_out(acc)
    assert out.cfn_stack_name == settings.CFN_STACK_NAME
    assert f"stackName={settings.CFN_STACK_NAME}" in out.cfn_launch_url
    assert f"--stack-name {settings.CFN_STACK_NAME}" in out.cfn_cli_command


def test_account_out_update_uses_db_stack_name():
    acc = _mock_account(status="connected", cfn_stack_name=settings.CFN_STACK_NAME_LEGACY)
    out = _account_out(acc)
    assert out.cfn_stack_name == settings.CFN_STACK_NAME_LEGACY
    assert f"stackName={settings.CFN_STACK_NAME_LEGACY}" in out.cfn_update_launch_url
    assert f"--stack-name {settings.CFN_STACK_NAME_LEGACY}" in out.cfn_update_cli_command
