"""Remediation automation modules — scoped write per finding family."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RemediationModuleSpec:
    id: str
    label: str
    badge_label: str
    enable_column: str
    deployed_column: str
    cfn_parameter: str
    iam_policy_name: str
    permissions: tuple[str, ...]
    runner_supported: bool


REMEDIATION_MODULES: tuple[RemediationModuleSpec, ...] = (
    RemediationModuleSpec(
        id="security_groups",
        label="Security Groups",
        badge_label="SG remediation",
        enable_column="enable_remediation_sg",
        deployed_column="remediation_sg_deployed",
        cfn_parameter="EnableSecurityGroupRemediation",
        iam_policy_name="VigilRemediationSecurityGroups",
        permissions=(
            "ec2:RevokeSecurityGroupIngress",
            "ec2:AuthorizeSecurityGroupIngress",
        ),
        runner_supported=True,
    ),
    RemediationModuleSpec(
        id="s3_public_access",
        label="S3 public access",
        badge_label="S3 remediation",
        enable_column="enable_remediation_s3",
        deployed_column="remediation_s3_deployed",
        cfn_parameter="EnableS3Remediation",
        iam_policy_name="VigilRemediationS3",
        permissions=(
            "s3:PutBucketPublicAccessBlock",
            "s3:PutBucketPolicy",
        ),
        runner_supported=False,
    ),
    RemediationModuleSpec(
        id="iam_access_keys",
        label="IAM access keys",
        badge_label="IAM keys remediation",
        enable_column="enable_remediation_iam_keys",
        deployed_column="remediation_iam_keys_deployed",
        cfn_parameter="EnableIamAccessKeyRemediation",
        iam_policy_name="VigilRemediationIamAccessKeys",
        permissions=(
            "iam:UpdateAccessKey",
            "iam:DeleteAccessKey",
        ),
        runner_supported=False,
    ),
    RemediationModuleSpec(
        id="iam_policies",
        label="IAM policies",
        badge_label="IAM policy remediation",
        enable_column="enable_remediation_iam_policy",
        deployed_column="remediation_iam_policy_deployed",
        cfn_parameter="EnableIamPolicyRemediation",
        iam_policy_name="VigilRemediationIamPolicy",
        permissions=(
            "iam:PutRolePolicy",
            "iam:DetachRolePolicy",
            "iam:AttachRolePolicy",
            "iam:CreatePolicyVersion",
            "iam:DeletePolicyVersion",
        ),
        runner_supported=False,
    ),
    RemediationModuleSpec(
        id="ssm_parameters",
        label="SSM parameters",
        badge_label="SSM remediation",
        enable_column="enable_remediation_ssm_parameters",
        deployed_column="remediation_ssm_parameters_deployed",
        cfn_parameter="EnableSsmParameterRemediation",
        iam_policy_name="VigilRemediationAutomation",
        permissions=(
            "ssm:GetParameter",
            "ssm:PutParameter",
        ),
        runner_supported=True,
    ),
    RemediationModuleSpec(
        id="cloudtrail_logging",
        label="CloudTrail logging",
        badge_label="CloudTrail remediation",
        enable_column="enable_remediation_cloudtrail",
        deployed_column="remediation_cloudtrail_deployed",
        cfn_parameter="EnableCloudTrailRemediation",
        iam_policy_name="VigilRemediationCloudTrail",
        permissions=(
            "cloudtrail:UpdateTrail",
            "cloudtrail:StartLogging",
        ),
        runner_supported=False,
    ),
)

REMEDIATION_MODULE_BY_ID = {m.id: m for m in REMEDIATION_MODULES}
DEFAULT_REMEDIATION_ROLE_NAME = "VigilRemediationAutomationRole"


def remediation_modules_dict(acc: Any) -> dict[str, bool]:
    return {m.id: bool(getattr(acc, m.enable_column)) for m in REMEDIATION_MODULES}


def remediation_deployed_dict(acc: Any) -> dict[str, bool]:
    return {m.id: bool(getattr(acc, m.deployed_column)) for m in REMEDIATION_MODULES}


def any_remediation_enabled(modules: dict[str, bool]) -> bool:
    return any(modules.values())


def set_remediation_modules(acc: Any, modules: dict[str, bool]) -> None:
    for spec in REMEDIATION_MODULES:
        setattr(acc, spec.enable_column, bool(modules.get(spec.id, False)))


def clear_remediation_deployed(acc: Any, *, module_id: str | None = None) -> None:
    if module_id:
        spec = REMEDIATION_MODULE_BY_ID[module_id]
        setattr(acc, spec.deployed_column, False)
        return
    for spec in REMEDIATION_MODULES:
        setattr(acc, spec.deployed_column, False)
