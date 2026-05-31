import copy
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from botocore.exceptions import BotoCoreError, ClientError

from app.core.aws import assume_role, ensure_vigil_role_trust, verify_account
from app.services.policy_generation_messages import (
    POLICY_GEN_ASSUME_FAILED_NOTE,
    POLICY_GEN_NO_CONNECTOR_NOTE,
    POLICY_GEN_NO_JOB_NOTE,
    POLICY_GEN_PASS_ROLE_HINT,
)
from app.services.access_analyzer_policy import (
    apply_aa_resources_to_policy_doc,
    confidence_for,
    derive_advanced_role_arn,
    derive_cloudtrail_access_role_arn,
    fetch_latest_generated_policy,
    latest_policy_generation_status,
    merge_access_analyzer,
    placeholder_resources_from_statements,
    start_policy_generation,
    statements_have_concrete_resources,
)
from app.core.config import get_settings
from app.core.db import get_db
from app.core.iam_usage import (
    augment_used_actions_with_granted_for_service_only,
    filter_stale_wildcard_preservation_warnings,
    remove_service_wildcards_when_specific_actions_exist,
    service_has_tracked_actions_in_window,
    services_with_action_evidence,
    services_with_service_only_evidence,
    unused_services_from_usages,
    used_actions_from_usages,
    used_services_from_usages,
)
from app.core.security import current_principal
from app.services.blast_radius_identity import blast_radius_identity
from app.services.evidence_coverage import compute_evidence_coverage, parse_as_of
from app.services.s3_https_policy import build_https_policy_suggestion
from app.services.compliance_timeline import build_compliance_timeline
from app.services.evidence_diff import build_evidence_diff
from app.models import AssumeRoleAudit, AwsAccount, EvidenceExport, IamPermUsage, IamRole, ScanRun
from app.models.cloudtrail import CloudTrailEvent
from app.models.github import IdentityProvider, PullRequest, Repo
from app.models.iam import IamAccessKey, IamUser
from app.models.resources import (
    AccessAnalyzer, AcmCertificate, CloudTrailTrail, ConfigRecorder, DynamoDbTable, Ec2Ami,
    Ec2Instance, EbsEncryptionDefault, EbsSnapshot, EbsVolume, ElbLoadBalancer,
    GuardDutyDetector, IamPasswordPolicy, KmsKey, LambdaFunction, RdsInstance,
    S3AccountPublicAccessBlock, S3Bucket, SecretsManagerSecret, SecurityGroup,
    SecurityHubStatus, SnsTopic, SsmParameter, SqsQueue, Vpc,
)
from app.data.remediation_modules import (
    REMEDIATION_MODULES,
    any_remediation_enabled,
    remediation_deployed_dict,
    remediation_modules_dict,
    set_remediation_modules,
)
from app.models.org import Org

router = APIRouter()
settings = get_settings()


class RemediationModulesIn(BaseModel):
    security_groups: bool = False
    s3_public_access: bool = False
    iam_access_keys: bool = False
    iam_policies: bool = False
    ssm_parameters: bool = False
    cloudtrail_logging: bool = False


class AccountIn(BaseModel):
    label: str = "AWS Account"
    enable_advanced_policy_generation: bool = False
    remediation_modules: RemediationModulesIn = RemediationModulesIn()


class ConnectionOptionsIn(BaseModel):
    enable_advanced_policy_generation: bool
    remediation_modules: RemediationModulesIn


class AccountOut(BaseModel):
    id: str
    label: str
    account_id: str | None
    status: str
    external_id: str
    role_arn: str | None = None
    enable_advanced_policy_generation: bool = False
    remediation_modules: RemediationModulesIn
    remediation_modules_deployed: RemediationModulesIn
    advanced_policy_generation_deployed: bool = False
    cfn_stack_name: str = "VigilAccountConnector"
    cfn_launch_url: str | None = None
    cfn_update_launch_url: str | None = None
    cfn_template_url: str | None = None
    cfn_cli_command: str | None = None
    cfn_update_cli_command: str | None = None
    remediation_cfn_launch_url: str | None = None
    remediation_cfn_template_url: str | None = None
    remediation_cfn_cli_command: str | None = None
    last_scan_at: datetime | None = None
    last_error: str | None = None


class VerifyIn(BaseModel):
    role_arn: str


def _yes_no(flag: bool) -> str:
    return "Yes" if flag else "No"


def _remediation_modules_in(modules: dict[str, bool]) -> RemediationModulesIn:
    return RemediationModulesIn(**{m.id: bool(modules.get(m.id, False)) for m in REMEDIATION_MODULES})


def _modules_from_body(body: RemediationModulesIn) -> dict[str, bool]:
    return body.model_dump()


def _cfn_console_base_url() -> str:
    """Regional CloudFormation console (stack create/update deep links)."""
    region = settings.CFN_CONSOLE_REGION or "us-east-1"
    return f"https://{region}.console.aws.amazon.com/cloudformation/home?region={region}"


def _cfn_stack_params(
    external_id: str,
    *,
    stack_name: str,
    enable_advanced_policy_generation: bool,
    remediation_modules: dict[str, bool],
) -> dict[str, str]:
    s = get_settings()
    safe_stack_name = stack_name.strip() or s.CFN_STACK_NAME
    params = {
        "stackName": safe_stack_name,
        "templateURL": s.CFN_TEMPLATE_URL,
        "param_ExternalId": external_id,
        "param_VigilAccountPrincipal": s.TRUST_PRINCIPAL_ARN,
        "param_RoleName": s.CFN_SCANNER_ROLE_NAME,
        "param_EnableAdvancedPolicyGeneration": _yes_no(enable_advanced_policy_generation),
    }
    for spec in REMEDIATION_MODULES:
        params[f"param_{spec.cfn_parameter}"] = _yes_no(remediation_modules.get(spec.id, False))
    return params


def _ordered_cfn_query(params: dict[str, str]) -> str:
    """Keep stackName before templateURL.

    The CloudFormation console deep-link router can sometimes drop the stackName
    and submit '*' when templateURL appears first, especially after an account
    was manually deleted/re-created. Ordering these two fields first keeps both
    create and update launch links stable.
    """
    stack = (params.get("stackName") or "").strip() or settings.CFN_STACK_NAME
    params["stackName"] = stack
    ordered: list[tuple[str, str]] = [
        ("stackName", stack),
        ("templateURL", params["templateURL"]),
    ]
    for key, value in params.items():
        if key not in ("stackName", "templateURL"):
            ordered.append((key, value))
    return "&".join(f"{k}={quote(v, safe='')}" for k, v in ordered)


def _launch_url(
    external_id: str,
    *,
    stack_name: str,
    enable_advanced_policy_generation: bool,
    remediation_modules: dict[str, bool],
) -> str:
    params = _cfn_stack_params(
        external_id,
        stack_name=stack_name,
        enable_advanced_policy_generation=enable_advanced_policy_generation,
        remediation_modules=remediation_modules,
    )
    return f"{_cfn_console_base_url()}#/stacks/create/review?{_ordered_cfn_query(params)}"


def _update_launch_url(
    external_id: str,
    *,
    stack_name: str,
    enable_advanced_policy_generation: bool,
    remediation_modules: dict[str, bool],
) -> str:
    params = _cfn_stack_params(
        external_id,
        stack_name=stack_name,
        enable_advanced_policy_generation=enable_advanced_policy_generation,
        remediation_modules=remediation_modules,
    )
    return f"{_cfn_console_base_url()}#/stacks/update/template?{_ordered_cfn_query(params)}"


def _cli_command(
    external_id: str,
    *,
    stack_name: str,
    enable_advanced_policy_generation: bool,
    remediation_modules: dict[str, bool],
) -> str:
    s = get_settings()
    region = s.CFN_CONSOLE_REGION or "us-east-1"
    stack = stack_name.strip() or s.CFN_STACK_NAME
    lines = [
        f"aws cloudformation create-stack --region {region} \\",
        f"  --stack-name {stack} \\",
        f"  --template-url {s.CFN_TEMPLATE_URL} \\",
        "  --parameters \\",
        f"    ParameterKey=ExternalId,ParameterValue={external_id} \\",
        f"    ParameterKey=VigilAccountPrincipal,ParameterValue={s.TRUST_PRINCIPAL_ARN} \\",
        f"    ParameterKey=RoleName,ParameterValue={s.CFN_SCANNER_ROLE_NAME} \\",
        f"    ParameterKey=EnableAdvancedPolicyGeneration,ParameterValue={_yes_no(enable_advanced_policy_generation)} \\",
    ]
    for spec in REMEDIATION_MODULES:
        lines.append(
            f"    ParameterKey={spec.cfn_parameter},ParameterValue={_yes_no(remediation_modules.get(spec.id, False))} \\")
    lines.append("  --capabilities CAPABILITY_NAMED_IAM")
    return "\n".join(lines)


def _update_cli_command(
    external_id: str,
    *,
    stack_name: str,
    enable_advanced_policy_generation: bool,
    remediation_modules: dict[str, bool],
) -> str:
    s = get_settings()
    region = s.CFN_CONSOLE_REGION or "us-east-1"
    stack = stack_name.strip() or s.CFN_STACK_NAME
    lines = [
        f"aws cloudformation update-stack --region {region} \\",
        f"  --stack-name {stack} \\",
        f"  --template-url {s.CFN_TEMPLATE_URL} \\",
        "  --parameters \\",
        f"    ParameterKey=ExternalId,ParameterValue={external_id} \\",
        f"    ParameterKey=VigilAccountPrincipal,ParameterValue={s.TRUST_PRINCIPAL_ARN} \\",
        f"    ParameterKey=RoleName,ParameterValue={s.CFN_SCANNER_ROLE_NAME} \\",
        f"    ParameterKey=EnableAdvancedPolicyGeneration,ParameterValue={_yes_no(enable_advanced_policy_generation)} \\",
    ]
    for spec in REMEDIATION_MODULES:
        lines.append(
            f"    ParameterKey={spec.cfn_parameter},ParameterValue={_yes_no(remediation_modules.get(spec.id, False))} \\")
    lines.append("  --capabilities CAPABILITY_NAMED_IAM")
    return "\n".join(lines)


def _remediation_launch_url() -> str:
    params = {
        "stackName": "VigilRemediationSSM",
        "templateURL": get_settings().CFN_REMEDIATION_SSM_TEMPLATE_URL,
    }
    qs = _ordered_cfn_query(params)
    return f"{_cfn_console_base_url()}#/stacks/create/review?{qs}"


def _remediation_update_launch_url(stack_name: str) -> str:
    """Nested remediation child stack (only if deployed standalone). Prefer parent stack update."""
    s = get_settings()
    params = {
        "stackName": stack_name.strip() or "VigilRemediationSSM",
        "templateURL": s.CFN_REMEDIATION_SSM_TEMPLATE_URL,
    }
    qs = _ordered_cfn_query(params)
    return f"{_cfn_console_base_url()}#/stacks/update/template?{qs}"


def _remediation_cli_command() -> str:
    return (
        "aws cloudformation create-stack \\\n"
        "  --stack-name VigilRemediationSSM \\\n"
        f"  --template-url {get_settings().CFN_REMEDIATION_SSM_TEMPLATE_URL} \\\n"
        "  --capabilities CAPABILITY_NAMED_IAM"
    )


def _create_stack_name() -> str:
    """Launch/create URLs and CLI always target the current connector stack."""
    return settings.CFN_STACK_NAME


def _update_stack_name(acc: AwsAccount) -> str:
    """Update URLs and CLI target the stack already deployed in the account."""
    return acc.cfn_stack_name


def _display_cfn_stack_name(acc: AwsAccount) -> str:
    return (acc.cfn_stack_name or settings.CFN_STACK_NAME or "VigilAccountConnector").strip()
