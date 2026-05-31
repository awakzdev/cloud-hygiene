"""Verify optional capabilities via IAM policy inspection (no resource mutations)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from botocore.exceptions import ClientError

from app.core.aws import assume_role
from app.data.remediation_modules import (
    DEFAULT_REMEDIATION_ROLE_NAME,
    REMEDIATION_MODULES,
    remediation_deployed_dict,
    remediation_modules_dict,
)
from app.models import AwsAccount
from app.services.iam_permission_check import (
    check_actions_on_documents,
    load_role_policy_documents,
    load_role_policy_names,
)
from app.services.access_analyzer_policy import (
    cloudtrail_monitor_role_exists,
    cloudtrail_monitor_role_name,
)
from app.services.remediation_runner_status import check_remediation_runner

ADVANCED_POLICY_ACTIONS = (
    "iam:GenerateServiceLastAccessedDetails",
    "access-analyzer:StartPolicyGeneration",
    "access-analyzer:CancelPolicyGeneration",
    "access-analyzer:GetGeneratedPolicy",
    "access-analyzer:ListPolicyGenerations",
    "iam:PassRole",
)

VERIFICATION_META = {
    "method": "iam_policy_inspection",
    "description": "Verified from deployed IAM role policy.",
    "safe": "No resources were created, modified, or deleted.",
}


@dataclass
class CapabilityVerificationContext:
    """One AssumeRole + cached IAM/SSM reads for a single Verify click."""

    session: Any | None = None
    account_id: str | None = None
    session_error: str | None = None
    scanner_role_name: str = ""
    scanner_documents: list[dict[str, Any]] = field(default_factory=list)
    remediation_documents: list[dict[str, Any]] = field(default_factory=list)
    remediation_inline_policy_names: set[str] = field(default_factory=set)
    remediation_attached_policy_names: set[str] = field(default_factory=set)
    runner_status: dict[str, Any] | None = None


def _permission_rows(actions: tuple[str, ...], granted: dict[str, bool]) -> list[dict[str, Any]]:
    return [{"action": a, "granted": bool(granted.get(a))} for a in actions]


def _module_result(
    *,
    requested: bool,
    role_arn: str | None = None,
) -> dict[str, Any]:
    return {
        "requested": requested,
        "deployed": False,
        "status": "not_requested",
        "assumable": None,
        "role_arn": role_arn,
        "error": None,
        "permissions": [],
        "granted_count": 0,
        "required_count": 0,
        "policy_found": False,
        "runner_ready": None,
    }


def _finalize_module_result(result: dict[str, Any]) -> dict[str, Any]:
    if not result["requested"]:
        result["status"] = "not_requested"
        return result
    if result.get("assumable") is False:
        result["status"] = "not_assumable"
    elif result["deployed"]:
        result["status"] = "ready"
    else:
        result["status"] = "missing_permissions"
    return result


def _scanner_session(acc: AwsAccount) -> tuple[Any | None, str | None, str | None]:
    """Assume saved scanner role ARN and confirm with sts:GetCallerIdentity."""
    if not acc.role_arn:
        return None, None, "Connect the core scanner role first"
    try:
        sess = assume_role(
            acc.role_arn,
            acc.external_id,
            session_name="vigil-capability-verify",
            aws_account=acc,
            purpose="capability_verify",
        )
        ident = sess.client("sts").get_caller_identity()
        return sess, ident.get("Account"), None
    except ClientError as exc:
        return None, None, str(exc)
    except Exception as exc:  # noqa: BLE001
        return None, None, str(exc)


def build_capability_verification_context(acc: AwsAccount) -> CapabilityVerificationContext:
    """Single AWS session + policy/SSM snapshot for all capability checks."""
    if not acc.role_arn:
        return CapabilityVerificationContext(session_error="Connect the Vigil connector role first")

    sess, account_id, sess_err = _scanner_session(acc)
    if not sess:
        return CapabilityVerificationContext(session_error=sess_err)

    scanner_role_name = acc.role_arn.rsplit("/", 1)[-1]
    iam = sess.client("iam")
    scanner_documents = load_role_policy_documents(iam, scanner_role_name)
    remediation_documents = load_role_policy_documents(iam, DEFAULT_REMEDIATION_ROLE_NAME)
    inline_names, attached_names = load_role_policy_names(iam, DEFAULT_REMEDIATION_ROLE_NAME)

    need_runner = any(getattr(acc, spec.enable_column, False) for spec in REMEDIATION_MODULES)
    runner_status = (
        check_remediation_runner(acc, session=sess, scanner_policy_documents=scanner_documents)
        if need_runner
        else None
    )

    return CapabilityVerificationContext(
        session=sess,
        account_id=account_id,
        scanner_role_name=scanner_role_name,
        scanner_documents=scanner_documents,
        remediation_documents=remediation_documents,
        remediation_inline_policy_names=inline_names,
        remediation_attached_policy_names=attached_names,
        runner_status=runner_status,
    )


def _verify_advanced_with_ctx(acc: AwsAccount, ctx: CapabilityVerificationContext) -> dict[str, Any]:
    wanted = bool(acc.enable_advanced_policy_generation)
    result = _module_result(requested=wanted, role_arn=acc.role_arn)
    result["required_count"] = len(ADVANCED_POLICY_ACTIONS)

    if ctx.session_error:
        result["assumable"] = False
        result["error"] = ctx.session_error
        return _finalize_module_result(result)

    result["assumable"] = True
    granted = check_actions_on_documents(ctx.scanner_documents, ADVANCED_POLICY_ACTIONS)
    rows = _permission_rows(ADVANCED_POLICY_ACTIONS, granted)
    monitor_name = cloudtrail_monitor_role_name(acc.role_arn)
    monitor_ok = cloudtrail_monitor_role_exists(ctx.session, acc.role_arn) if monitor_name else False
    result["permissions"] = rows
    result["required_count"] = len(ADVANCED_POLICY_ACTIONS)
    action_granted = sum(1 for r in rows if r["granted"])
    result["granted_count"] = action_granted
    result["cloudtrail_monitor_role"] = monitor_name
    result["cloudtrail_monitor_role_present"] = monitor_ok
    result["deployed"] = action_granted == result["required_count"] and monitor_ok
    if not result["deployed"]:
        missing = [r["action"] for r in rows if not r["granted"]]
        if monitor_name and not monitor_ok and not missing:
            result["error"] = (
                "Advanced policy generation stack is incomplete. "
                "Update the Vigil connector (Advanced IAM policy generation), then verify again."
            )
        elif monitor_name and not monitor_ok:
            result["error"] = (
                "Advanced policy generation stack is incomplete. "
                f"Missing: {', '.join(missing)}. "
                "Update the Vigil connector, then verify again."
            )
        else:
            result["error"] = f"Missing permissions: {', '.join(missing)}"

    result["requested"] = wanted or result["deployed"]
    return _finalize_module_result(result)


def _remediation_role_has_policy(ctx: CapabilityVerificationContext, policy_name: str) -> bool:
    if policy_name in ctx.remediation_inline_policy_names:
        return True
    return policy_name in ctx.remediation_attached_policy_names


def _ssm_remediation_ready(ctx: CapabilityVerificationContext) -> bool:
    """True when connector can start SSM Automation and the document is active."""
    if ctx.session_error or ctx.runner_status is None:
        return False
    return bool(ctx.runner_status.get("ready"))


def _ssm_remediation_blockers(ctx: CapabilityVerificationContext) -> list[str]:
    if ctx.session_error:
        return [ctx.session_error]
    if ctx.runner_status is None:
        return ["SSM remediation runner was not checked"]
    return list(ctx.runner_status.get("blockers") or [])


def _ssm_remediation_error(ctx: CapabilityVerificationContext) -> str | None:
    blockers = _ssm_remediation_blockers(ctx)
    if not blockers:
        return None
    return "; ".join(blockers)


def verify_ssm_remediation(
    acc: AwsAccount, ctx: CapabilityVerificationContext | None = None
) -> dict[str, Any]:
    """Aggregate SSM remediation readiness (document + connector StartAutomationExecution)."""
    if ctx is None:
        ctx = build_capability_verification_context(acc)
    wanted = any(getattr(acc, spec.enable_column) for spec in REMEDIATION_MODULES)
    ready = _ssm_remediation_ready(ctx)
    blockers = _ssm_remediation_blockers(ctx)
    result: dict[str, Any] = {
        "requested": wanted,
        "deployed": ready,
        "ready": ready,
        "status": "not_requested",
        "blockers": blockers,
        "error": None,
        "runner_status": ctx.runner_status,
    }
    if not wanted:
        result["status"] = "not_requested"
        return result
    if ctx.session_error:
        result["status"] = "not_assumable"
        result["error"] = ctx.session_error
        return result
    if ready:
        result["status"] = "ready"
        return result
    result["status"] = "missing_permissions"
    result["error"] = _ssm_remediation_error(ctx) or "SSM remediation not ready"
    return result


def _verify_remediation_module_with_ctx(
    acc: AwsAccount, spec, ctx: CapabilityVerificationContext
) -> dict[str, Any]:
    wanted = bool(getattr(acc, spec.enable_column))
    result = _module_result(requested=wanted)
    result["required_count"] = len(spec.permissions)

    if ctx.session_error:
        result["assumable"] = False
        result["error"] = ctx.session_error
        return _finalize_module_result(result)

    if ctx.account_id:
        result["role_arn"] = f"arn:aws:iam::{ctx.account_id}:role/{DEFAULT_REMEDIATION_ROLE_NAME}"

    result["assumable"] = True
    result["policy_found"] = _remediation_role_has_policy(ctx, spec.iam_policy_name)

    granted = check_actions_on_documents(ctx.remediation_documents, spec.permissions)
    rows = _permission_rows(spec.permissions, granted)
    result["permissions"] = rows
    result["granted_count"] = sum(1 for r in rows if r["granted"])
    perms_ok = result["granted_count"] == result["required_count"]

    ssm_ready = _ssm_remediation_ready(ctx)
    if spec.runner_supported and ctx.runner_status is not None:
        result["runner_ready"] = bool(ctx.runner_status.get("ready"))

    if wanted and ssm_ready:
        # SSM-first: execution role permissions are enforced by vigil-remediation-ssm.yaml at runtime.
        result["deployed"] = True
        result["via_ssm"] = True
        result["error"] = None
        if spec.runner_supported:
            result["runner_ready"] = True
    elif wanted:
        # Report SSM blockers only — avoid noisy per-module IAM action lists on the connector role.
        result["deployed"] = False
        result["error"] = _ssm_remediation_error(ctx) or "SSM remediation not ready"
    elif perms_ok and (not spec.runner_supported or result.get("runner_ready")):
        result["deployed"] = True
        result["error"] = None
    else:
        result["deployed"] = False
        if perms_ok and spec.runner_supported and not result.get("runner_ready"):
            blockers = ctx.runner_status.get("blockers") if ctx.runner_status else []
            result["error"] = "; ".join(blockers) if blockers else "Remediation runner not ready"
        elif not perms_ok:
            missing = [r["action"] for r in rows if not r["granted"]]
            result["error"] = f"Missing permissions: {', '.join(missing)}"

    result["requested"] = wanted or result["deployed"]
    return _finalize_module_result(result)


def verify_advanced_policy_generation(
    acc: AwsAccount, ctx: CapabilityVerificationContext | None = None
) -> dict[str, Any]:
    """Inspect connector role IAM policies; deployed = permissions present on role_arn."""
    if ctx is None:
        ctx = build_capability_verification_context(acc)
    return _verify_advanced_with_ctx(acc, ctx)


def verify_remediation_module(
    acc: AwsAccount, spec, ctx: CapabilityVerificationContext | None = None
) -> dict[str, Any]:
    if ctx is None:
        ctx = build_capability_verification_context(acc)
    return _verify_remediation_module_with_ctx(acc, spec, ctx)


def apply_capability_verification(acc: AwsAccount) -> dict[str, Any]:
    """Update deployed + enabled flags from IAM inspection of the connected role(s)."""
    ctx = build_capability_verification_context(acc)

    adv = verify_advanced_policy_generation(acc, ctx)
    acc.advanced_policy_generation_deployed = adv["deployed"]
    if adv["deployed"]:
        acc.enable_advanced_policy_generation = True

    ssm = verify_ssm_remediation(acc, ctx)
    remediation_results: dict[str, Any] = {}
    for spec in REMEDIATION_MODULES:
        mod = verify_remediation_module(acc, spec, ctx)
        setattr(acc, spec.deployed_column, mod["deployed"])
        if mod["deployed"]:
            setattr(acc, spec.enable_column, True)
        remediation_results[spec.id] = mod

    return {
        "advanced_policy_generation": adv,
        "ssm_remediation": ssm,
        "remediation_modules": remediation_results,
        "verification": {
            **VERIFICATION_META,
            "scanner_role_arn": acc.role_arn,
        },
    }


def remediation_modules_payload(acc: AwsAccount) -> dict[str, Any]:
    return {
        "enabled": remediation_modules_dict(acc),
        "deployed": remediation_deployed_dict(acc),
    }
