"""Verify optional capabilities via IAM policy inspection (no resource mutations)."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from app.core.aws import assume_role, verify_account
from app.data.remediation_modules import (
    DEFAULT_REMEDIATION_ROLE_NAME,
    REMEDIATION_MODULES,
    remediation_deployed_dict,
    remediation_modules_dict,
)
from app.models import AwsAccount
from app.services.iam_permission_check import check_role_actions
from app.services.remediation_runner_status import check_remediation_runner

ADVANCED_POLICY_ACTIONS = (
    "iam:GenerateServiceLastAccessedDetails",
    "access-analyzer:StartPolicyGeneration",
    "access-analyzer:CancelPolicyGeneration",
    "access-analyzer:GetGeneratedPolicy",
    "access-analyzer:ListPolicyGenerations",
)

VERIFICATION_META = {
    "method": "iam_policy_inspection",
    "description": "Verified from deployed IAM role policy.",
    "safe": "No resources were created, modified, or deleted.",
}


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


def verify_advanced_policy_generation(acc: AwsAccount) -> dict[str, Any]:
    """Inspect connector role IAM policies; deployed = permissions present on role_arn."""
    wanted = bool(acc.enable_advanced_policy_generation)
    result = _module_result(requested=wanted, role_arn=acc.role_arn)
    result["required_count"] = len(ADVANCED_POLICY_ACTIONS)

    if not acc.role_arn:
        result["assumable"] = False
        result["error"] = "Connect the Vigil connector role first"
        return _finalize_module_result(result)

    sess, _, sess_err = _scanner_session(acc)
    if not sess:
        result["assumable"] = False
        result["error"] = sess_err
        return _finalize_module_result(result)

    result["assumable"] = True
    role_name = acc.role_arn.rsplit("/", 1)[-1]
    try:
        granted = check_role_actions(sess.client("iam"), role_name, ADVANCED_POLICY_ACTIONS)
        rows = _permission_rows(ADVANCED_POLICY_ACTIONS, granted)
        result["permissions"] = rows
        result["granted_count"] = sum(1 for r in rows if r["granted"])
        result["deployed"] = result["granted_count"] == result["required_count"]
        if not result["deployed"]:
            missing = [r["action"] for r in rows if not r["granted"]]
            result["error"] = f"Missing permissions: {', '.join(missing)}"
    except ClientError as exc:
        result["error"] = f"Cannot read IAM policies for {role_name}: {exc}"
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"Cannot read IAM policies: {exc}"

    result["requested"] = wanted or result["deployed"]
    return _finalize_module_result(result)


def _remediation_role_has_policy(iam_client, role_name: str, policy_name: str) -> bool:
    try:
        names = iam_client.list_role_policies(RoleName=role_name).get("PolicyNames") or []
        if policy_name in names:
            return True
        attached = iam_client.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies") or []
        return any(p.get("PolicyName") == policy_name for p in attached)
    except ClientError:
        return False


def verify_remediation_module(acc: AwsAccount, spec) -> dict[str, Any]:
    wanted = bool(getattr(acc, spec.enable_column))
    result = _module_result(requested=wanted)
    result["required_count"] = len(spec.permissions)

    sess, account_id, sess_err = _scanner_session(acc)
    if not sess:
        result["assumable"] = False
        result["error"] = sess_err
        return _finalize_module_result(result)

    if account_id:
        result["role_arn"] = f"arn:aws:iam::{account_id}:role/{DEFAULT_REMEDIATION_ROLE_NAME}"

    result["assumable"] = True
    iam = sess.client("iam")
    result["policy_found"] = _remediation_role_has_policy(
        iam, DEFAULT_REMEDIATION_ROLE_NAME, spec.iam_policy_name
    )

    try:
        granted = check_role_actions(iam, DEFAULT_REMEDIATION_ROLE_NAME, spec.permissions)
        rows = _permission_rows(spec.permissions, granted)
        result["permissions"] = rows
        result["granted_count"] = sum(1 for r in rows if r["granted"])
    except ClientError as exc:
        result["error"] = f"Cannot read IAM policies for {DEFAULT_REMEDIATION_ROLE_NAME}: {exc}"
        return _finalize_module_result(result)

    perms_ok = result["granted_count"] == result["required_count"]
    if not perms_ok:
        missing = [r["action"] for r in rows if not r["granted"]]
        result["error"] = f"Missing permissions: {', '.join(missing)}"

    if spec.runner_supported:
        status: dict[str, Any] = check_remediation_runner(acc)
        result["runner_ready"] = bool(status.get("ready"))
        if not result["runner_ready"]:
            blockers = status.get("blockers") or []
            runner_err = "; ".join(blockers) if blockers else "Remediation runner not ready"
            result["error"] = (
                f"{result['error']}; {runner_err}" if result["error"] else runner_err
            )

    if spec.runner_supported:
        result["deployed"] = perms_ok and bool(result["runner_ready"])
    else:
        result["deployed"] = perms_ok

    if result["deployed"]:
        result["error"] = None

    result["requested"] = wanted or result["deployed"]
    return _finalize_module_result(result)


def apply_capability_verification(acc: AwsAccount) -> dict[str, Any]:
    """Update deployed + enabled flags from IAM inspection of the connected role(s)."""
    adv = verify_advanced_policy_generation(acc)
    acc.advanced_policy_generation_deployed = adv["deployed"]
    if adv["deployed"]:
        acc.enable_advanced_policy_generation = True

    remediation_results: dict[str, Any] = {}
    for spec in REMEDIATION_MODULES:
        mod = verify_remediation_module(acc, spec)
        setattr(acc, spec.deployed_column, mod["deployed"])
        if mod["deployed"]:
            setattr(acc, spec.enable_column, True)
        remediation_results[spec.id] = mod

    return {
        "advanced_policy_generation": adv,
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
