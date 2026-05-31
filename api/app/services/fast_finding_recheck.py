"""Fast, resource-scoped verification after remediation.

The full recheck path re-collects an entire resource family (for example all IAM
users, roles, policies, and keys). That is useful for background scan freshness,
but it is too slow for the Finding drawer "Verify" button after a user just ran
an approved remediation. These helpers inspect only the affected resource and
resolve the finding immediately when AWS already reflects the fix.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog
from botocore.exceptions import ClientError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.aws import assume_role
from app.models import AwsAccount, Finding, FindingEvent
from app.models.iam import IamAccessKey
from app.models.resources import SsmParameter

log = structlog.get_logger()

IAM_ACCESS_KEY_CHECKS = frozenset({"iam.access_key.unused_45d", "iam.access_key.unused_90d"})
SECURITY_GROUP_CHECKS = frozenset({
    "ec2.security_group.unrestricted_ssh",
    "ec2.security_group.unrestricted_rdp",
})
SSM_PARAMETER_CHECKS = frozenset({"ssm.parameter.plaintext_secret"})


def try_fast_finding_recheck(
    db: Session,
    *,
    account: AwsAccount,
    finding: Finding,
    actor: str,
) -> dict[str, Any]:
    """Attempt a direct AWS verification for remediation-backed checks.

    Returns:
      checked=False: unsupported check, caller should use the normal async recheck.
      checked=True/resolved=True: finding was resolved synchronously.
      checked=True/resolved=False: resource still fails or could not be verified;
                                   caller may choose whether to queue a full recheck.
    """
    try:
        if finding.check_id in IAM_ACCESS_KEY_CHECKS:
            return _verify_iam_access_key(db, account=account, finding=finding, actor=actor)
        if finding.check_id in SECURITY_GROUP_CHECKS:
            return _verify_security_group(db, account=account, finding=finding, actor=actor)
        if finding.check_id in SSM_PARAMETER_CHECKS:
            return _verify_ssm_parameter(db, account=account, finding=finding, actor=actor)
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        log.warning(
            "finding.fast_recheck_failed",
            account_id=str(account.id),
            finding_id=str(finding.id),
            check_id=finding.check_id,
            error=str(exc),
        )
        return {"checked": True, "resolved": False, "error": str(exc)[:300]}
    return {"checked": False, "resolved": False}


def _resolve(db: Session, finding: Finding, *, actor: str, note: str) -> dict[str, Any]:
    finding.status = "resolved"
    finding.resolved_at = datetime.now(timezone.utc)
    db.add(FindingEvent(id=uuid.uuid4(), finding_id=finding.id, action="resolved", actor=actor, note=note))
    db.commit()
    return {
        "queued": False,
        "checked": True,
        "resolved": True,
        "finding_id": str(finding.id),
        "check_id": finding.check_id,
    }


def _user_name_from_arn(user_arn: str | None) -> str | None:
    if not user_arn:
        return None
    return user_arn.split("/")[-1] if "/" in user_arn else user_arn


def _access_key_from_finding(finding: Finding) -> tuple[str | None, str | None]:
    evidence = finding.evidence or {}
    user_arn = evidence.get("user_arn")
    key_id = evidence.get("key_id")
    if user_arn and key_id:
        return str(user_arn), str(key_id)
    raw = finding.resource_arn or ""
    if "#" in raw:
        user, key = raw.split("#", 1)
        return user, key
    return None, None


def _verify_iam_access_key(db: Session, *, account: AwsAccount, finding: Finding, actor: str) -> dict[str, Any]:
    user_arn, key_id = _access_key_from_finding(finding)
    user_name = _user_name_from_arn(user_arn)
    if not user_name or not key_id:
        return {"checked": True, "resolved": False, "error": "missing access key context"}

    sess = assume_role(
        account.role_arn,
        account.external_id,
        session_name="vigil-fast-recheck",
        aws_account=account,
        purpose="fast_recheck_iam_access_key",
    )
    iam = sess.client("iam")
    try:
        keys = iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", [])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return _resolve(db, finding, actor=actor, note="Fast verify: IAM user no longer exists")
        raise

    match = next((k for k in keys if k.get("AccessKeyId") == key_id), None)
    if not match:
        row = db.scalar(
            select(IamAccessKey).where(IamAccessKey.account_id == account.id, IamAccessKey.key_id == key_id)
        )
        if row:
            row.status = "Deleted"
        return _resolve(db, finding, actor=actor, note="Fast verify: access key no longer exists")

    status = match.get("Status")
    row = db.scalar(select(IamAccessKey).where(IamAccessKey.account_id == account.id, IamAccessKey.key_id == key_id))
    if row:
        row.status = status or row.status
    if status != "Active":
        return _resolve(db, finding, actor=actor, note=f"Fast verify: access key is {status or 'not active'}")

    db.commit()
    return {"queued": False, "checked": True, "resolved": False, "reason": "access_key_still_active"}


def _resource_region(finding: Finding) -> str:
    evidence = finding.evidence or {}
    if evidence.get("region"):
        return str(evidence["region"])
    parts = (finding.resource_arn or "").split(":")
    if len(parts) > 3 and parts[3]:
        return parts[3]
    return "us-east-1"


def _security_group_id(finding: Finding) -> str | None:
    evidence = finding.evidence or {}
    if evidence.get("group_id"):
        return str(evidence["group_id"])
    arn = finding.resource_arn or ""
    if "/security-group/" in arn:
        return arn.split("/security-group/")[-1]
    if "/" in arn:
        return arn.rsplit("/", 1)[-1]
    return arn or None


def _expected_port(check_id: str) -> int | None:
    if check_id == "ec2.security_group.unrestricted_ssh":
        return 22
    if check_id == "ec2.security_group.unrestricted_rdp":
        return 3389
    return None


def _permission_publicly_exposes_port(perm: dict[str, Any], port: int | None) -> bool:
    public = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", [])) or any(
        r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", [])
    )
    if not public:
        return False
    proto = str(perm.get("IpProtocol", ""))
    if proto == "-1":
        return True
    if port is None:
        return True
    from_port = perm.get("FromPort")
    to_port = perm.get("ToPort")
    if from_port is None or to_port is None:
        return False
    return int(from_port) <= port <= int(to_port)


def _verify_security_group(db: Session, *, account: AwsAccount, finding: Finding, actor: str) -> dict[str, Any]:
    group_id = _security_group_id(finding)
    if not group_id:
        return {"checked": True, "resolved": False, "error": "missing security group id"}
    region = _resource_region(finding)
    sess = assume_role(
        account.role_arn,
        account.external_id,
        session_name="vigil-fast-recheck",
        aws_account=account,
        purpose="fast_recheck_security_group",
    )
    ec2 = sess.client("ec2", region_name=region)
    try:
        group = ec2.describe_security_groups(GroupIds=[group_id]).get("SecurityGroups", [])[0]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in {"InvalidGroup.NotFound", "InvalidGroupId.NotFound"}:
            return _resolve(db, finding, actor=actor, note="Fast verify: security group no longer exists")
        raise

    port = _expected_port(finding.check_id)
    still_exposed = any(_permission_publicly_exposes_port(perm, port) for perm in group.get("IpPermissions", []))
    if not still_exposed:
        return _resolve(db, finding, actor=actor, note="Fast verify: public ingress is no longer present")
    return {"queued": False, "checked": True, "resolved": False, "reason": "security_group_still_exposed"}


def _ssm_parameter_name(finding: Finding) -> str | None:
    evidence = finding.evidence or {}
    if evidence.get("parameter_name"):
        return str(evidence["parameter_name"])
    arn = finding.resource_arn or ""
    if ":parameter/" in arn:
        return "/" + arn.split(":parameter/", 1)[-1]
    if ":parameter" in arn:
        return arn.split(":parameter", 1)[-1]
    return None


def _verify_ssm_parameter(db: Session, *, account: AwsAccount, finding: Finding, actor: str) -> dict[str, Any]:
    name = _ssm_parameter_name(finding)
    if not name:
        return {"checked": True, "resolved": False, "error": "missing SSM parameter name"}
    region = _resource_region(finding)
    sess = assume_role(
        account.role_arn,
        account.external_id,
        session_name="vigil-fast-recheck",
        aws_account=account,
        purpose="fast_recheck_ssm_parameter",
    )
    ssm = sess.client("ssm", region_name=region)
    try:
        param = ssm.get_parameter(Name=name, WithDecryption=False).get("Parameter", {})
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ParameterNotFound":
            return _resolve(db, finding, actor=actor, note="Fast verify: SSM parameter no longer exists")
        raise

    ptype = param.get("Type")
    row = db.scalar(select(SsmParameter).where(SsmParameter.account_id == account.id, SsmParameter.name == name))
    if row:
        row.type = ptype or row.type
    if ptype == "SecureString":
        return _resolve(db, finding, actor=actor, note="Fast verify: SSM parameter is SecureString")

    db.commit()
    return {"queued": False, "checked": True, "resolved": False, "reason": "ssm_parameter_still_plaintext"}
