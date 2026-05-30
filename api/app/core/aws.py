from __future__ import annotations

import json
import os
import uuid
from typing import TYPE_CHECKING

import boto3
import structlog
from botocore.config import Config
from botocore.exceptions import ClientError

from app.core.aws_trust import merge_trust_principal, parse_role_account, parse_role_name
from app.core.config import get_settings

if TYPE_CHECKING:
    from app.models import AwsAccount

log = structlog.get_logger()

# Docker Compose passes unset vars as empty strings, which breaks boto3's
# credential chain (e.g. AWS_PROFILE="" → "profile () not found").
for _var in ("AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
    if _var in os.environ and os.environ[_var] == "":
        del os.environ[_var]

settings = get_settings()
_boto_cfg = Config(retries={"max_attempts": 8, "mode": "standard"}, user_agent_extra="vigil/0.1")


def _audit_assume_role(
    *,
    aws_account: "AwsAccount | None",
    role_arn: str | None,
    session_name: str,
    purpose: str | None,
    success: bool,
    error_code: str | None,
    error_message: str | None,
) -> None:
    """Persist an audit log row for every sts:AssumeRole attempt."""
    try:
        from app.core.db import SessionLocal
        from app.models import AssumeRoleAudit

        db = SessionLocal()
        try:
            db.add(AssumeRoleAudit(
                id=uuid.uuid4(),
                org_id=aws_account.org_id if aws_account is not None else None,
                aws_account_id=aws_account.id if aws_account is not None else None,
                role_arn=role_arn,
                session_name=session_name[:120] if session_name else None,
                purpose=(purpose or session_name or "")[:80] or None,
                success=success,
                error_code=(error_code or "")[:120] or None,
                error_message=(error_message or "")[:500] or None,
            ))
            db.commit()
        finally:
            db.close()
    except Exception:  # noqa: BLE001
        log.exception("assume_role_audit.write_failed")


def _caller_iam_principal() -> tuple[str, str]:
    """Return (account_id, IAM ARN suitable for role trust Principal.AWS)."""
    sts = boto3.client("sts", config=_boto_cfg)
    ident = sts.get_caller_identity()
    arn = ident["Arn"]
    account_id = ident["Account"]
    if ":assumed-role/" in arn:
        role_name = arn.split(":assumed-role/")[1].split("/")[0]
        iam = boto3.client("iam", config=_boto_cfg)
        role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
        return account_id, role_arn
    return account_id, arn


def ensure_vigil_role_trust(role_arn: str, external_id: str) -> bool:
    """Add current caller + external_id to VigilReadOnly trust (dev only). Returns True if updated."""
    if settings.APP_ENV != "dev":
        return False
    role_name = parse_role_name(role_arn)
    if not role_name or not external_id:
        return False
    try:
        caller_acct, caller_iam = _caller_iam_principal()
    except ClientError:
        log.warning("ensure_vigil_role_trust.caller_identity_failed")
        return False
    if caller_acct != parse_role_account(role_arn):
        return False
    iam = boto3.client("iam", config=_boto_cfg)
    try:
        doc = iam.get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"]
        merged = merge_trust_principal(doc, caller_iam, external_id)
        if merged == doc:
            return False
        iam.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(merged),
        )
        log.info(
            "ensure_vigil_role_trust.updated",
            role_name=role_name,
            principal=caller_iam,
        )
        return True
    except ClientError as e:
        log.warning(
            "ensure_vigil_role_trust.failed",
            role_name=role_name,
            error_code=e.response.get("Error", {}).get("Code"),
        )
        return False


def _dev_use_direct_session(role_arn: str) -> bool:
    """Same-account dev: scan with SSO/admin creds when AssumeRole is blocked."""
    if settings.APP_ENV != "dev":
        return False
    try:
        caller_acct, _ = _caller_iam_principal()
    except ClientError:
        return False
    return caller_acct == parse_role_account(role_arn)


def _sts_assume(role_arn: str, external_id: str, session_name: str) -> dict:
    sts = boto3.client("sts", config=_boto_cfg)
    return sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name,
        ExternalId=external_id,
        DurationSeconds=3600,
    )


def assume_role(
    role_arn: str,
    external_id: str,
    session_name: str = "vigil-scan",
    *,
    aws_account: "AwsAccount | None" = None,
    purpose: str | None = None,
    strict: bool = False,
) -> boto3.Session:
    """Assume the customer's read-only role and return a session.

    In ``APP_ENV=dev``, if AssumeRole is denied for same-account SSO users we:
    1) try to add the caller to the role trust policy, then retry AssumeRole;
    2) if still denied, use the caller session directly (admin SSO already has read access).
    """
    try:
        resp = _sts_assume(role_arn, external_id, session_name)
    except ClientError as e:
        err = e.response.get("Error", {})
        code = err.get("Code")
        if code == "AccessDenied" and settings.APP_ENV == "dev" and not strict:
            if ensure_vigil_role_trust(role_arn, external_id):
                try:
                    resp = _sts_assume(role_arn, external_id, session_name)
                    _audit_assume_role(
                        aws_account=aws_account,
                        role_arn=role_arn,
                        session_name=session_name,
                        purpose=purpose,
                        success=True,
                        error_code=None,
                        error_message="dev: trust policy auto-updated",
                    )
                    c = resp["Credentials"]
                    return boto3.Session(
                        aws_access_key_id=c["AccessKeyId"],
                        aws_secret_access_key=c["SecretAccessKey"],
                        aws_session_token=c["SessionToken"],
                    )
                except ClientError:
                    pass
            if not strict and _dev_use_direct_session(role_arn):
                log.warning(
                    "assume_role.dev_direct_session",
                    role_arn=role_arn,
                    purpose=purpose,
                )
                _audit_assume_role(
                    aws_account=aws_account,
                    role_arn=role_arn,
                    session_name=session_name,
                    purpose=purpose,
                    success=True,
                    error_code=None,
                    error_message="dev: direct session (SSO same account)",
                )
                return boto3.Session()
        _audit_assume_role(
            aws_account=aws_account,
            role_arn=role_arn,
            session_name=session_name,
            purpose=purpose,
            success=False,
            error_code=code,
            error_message=err.get("Message"),
        )
        raise
    except Exception as e:  # noqa: BLE001
        _audit_assume_role(
            aws_account=aws_account,
            role_arn=role_arn,
            session_name=session_name,
            purpose=purpose,
            success=False,
            error_code=type(e).__name__,
            error_message=str(e),
        )
        raise

    _audit_assume_role(
        aws_account=aws_account,
        role_arn=role_arn,
        session_name=session_name,
        purpose=purpose,
        success=True,
        error_code=None,
        error_message=None,
    )

    c = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=c["AccessKeyId"],
        aws_secret_access_key=c["SecretAccessKey"],
        aws_session_token=c["SessionToken"],
    )


def verify_account(
    role_arn: str,
    external_id: str,
    *,
    aws_account: "AwsAccount | None" = None,
) -> tuple[bool, str | None, str | None, str | None]:
    """Returns (ok, account_id, alias, error)."""
    try:
        sess = assume_role(
            role_arn,
            external_id,
            session_name="vigil-verify",
            aws_account=aws_account,
            purpose="verify",
            strict=True,
        )
        ident = sess.client("sts", config=_boto_cfg).get_caller_identity()
        account_id = ident["Account"]
        alias = None
        try:
            org = sess.client("organizations", config=_boto_cfg, region_name="us-east-1")
            alias = org.describe_account(AccountId=account_id)["Account"]["Name"]
        except ClientError:
            pass
        if not alias:
            try:
                aliases = sess.client("iam", config=_boto_cfg).list_account_aliases().get("AccountAliases", [])
                alias = aliases[0] if aliases else None
            except ClientError:
                pass
        return True, account_id, alias, None
    except ClientError as e:
        return False, None, None, f"{e.response['Error'].get('Code')}: {e.response['Error'].get('Message')}"
    except Exception as e:  # noqa: BLE001
        return False, None, None, str(e)
