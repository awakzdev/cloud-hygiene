"""IAM collectors. Pull raw AWS data → upsert into normalized tables."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Iterable

import structlog
from botocore.exceptions import ClientError
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.aws import assume_role
from app.models import AwsAccount, IamAccessKey, IamPolicy, IamRole, IamUser
from app.models.resources import IamPasswordPolicy

log = structlog.get_logger()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def collect_iam(db: Session, account: AwsAccount) -> dict:
    """Collect IAM users, console password state, MFA, access keys + last-used."""
    log.info("collect_iam.start", account_id=str(account.id), role_arn=account.role_arn)
    sess = assume_role(account.role_arn, account.external_id, session_name="vigil-collect")
    iam = sess.client("iam")

    user_count = 0
    key_count = 0

    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for u in page["Users"]:
            user_count += 1
            log.debug("collect_iam.user", username=u["UserName"], n=user_count)
            mfa_enabled = _has_mfa(iam, u["UserName"])
            has_pw = _has_console_password(iam, u["UserName"])
            _upsert_user(
                db,
                account.id,
                arn=u["Arn"],
                name=u["UserName"],
                created=u.get("CreateDate"),
                password_last_used=u.get("PasswordLastUsed"),
                has_console_password=has_pw,
                mfa_enabled=mfa_enabled,
            )
            for k in iam.list_access_keys(UserName=u["UserName"]).get("AccessKeyMetadata", []):
                key_count += 1
                last_used = iam.get_access_key_last_used(AccessKeyId=k["AccessKeyId"]).get("AccessKeyLastUsed", {})
                _upsert_key(
                    db,
                    account.id,
                    user_arn=u["Arn"],
                    key_id=k["AccessKeyId"],
                    status=k["Status"],
                    created=k.get("CreateDate"),
                    last_used=last_used.get("LastUsedDate"),
                    last_used_service=last_used.get("ServiceName"),
                    last_used_region=last_used.get("Region"),
                )

    log.info("collect_iam.users_done", users=user_count, access_keys=key_count)
    db.commit()

    role_count = _collect_roles(db, sess, account)
    db.commit()

    _collect_password_policy(db, iam, account)
    db.commit()

    policy_count = _collect_managed_policies(db, iam, account)
    db.commit()

    log.info("collect_iam.done", users=user_count, access_keys=key_count, roles=role_count, policies=policy_count)
    return {"iam_users": user_count, "iam_access_keys": key_count, "iam_roles": role_count}


def _collect_password_policy(db: Session, iam_client, account: AwsAccount) -> None:
    try:
        pol = iam_client.get_account_password_policy()["PasswordPolicy"]
        exists = True
        min_length = pol.get("MinimumPasswordLength")
        require_uppercase = pol.get("RequireUppercaseCharacters", False)
        require_lowercase = pol.get("RequireLowercaseCharacters", False)
        require_numbers = pol.get("RequireNumbers", False)
        require_symbols = pol.get("RequireSymbols", False)
        max_age = pol.get("MaxPasswordAge")
        reuse = pol.get("PasswordReusePrevention")
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            exists = False
            min_length = require_uppercase = require_lowercase = require_numbers = require_symbols = None
            max_age = reuse = None
        else:
            return

    stmt = pg_insert(IamPasswordPolicy).values(
        id=uuid.uuid5(uuid.NAMESPACE_URL, f"{account.id}:password_policy"),
        account_id=account.id,
        exists=exists,
        min_length=min_length,
        require_uppercase=bool(require_uppercase),
        require_lowercase=bool(require_lowercase),
        require_numbers=bool(require_numbers),
        require_symbols=bool(require_symbols),
        max_age=max_age,
        password_reuse_prevention=reuse,
        last_seen=_now(),
    ).on_conflict_do_update(
        index_elements=["account_id"],
        set_={
            "exists": exists,
            "min_length": min_length,
            "require_uppercase": bool(require_uppercase),
            "require_lowercase": bool(require_lowercase),
            "require_numbers": bool(require_numbers),
            "require_symbols": bool(require_symbols),
            "max_age": max_age,
            "password_reuse_prevention": reuse,
            "last_seen": _now(),
        },
    )
    db.execute(stmt)


def _collect_roles(db: Session, sess, account: AwsAccount) -> int:
    log.info("collect_roles.start", account_id=str(account.id))
    iam = sess.client("iam")
    role_count = 0
    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for r in page["Roles"]:
            role_count += 1
            last_used = r.get("RoleLastUsed", {}).get("LastUsedDate")

            inline_policies: dict = {}
            try:
                for pname in iam.list_role_policies(RoleName=r["RoleName"]).get("PolicyNames", []):
                    doc = iam.get_role_policy(RoleName=r["RoleName"], PolicyName=pname)
                    inline_policies[pname] = doc["PolicyDocument"]
            except ClientError:
                pass

            attached_policies: list = []
            try:
                attached = iam.list_attached_role_policies(RoleName=r["RoleName"]).get("AttachedPolicies", [])
                for pol in attached:
                    pol_arn = pol["PolicyArn"]
                    pol_name = pol["PolicyName"]
                    pol_type = "aws_managed" if pol_arn.startswith("arn:aws:iam::aws:") else "customer_managed"
                    statements = []
                    try:
                        version_id = iam.get_policy(PolicyArn=pol_arn)["Policy"]["DefaultVersionId"]
                        doc = iam.get_policy_version(PolicyArn=pol_arn, VersionId=version_id)
                        raw = doc["PolicyVersion"]["Document"].get("Statement", [])
                        statements = raw if isinstance(raw, list) else [raw]
                    except ClientError:
                        pass
                    attached_policies.append({
                        "policy_arn": pol_arn,
                        "policy_name": pol_name,
                        "policy_type": pol_type,
                        "statements": statements,
                    })
            except ClientError:
                pass

            _upsert_role(
                db,
                account.id,
                arn=r["Arn"],
                name=r["RoleName"],
                created=r.get("CreateDate"),
                last_assumed=last_used,
                trust_policy=r["AssumeRolePolicyDocument"],
                inline_policies=inline_policies,
                attached_policies=attached_policies,
            )
    log.info("collect_roles.done", roles=role_count)
    return role_count


def _upsert_role(db: Session, account_id, *, arn, name, created, last_assumed, trust_policy, inline_policies, attached_policies):
    stmt = pg_insert(IamRole).values(
        id=uuid.uuid4(),
        account_id=account_id,
        arn=arn,
        name=name,
        created=created,
        last_assumed=last_assumed,
        trust_policy=trust_policy,
        inline_policies=inline_policies,
        attached_policies=attached_policies,
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["account_id", "arn"],
        set_={
            "name": stmt.excluded.name,
            "last_assumed": stmt.excluded.last_assumed,
            "trust_policy": stmt.excluded.trust_policy,
            "inline_policies": stmt.excluded.inline_policies,
            "attached_policies": stmt.excluded.attached_policies,
        },
    )
    db.execute(stmt)


def _has_mfa(iam, username: str) -> bool:
    try:
        devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
        return len(devices) > 0
    except ClientError:
        return False


def _has_console_password(iam, username: str) -> bool:
    try:
        iam.get_login_profile(UserName=username)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return False
        raise


def _upsert_user(db: Session, account_id, *, arn, name, created, password_last_used, has_console_password, mfa_enabled):
    stmt = pg_insert(IamUser).values(
        id=uuid.uuid4(),
        account_id=account_id,
        arn=arn,
        name=name,
        created=created,
        password_last_used=password_last_used,
        has_console_password=has_console_password,
        mfa_enabled=mfa_enabled,
        last_seen_at=_now(),
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["account_id", "arn"],
        set_={
            "name": stmt.excluded.name,
            "created": stmt.excluded.created,
            "password_last_used": stmt.excluded.password_last_used,
            "has_console_password": stmt.excluded.has_console_password,
            "mfa_enabled": stmt.excluded.mfa_enabled,
            "last_seen_at": stmt.excluded.last_seen_at,
        },
    )
    db.execute(stmt)


def _upsert_key(db: Session, account_id, *, user_arn, key_id, status, created, last_used, last_used_service, last_used_region):
    stmt = pg_insert(IamAccessKey).values(
        id=uuid.uuid4(),
        account_id=account_id,
        user_arn=user_arn,
        key_id=key_id,
        status=status,
        created=created,
        last_used=last_used,
        last_used_service=last_used_service,
        last_used_region=last_used_region,
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["account_id", "key_id"],
        set_={
            "user_arn": stmt.excluded.user_arn,
            "status": stmt.excluded.status,
            "created": stmt.excluded.created,
            "last_used": stmt.excluded.last_used,
            "last_used_service": stmt.excluded.last_used_service,
            "last_used_region": stmt.excluded.last_used_region,
        },
    )
    db.execute(stmt)


def _collect_managed_policies(db: Session, iam_client, account: AwsAccount) -> int:
    """Collect customer-managed IAM policies with attachment count and policy document."""
    count = 0
    paginator = iam_client.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local"):
        for pol in page.get("Policies", []):
            arn = pol["Arn"]
            name = pol["PolicyName"]
            attachment_count = pol.get("AttachmentCount", 0)
            version_id = pol.get("DefaultVersionId", "v1")
            document: dict = {}
            try:
                doc_resp = iam_client.get_policy_version(PolicyArn=arn, VersionId=version_id)
                document = doc_resp["PolicyVersion"].get("Document", {})
            except ClientError:
                pass
            stmt = pg_insert(IamPolicy).values(
                id=uuid.uuid5(uuid.NAMESPACE_URL, f"{account.id}:{arn}"),
                account_id=account.id,
                arn=arn,
                name=name,
                attachment_count=attachment_count,
                document=document,
            ).on_conflict_do_update(
                index_elements=["account_id", "arn"],
                set_={
                    "attachment_count": attachment_count,
                    "document": document,
                },
            )
            db.execute(stmt)
            count += 1
    return count
