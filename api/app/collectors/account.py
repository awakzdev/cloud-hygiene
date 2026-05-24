"""Account-level collectors: S3 buckets, KMS keys, account summary."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import structlog
from botocore.exceptions import ClientError
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.aws import assume_role
from app.models import AwsAccount
from app.models.resources import KmsKey, S3Bucket

log = structlog.get_logger()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def collect_s3(db: Session, account: AwsAccount) -> int:
    sess = assume_role(account.role_arn, account.external_id, session_name="vigil-s3")
    s3 = sess.client("s3", region_name="us-east-1")
    count = 0

    buckets = s3.list_buckets().get("Buckets", [])
    for b in buckets:
        name = b["Name"]
        arn = f"arn:aws:s3:::{name}"

        # logging
        try:
            log_cfg = s3.get_bucket_logging(Bucket=name).get("LoggingEnabled")
            logging_enabled = log_cfg is not None
        except ClientError:
            logging_enabled = False

        # encryption
        try:
            enc = s3.get_bucket_encryption(Bucket=name)
            rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
            sse_algo = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
            kms_encrypted = sse_algo == "aws:kms"
            encrypted = True
        except ClientError:
            kms_encrypted = False
            encrypted = False

        # versioning
        try:
            ver = s3.get_bucket_versioning(Bucket=name)
            versioning_enabled = ver.get("Status") == "Enabled"
        except ClientError:
            versioning_enabled = False

        # public access block
        try:
            pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            public_access_blocked = all([
                pab.get("BlockPublicAcls", False),
                pab.get("IgnorePublicAcls", False),
                pab.get("BlockPublicPolicy", False),
                pab.get("RestrictPublicBuckets", False),
            ])
        except ClientError:
            public_access_blocked = False

        # https-only policy
        try:
            policy_str = s3.get_bucket_policy(Bucket=name).get("Policy", "")
            https_only = "aws:SecureTransport" in policy_str
        except ClientError:
            https_only = False

        stmt = pg_insert(S3Bucket).values(
            id=uuid.uuid5(uuid.NAMESPACE_URL, f"{account.id}:{arn}"),
            account_id=account.id,
            name=name,
            arn=arn,
            logging_enabled=logging_enabled,
            encrypted=encrypted,
            kms_encrypted=kms_encrypted,
            versioning_enabled=versioning_enabled,
            public_access_blocked=public_access_blocked,
            https_only=https_only,
            last_seen=_now(),
        ).on_conflict_do_update(
            index_elements=["account_id", "arn"],
            set_={
                "logging_enabled": logging_enabled,
                "encrypted": encrypted,
                "kms_encrypted": kms_encrypted,
                "versioning_enabled": versioning_enabled,
                "public_access_blocked": public_access_blocked,
                "https_only": https_only,
                "last_seen": _now(),
            },
        )
        db.execute(stmt)
        count += 1

    db.commit()
    log.info("collect_s3.done", account_id=str(account.id), buckets=count)
    return count


def collect_kms(db: Session, account: AwsAccount) -> int:
    sess = assume_role(account.role_arn, account.external_id, session_name="vigil-kms")
    kms = sess.client("kms", region_name="us-east-1")
    count = 0

    paginator = kms.get_paginator("list_keys")
    for page in paginator.paginate():
        for k in page["Keys"]:
            key_id = k["KeyId"]
            key_arn = k["KeyArn"]

            try:
                meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
            except ClientError:
                continue

            # skip AWS-managed and AWS-owned keys
            if meta.get("KeyManager") != "CUSTOMER":
                continue
            if meta.get("KeyState") in ("PendingDeletion", "Disabled"):
                continue

            try:
                rotation = kms.get_key_rotation_status(KeyId=key_id)
                rotation_enabled = rotation.get("KeyRotationEnabled", False)
            except ClientError:
                rotation_enabled = False

            try:
                policy_str = kms.get_key_policy(KeyId=key_id, PolicyName="default").get("Policy", "")
                has_wildcard_principal = '"Principal": "*"' in policy_str or '"AWS": "*"' in policy_str
            except ClientError:
                has_wildcard_principal = False

            alias = None
            try:
                aliases = kms.list_aliases(KeyId=key_id).get("Aliases", [])
                alias = aliases[0]["AliasName"] if aliases else None
            except ClientError:
                pass

            stmt = pg_insert(KmsKey).values(
                id=uuid.uuid5(uuid.NAMESPACE_URL, f"{account.id}:{key_arn}"),
                account_id=account.id,
                key_id=key_id,
                arn=key_arn,
                alias=alias,
                rotation_enabled=rotation_enabled,
                has_wildcard_principal=has_wildcard_principal,
                key_state=meta.get("KeyState"),
                last_seen=_now(),
            ).on_conflict_do_update(
                index_elements=["account_id", "arn"],
                set_={
                    "alias": alias,
                    "rotation_enabled": rotation_enabled,
                    "has_wildcard_principal": has_wildcard_principal,
                    "key_state": meta.get("KeyState"),
                    "last_seen": _now(),
                },
            )
            db.execute(stmt)
            count += 1

    db.commit()
    log.info("collect_kms.done", account_id=str(account.id), keys=count)
    return count
