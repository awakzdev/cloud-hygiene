"""Collect AWS Security Hub enablement per region."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import structlog
from botocore.exceptions import ClientError
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.aws import assume_role
from app.models import AwsAccount
from app.models.resources import SecurityHubStatus

log = structlog.get_logger()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _get_regions(sess) -> list[str]:
    ec2 = sess.client("ec2", region_name="us-east-1")
    return [
        r["RegionName"]
        for r in ec2.describe_regions(
            Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
        )["Regions"]
    ]


def collect_securityhub(db: Session, account: AwsAccount) -> int:
    sess = assume_role(account.role_arn, account.external_id, session_name="vigil-securityhub")
    regions = _get_regions(sess)
    count = 0

    for region in regions:
        enabled = False
        hub_arn = None
        try:
            client = sess.client("securityhub", region_name=region)
            hub = client.describe_hub()
            hub_arn = hub.get("HubArn")
            enabled = bool(hub_arn)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code not in {"InvalidAccessException", "ResourceNotFoundException"}:
                log.debug("collect_securityhub.region_failed", region=region, error=code)

        stmt = pg_insert(SecurityHubStatus).values(
            id=uuid.uuid5(uuid.NAMESPACE_URL, f"{account.id}:securityhub:{region}"),
            account_id=account.id,
            region=region,
            hub_arn=hub_arn,
            enabled=enabled,
            last_seen=_now(),
        ).on_conflict_do_update(
            index_elements=["account_id", "region"],
            set_={"hub_arn": hub_arn, "enabled": enabled, "last_seen": _now()},
        )
        db.execute(stmt)
        count += 1

    db.commit()
    log.info("collect_securityhub.done", account_id=str(account.id), regions=count)
    return count
