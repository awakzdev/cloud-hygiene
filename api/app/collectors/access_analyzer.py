"""Collect IAM Access Analyzer status per region."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import structlog
from botocore.exceptions import ClientError
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.aws import assume_role
from app.models import AwsAccount
from app.models.resources import AccessAnalyzer

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


def collect_access_analyzer(db: Session, account: AwsAccount) -> int:
    sess = assume_role(account.role_arn, account.external_id, session_name="vigil-access-analyzer")
    regions = _get_regions(sess)
    count = 0

    for region in regions:
        try:
            client = sess.client("accessanalyzer", region_name=region)
            analyzers = client.list_analyzers(type="ACCOUNT").get("analyzers", [])

            active = next((a for a in analyzers if a.get("status") == "ACTIVE"), None)

            if active:
                name = active["name"]
                status = "ACTIVE"
            elif analyzers:
                name = analyzers[0]["name"]
                status = analyzers[0].get("status", "DISABLED")
            else:
                name = None
                status = "none"

            stmt = pg_insert(AccessAnalyzer).values(
                id=uuid.uuid5(uuid.NAMESPACE_URL, f"{account.id}:access_analyzer:{region}"),
                account_id=account.id,
                region=region,
                analyzer_name=name,
                status=status,
                last_seen=_now(),
            ).on_conflict_do_update(
                index_elements=["account_id", "region"],
                set_={"analyzer_name": name, "status": status, "last_seen": _now()},
            )
            db.execute(stmt)
            count += 1

        except ClientError:
            # Region may not support Access Analyzer — record as none
            stmt = pg_insert(AccessAnalyzer).values(
                id=uuid.uuid5(uuid.NAMESPACE_URL, f"{account.id}:access_analyzer:{region}"),
                account_id=account.id,
                region=region,
                analyzer_name=None,
                status="none",
                last_seen=_now(),
            ).on_conflict_do_update(
                index_elements=["account_id", "region"],
                set_={"status": "none", "last_seen": _now()},
            )
            db.execute(stmt)
            count += 1

    db.commit()
    log.info("collect_access_analyzer.done", account_id=str(account.id), regions=count)
    return count
