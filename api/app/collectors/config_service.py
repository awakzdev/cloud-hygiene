"""Collect AWS Config recorder + delivery channel status per region."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import structlog
from botocore.exceptions import ClientError
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.aws import assume_role
from app.models import AwsAccount
from app.models.resources import ConfigRecorder

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


def collect_config_service(db: Session, account: AwsAccount) -> int:
    sess = assume_role(account.role_arn, account.external_id, session_name="vigil-config")
    regions = _get_regions(sess)
    count = 0

    for region in regions:
        recorder_name = None
        recording = False
        delivery_channel_exists = False

        try:
            client = sess.client("config", region_name=region)

            recorders = client.describe_configuration_recorders().get("ConfigurationRecorders", [])
            if recorders:
                recorder_name = recorders[0].get("name")
                try:
                    statuses = client.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
                    if statuses:
                        recording = statuses[0].get("recording", False)
                except ClientError:
                    pass

            channels = client.describe_delivery_channels().get("DeliveryChannels", [])
            delivery_channel_exists = len(channels) > 0

        except ClientError:
            pass

        stmt = pg_insert(ConfigRecorder).values(
            id=uuid.uuid5(uuid.NAMESPACE_URL, f"{account.id}:config:{region}"),
            account_id=account.id,
            region=region,
            recorder_name=recorder_name,
            recording=recording,
            delivery_channel_exists=delivery_channel_exists,
            last_seen=_now(),
        ).on_conflict_do_update(
            index_elements=["account_id", "region"],
            set_={
                "recorder_name": recorder_name,
                "recording": recording,
                "delivery_channel_exists": delivery_channel_exists,
                "last_seen": _now(),
            },
        )
        db.execute(stmt)
        count += 1

    db.commit()
    log.info("collect_config_service.done", account_id=str(account.id), regions=count)
    return count
