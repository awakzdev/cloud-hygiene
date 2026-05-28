"""Collect significant CloudTrail write events for correlation analysis.

Uses LookupEvents to pull infrastructure-changing events from the last 90 days.
Only collects management/write events (not read-only calls) for a focused signal.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import structlog
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.aws import assume_role
from app.models import AwsAccount
from app.models.cloudtrail import CloudTrailEvent

log = structlog.get_logger()

# High-signal write events to collect for correlation
TRACKED_EVENTS = {
    # IAM
    "CreateUser", "DeleteUser", "AttachUserPolicy", "DetachUserPolicy",
    "CreateRole", "DeleteRole", "AttachRolePolicy", "DetachRolePolicy",
    "CreatePolicy", "DeletePolicy",
    "AddUserToGroup", "RemoveUserFromGroup",
    # Security groups
    "AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress",
    "AuthorizeSecurityGroupEgress", "RevokeSecurityGroupEgress",
    "CreateSecurityGroup", "DeleteSecurityGroup",
    # S3
    "PutBucketPolicy", "DeleteBucketPolicy", "PutBucketAcl",
    "PutBucketPublicAccessBlock",
    # EC2 / compute
    "RunInstances", "TerminateInstances",
    # KMS
    "CreateKey", "DisableKey", "ScheduleKeyDeletion",
    # CloudTrail
    "StopLogging", "DeleteTrail",
    # Config / GuardDuty
    "DeleteDetector", "StopConfigurationRecorder",
}

_LOOKBACK_DAYS = 90
_MAX_EVENTS_PER_RUN = 1000


def _dedupe_resources(resources: list[dict]) -> list[dict]:
    seen: set[str] = set()
    out: list[dict] = []
    for r in resources:
        name = r.get("name") or ""
        typ = (r.get("type") or "").lower()
        display = name.split("/")[-1] if name.startswith("arn:") else name
        key = f"{typ}|{display.lower()}"
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def collect_cloudtrail_events(db: Session, account: AwsAccount) -> int:
    sess = assume_role(account.role_arn, account.external_id, session_name="vigil-ct-events", aws_account=account, purpose="collect_cloudtrail_events")
    ct = sess.client("cloudtrail", region_name="us-east-1")
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=_LOOKBACK_DAYS)

    collected = 0
    paginator = ct.get_paginator("lookup_events")
    pages = paginator.paginate(
        StartTime=start,
        EndTime=now,
        PaginationConfig={"MaxItems": _MAX_EVENTS_PER_RUN, "PageSize": 50},
    )

    try:
        for page in pages:
            for evt in page.get("Events", []):
                event_name = evt.get("EventName", "")
                if event_name not in TRACKED_EVENTS:
                    continue

                event_id = evt.get("EventId", "")
                if not event_id:
                    continue

                ct_event = (evt.get("CloudTrailEvent") or "{}")
                if isinstance(ct_event, str):
                    import json
                    try:
                        ct_event = json.loads(ct_event)
                    except Exception:
                        ct_event = {}

                actor = (
                    (ct_event.get("userIdentity") or {}).get("arn")
                    or (ct_event.get("userIdentity") or {}).get("userName")
                    or evt.get("Username")
                )
                source_ip = ct_event.get("sourceIPAddress")
                event_time = evt.get("EventTime", now)
                resources = _dedupe_resources([
                    {"type": r.get("ResourceType"), "name": r.get("ResourceName")}
                    for r in (evt.get("Resources") or [])
                ])

                stmt = pg_insert(CloudTrailEvent).values(
                    id=uuid.uuid4(),
                    account_id=account.id,
                    event_id=event_id,
                    event_name=event_name,
                    event_source=evt.get("EventSource", ""),
                    event_time=event_time,
                    actor=actor,
                    source_ip=source_ip,
                    resources=resources,
                    raw=ct_event,
                    last_seen=now,
                ).on_conflict_do_update(
                    constraint="uq_cloudtrail_event_account_id",
                    set_={"last_seen": now, "raw": ct_event},
                )
                db.execute(stmt)
                collected += 1

            if collected >= _MAX_EVENTS_PER_RUN:
                break
    except Exception as e:  # noqa: BLE001
        log.warning("cloudtrail_events.error", account_id=str(account.id), error=str(e))

    db.commit()
    log.info("cloudtrail_events.done", account_id=str(account.id), collected=collected)
    return collected
