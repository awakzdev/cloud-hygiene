"""Collect IAM service last-accessed details per role via AWS async job API.

Strategy: submit all jobs in parallel, then collect whatever is ready.
AWS caches last-accessed data so most jobs complete in <2s.
"""
from __future__ import annotations

import time
import uuid

import structlog
from botocore.exceptions import ClientError
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.aws import assume_role
from app.models import AwsAccount, IamPermUsage, IamRole

log = structlog.get_logger()

_COLLECT_WAIT = 8    # seconds to wait after submitting all jobs before collecting
_POLL_MAX = 12       # collect-phase retries per job
_ROLE_LIMIT = 100    # process up to 100 non-service roles per scan


def collect_perm_usage(db: Session, account: AwsAccount) -> int:
    sess = assume_role(account.role_arn, account.external_id, session_name="vigil-perm-usage")
    iam = sess.client("iam")

    roles = db.scalars(select(IamRole).where(IamRole.account_id == account.id)).all()
    roles = [r for r in roles if "/aws-service-role/" not in r.arn][:_ROLE_LIMIT]

    # submit all jobs first — ACTION_LEVEL is a superset of SERVICE_LEVEL
    jobs: list[tuple[str, str]] = []  # (role_arn, job_id)
    for role in roles:
        try:
            job_id = iam.generate_service_last_accessed_details(
                Arn=role.arn,
                Granularity="ACTION_LEVEL",
            )["JobId"]
            jobs.append((role.arn, job_id))
        except ClientError as e:
            log.warning("perm_usage.submit_skip", arn=role.arn, error=str(e))

    if not jobs:
        return 0

    # wait once for AWS to process the batch
    time.sleep(_COLLECT_WAIT)

    # collect results — retry briefly per job if still IN_PROGRESS
    upserted = 0
    for role_arn, job_id in jobs:
        try:
            upserted += _collect_job(db, iam, account.id, role_arn, job_id)
        except ClientError as e:
            log.warning("perm_usage.collect_skip", arn=role_arn, error=str(e))

    db.commit()
    log.info("perm_usage.done", roles=len(jobs), upserted=upserted)
    return upserted


def _collect_job(db: Session, iam, account_id, role_arn: str, job_id: str) -> int:
    for attempt in range(_POLL_MAX):
        resp = iam.get_service_last_accessed_details(JobId=job_id)
        status = resp["JobStatus"]
        if status == "COMPLETED":
            count = 0
            for svc in resp.get("ServicesLastAccessed", []):
                _upsert(db, account_id, role_arn, svc)
                count += 1
            return count
        if status == "FAILED":
            return 0
        # still IN_PROGRESS — wait 1s and retry
        time.sleep(1)
    return 0


def _upsert(db: Session, account_id, principal_arn: str, svc: dict) -> None:
    service_ns = (svc.get("ServiceNamespace") or "").lower()
    action_entries = svc.get("ActionLastAccessed", [])
    actions = None
    if action_entries:
        actions = []
        for a in action_entries:
            name = a.get("ActionName")
            la = a.get("LastAuthenticated")
            if not name or la is None:
                continue
            if ":" not in name and service_ns:
                name = f"{service_ns}:{name}"
            if hasattr(la, "isoformat"):
                la = la.isoformat()
            actions.append({"action": name, "last_authenticated": la})
        actions = actions or None

    stmt = pg_insert(IamPermUsage).values(
        id=uuid.uuid4(),
        account_id=account_id,
        principal_arn=principal_arn,
        service=svc["ServiceNamespace"],
        last_authenticated=svc.get("LastAuthenticated"),
        actions_json=actions,
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["account_id", "principal_arn", "service"],
        set_={
            "last_authenticated": stmt.excluded.last_authenticated,
            "actions_json": stmt.excluded.actions_json,
        },
    )
    db.execute(stmt)
