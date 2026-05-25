from __future__ import annotations

import uuid
from datetime import datetime, timezone

import structlog
from sqlalchemy import select

from app.checks.persist import persist_findings
from app.checks.registry import ALL_CHECKS
from app.checks import role_unused_services
from app.collectors.iam import collect_iam
from app.collectors.last_accessed import collect_perm_usage
from app.collectors.account import collect_s3, collect_kms
from app.core.db import SessionLocal
from app.models import AwsAccount, ScanRun, EvidenceSnapshot
from app.models.iam import IamUser, IamAccessKey, IamRole
from app.models.resources import S3Bucket, KmsKey
from app.models.org import Org
from app.worker.celery_app import celery_app

# maps check_id prefix → collector function(db, acc)
_COLLECTOR_FOR_CHECK = {
    "iam.": lambda db, acc: collect_iam(db, acc),
    "s3.": lambda db, acc: collect_s3(db, acc),
    "kms.": lambda db, acc: collect_kms(db, acc),
}

_CHECK_BY_ID = {mod.CHECK_ID: mod for mod in ALL_CHECKS}

log = structlog.get_logger()


def _write_evidence_snapshots(db, acc: AwsAccount, run: ScanRun) -> int:
    """Snapshot all collected entities for this scan run into evidence_snapshots."""
    snaps = []

    # IAM users
    for u in db.scalars(select(IamUser).where(IamUser.account_id == acc.id)).all():
        snaps.append(EvidenceSnapshot(
            id=uuid.uuid4(),
            scan_run_id=run.id,
            account_id=acc.id,
            org_id=acc.org_id,
            entity_type="iam_user",
            entity_id=u.arn,
            payload_json={
                "username": u.username,
                "arn": u.arn,
                "has_console_password": u.has_console_password,
                "mfa_active": u.mfa_active,
                "last_used_at": u.last_used_at.isoformat() if u.last_used_at else None,
                "created_at": u.created_at.isoformat() if u.created_at else None,
            },
        ))

    # IAM access keys
    for k in db.scalars(select(IamAccessKey).where(IamAccessKey.account_id == acc.id)).all():
        snaps.append(EvidenceSnapshot(
            id=uuid.uuid4(),
            scan_run_id=run.id,
            account_id=acc.id,
            org_id=acc.org_id,
            entity_type="iam_access_key",
            entity_id=k.access_key_id,
            payload_json={
                "access_key_id": k.access_key_id,
                "username": k.username,
                "status": k.status,
                "created_at": k.created_at.isoformat() if k.created_at else None,
                "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
            },
        ))

    # IAM roles
    for r in db.scalars(select(IamRole).where(IamRole.account_id == acc.id)).all():
        snaps.append(EvidenceSnapshot(
            id=uuid.uuid4(),
            scan_run_id=run.id,
            account_id=acc.id,
            org_id=acc.org_id,
            entity_type="iam_role",
            entity_id=r.arn,
            payload_json={
                "role_name": r.role_name,
                "arn": r.arn,
                "last_used_at": r.last_used_at.isoformat() if r.last_used_at else None,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "trust_policy": r.trust_policy,
            },
        ))

    # S3 buckets
    for b in db.scalars(select(S3Bucket).where(S3Bucket.account_id == acc.id)).all():
        snaps.append(EvidenceSnapshot(
            id=uuid.uuid4(),
            scan_run_id=run.id,
            account_id=acc.id,
            org_id=acc.org_id,
            entity_type="s3_bucket",
            entity_id=b.arn,
            payload_json={
                "name": b.name,
                "arn": b.arn,
                "logging_enabled": b.logging_enabled,
                "encrypted": b.encrypted,
                "kms_encrypted": b.kms_encrypted,
                "versioning_enabled": b.versioning_enabled,
                "public_access_blocked": b.public_access_blocked,
                "https_only": b.https_only,
            },
        ))

    # KMS keys
    for k in db.scalars(select(KmsKey).where(KmsKey.account_id == acc.id)).all():
        snaps.append(EvidenceSnapshot(
            id=uuid.uuid4(),
            scan_run_id=run.id,
            account_id=acc.id,
            org_id=acc.org_id,
            entity_type="kms_key",
            entity_id=k.arn,
            payload_json={
                "key_id": k.key_id,
                "arn": k.arn,
                "alias": k.alias,
                "rotation_enabled": k.rotation_enabled,
                "key_state": k.key_state,
                "has_wildcard_principal": k.has_wildcard_principal,
            },
        ))

    db.add_all(snaps)
    return len(snaps)


@celery_app.task(name="app.worker.tasks.run_scan")
def run_scan(account_id: str) -> dict:
    db = SessionLocal()
    acc = db.get(AwsAccount, uuid.UUID(account_id))
    if not acc:
        return {"error": "account not found"}

    run = ScanRun(id=uuid.uuid4(), account_id=acc.id, status="running")
    db.add(run)
    db.commit()

    try:
        stats = collect_iam(db, acc)
        stats["s3_buckets"] = collect_s3(db, acc)
        stats["kms_keys"] = collect_kms(db, acc)

        org_obj = db.get(Org, acc.org_id)
        check_cfg = (org_obj.settings or {}).get("checks", {}) if org_obj else {}

        drafts = []
        check_ids_run: set[str] = set()
        for mod in ALL_CHECKS:
            if check_cfg.get(mod.CHECK_ID, {}).get("enabled", True) is False:
                continue
            check_ids_run.add(mod.CHECK_ID)
            drafts.extend(mod.run(db, acc.id))

        opened, resolved = persist_findings(
            db,
            org_id=acc.org_id,
            account_id=acc.id,
            drafts=drafts,
            check_ids_run=check_ids_run,
        )

        snap_count = _write_evidence_snapshots(db, acc, run)

        run.status = "ok"
        run.finished_at = datetime.now(timezone.utc)
        run.stats = stats | {"checks_run": list(check_ids_run), "drafts": len(drafts), "snapshots": snap_count}
        run.findings_opened = opened
        run.findings_resolved = resolved
        acc.last_scan_at = run.finished_at
        db.commit()
        log.info("scan.complete", account_id=str(acc.id), opened=opened, resolved=resolved, snapshots=snap_count)

        collect_perm_usage_task.delay(account_id)

        return {"ok": True, "opened": opened, "resolved": resolved, "snapshots": snap_count}
    except Exception as e:  # noqa: BLE001
        db.rollback()
        run.status = "error"
        run.error = str(e)[:1900]
        run.finished_at = datetime.now(timezone.utc)
        db.commit()
        log.exception("scan.failed", account_id=str(acc.id))
        return {"ok": False, "error": str(e)}
    finally:
        db.close()


@celery_app.task(name="app.worker.tasks.collect_perm_usage_task")
def collect_perm_usage_task(account_id: str) -> dict:
    """Background task: collect service last-accessed per role, then re-run unused_services check."""
    db = SessionLocal()
    try:
        acc = db.get(AwsAccount, uuid.UUID(account_id))
        if not acc:
            return {"error": "account not found"}

        count = collect_perm_usage(db, acc)

        drafts = role_unused_services.run(db, acc.id)
        if drafts:
            persist_findings(
                db,
                org_id=acc.org_id,
                account_id=acc.id,
                drafts=drafts,
                check_ids_run={role_unused_services.CHECK_ID},
            )

        log.info("perm_usage.complete", account_id=account_id, upserted=count, findings=len(drafts))
        return {"ok": True, "upserted": count, "findings": len(drafts)}
    except Exception as e:  # noqa: BLE001
        db.rollback()
        log.exception("perm_usage.failed", account_id=account_id)
        return {"ok": False, "error": str(e)}
    finally:
        db.close()


@celery_app.task(name="app.worker.tasks.recheck_finding")
def recheck_finding(account_id: str, check_id: str) -> dict:
    """Re-collect only what's needed for check_id, then rerun that check."""
    db = SessionLocal()
    try:
        acc = db.get(AwsAccount, uuid.UUID(account_id))
        if not acc:
            return {"error": "account not found"}

        collector = next(
            (fn for prefix, fn in _COLLECTOR_FOR_CHECK.items() if check_id.startswith(prefix)),
            None,
        )
        if collector:
            collector(db, acc)

        mod = _CHECK_BY_ID.get(check_id)
        if not mod:
            return {"error": f"unknown check: {check_id}"}

        drafts = mod.run(db, acc.id)
        opened, resolved = persist_findings(
            db,
            org_id=acc.org_id,
            account_id=acc.id,
            drafts=drafts,
            check_ids_run={check_id},
        )
        log.info("recheck.complete", account_id=account_id, check_id=check_id, opened=opened, resolved=resolved)
        return {"ok": True, "opened": opened, "resolved": resolved}
    except Exception as e:  # noqa: BLE001
        db.rollback()
        log.exception("recheck.failed", account_id=account_id, check_id=check_id)
        return {"ok": False, "error": str(e)}
    finally:
        db.close()


@celery_app.task(name="app.worker.tasks.scan_all_accounts")
def scan_all_accounts() -> dict:
    db = SessionLocal()
    try:
        rows = db.scalars(select(AwsAccount).where(AwsAccount.status == "connected")).all()
        for acc in rows:
            run_scan.delay(str(acc.id))
        return {"queued": len(rows)}
    finally:
        db.close()
