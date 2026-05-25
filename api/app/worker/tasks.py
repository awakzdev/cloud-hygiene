from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import structlog
from sqlalchemy import select

from app.checks.persist import persist_findings
from app.checks.registry import ALL_CHECKS
from app.checks import role_unused_services
from app.collectors.iam import collect_iam
from app.collectors.last_accessed import collect_perm_usage
from app.collectors.account import collect_s3, collect_kms
from app.collectors.cloudtrail import collect_cloudtrail
from app.collectors.guardduty import collect_guardduty
from app.collectors.vpc import collect_vpc
from app.collectors.rds import collect_rds
from app.collectors.ec2 import collect_ec2
from app.collectors.access_analyzer import collect_access_analyzer
from app.collectors.config_service import collect_config_service
from app.core.db import SessionLocal
from app.models import AwsAccount, ScanRun, EvidenceSnapshot, Finding
from app.models.iam import IamUser, IamAccessKey, IamRole
from app.models.resources import S3Bucket, KmsKey
from app.models.org import Org, User
from app.worker.celery_app import celery_app

# maps check_id prefix → collector function(db, acc)
# More-specific prefixes must come before less-specific ones
_COLLECTOR_FOR_CHECK = {
    "iam.": lambda db, acc: collect_iam(db, acc),
    "s3.": lambda db, acc: collect_s3(db, acc),
    "kms.": lambda db, acc: collect_kms(db, acc),
    "cloudtrail.": lambda db, acc: collect_cloudtrail(db, acc),
    "guardduty.": lambda db, acc: collect_guardduty(db, acc),
    "aws.access_analyzer.": lambda db, acc: collect_access_analyzer(db, acc),
    "aws.config.": lambda db, acc: collect_config_service(db, acc),
    "vpc.": lambda db, acc: collect_vpc(db, acc),
    "ec2.security_group.": lambda db, acc: collect_vpc(db, acc),
    "ec2.instance.": lambda db, acc: collect_ec2(db, acc),
    "ec2.ebs.": lambda db, acc: collect_ec2(db, acc),
    "rds.": lambda db, acc: collect_rds(db, acc),
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
                "username": u.name,
                "arn": u.arn,
                "has_console_password": u.has_console_password,
                "mfa_active": u.mfa_enabled,
                "last_used_at": u.password_last_used.isoformat() if u.password_last_used else None,
                "created_at": u.created.isoformat() if u.created else None,
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
            entity_id=k.key_id,
            payload_json={
                "access_key_id": k.key_id,
                "user_arn": k.user_arn,
                "status": k.status,
                "created_at": k.created.isoformat() if k.created else None,
                "last_used_at": k.last_used.isoformat() if k.last_used else None,
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
                "role_name": r.name,
                "arn": r.arn,
                "last_used_at": r.last_assumed.isoformat() if r.last_assumed else None,
                "created_at": r.created.isoformat() if r.created else None,
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
        stats["cloudtrail_trails"] = collect_cloudtrail(db, acc)
        vpc_stats = collect_vpc(db, acc)
        stats["vpcs"] = vpc_stats.get("vpcs", 0)
        stats["security_groups"] = vpc_stats.get("security_groups", 0)
        stats["guardduty_detectors"] = collect_guardduty(db, acc)
        stats["rds_instances"] = collect_rds(db, acc)
        ec2_stats = collect_ec2(db, acc)
        stats["ec2_instances"] = ec2_stats.get("instances", 0)
        stats["ebs_regions"] = ec2_stats.get("ebs_regions", 0)
        stats["access_analyzers"] = collect_access_analyzer(db, acc)
        stats["config_regions"] = collect_config_service(db, acc)

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


@celery_app.task(name="app.worker.tasks.send_weekly_digests")
def send_weekly_digests() -> dict:
    """Send Monday digest to all org members with a connected account."""
    from app.services.digest import send_digest

    db = SessionLocal()
    sent = 0
    skipped = 0
    try:
        orgs = db.scalars(select(Org)).all()
        since = datetime.now(timezone.utc) - timedelta(days=7)

        for org in orgs:
            org_settings = org.settings or {}
            if not org_settings.get("notifications", {}).get("email_digest_enabled", False):
                skipped += 1
                continue

            acc = db.scalars(
                select(AwsAccount).where(
                    AwsAccount.org_id == org.id,
                    AwsAccount.status == "connected",
                )
            ).first()
            if not acc:
                skipped += 1
                continue

            open_findings = db.scalars(
                select(Finding).where(
                    Finding.account_id == acc.id,
                    Finding.status == "open",
                ).order_by(Finding.risk_score.desc())
            ).all()

            new_this_week = db.scalars(
                select(Finding).where(
                    Finding.account_id == acc.id,
                    Finding.first_seen >= since,
                )
            ).all()

            from sqlalchemy import func as sa_func
            resolved_count = db.scalar(
                select(sa_func.count()).select_from(
                    select(Finding).where(
                        Finding.account_id == acc.id,
                        Finding.status == "resolved",
                        Finding.last_seen >= since,
                    ).subquery()
                )
            ) or 0

            findings_dicts = [
                {
                    "title": f.title,
                    "severity": f.severity,
                    "risk_score": f.risk_score,
                    "resource_arn": f.resource_arn,
                    "check_id": f.check_id,
                }
                for f in open_findings
            ]
            new_dicts = [
                {"title": f.title, "severity": f.severity}
                for f in new_this_week
            ]

            digest_email = org_settings.get("notifications", {}).get("digest_email")
            if digest_email:
                recipients = [digest_email]
            else:
                recipients = [
                    u.email
                    for u in db.scalars(select(User).where(User.org_id == org.id)).all()
                    if u.email
                ]

            for email in recipients:
                ok = send_digest(
                    to=email,
                    org_name=org.name if hasattr(org, "name") else str(org.id),
                    account_label=acc.label,
                    open_findings=findings_dicts,
                    new_this_week=new_dicts,
                    resolved_this_week=resolved_count,
                )
                if ok:
                    sent += 1

        log.info("digests.complete", sent=sent, skipped=skipped)
        return {"sent": sent, "skipped": skipped}
    except Exception as e:  # noqa: BLE001
        log.exception("digests.failed")
        return {"ok": False, "error": str(e)}
    finally:
        db.close()
