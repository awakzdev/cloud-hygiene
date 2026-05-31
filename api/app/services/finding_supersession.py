"""Retired finding check_ids superseded by CIS 45-day checks.

Legacy 90-day checks may still exist in the DB from older scans. They must not
appear as separate findings — SOC2/ISO 90-day thresholds are shown on the 45d
finding via framework impact UI only.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Finding, FindingEvent

# Canonical check_id -> retired check_ids for the same resource_arn
CANONICAL_TO_RETIRED: dict[str, tuple[str, ...]] = {
    "iam.access_key.unused_45d": ("iam.access_key.unused_90d",),
    "iam.user.credentials_unused_45d": ("iam.user.inactive_90d",),
}

RETIRED_FINDING_CHECKS: frozenset[str] = frozenset(
    retired for retired_ids in CANONICAL_TO_RETIRED.values() for retired in retired_ids
)


def resolve_retired_superseded(
    db: Session,
    *,
    account_id,
    now: datetime,
    check_ids_run: set[str],
) -> int:
    """Close open retired findings when the canonical check ran (scan/recheck)."""
    resolved = 0
    for canonical_id, retired_ids in CANONICAL_TO_RETIRED.items():
        if canonical_id not in check_ids_run:
            continue
        for retired_id in retired_ids:
            rows = db.scalars(
                select(Finding).where(
                    Finding.account_id == account_id,
                    Finding.check_id == retired_id,
                    Finding.status == "open",
                )
            ).all()
            for f in rows:
                f.status = "resolved"
                f.resolved_at = now
                db.add(
                    FindingEvent(
                        id=uuid.uuid4(),
                        finding_id=f.id,
                        action="resolved",
                        actor="system",
                        note=f"superseded by {canonical_id}",
                    )
                )
                resolved += 1
    return resolved


def resolve_retired_for_resource(
    db: Session,
    *,
    canonical: Finding,
    now: datetime,
    actor: str | None = None,
    note: str | None = None,
) -> int:
    """When a canonical finding is resolved manually, close retired siblings on same resource."""
    retired_ids = CANONICAL_TO_RETIRED.get(canonical.check_id, ())
    if not retired_ids:
        return 0
    resolved = 0
    for retired_id in retired_ids:
        rows = db.scalars(
            select(Finding).where(
                Finding.account_id == canonical.account_id,
                Finding.check_id == retired_id,
                Finding.resource_arn == canonical.resource_arn,
                Finding.status == "open",
            )
        ).all()
        for f in rows:
            f.status = "resolved"
            f.resolved_at = now
            db.add(
                FindingEvent(
                    id=uuid.uuid4(),
                    finding_id=f.id,
                    action="resolved",
                    actor=actor or "system",
                    note=note or f"superseded by {canonical.check_id}",
                )
            )
            resolved += 1
    return resolved
