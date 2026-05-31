"""Persist FindingDrafts into findings table with diff-aware semantics."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Iterable

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.checks.base import FindingDraft
from app.models import Finding, FindingEvent
from app.services.finding_supersession import resolve_retired_superseded


def persist_findings(
    db: Session,
    *,
    org_id,
    account_id,
    drafts: Iterable[FindingDraft],
    check_ids_run: set[str],
) -> tuple[int, int]:
    """Returns (opened, resolved).

    - New (account_id, check_id, resource_arn) → insert, log 'opened' event.
    - Existing + still present → bump last_seen + refresh risk_score/title/evidence.
    - Existing open finding for a ran check but no longer present → mark resolved.
    """
    now = datetime.now(timezone.utc)
    opened = 0

    # Index drafts by (check_id, resource_arn)
    by_key = {(d.check_id, d.resource_arn): d for d in drafts}

    # Fetch existing findings for this account scoped to the checks we just ran
    existing = db.scalars(
        select(Finding).where(
            Finding.account_id == account_id,
            Finding.check_id.in_(check_ids_run),
        )
    ).all()
    existing_keys = {(f.check_id, f.resource_arn): f for f in existing}

    # Insert / update
    for key, d in by_key.items():
        if key in existing_keys:
            f = existing_keys[key]
            f.last_seen = now
            f.risk_score = d.risk_score
            f.title = d.title
            f.severity = d.severity
            f.evidence = d.evidence
            if f.status == "resolved":
                f.status = "open"
                f.resolved_at = None
                db.add(FindingEvent(id=uuid.uuid4(), finding_id=f.id, action="reopened"))
        else:
            new = Finding(
                id=uuid.uuid4(),
                org_id=org_id,
                account_id=account_id,
                check_id=d.check_id,
                resource_arn=d.resource_arn,
                title=d.title,
                severity=d.severity,
                risk_score=d.risk_score,
                evidence=d.evidence,
                status="open",
                first_seen=now,
                last_seen=now,
            )
            db.add(new)
            db.flush()
            db.add(FindingEvent(id=uuid.uuid4(), finding_id=new.id, action="opened"))
            opened += 1

    # Auto-resolve: open findings the current scan no longer reports
    resolved = 0
    for key, f in existing_keys.items():
        if key not in by_key and f.status == "open":
            f.status = "resolved"
            f.resolved_at = now
            db.add(FindingEvent(id=uuid.uuid4(), finding_id=f.id, action="resolved", actor="system", note="not present in latest scan"))
            resolved += 1

    resolved += resolve_retired_superseded(
        db, account_id=account_id, now=now, check_ids_run=check_ids_run
    )

    db.commit()
    return opened, resolved
