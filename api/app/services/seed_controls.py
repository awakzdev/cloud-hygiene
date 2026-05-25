"""Load control_mappings.json into controls + check_controls tables (idempotent)."""
from __future__ import annotations

import json
import uuid
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.control import Control, CheckControl

_MAPPINGS_PATH = Path(__file__).parent.parent.parent / "data" / "control_mappings.json"


def seed_controls(db: Session) -> int:
    raw = json.loads(_MAPPINGS_PATH.read_text())
    upserted = 0

    for entry in raw:
        framework = entry["framework"]
        control_id_str = entry["control_id"]

        ctrl = db.scalars(
            select(Control).where(
                Control.framework == framework,
                Control.control_id == control_id_str,
            )
        ).first()

        if ctrl is None:
            ctrl = Control(
                id=uuid.uuid4(),
                framework=framework,
                control_id=control_id_str,
                title=entry["title"],
                description=entry.get("description", ""),
                guidance=entry.get("guidance"),
            )
            db.add(ctrl)
            db.flush()
            upserted += 1
        else:
            ctrl.title = entry["title"]
            ctrl.description = entry.get("description", "")
            ctrl.guidance = entry.get("guidance")

        existing_links = set(
            db.scalars(
                select(CheckControl.check_id).where(CheckControl.control_id == ctrl.id)
            ).all()
        )
        for check_id in entry.get("checks", []):
            if check_id not in existing_links:
                db.add(CheckControl(id=uuid.uuid4(), check_id=check_id, control_id=ctrl.id))

    db.commit()
    return upserted
