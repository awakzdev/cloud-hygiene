"""Check: GitHub repo has no CODEOWNERS file."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks._identity_helpers import _providers_of_type
from app.checks.base import FindingDraft, score
from app.models.github import Repo

CHECK_ID = "github.repo.no_codeowners"


def run(db: Session, account_id) -> list[FindingDraft]:
    providers = _providers_of_type(db, account_id, "github")

    out: list[FindingDraft] = []
    for provider in providers:
        repos = db.scalars(select(Repo).where(Repo.provider_id == provider.id)).all()
        for repo in repos:
            if repo.has_codeowners is None:
                continue  # not yet collected
            if repo.has_codeowners:
                continue
            out.append(FindingDraft(
                check_id=CHECK_ID,
                resource_arn=f"github://repo/{repo.name}",
                title=f"Repository `{repo.name}` has no CODEOWNERS file",
                severity="medium",
                risk_score=score("medium"),
                evidence={
                    "repo": repo.name,
                    "note": "No CODEOWNERS file found in /, .github/, or docs/",
                },
            ))
    return out
