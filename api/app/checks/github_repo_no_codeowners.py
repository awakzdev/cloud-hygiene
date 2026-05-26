"""Check: GitHub repo has no CODEOWNERS file."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks.base import FindingDraft, score
from app.models.github import IdentityProvider, Repo

CHECK_ID = "github.repo.no_codeowners"


def run(db: Session, account_id) -> list[FindingDraft]:
    providers = db.scalars(
        select(IdentityProvider).where(
            IdentityProvider.org_id == account_id,
            IdentityProvider.type == "github",
        )
    ).all()

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
