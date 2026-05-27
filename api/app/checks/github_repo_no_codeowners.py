"""Check: GitHub repo requires code-owner review but has no CODEOWNERS file."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks._identity_helpers import _providers_of_type
from app.checks.base import FindingDraft, score
from app.models.github import Repo, RepoProtection

CHECK_ID = "github.repo.no_codeowners"


def run(db: Session, account_id) -> list[FindingDraft]:
    """Only flag when branch protection requires code-owner reviews but no CODEOWNERS exists."""
    providers = _providers_of_type(db, account_id, "github")

    out: list[FindingDraft] = []
    for provider in providers:
        repos = db.scalars(select(Repo).where(Repo.provider_id == provider.id)).all()
        for repo in repos:
            if repo.has_codeowners is None or repo.has_codeowners:
                continue
            protection = db.scalars(
                select(RepoProtection).where(RepoProtection.repo_id == repo.id)
            ).first()
            if not protection or not protection.require_code_owners:
                continue
            out.append(FindingDraft(
                check_id=CHECK_ID,
                resource_arn=f"github://repo/{repo.name}",
                title=f"Repository `{repo.name}` requires code-owner review but has no CODEOWNERS file",
                severity="low",
                risk_score=score("low"),
                evidence={
                    "repo": repo.name,
                    "require_code_owners": True,
                    "note": "Branch protection requires code-owner review; add CODEOWNERS or disable that requirement.",
                },
            ))
    return out
