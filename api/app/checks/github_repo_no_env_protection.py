"""Check: GitHub repo has deployment environments with no required reviewers."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks._identity_helpers import _providers_of_type
from app.checks.base import FindingDraft, score
from app.models.github import Repo

CHECK_ID = "github.repo.no_env_protection"


def run(db: Session, account_id) -> list[FindingDraft]:
    providers = _providers_of_type(db, account_id, "github")

    out: list[FindingDraft] = []
    for provider in providers:
        repos = db.scalars(select(Repo).where(Repo.provider_id == provider.id)).all()
        for repo in repos:
            envs = repo.protected_envs
            if not envs:
                continue  # no environments defined — skip
            unprotected = [e["name"] for e in envs if not e.get("has_required_reviewers")]
            if not unprotected:
                continue
            out.append(FindingDraft(
                check_id=CHECK_ID,
                resource_arn=f"github://repo/{repo.name}",
                title=f"Repository `{repo.name}` has deployment environments with no required reviewers",
                severity="high",
                risk_score=score("high"),
                evidence={
                    "repo": repo.name,
                    "unprotected_environments": unprotected,
                    "all_environments": [e["name"] for e in envs],
                },
            ))
    return out
