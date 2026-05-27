"""What-if blast radius for GitHub/GitLab identity findings."""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AwsAccount
from app.models.github import IdentityProvider, IdentityUser, PullRequest, Repo, RepoProtection

_IDENTITY_ARN = re.compile(r"^(github|gitlab)://([^/]+)(?:/(.+))?$")


def _parse_identity_arn(resource_arn: str) -> tuple[str, str, str | None]:
    """Return (provider_type, first_segment, second_segment or None)."""
    m = _IDENTITY_ARN.match(resource_arn.strip())
    if not m:
        raise ValueError(f"invalid identity resource_arn: {resource_arn}")
    provider_type, first, rest = m.group(1), unquote(m.group(2)), m.group(3)
    return provider_type, first, unquote(rest) if rest else None


def _providers(db: Session, acc: AwsAccount, provider_type: str) -> list[IdentityProvider]:
    return list(
        db.scalars(
            select(IdentityProvider).where(
                IdentityProvider.org_id == acc.org_id,
                IdentityProvider.type == provider_type,
            )
        ).all()
    )


def _source_label(provider: IdentityProvider) -> str:
    try:
        cfg = json.loads(provider.config_json_encrypted or "{}")
    except Exception:
        cfg = {}
    if provider.type == "github":
        return cfg.get("org_login") or cfg.get("login") or "github"
    groups = cfg.get("group_ids") or ([cfg["group_id"]] if cfg.get("group_id") else [])
    return groups[0] if groups else cfg.get("username") or "gitlab"


def _find_repo(db: Session, providers: list[IdentityProvider], repo_name: str) -> Repo | None:
    for provider in providers:
        repo = db.scalar(
            select(Repo).where(Repo.provider_id == provider.id, Repo.name == repo_name)
        )
        if repo:
            return repo
    return None


def blast_radius_identity(
    db: Session,
    acc: AwsAccount,
    check_id: str,
    resource_arn: str,
    *,
    now: datetime | None = None,
) -> dict:
    now = now or datetime.now(timezone.utc)
    provider_type = "github" if check_id.startswith("github.") else "gitlab"
    providers = _providers(db, acc, provider_type)
    if not providers:
        return {
            "resource_type": "identity_provider",
            "confidence": "medium",
            "provider_type": provider_type,
            "warnings": ["No identity provider connected — connect GitHub or GitLab to refresh this analysis"],
        }

    _, first, second = _parse_identity_arn(resource_arn)

    # Org-level: github://org/{login}
    if first == "org" and second:
        return _org_blast(db, providers, provider_type, second, check_id)

    # Repo shorthand: github://repo/{name}
    if first == "repo" and second:
        return _repo_blast(db, providers, provider_type, second, check_id, now)

    # github://{source}/{member_or_repo}
    source, name = first, second
    if not name:
        return _org_blast(db, providers, provider_type, source, check_id)

    if check_id.endswith(".mfa_not_enforced") or check_id.endswith(".dormant_members"):
        return _user_blast(db, providers, provider_type, source, name, check_id, now)

    return _repo_blast(db, providers, provider_type, name, check_id, now, source_hint=source)


def _org_blast(
    db: Session,
    providers: list[IdentityProvider],
    provider_type: str,
    org_key: str,
    check_id: str,
) -> dict:
    warnings: list[str] = []
    confidence = "high"
    member_count = 0
    outside_count = 0

    for provider in providers:
        source = _source_label(provider)
        if source != org_key and org_key not in ("org", source):
            continue
        if check_id.endswith("outside_collaborators"):
            try:
                cfg = json.loads(provider.config_json_encrypted or "{}")
            except Exception:
                cfg = {}
            collabs = cfg.get("outside_collaborators") or []
            outside_count = len(collabs)
            if outside_count:
                confidence = "medium"
                warnings.append(
                    f"{outside_count} outside collaborator(s) have direct repo access — removing access may break contractors or bots"
                )
        else:
            member_count = db.scalar(
                select(func.count())
                .select_from(IdentityUser)
                .where(IdentityUser.provider_id == provider.id, IdentityUser.status == "active")
            ) or 0
            if check_id.endswith("mfa_not_enforced"):
                warnings.append(
                    "Enforcing MFA blocks password-only sign-in — members without MFA must register a device before their next login"
                )

    return {
        "resource_type": "identity_org",
        "confidence": confidence,
        "provider_type": provider_type,
        "org": org_key,
        "active_member_count": member_count,
        "outside_collaborator_count": outside_count,
        "warnings": warnings,
    }


def _user_blast(
    db: Session,
    providers: list[IdentityProvider],
    provider_type: str,
    source: str,
    username: str,
    check_id: str,
    now: datetime,
) -> dict:
    user: IdentityUser | None = None
    for provider in providers:
        if _source_label(provider) != source:
            continue
        user = db.scalar(
            select(IdentityUser).where(
                IdentityUser.provider_id == provider.id,
                IdentityUser.external_id == username,
            )
        )
        if user:
            break

    warnings: list[str] = []
    confidence = "high"
    days_inactive = None
    if user and user.last_active_at:
        days_inactive = int((now - user.last_active_at).total_seconds() / 86400)

    if check_id.endswith("dormant_members"):
        if days_inactive is not None and days_inactive < 30:
            confidence = "medium"
            warnings.append("User was active within 30 days — confirm they no longer need access before suspension")
        warnings.append("Suspending or removing a member revokes access to all org repositories immediately")
    elif check_id.endswith("mfa_not_enforced"):
        warnings.append("User must enroll MFA at next login — API tokens and SSH keys are unaffected")

    return {
        "resource_type": "identity_user",
        "confidence": confidence,
        "provider_type": provider_type,
        "username": username,
        "source": source,
        "email": user.email if user else None,
        "mfa_enabled": user.mfa_enabled if user else None,
        "days_inactive": days_inactive,
        "warnings": warnings,
    }


def _repo_blast(
    db: Session,
    providers: list[IdentityProvider],
    provider_type: str,
    repo_name: str,
    check_id: str,
    now: datetime,
    *,
    source_hint: str | None = None,
) -> dict:
    repo = _find_repo(db, providers, repo_name)
    warnings: list[str] = []
    confidence = "high"
    default_branch = repo.default_branch if repo else "main"
    protection: RepoProtection | None = None
    if repo:
        protection = db.scalar(
            select(RepoProtection).where(
                RepoProtection.repo_id == repo.id,
                RepoProtection.branch == default_branch,
            )
        )

    cutoff = now - timedelta(days=90)
    recent_merge_count = 0
    if repo and check_id.endswith(("self_merge_allowed", "insufficient_reviews")):
        recent_merge_count = (
            db.scalar(
                select(func.count())
                .select_from(PullRequest)
                .where(
                    PullRequest.repo_id == repo.id,
                    PullRequest.merged_at >= cutoff,
                )
            )
            or 0
        )

    if check_id.endswith("no_branch_protection"):
        warnings.append(
            f"Enabling branch protection on `{default_branch}` blocks direct pushes — open PRs may need rebasing"
        )
    elif check_id.endswith("no_codeowners"):
        warnings.append("Adding CODEOWNERS auto-requests reviews — existing PRs are unaffected until updated")
    elif check_id.endswith("no_env_protection"):
        confidence = "medium"
        warnings.append(
            "Requiring reviewers on deployment environments blocks production deploys until approved — coordinate with release owners"
        )
    elif check_id.endswith("self_merge_allowed"):
        confidence = "medium" if recent_merge_count else "high"
        warnings.append(
            "Require pull request reviews and disable admin bypass to stop self-merge — may slow hotfix workflows"
        )
    elif check_id.endswith("insufficient_reviews"):
        confidence = "medium"
        warnings.append("Raising required approvals increases merge latency — align with team on minimum reviewer count")
    elif check_id.endswith("weak_tls_policy"):
        pass  # N/A for identity

    return {
        "resource_type": "identity_repo",
        "confidence": confidence,
        "provider_type": provider_type,
        "repo": repo_name,
        "source": source_hint,
        "default_branch": default_branch,
        "has_branch_protection": protection is not None,
        "required_reviews": protection.required_reviews if protection else 0,
        "recent_merge_count": recent_merge_count,
        "warnings": warnings,
    }
