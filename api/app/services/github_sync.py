from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.github import IdentityProvider, IdentityUser, PullRequest, Repo, RepoProtection


GITHUB_API = "https://api.github.com"


@dataclass
class GitHubSyncStats:
    identity_users: int = 0
    repos: int = 0
    repo_protections: int = 0
    pull_requests: int = 0


def provider_config(provider: IdentityProvider) -> dict[str, Any]:
    try:
        return json.loads(provider.config_json_encrypted or "{}")
    except json.JSONDecodeError:
        return {}


def set_provider_config(provider: IdentityProvider, config: dict[str, Any]) -> None:
    provider.config_json_encrypted = json.dumps(config, separators=(",", ":"))


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        try:
            return parsedate_to_datetime(value)
        except Exception:
            return None


def _headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _paginate(client: httpx.Client, path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    url = f"{GITHUB_API}{path}"
    next_params = {"per_page": 100, **(params or {})}
    while url:
        resp = client.get(url, params=next_params)
        if resp.status_code == 404:
            return rows
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list):
            rows.extend(data)
        else:
            return rows
        url = resp.links.get("next", {}).get("url")
        next_params = None
    return rows


def _upsert_identity_user(db: Session, provider_id: uuid.UUID, member: dict[str, Any], now: datetime) -> None:
    external_id = str(member["id"])
    row = db.scalar(
        select(IdentityUser).where(
            IdentityUser.provider_id == provider_id,
            IdentityUser.external_id == external_id,
        )
    )
    if not row:
        row = IdentityUser(id=uuid.uuid4(), provider_id=provider_id, external_id=external_id)
        db.add(row)
    row.email = member.get("email")
    row.name = member.get("name") or member.get("login")
    row.mfa_enabled = member.get("two_factor_authentication")
    row.status = "active"
    row.roles_json = {
        "login": member.get("login"),
        "site_admin": bool(member.get("site_admin")),
        "type": member.get("type"),
    }
    row.last_active_at = _parse_dt(member.get("last_activity_at") or member.get("updated_at"))
    row.snapshot_taken_at = now


def _upsert_repo(
    db: Session,
    provider_id: uuid.UUID,
    gh_repo: dict[str, Any],
    now: datetime,
    has_codeowners: bool | None = None,
    protected_envs: list | None = None,
) -> "Repo":
    external_id = str(gh_repo["id"])
    row = db.scalar(select(Repo).where(Repo.provider_id == provider_id, Repo.external_id == external_id))
    if not row:
        row = Repo(id=uuid.uuid4(), provider_id=provider_id, external_id=external_id)
        db.add(row)
    row.name = gh_repo["full_name"]
    row.default_branch = gh_repo.get("default_branch")
    if has_codeowners is not None:
        row.has_codeowners = has_codeowners
    if protected_envs is not None:
        row.protected_envs = protected_envs
    row.snapshot_taken_at = now
    return row


def _check_codeowners(client: httpx.Client, owner: str, repo_name: str) -> bool:
    """Return True if CODEOWNERS file exists in any standard location."""
    for path in ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"):
        resp = client.get(f"{GITHUB_API}/repos/{owner}/{repo_name}/contents/{path}")
        if resp.status_code == 200:
            return True
    return False


def _collect_environments(client: httpx.Client, owner: str, repo_name: str) -> list[dict[str, Any]]:
    """Collect deployment environments with their protection rules."""
    resp = client.get(f"{GITHUB_API}/repos/{owner}/{repo_name}/environments")
    if resp.status_code != 200:
        return []
    envs = []
    for env in (resp.json().get("environments") or []):
        env_name = env.get("name", "")
        protection_rules = env.get("protection_rules") or []
        required_reviewers = [
            r for r in protection_rules if r.get("type") == "required_reviewers"
        ]
        envs.append({
            "name": env_name,
            "has_required_reviewers": bool(required_reviewers),
            "reviewer_count": sum(
                len(r.get("reviewers") or []) for r in required_reviewers
            ),
        })
    return envs


def _upsert_protection(db: Session, repo_id: uuid.UUID, branch: str, protection: dict[str, Any], now: datetime) -> None:
    row = db.get(RepoProtection, {"repo_id": repo_id, "branch": branch})
    if not row:
        row = RepoProtection(repo_id=repo_id, branch=branch)
        db.add(row)

    reviews = protection.get("required_pull_request_reviews") or {}
    status_checks = protection.get("required_status_checks") or {}
    restrictions = protection.get("restrictions")
    allow_force_pushes = protection.get("allow_force_pushes") or {}

    row.required_reviews = int(reviews.get("required_approving_review_count") or 0)
    row.dismiss_stale = bool(reviews.get("dismiss_stale_reviews"))
    row.require_code_owners = bool(reviews.get("require_code_owner_reviews"))
    row.allow_force_push = bool(allow_force_pushes.get("enabled")) if allow_force_pushes else False
    row.required_status_checks = status_checks.get("contexts") or []
    row.snapshot_taken_at = now
    if restrictions and isinstance(row.required_status_checks, list):
        row.required_status_checks = [
            *row.required_status_checks,
            {"restrictions": True},
        ]


def _upsert_pr(
    db: Session,
    repo_id: uuid.UUID,
    pr: dict[str, Any],
    required_review_count: int,
    approval_count: int,
    now: datetime,
) -> None:
    row = db.scalar(select(PullRequest).where(PullRequest.repo_id == repo_id, PullRequest.number == pr["number"]))
    if not row:
        row = PullRequest(id=uuid.uuid4(), repo_id=repo_id, number=pr["number"])
        db.add(row)
    author = (pr.get("user") or {}).get("login")
    merged_by = (pr.get("merged_by") or {}).get("login")
    row.author = author
    row.merged_at = _parse_dt(pr.get("merged_at"))
    row.merged_by = merged_by
    row.required_review_count = required_review_count
    row.approval_count = approval_count
    row.self_merge = bool(author and merged_by and author == merged_by)
    row.snapshot_taken_at = now


def sync_github_provider(db: Session, provider: IdentityProvider, org_login: str | None = None) -> GitHubSyncStats:
    """Sync the configured GitHub evidence scope."""
    config = provider_config(provider)
    token = config.get("access_token")
    if not token:
        raise ValueError("GitHub provider is missing an access token")

    now = datetime.now(timezone.utc)
    owners = [org_login.strip()] if org_login and org_login.strip() else [str(owner).strip() for owner in config.get("org_logins") or [] if str(owner).strip()]
    if not owners:
        fallback_owner = (config.get("org_login") or config.get("login") or "").strip()
        owners = [fallback_owner] if fallback_owner else []
    owners = list(dict.fromkeys(owners))
    if not owners:
        raise ValueError("GitHub owner/org login is required")
    selected_repos = set(config.get("selected_repos") or [])

    stats = GitHubSyncStats()
    with httpx.Client(headers=_headers(token), timeout=20) as client:
        viewer = client.get(f"{GITHUB_API}/user")
        viewer.raise_for_status()
        config["login"] = viewer.json().get("login")

        for owner in owners:
            # Org members expose 2FA state only when the OAuth token has suitable org access.
            members = _paginate(client, f"/orgs/{owner}/members")
            if not members:
                user_resp = client.get(f"{GITHUB_API}/users/{owner}")
                user_resp.raise_for_status()
                members = [user_resp.json()]
            for member in members:
                _upsert_identity_user(db, provider.id, member, now)
            stats.identity_users += len(members)

            org_repos = _paginate(client, f"/orgs/{owner}/repos", {"type": "all", "sort": "updated"})
            repos = org_repos or _paginate(client, "/user/repos", {"affiliation": "owner,collaborator,organization_member", "sort": "updated"})
            repos = [r for r in repos if r.get("full_name", "").split("/")[0].lower() == owner.lower()]
            if selected_repos:
                repos = [r for r in repos if r.get("full_name") in selected_repos]
            for gh_repo in repos:
                owner_name, repo_name = gh_repo["full_name"].split("/", 1)
                has_codeowners = _check_codeowners(client, owner_name, repo_name)
                protected_envs = _collect_environments(client, owner_name, repo_name)
                repo = _upsert_repo(db, provider.id, gh_repo, now,
                                    has_codeowners=has_codeowners, protected_envs=protected_envs)
                db.flush()
                stats.repos += 1

                branch = gh_repo.get("default_branch")
                if not branch:
                    continue
                protection_resp = client.get(f"{GITHUB_API}/repos/{owner_name}/{repo_name}/branches/{branch}/protection")
                required_reviews = 0
                if protection_resp.status_code == 200:
                    protection = protection_resp.json()
                    reviews = protection.get("required_pull_request_reviews") or {}
                    required_reviews = int(reviews.get("required_approving_review_count") or 0)
                    _upsert_protection(db, repo.id, branch, protection, now)
                    stats.repo_protections += 1

                pulls = _paginate(
                    client,
                    f"/repos/{owner_name}/{repo_name}/pulls",
                    {"state": "closed", "sort": "updated", "direction": "desc"},
                )[:100]
                for pr in pulls:
                    if not pr.get("merged_at"):
                        continue
                    reviews = _paginate(client, f"/repos/{owner_name}/{repo_name}/pulls/{pr['number']}/reviews")
                    approvers = {
                        (r.get("user") or {}).get("login")
                        for r in reviews
                        if r.get("state") == "APPROVED" and (r.get("user") or {}).get("login")
                    }
                    _upsert_pr(db, repo.id, pr, required_reviews, len(approvers), now)
                    stats.pull_requests += 1

    config["org_login"] = owners[0]
    config["org_logins"] = owners
    set_provider_config(provider, config)
    provider.status = "connected"
    provider.last_synced_at = now
    db.commit()
    return stats
