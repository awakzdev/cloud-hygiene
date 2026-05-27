from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import RedirectResponse
from jose import JWTError, jwt
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.db import get_db
from app.core.security import current_principal
from app.models.github import IdentityProvider, IdentityUser, PullRequest, Repo, RepoProtection
from app.services.gitlab_sync import provider_config, set_provider_config, sync_gitlab_provider
from app.services.gitlab_tokens import GitLabReconnectRequired, apply_oauth_tokens, ensure_gitlab_token

router = APIRouter()
settings = get_settings()


class GitLabProviderOut(BaseModel):
    id: str
    status: str
    username: str | None
    group_id: str | None
    group_ids: list[str]
    base_url: str | None
    last_synced_at: str | None
    identity_users: int
    repos: int
    protected_branches: int
    pull_requests: int
    selected_repos: list[str]


class GitLabSyncIn(BaseModel):
    group_id: str | None = None


class GitLabSyncOut(BaseModel):
    identity_users: int
    repos: int
    repo_protections: int
    pull_requests: int


class GitLabGroupOut(BaseModel):
    full_path: str
    name: str


class GitLabRepoOut(BaseModel):
    path_with_namespace: str
    visibility: str
    default_branch: str | None


class GitLabScopeOut(BaseModel):
    group_id: str | None
    group_ids: list[str]
    selected_repos: list[str]


class GitLabScopeIn(BaseModel):
    group_id: str | None = None
    group_ids: list[str] = []
    selected_repos: list[str] = []
    base_url: str | None = None


class ConnectUrlOut(BaseModel):
    url: str


def _frontend_url() -> str:
    return settings.API_PUBLIC_URL.replace(":8000", ":5173")


def _callback_uri() -> str:
    path_or_url = settings.GITLAB_INTEGRATION_CALLBACK_PATH
    if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
        return path_or_url
    return f"{settings.API_PUBLIC_URL}{path_or_url}"


def _issue_state(user_id: str, org_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "type": "gitlab_integration",
        "sub": user_id,
        "org_id": org_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=10)).timestamp()),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALG)


def _decode_state(state: str) -> dict:
    try:
        payload = jwt.decode(state, settings.JWT_SECRET, algorithms=[settings.JWT_ALG])
    except JWTError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"bad state: {e}") from e
    if payload.get("type") != "gitlab_integration":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "bad state type")
    return payload


def _provider_for_org(db: Session, org_id: str) -> IdentityProvider | None:
    return db.scalar(
        select(IdentityProvider).where(
            IdentityProvider.org_id == uuid.UUID(org_id),
            IdentityProvider.type == "gitlab",
        )
    )


def _provider_out(db: Session, provider: IdentityProvider) -> GitLabProviderOut:
    config = provider_config(provider)
    group_ids = config.get("group_ids") or ([config["group_id"]] if config.get("group_id") else [])
    identity_users = db.scalar(select(func.count()).select_from(IdentityUser).where(IdentityUser.provider_id == provider.id)) or 0
    repos = db.scalar(select(func.count()).select_from(Repo).where(Repo.provider_id == provider.id)) or 0
    protected = (
        db.scalar(
            select(func.count())
            .select_from(RepoProtection)
            .join(Repo, Repo.id == RepoProtection.repo_id)
            .where(Repo.provider_id == provider.id)
        )
        or 0
    )
    prs = (
        db.scalar(
            select(func.count())
            .select_from(PullRequest)
            .join(Repo, Repo.id == PullRequest.repo_id)
            .where(Repo.provider_id == provider.id)
        )
        or 0
    )
    return GitLabProviderOut(
        id=str(provider.id),
        status=provider.status,
        username=config.get("username"),
        group_id=config.get("group_id"),
        group_ids=group_ids,
        base_url=config.get("base_url"),
        last_synced_at=provider.last_synced_at.isoformat() if provider.last_synced_at else None,
        identity_users=identity_users,
        repos=repos,
        protected_branches=protected,
        pull_requests=prs,
        selected_repos=config.get("selected_repos") or [],
    )


def _gitlab_headers(db: Session, provider: IdentityProvider) -> dict[str, str]:
    token = ensure_gitlab_token(db, provider)
    return {"Authorization": f"Bearer {token}"}


def _api_base(provider: IdentityProvider) -> str:
    config = provider_config(provider)
    base = (config.get("base_url") or "https://gitlab.com").rstrip("/")
    return f"{base}/api/v4"


def _connect_url(p: dict, base_url: str | None = None) -> str:
    if not settings.GITLAB_CLIENT_ID:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "GitLab OAuth not configured")
    state = _issue_state(p["sub"], p["org_id"])
    gl_base = (base_url or "https://gitlab.com").rstrip("/")
    params = {
        "client_id": settings.GITLAB_CLIENT_ID,
        "redirect_uri": _callback_uri(),
        "response_type": "code",
        "scope": "read_api",
        "state": state,
    }
    return f"{gl_base}/oauth/authorize?{urlencode(params)}"


@router.get("/gitlab/connect-url", response_model=ConnectUrlOut)
def gitlab_connect_url(base_url: str | None = None, p=Depends(current_principal)):
    return ConnectUrlOut(url=_connect_url(p, base_url))


@router.get("/gitlab/callback")
def gitlab_callback(
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    db: Session = Depends(get_db),
):
    if error or not code or not state:
        return RedirectResponse(f"{_frontend_url()}/integrations/gitlab?error=oauth_denied")
    try:
        payload = _decode_state(state)
        # retrieve the base_url from any existing provider for this org (set before OAuth redirect)
        org_id = payload["org_id"]
        existing = _provider_for_org(db, org_id)
        base_url = "https://gitlab.com"
        if existing:
            cfg = provider_config(existing)
            base_url = cfg.get("base_url") or base_url

        with httpx.Client(timeout=10) as client:
            token_resp = client.post(
                f"{base_url.rstrip('/')}/oauth/token",
                data={
                    "client_id": settings.GITLAB_CLIENT_ID,
                    "client_secret": settings.GITLAB_CLIENT_SECRET,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": _callback_uri(),
                },
                headers={"Accept": "application/json"},
            )
            if token_resp.status_code != 200:
                return RedirectResponse(f"{_frontend_url()}/integrations/gitlab?error=oauth_failed")
            token_data = token_resp.json()
            access_token = token_data.get("access_token")
            if not access_token:
                return RedirectResponse(f"{_frontend_url()}/integrations/gitlab?error=oauth_failed")

            api = f"{base_url.rstrip('/')}/api/v4"
            user_resp = client.get(f"{api}/user", headers={"Authorization": f"Bearer {access_token}"})
            user_resp.raise_for_status()
            gl_user = user_resp.json()

        provider = existing
        if not provider:
            provider = IdentityProvider(
                id=uuid.uuid4(),
                org_id=uuid.UUID(org_id),
                type="gitlab",
                config_json_encrypted="{}",
            )
            db.add(provider)
        set_provider_config(
            provider,
            apply_oauth_tokens(
                {
                    **(provider_config(provider)),
                    "username": gl_user.get("username"),
                    "gitlab_user_id": str(gl_user.get("id")),
                    "base_url": base_url if base_url != "https://gitlab.com" else None,
                },
                token_data,
            ),
        )
        provider.status = "connected"
        db.commit()
        return RedirectResponse(f"{_frontend_url()}/integrations/gitlab/edit?connected=1")
    except Exception:
        db.rollback()
        return RedirectResponse(f"{_frontend_url()}/integrations/gitlab?error=server_error")


@router.get("/gitlab", response_model=GitLabProviderOut | None)
def get_gitlab_provider(p=Depends(current_principal), db: Session = Depends(get_db)):
    provider = _provider_for_org(db, p["org_id"])
    if not provider:
        return None
    return _provider_out(db, provider)


@router.get("/gitlab/groups", response_model=list[GitLabGroupOut])
def list_gitlab_groups(p=Depends(current_principal), db: Session = Depends(get_db)):
    provider = _provider_for_org(db, p["org_id"])
    if not provider:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "GitLab is not connected")
    try:
        api = _api_base(provider)
        with httpx.Client(headers=_gitlab_headers(db, provider), timeout=20) as client:
            groups_resp = client.get(f"{api}/groups", params={"per_page": 100, "min_access_level": 20})
            groups_resp.raise_for_status()
            groups = groups_resp.json() if isinstance(groups_resp.json(), list) else []
            user_resp = client.get(f"{api}/user")
            user_resp.raise_for_status()
            username = user_resp.json().get("username", "")
    except GitLabReconnectRequired as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e
    result = [GitLabGroupOut(full_path=g["full_path"], name=g["name"]) for g in groups]
    if username:
        result.insert(0, GitLabGroupOut(full_path=username, name=f"{username} (personal)"))
    return result


@router.get("/gitlab/repos", response_model=list[GitLabRepoOut])
def list_gitlab_repos(namespace: str, p=Depends(current_principal), db: Session = Depends(get_db)):
    provider = _provider_for_org(db, p["org_id"])
    if not provider:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "GitLab is not connected")
    try:
        api = _api_base(provider)
        with httpx.Client(headers=_gitlab_headers(db, provider), timeout=20) as client:
            projects = []
            group_resp = client.get(f"{api}/groups/{namespace}/projects", params={"per_page": 100, "include_subgroups": "true", "archived": "false"})
            if group_resp.status_code == 200 and isinstance(group_resp.json(), list):
                projects = group_resp.json()
            if not projects:
                user_resp = client.get(f"{api}/users/{namespace}/projects", params={"per_page": 100})
                if user_resp.status_code == 200 and isinstance(user_resp.json(), list):
                    projects = user_resp.json()
    except GitLabReconnectRequired as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e
    return [
        GitLabRepoOut(
            path_with_namespace=p["path_with_namespace"],
            visibility=p.get("visibility", "private"),
            default_branch=p.get("default_branch"),
        )
        for p in projects
    ]


@router.put("/gitlab/scope", response_model=GitLabScopeOut)
def update_gitlab_scope(body: GitLabScopeIn, p=Depends(current_principal), db: Session = Depends(get_db)):
    provider = _provider_for_org(db, p["org_id"])
    if not provider:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "GitLab is not connected")
    group_ids = [g.strip() for g in body.group_ids if g.strip()]
    if body.group_id and body.group_id.strip():
        group_ids.insert(0, body.group_id.strip())
    group_ids = list(dict.fromkeys(group_ids))
    if not group_ids:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "At least one GitLab group or namespace is required")
    selected_repos = sorted({r.strip() for r in body.selected_repos if r.strip()})
    config = provider_config(provider)
    config["group_id"] = group_ids[0]
    config["group_ids"] = group_ids
    config["selected_repos"] = selected_repos
    if body.base_url:
        config["base_url"] = body.base_url.rstrip("/")
    set_provider_config(provider, config)
    db.commit()
    return GitLabScopeOut(group_id=group_ids[0], group_ids=group_ids, selected_repos=selected_repos)


@router.post("/gitlab/sync", response_model=GitLabSyncOut)
def sync_gitlab(body: GitLabSyncIn, p=Depends(current_principal), db: Session = Depends(get_db)):
    provider = _provider_for_org(db, p["org_id"])
    if not provider:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "GitLab is not connected")
    try:
        stats = sync_gitlab_provider(db, provider, body.group_id)
    except GitLabReconnectRequired as e:
        provider.status = "error"
        db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e
    except httpx.HTTPStatusError as e:
        provider.status = "error"
        db.commit()
        if e.response is not None and e.response.status_code == 401:
            body = e.response.text.lower()
            if "invalid_token" in body or "expired" in body:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, str(GitLabReconnectRequired())) from e
        detail = e.response.text[:500] if e.response is not None else str(e)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"GitLab sync failed: {detail}") from e
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e
    return GitLabSyncOut(**stats.__dict__)


@router.delete("/gitlab", status_code=status.HTTP_204_NO_CONTENT)
def disconnect_gitlab(p=Depends(current_principal), db: Session = Depends(get_db)):
    provider = _provider_for_org(db, p["org_id"])
    if provider:
        db.delete(provider)
        db.commit()
