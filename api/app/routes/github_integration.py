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
from app.services.github_sync import provider_config, set_provider_config, sync_github_provider

router = APIRouter()
settings = get_settings()



_GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"
_GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
_GITHUB_USER_URL = "https://api.github.com/user"


class GitHubProviderOut(BaseModel):
    id: str
    status: str
    login: str | None
    org_login: str | None
    org_logins: list[str]
    last_synced_at: str | None
    identity_users: int
    repos: int
    protected_branches: int
    pull_requests: int
    selected_repos: list[str]


class GitHubSyncIn(BaseModel):
    org_login: str | None = None


class GitHubSyncOut(BaseModel):
    identity_users: int
    repos: int
    repo_protections: int
    pull_requests: int


class GitHubOrgOut(BaseModel):
    login: str


class GitHubRepoOut(BaseModel):
    full_name: str
    private: bool
    default_branch: str | None


class GitHubScopeOut(BaseModel):
    org_login: str | None
    org_logins: list[str]
    selected_repos: list[str]


class GitHubScopeIn(BaseModel):
    org_login: str | None = None
    org_logins: list[str] = []
    selected_repos: list[str] = []


class ConnectUrlOut(BaseModel):
    url: str


class ManageUrlOut(BaseModel):
    url: str


def _frontend_url() -> str:
    return settings.API_PUBLIC_URL.replace(":8000", ":5173")


def _callback_uri() -> str:
    path_or_url = settings.GITHUB_INTEGRATION_CALLBACK_PATH
    if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
        return path_or_url
    return f"{settings.API_PUBLIC_URL}{path_or_url}"


def _issue_state(user_id: str, org_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "type": "github_integration",
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
    if payload.get("type") != "github_integration":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "bad state type")
    return payload


def is_github_integration_state(state: str | None) -> bool:
    if not state:
        return False
    try:
        payload = jwt.get_unverified_claims(state)
    except JWTError:
        return False
    return payload.get("type") == "github_integration"


def _provider_for_org(db: Session, org_id: str) -> IdentityProvider | None:
    return db.scalar(
        select(IdentityProvider).where(
            IdentityProvider.org_id == uuid.UUID(org_id),
            IdentityProvider.type == "github",
        )
    )


def _provider_out(db: Session, provider: IdentityProvider) -> GitHubProviderOut:
    config = provider_config(provider)
    org_logins = config.get("org_logins") or ([config["org_login"]] if config.get("org_login") else [])
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
    return GitHubProviderOut(
        id=str(provider.id),
        status=provider.status,
        login=config.get("login"),
        org_login=config.get("org_login"),
        org_logins=org_logins,
        last_synced_at=provider.last_synced_at.isoformat() if provider.last_synced_at else None,
        identity_users=identity_users,
        repos=repos,
        protected_branches=protected,
        pull_requests=prs,
        selected_repos=config.get("selected_repos") or [],
    )


def _github_headers(provider: IdentityProvider) -> dict[str, str]:
    token = provider_config(provider).get("access_token")
    if not token:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "GitHub provider is missing an access token")
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _paginate_github(client: httpx.Client, url: str, params: dict | None = None) -> list[dict]:
    rows: list[dict] = []
    next_url = url
    next_params = {"per_page": 100, **(params or {})}
    while next_url:
        resp = client.get(next_url, params=next_params)
        if resp.status_code == 404:
            return rows
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, list):
            return rows
        rows.extend(data)
        next_url = resp.links.get("next", {}).get("url")
        next_params = None
    return rows


def _connect_url(p: dict) -> str:
    if not settings.GITHUB_CLIENT_ID:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "GitHub OAuth not configured")
    state = _issue_state(p["sub"], p["org_id"])
    params = {
        "client_id": settings.GITHUB_CLIENT_ID,
        "redirect_uri": _callback_uri(),
        "scope": "read:user user:email read:org repo",
        "state": state,
    }
    return f"{_GITHUB_AUTH_URL}?{urlencode(params)}"


@router.get("/github/connect")
def connect_github(p=Depends(current_principal)):
    return RedirectResponse(_connect_url(p))


@router.get("/github/connect-url", response_model=ConnectUrlOut)
def github_connect_url(p=Depends(current_principal)):
    return ConnectUrlOut(url=_connect_url(p))


@router.get("/github/manage-url", response_model=ManageUrlOut)
def github_manage_url(p=Depends(current_principal)):
    if not settings.GITHUB_CLIENT_ID:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "GitHub OAuth not configured")
    return ManageUrlOut(url=f"https://github.com/settings/connections/applications/{settings.GITHUB_CLIENT_ID}")


def handle_github_integration_callback(
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    db: Session = Depends(get_db),
) -> RedirectResponse:
    if error or not code or not state:
        return RedirectResponse(f"{_frontend_url()}/integrations/github?error=oauth_denied")
    try:
        payload = _decode_state(state)
        with httpx.Client(timeout=10) as client:
            token_resp = client.post(
                _GITHUB_TOKEN_URL,
                data={
                    "client_id": settings.GITHUB_CLIENT_ID,
                    "client_secret": settings.GITHUB_CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": _callback_uri(),
                },
                headers={"Accept": "application/json"},
            )
            if token_resp.status_code != 200:
                return RedirectResponse(f"{_frontend_url()}/integrations/github?error=oauth_failed")
            access_token = token_resp.json().get("access_token")
            if not access_token:
                return RedirectResponse(f"{_frontend_url()}/integrations/github?error=oauth_failed")

            user_resp = client.get(
                _GITHUB_USER_URL,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github+json",
                },
            )
            user_resp.raise_for_status()
            gh_user = user_resp.json()

        provider = _provider_for_org(db, payload["org_id"])
        if not provider:
            provider = IdentityProvider(
                id=uuid.uuid4(),
                org_id=uuid.UUID(payload["org_id"]),
                type="github",
                config_json_encrypted="{}",
            )
            db.add(provider)
        set_provider_config(
            provider,
            {
                "access_token": access_token,
                "login": gh_user.get("login"),
                "github_user_id": str(gh_user.get("id")),
            },
        )
        provider.status = "connected"
        db.commit()
        return RedirectResponse(f"{_frontend_url()}/integrations/github/edit?connected=1")
    except Exception:
        db.rollback()
        return RedirectResponse(f"{_frontend_url()}/integrations/github?error=server_error")


@router.get("/github/callback")
def github_callback(
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    db: Session = Depends(get_db),
):
    return handle_github_integration_callback(code=code, state=state, error=error, db=db)


@router.get("/github", response_model=GitHubProviderOut | None)
def get_github_provider(p=Depends(current_principal), db: Session = Depends(get_db)):
    provider = _provider_for_org(db, p["org_id"])
    if not provider:
        return None
    return _provider_out(db, provider)


@router.get("/github/orgs", response_model=list[GitHubOrgOut])
def list_github_orgs(p=Depends(current_principal), db: Session = Depends(get_db)):
    provider = _provider_for_org(db, p["org_id"])
    if not provider:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "GitHub is not connected")
    config = provider_config(provider)
    with httpx.Client(headers=_github_headers(provider), timeout=20) as client:
        viewer = client.get("https://api.github.com/user")
        viewer.raise_for_status()
        logins = [viewer.json().get("login")]
        orgs = _paginate_github(client, "https://api.github.com/user/orgs")
        logins.extend(org.get("login") for org in orgs)
    current = config.get("org_login")
    if current and current not in logins:
        logins.insert(0, current)
    for current_org in config.get("org_logins") or []:
        if current_org and current_org not in logins:
            logins.append(current_org)
    return [GitHubOrgOut(login=login) for login in dict.fromkeys(login for login in logins if login)]


@router.get("/github/repos", response_model=list[GitHubRepoOut])
def list_github_repos(owner: str, p=Depends(current_principal), db: Session = Depends(get_db)):
    provider = _provider_for_org(db, p["org_id"])
    if not provider:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "GitHub is not connected")
    with httpx.Client(headers=_github_headers(provider), timeout=20) as client:
        repos = _paginate_github(
            client,
            f"https://api.github.com/orgs/{owner}/repos",
            {"type": "all", "sort": "updated"},
        )
        if not repos:
            repos = _paginate_github(
                client,
                "https://api.github.com/user/repos",
                {"affiliation": "owner,collaborator,organization_member", "sort": "updated"},
            )
            repos = [r for r in repos if r.get("full_name", "").split("/")[0].lower() == owner.lower()]
    return [
        GitHubRepoOut(
            full_name=repo["full_name"],
            private=bool(repo.get("private")),
            default_branch=repo.get("default_branch"),
        )
        for repo in repos
    ]


@router.put("/github/scope", response_model=GitHubScopeOut)
def update_github_scope(body: GitHubScopeIn, p=Depends(current_principal), db: Session = Depends(get_db)):
    provider = _provider_for_org(db, p["org_id"])
    if not provider:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "GitHub is not connected")
    org_logins = [org.strip() for org in body.org_logins if org.strip()]
    if body.org_login and body.org_login.strip():
        org_logins.insert(0, body.org_login.strip())
    org_logins = list(dict.fromkeys(org_logins))
    if not org_logins:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "At least one GitHub organization or owner is required")
    selected_repos = sorted({repo.strip() for repo in body.selected_repos if repo.strip()})
    config = provider_config(provider)
    config["org_login"] = org_logins[0]
    config["org_logins"] = org_logins
    config["selected_repos"] = selected_repos
    set_provider_config(provider, config)
    db.commit()
    return GitHubScopeOut(org_login=org_logins[0], org_logins=org_logins, selected_repos=selected_repos)


@router.post("/github/sync", response_model=GitHubSyncOut)
def sync_github(body: GitHubSyncIn, p=Depends(current_principal), db: Session = Depends(get_db)):
    provider = _provider_for_org(db, p["org_id"])
    if not provider:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "GitHub is not connected")
    try:
        stats = sync_github_provider(db, provider, body.org_login)
    except httpx.HTTPStatusError as e:
        provider.status = "error"
        db.commit()
        detail = e.response.text[:500] if e.response is not None else str(e)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"GitHub sync failed: {detail}") from e
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e
    return GitHubSyncOut(**stats.__dict__)


@router.delete("/github", status_code=status.HTTP_204_NO_CONTENT)
def disconnect_github(p=Depends(current_principal), db: Session = Depends(get_db)):
    provider = _provider_for_org(db, p["org_id"])
    if provider:
        db.delete(provider)
        db.commit()
