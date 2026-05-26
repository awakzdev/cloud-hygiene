"""OAuth 2.0 — Google and GitHub authorization code flows."""
from __future__ import annotations

import uuid
from urllib.parse import urlencode

import httpx
import structlog
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.db import get_db
from app.core.security import current_principal, issue_refresh_token, issue_token
from app.models import Org, User
from app.routes.github_integration import handle_github_integration_callback, is_github_integration_state

router = APIRouter()
settings = get_settings()
log = structlog.get_logger()

_GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
_GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
_GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"

_GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"
_GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
_GITHUB_USER_URL = "https://api.github.com/user"
_GITHUB_EMAIL_URL = "https://api.github.com/user/emails"


def _google_callback_uri() -> str:
    return f"{settings.API_PUBLIC_URL}/v1/auth/google/callback"


def _github_callback_uri() -> str:
    return f"{settings.API_PUBLIC_URL}/v1/auth/github/callback"


def _frontend_url() -> str:
    base = settings.API_PUBLIC_URL.replace(":8000", ":5173")
    return base


# ── Google ────────────────────────────────────────────────────────────────────

@router.get("/google")
def google_login():
    if not settings.GOOGLE_CLIENT_ID:
        raise HTTPException(400, "Google OAuth not configured")
    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": _google_callback_uri(),
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "select_account",
    }
    return RedirectResponse(f"{_GOOGLE_AUTH_URL}?{urlencode(params)}")


@router.get("/google/callback")
def google_callback(code: str | None = None, error: str | None = None, db: Session = Depends(get_db)):
    if error or not code:
        return RedirectResponse(f"{_frontend_url()}/login?error=oauth_denied")

    try:
        with httpx.Client(timeout=10) as client:
            token_resp = client.post(_GOOGLE_TOKEN_URL, data={
                "code": code,
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "redirect_uri": _google_callback_uri(),
                "grant_type": "authorization_code",
            })
            if token_resp.status_code != 200:
                return RedirectResponse(f"{_frontend_url()}/login?error=oauth_failed")

            access_token = token_resp.json()["access_token"]
            info_resp = client.get(_GOOGLE_USERINFO_URL, headers={"Authorization": f"Bearer {access_token}"})
            if info_resp.status_code != 200:
                return RedirectResponse(f"{_frontend_url()}/login?error=oauth_failed")

        info = info_resp.json()
        email: str = info.get("email", "").lower()
        name: str = info.get("name") or email.split("@")[0]

        if not email:
            return RedirectResponse(f"{_frontend_url()}/login?error=no_email")

        user = db.scalar(select(User).where(User.email == email))
        if not user:
            org = Org(id=uuid.uuid4(), name=name)
            user = User(id=uuid.uuid4(), org_id=org.id, email=email, password_hash="")
            db.add_all([org, user])
            db.commit()

        uid, oid = str(user.id), str(user.org_id)
        token = issue_token(uid, oid)
        refresh = issue_refresh_token(uid, oid)
        return RedirectResponse(f"{_frontend_url()}/auth/callback?token={token}&refresh_token={refresh}")

    except Exception as e:
        log.exception("google.callback_error", error=str(e))
        return RedirectResponse(f"{_frontend_url()}/login?error=server_error")


# ── GitHub ────────────────────────────────────────────────────────────────────

@router.get("/github")
def github_login(link_token: str | None = None):
    if not settings.GITHUB_CLIENT_ID:
        raise HTTPException(400, "GitHub OAuth not configured")
    state = f"link:{link_token}" if link_token else "login"
    params = {
        "client_id": settings.GITHUB_CLIENT_ID,
        "redirect_uri": _github_callback_uri(),
        "scope": "read:user user:email",
        "state": state,
    }
    return RedirectResponse(f"{_GITHUB_AUTH_URL}?{urlencode(params)}")


@router.get("/github/callback")
def github_callback(
    code: str | None = None,
    error: str | None = None,
    state: str | None = None,
    db: Session = Depends(get_db),
):
    if is_github_integration_state(state):
        return handle_github_integration_callback(code=code, state=state, error=error, db=db)

    if error or not code:
        return RedirectResponse(f"{_frontend_url()}/login?error=oauth_denied")

    try:
        with httpx.Client(timeout=10) as client:
            token_resp = client.post(
                _GITHUB_TOKEN_URL,
                data={
                    "client_id": settings.GITHUB_CLIENT_ID,
                    "client_secret": settings.GITHUB_CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": _github_callback_uri(),
                },
                headers={"Accept": "application/json"},
            )
            if token_resp.status_code != 200:
                return RedirectResponse(f"{_frontend_url()}/login?error=oauth_failed")

            gh_token = token_resp.json().get("access_token")
            if not gh_token:
                return RedirectResponse(f"{_frontend_url()}/login?error=oauth_failed")

            auth_headers = {"Authorization": f"Bearer {gh_token}", "Accept": "application/json"}

            user_resp = client.get(_GITHUB_USER_URL, headers=auth_headers)
            if user_resp.status_code != 200:
                return RedirectResponse(f"{_frontend_url()}/login?error=oauth_failed")

            gh_user = user_resp.json()
            github_id = str(gh_user["id"])

            # fetch primary verified email
            email_resp = client.get(_GITHUB_EMAIL_URL, headers=auth_headers)
            emails = email_resp.json() if email_resp.status_code == 200 else []
            primary = next(
                (e["email"] for e in emails if e.get("primary") and e.get("verified")),
                gh_user.get("email", ""),
            )
            email = (primary or "").lower()

        # ── link flow: attach github_id to existing account ──────────────────
        if state and state.startswith("link:"):
            link_token_val = state[5:]
            try:
                from app.core.security import get_settings as _gs
                from jose import jwt as _jwt
                s = get_settings()
                payload = _jwt.decode(link_token_val, s.JWT_SECRET, algorithms=[s.JWT_ALG])
                user_id = payload["sub"]
            except Exception:
                return RedirectResponse(f"{_frontend_url()}/account?error=bad_link_token")

            existing = db.scalar(select(User).where(User.github_id == github_id))
            if existing and str(existing.id) != user_id:
                return RedirectResponse(f"{_frontend_url()}/account?error=github_already_linked")

            user = db.get(User, uuid.UUID(user_id))
            if not user:
                return RedirectResponse(f"{_frontend_url()}/account?error=not_found")

            user.github_id = github_id
            db.commit()
            return RedirectResponse(f"{_frontend_url()}/account?github=linked")

        # ── login/signup flow ─────────────────────────────────────────────────
        user = db.scalar(select(User).where(User.github_id == github_id))
        if not user and email:
            user = db.scalar(select(User).where(User.email == email))

        if not user:
            if not email:
                return RedirectResponse(f"{_frontend_url()}/login?error=no_email")
            name = gh_user.get("name") or gh_user.get("login") or email.split("@")[0]
            org = Org(id=uuid.uuid4(), name=name)
            user = User(id=uuid.uuid4(), org_id=org.id, email=email, password_hash="", github_id=github_id)
            db.add_all([org, user])
        elif not user.github_id:
            user.github_id = github_id

        db.commit()
        uid, oid = str(user.id), str(user.org_id)
        token = issue_token(uid, oid)
        refresh = issue_refresh_token(uid, oid)
        return RedirectResponse(f"{_frontend_url()}/auth/callback?token={token}&refresh_token={refresh}")

    except Exception as e:
        log.exception("github.callback_error", error=str(e))
        return RedirectResponse(f"{_frontend_url()}/login?error=server_error")
