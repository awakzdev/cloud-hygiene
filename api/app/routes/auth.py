import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.passwords import hash_password, verify_password
from app.core.ratelimit import limiter
from app.core.security import current_principal, decode_refresh_token, issue_mfa_challenge_token, issue_refresh_token, issue_token
from app.models import Org, User

router = APIRouter()


class SignupIn(BaseModel):
    email: EmailStr
    password: str
    org_name: str

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 12:
            raise ValueError("password must be at least 12 characters")
        return v


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    org_id: str


class RefreshIn(BaseModel):
    refresh_token: str


@router.post("/signup", response_model=TokenOut)
@limiter.limit("5/minute")
def signup(request: Request, body: SignupIn, db: Session = Depends(get_db)):
    if db.scalar(select(User).where(User.email == body.email)):
        raise HTTPException(status.HTTP_409_CONFLICT, "email already registered")
    org = Org(id=uuid.uuid4(), name=body.org_name)
    user = User(
        id=uuid.uuid4(),
        org_id=org.id,
        email=body.email,
        password_hash=hash_password(body.password),
    )
    db.add_all([org, user])
    db.commit()
    uid, oid = str(user.id), str(org.id)
    return TokenOut(access_token=issue_token(uid, oid), refresh_token=issue_refresh_token(uid, oid), org_id=oid)


@router.post("/login", response_model=TokenOut)
@limiter.limit("10/minute")
def login(request: Request, body: LoginIn, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == body.email))
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "bad credentials")
    uid, oid = str(user.id), str(user.org_id)
    return TokenOut(access_token=issue_token(uid, oid), refresh_token=issue_refresh_token(uid, oid), org_id=oid)


@router.post("/refresh", response_model=TokenOut)
def refresh(body: RefreshIn, db: Session = Depends(get_db)):
    payload = decode_refresh_token(body.refresh_token)
    user = db.get(User, uuid.UUID(payload["sub"]))
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user not found")
    uid, oid = str(user.id), str(user.org_id)
    return TokenOut(
        access_token=issue_token(uid, oid),
        refresh_token=issue_refresh_token(uid, oid),
        org_id=oid,
    )


class MeOut(BaseModel):
    id: str
    email: str
    github_id: str | None
    totp_enabled: bool
    has_password: bool


@router.get("/me", response_model=MeOut)
def get_me(principal: dict = Depends(current_principal), db: Session = Depends(get_db)):
    user = db.get(User, uuid.UUID(principal["sub"]))
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    return MeOut(
        id=str(user.id),
        email=user.email,
        github_id=user.github_id,
        totp_enabled=user.totp_enabled,
        has_password=bool(user.password_hash),
    )


class ChangePasswordIn(BaseModel):
    current_password: str | None = None
    new_password: str


@router.put("/me/password", status_code=204)
def change_password(
    body: ChangePasswordIn,
    principal: dict = Depends(current_principal),
    db: Session = Depends(get_db),
):
    user = db.get(User, uuid.UUID(principal["sub"]))
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    if user.password_hash:
        # existing password — must verify current
        if not body.current_password or not verify_password(body.current_password, user.password_hash):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "current password incorrect")
    if len(body.new_password) < 12:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "password must be at least 8 characters")
    user.password_hash = hash_password(body.new_password)
    db.commit()


@router.delete("/me/github", status_code=204)
def disconnect_github(
    principal: dict = Depends(current_principal),
    db: Session = Depends(get_db),
):
    user = db.get(User, uuid.UUID(principal["sub"]))
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    if not user.password_hash:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "set a password before disconnecting GitHub")
    user.github_id = None
    db.commit()
