import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.core.encryption import EncryptedString


class IdentityProvider(Base):
    __tablename__ = "identity_providers"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String(40), nullable=False)
    config_json_encrypted: Mapped[str] = mapped_column(EncryptedString(4000), nullable=False)
    status: Mapped[str] = mapped_column(String(40), default="connected")
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (UniqueConstraint("org_id", "type", name="uq_identity_provider_org_type"),)


class IdentityUser(Base):
    __tablename__ = "identity_users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    provider_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("identity_providers.id", ondelete="CASCADE"), index=True)
    external_id: Mapped[str] = mapped_column(String(120), nullable=False)
    email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    name: Mapped[str | None] = mapped_column(String(320), nullable=True)
    mfa_enabled: Mapped[bool | None] = mapped_column(Boolean(), nullable=True)
    status: Mapped[str] = mapped_column(String(40), default="active")
    roles_json: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    last_active_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    snapshot_taken_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (UniqueConstraint("provider_id", "external_id", name="uq_identity_user_provider_external"),)


class Repo(Base):
    __tablename__ = "repos"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    provider_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("identity_providers.id", ondelete="CASCADE"), index=True)
    external_id: Mapped[str] = mapped_column(String(120), nullable=False)
    name: Mapped[str] = mapped_column(String(320), nullable=False)
    default_branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
    has_codeowners: Mapped[bool | None] = mapped_column(Boolean(), nullable=True)
    protected_envs: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    snapshot_taken_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (UniqueConstraint("provider_id", "external_id", name="uq_repo_provider_external"),)


class RepoProtection(Base):
    __tablename__ = "repo_protections"

    repo_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repos.id", ondelete="CASCADE"), primary_key=True)
    branch: Mapped[str] = mapped_column(String(255), primary_key=True)
    required_reviews: Mapped[int] = mapped_column(Integer(), default=0)
    dismiss_stale: Mapped[bool] = mapped_column(Boolean(), default=False)
    require_code_owners: Mapped[bool] = mapped_column(Boolean(), default=False)
    allow_force_push: Mapped[bool] = mapped_column(Boolean(), default=True)
    required_status_checks: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    snapshot_taken_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class PullRequest(Base):
    __tablename__ = "pull_requests"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    repo_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repos.id", ondelete="CASCADE"), index=True)
    number: Mapped[int] = mapped_column(Integer(), nullable=False)
    author: Mapped[str | None] = mapped_column(String(255), nullable=True)
    merged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    merged_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    required_review_count: Mapped[int] = mapped_column(Integer(), default=0)
    approval_count: Mapped[int] = mapped_column(Integer(), default=0)
    self_merge: Mapped[bool] = mapped_column(Boolean(), default=False)
    snapshot_taken_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (UniqueConstraint("repo_id", "number", name="uq_pull_request_repo_number"),)
