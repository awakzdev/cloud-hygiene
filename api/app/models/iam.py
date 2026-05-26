import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, DateTime, Boolean, JSON, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class IamUser(Base):
    __tablename__ = "iam_users"
    __table_args__ = (UniqueConstraint("account_id", "arn"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("aws_accounts.id", ondelete="CASCADE"), index=True)
    arn: Mapped[str] = mapped_column(String(400), index=True)
    name: Mapped[str] = mapped_column(String(200))
    created: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    password_last_used: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    has_console_password: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class IamAccessKey(Base):
    __tablename__ = "iam_access_keys"
    __table_args__ = (UniqueConstraint("account_id", "key_id"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("aws_accounts.id", ondelete="CASCADE"), index=True)
    user_arn: Mapped[str] = mapped_column(String(400), index=True)
    key_id: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(20))  # Active|Inactive
    created: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_service: Mapped[str | None] = mapped_column(String(100), nullable=True)
    last_used_region: Mapped[str | None] = mapped_column(String(40), nullable=True)


class IamRole(Base):
    __tablename__ = "iam_roles"
    __table_args__ = (UniqueConstraint("account_id", "arn"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("aws_accounts.id", ondelete="CASCADE"), index=True)
    arn: Mapped[str] = mapped_column(String(400))
    name: Mapped[str] = mapped_column(String(200))
    created: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_assumed: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    trust_policy: Mapped[dict] = mapped_column(JSON, default=dict)
    inline_policies: Mapped[dict] = mapped_column(JSON, default=dict)
    attached_policies: Mapped[list] = mapped_column(JSON, default=list)


class IamPolicy(Base):
    __tablename__ = "iam_policies"
    __table_args__ = (UniqueConstraint("account_id", "arn"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("aws_accounts.id", ondelete="CASCADE"), index=True)
    arn: Mapped[str] = mapped_column(String(400))
    name: Mapped[str] = mapped_column(String(200))
    attachment_count: Mapped[int] = mapped_column(default=0)
    document: Mapped[dict] = mapped_column(JSON, default=dict)


class IamPermUsage(Base):
    __tablename__ = "iam_perm_usage"
    __table_args__ = (UniqueConstraint("account_id", "principal_arn", "service"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("aws_accounts.id", ondelete="CASCADE"), index=True)
    principal_arn: Mapped[str] = mapped_column(String(400), index=True)
    service: Mapped[str] = mapped_column(String(100))
    last_authenticated: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    actions_json: Mapped[list | None] = mapped_column(JSON, nullable=True)
