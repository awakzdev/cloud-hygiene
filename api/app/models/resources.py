import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class S3Bucket(Base):
    __tablename__ = "s3_buckets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("aws_accounts.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    arn: Mapped[str] = mapped_column(String(512))
    logging_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    encrypted: Mapped[bool] = mapped_column(Boolean, default=False)
    kms_encrypted: Mapped[bool] = mapped_column(Boolean, default=False)
    versioning_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    public_access_blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    https_only: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        __import__("sqlalchemy").UniqueConstraint("account_id", "arn"),
    )


class KmsKey(Base):
    __tablename__ = "kms_keys"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("aws_accounts.id", ondelete="CASCADE"), index=True)
    key_id: Mapped[str] = mapped_column(String(64))
    arn: Mapped[str] = mapped_column(String(512))
    alias: Mapped[str | None] = mapped_column(String(256), nullable=True)
    rotation_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    has_wildcard_principal: Mapped[bool] = mapped_column(Boolean, default=False)
    key_state: Mapped[str | None] = mapped_column(String(40), nullable=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        __import__("sqlalchemy").UniqueConstraint("account_id", "arn"),
    )
