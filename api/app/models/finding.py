import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, DateTime, Integer, JSON, func, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("account_id", "check_id", "resource_arn"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("aws_accounts.id", ondelete="CASCADE"), index=True)
    check_id: Mapped[str] = mapped_column(String(120), index=True)
    resource_arn: Mapped[str] = mapped_column(String(400), index=True)
    title: Mapped[str] = mapped_column(String(300))
    severity: Mapped[str] = mapped_column(String(20))  # low|medium|high|critical
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="open")  # open|snoozed|resolved|ignored|excepted
    snooze_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    exception_reason: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    exception_approved_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    exception_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class FindingEvent(Base):
    __tablename__ = "finding_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    actor: Mapped[str] = mapped_column(String(200), default="system")
    action: Mapped[str] = mapped_column(String(40))  # opened|snoozed|resolved|ignored|reopened|note
    note: Mapped[str | None] = mapped_column(String(2000), nullable=True)
