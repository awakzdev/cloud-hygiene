import uuid

from sqlalchemy import ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class Control(Base):
    __tablename__ = "controls"
    __table_args__ = (UniqueConstraint("framework", "control_id"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    framework: Mapped[str] = mapped_column(String(40), index=True)   # soc2 | cis_aws_l1 | iso27001
    control_id: Mapped[str] = mapped_column(String(30))              # CC6.2 | 1.4
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    guidance: Mapped[str | None] = mapped_column(Text, nullable=True)


class CheckControl(Base):
    __tablename__ = "check_controls"
    __table_args__ = (UniqueConstraint("check_id", "control_id"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    check_id: Mapped[str] = mapped_column(String(120), index=True)
    control_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("controls.id", ondelete="CASCADE"), index=True
    )
