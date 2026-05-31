import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, String, DateTime, func, JSON, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.core.encryption import EncryptedString


class AwsAccount(Base):
    __tablename__ = "aws_accounts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)
    label: Mapped[str] = mapped_column(String(120))
    account_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    role_arn: Mapped[str | None] = mapped_column(EncryptedString(700), nullable=True)
    external_id: Mapped[str] = mapped_column(EncryptedString(200))
    status: Mapped[str] = mapped_column(String(40), default="pending")  # pending|connected|error
    cfn_stack_name: Mapped[str] = mapped_column(String(64), default="VigilAccountConnector", nullable=False)
    enable_advanced_policy_generation: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    advanced_policy_generation_deployed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    enable_remediation_sg: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    enable_remediation_s3: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    enable_remediation_iam_keys: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    enable_remediation_iam_policy: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    enable_remediation_cloudtrail: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    enable_remediation_ssm_parameters: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    remediation_sg_deployed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    remediation_s3_deployed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    remediation_iam_keys_deployed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    remediation_iam_policy_deployed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    remediation_cloudtrail_deployed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    remediation_ssm_parameters_deployed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_error: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("aws_accounts.id", ondelete="CASCADE"), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(40), default="running")  # running|ok|error
    stats: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    findings_opened: Mapped[int] = mapped_column(Integer, default=0)
    findings_resolved: Mapped[int] = mapped_column(Integer, default=0)


class AssumeRoleAudit(Base):
    """One row per sts:AssumeRole call against a customer account.

    Purpose: customer transparency ("show me when Vigil touched my account"),
    forensic trail, and operational debugging (verify failures, throttles).
    """

    __tablename__ = "assume_role_audit"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("orgs.id", ondelete="CASCADE"), nullable=True, index=True
    )
    aws_account_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("aws_accounts.id", ondelete="SET NULL"), nullable=True, index=True
    )
    role_arn: Mapped[str | None] = mapped_column(String(700), nullable=True)
    session_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    purpose: Mapped[str | None] = mapped_column(String(80), nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(120), nullable=True)
    error_message: Mapped[str | None] = mapped_column(String(500), nullable=True)
    called_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
