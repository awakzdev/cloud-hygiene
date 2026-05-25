import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSON, UUID
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


class CloudTrailTrail(Base):
    __tablename__ = "cloudtrail_trails"
    __table_args__ = (UniqueConstraint("account_id", "arn"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("aws_accounts.id", ondelete="CASCADE"), index=True)
    arn: Mapped[str] = mapped_column(String(512))
    name: Mapped[str] = mapped_column(String(256))
    home_region: Mapped[str] = mapped_column(String(40))
    is_multi_region: Mapped[bool] = mapped_column(Boolean, default=False)
    is_logging: Mapped[bool] = mapped_column(Boolean, default=False)
    log_validation_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class GuardDutyDetector(Base):
    __tablename__ = "guardduty_detectors"
    __table_args__ = (UniqueConstraint("account_id", "detector_id", "region"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("aws_accounts.id", ondelete="CASCADE"), index=True)
    detector_id: Mapped[str] = mapped_column(String(64))
    region: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(20))  # ENABLED | DISABLED
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Vpc(Base):
    __tablename__ = "vpcs"
    __table_args__ = (UniqueConstraint("account_id", "vpc_id", "region"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("aws_accounts.id", ondelete="CASCADE"), index=True)
    vpc_id: Mapped[str] = mapped_column(String(64))
    region: Mapped[str] = mapped_column(String(40))
    flow_logs_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class SecurityGroup(Base):
    __tablename__ = "security_groups"
    __table_args__ = (UniqueConstraint("account_id", "group_id", "region"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("aws_accounts.id", ondelete="CASCADE"), index=True)
    group_id: Mapped[str] = mapped_column(String(64))
    group_name: Mapped[str] = mapped_column(String(256))
    region: Mapped[str] = mapped_column(String(40))
    vpc_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    unrestricted_ssh: Mapped[bool] = mapped_column(Boolean, default=False)
    unrestricted_rdp: Mapped[bool] = mapped_column(Boolean, default=False)
    has_any_inbound_rules: Mapped[bool] = mapped_column(Boolean, default=False)
    has_any_outbound_rules: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Ec2Instance(Base):
    __tablename__ = "ec2_instances"
    __table_args__ = (UniqueConstraint("account_id", "region", "instance_id"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("aws_accounts.id", ondelete="CASCADE"), index=True)
    instance_id: Mapped[str] = mapped_column(String(64))
    region: Mapped[str] = mapped_column(String(40))
    instance_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    state: Mapped[str] = mapped_column(String(20))
    imdsv2_required: Mapped[bool] = mapped_column(Boolean, default=False)
    vpc_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    subnet_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    security_group_ids: Mapped[list] = mapped_column(JSON, default=list)
    tags: Mapped[dict] = mapped_column(JSON, default=dict)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class EbsEncryptionDefault(Base):
    __tablename__ = "ebs_encryption_defaults"
    __table_args__ = (UniqueConstraint("account_id", "region"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("aws_accounts.id", ondelete="CASCADE"), index=True)
    region: Mapped[str] = mapped_column(String(40))
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class IamPasswordPolicy(Base):
    __tablename__ = "iam_password_policies"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("aws_accounts.id", ondelete="CASCADE"), unique=True, index=True)
    exists: Mapped[bool] = mapped_column(Boolean, default=False)
    min_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    require_uppercase: Mapped[bool] = mapped_column(Boolean, default=False)
    require_lowercase: Mapped[bool] = mapped_column(Boolean, default=False)
    require_numbers: Mapped[bool] = mapped_column(Boolean, default=False)
    require_symbols: Mapped[bool] = mapped_column(Boolean, default=False)
    max_age: Mapped[int | None] = mapped_column(Integer, nullable=True)
    password_reuse_prevention: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AccessAnalyzer(Base):
    __tablename__ = "access_analyzers"
    __table_args__ = (UniqueConstraint("account_id", "region"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("aws_accounts.id", ondelete="CASCADE"), index=True)
    region: Mapped[str] = mapped_column(String(40))
    analyzer_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    status: Mapped[str] = mapped_column(String(20))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ConfigRecorder(Base):
    __tablename__ = "config_recorders"
    __table_args__ = (UniqueConstraint("account_id", "region"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("aws_accounts.id", ondelete="CASCADE"), index=True)
    region: Mapped[str] = mapped_column(String(40))
    recorder_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    recording: Mapped[bool] = mapped_column(Boolean, default=False)
    delivery_channel_exists: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class RdsInstance(Base):
    __tablename__ = "rds_instances"
    __table_args__ = (UniqueConstraint("account_id", "arn"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("aws_accounts.id", ondelete="CASCADE"), index=True)
    db_instance_id: Mapped[str] = mapped_column(String(256))
    arn: Mapped[str] = mapped_column(String(512))
    region: Mapped[str] = mapped_column(String(40))
    publicly_accessible: Mapped[bool] = mapped_column(Boolean, default=False)
    storage_encrypted: Mapped[bool] = mapped_column(Boolean, default=False)
    engine: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
