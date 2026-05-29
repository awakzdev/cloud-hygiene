"""Immutable evidence vault (WORM) — scaffold only.

Upload and auditor-share flows are NOT wired. Configure EVIDENCE_VAULT_S3_URI
for where packs will land when implementation is enabled.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from app.core.config import get_settings

_S3_URI_RE = re.compile(r"^s3://([^/]+)/?(.*)$")


class AuditorAccessMode(str, Enum):
    """How auditors reach a vaulted object (future)."""

    NONE = "none"
    PRESIGNED = "presigned"
    APPROVED_LINK = "approved_link"


class VaultWriteMode(str, Enum):
    """Planned Object Lock mode on PutObject (future)."""

    GOVERNANCE = "GOVERNANCE"
    COMPLIANCE = "COMPLIANCE"


@dataclass(frozen=True)
class VaultLocation:
    """Parsed destination for immutable evidence objects."""

    bucket: str
    prefix: str
    region: str | None = None

    @property
    def base_uri(self) -> str:
        p = self.prefix.rstrip("/")
        return f"s3://{self.bucket}/{p}" if p else f"s3://{self.bucket}"


@dataclass(frozen=True)
class VaultUploadPlan:
    """Describes a single immutable pack write (no bytes uploaded yet)."""

    org_id: uuid.UUID
    account_id: uuid.UUID
    report_id: str
    framework: str
    object_key: str
    s3_uri: str
    content_sha256: str | None
    retention_days: int
    object_lock_mode: VaultWriteMode
    generated_at: str

    def to_manifest(self) -> dict[str, Any]:
        return {
            "status": "planned",
            "implementation": "not_wired",
            "s3_uri": self.s3_uri,
            "object_key": self.object_key,
            "report_id": self.report_id,
            "retention_days": self.retention_days,
            "object_lock_mode": self.object_lock_mode.value,
            "generated_at": self.generated_at,
        }


@dataclass(frozen=True)
class AuditorAccessPlan:
    """Future: time-limited read access to one vaulted object."""

    report_id: str
    s3_uri: str
    mode: AuditorAccessMode
    expires_at: str | None
    share_token_placeholder: str | None

    def to_manifest(self) -> dict[str, Any]:
        return {
            "status": "planned",
            "implementation": "not_wired",
            "mode": self.mode.value,
            "s3_uri": self.s3_uri,
            "report_id": self.report_id,
            "expires_at": self.expires_at,
            "note": "Auditor link must reference a fixed report_id object, not a mutable latest URL.",
        }


def parse_s3_uri(uri: str) -> VaultLocation:
    uri = (uri or "").strip()
    match = _S3_URI_RE.match(uri)
    if not match:
        raise ValueError(f"EVIDENCE_VAULT_S3_URI must be s3://bucket/prefix, got: {uri!r}")
    bucket, prefix = match.group(1), match.group(2)
    if not bucket:
        raise ValueError("S3 bucket name is required")
    return VaultLocation(bucket=bucket, prefix=prefix.strip("/"))


def vault_config() -> dict[str, Any]:
    """Resolved vault settings from environment (and future org overrides)."""
    s = get_settings()
    loc: VaultLocation | None = None
    if s.EVIDENCE_VAULT_S3_URI.strip():
        loc = parse_s3_uri(s.EVIDENCE_VAULT_S3_URI)
        if s.EVIDENCE_VAULT_S3_REGION.strip():
            loc = VaultLocation(bucket=loc.bucket, prefix=loc.prefix, region=s.EVIDENCE_VAULT_S3_REGION.strip())
    mode = VaultWriteMode.GOVERNANCE
    raw_mode = (s.EVIDENCE_VAULT_OBJECT_LOCK_MODE or "GOVERNANCE").upper()
    if raw_mode == VaultWriteMode.COMPLIANCE.value:
        mode = VaultWriteMode.COMPLIANCE
    auditor = AuditorAccessMode.NONE
    raw_auditor = (s.EVIDENCE_VAULT_AUDITOR_ACCESS_MODE or "none").lower()
    try:
        auditor = AuditorAccessMode(raw_auditor)
    except ValueError:
        auditor = AuditorAccessMode.NONE
    return {
        "enabled": bool(s.EVIDENCE_VAULT_ENABLED) and loc is not None,
        "location": loc,
        "retention_days": s.EVIDENCE_VAULT_RETENTION_DAYS,
        "object_lock_mode": mode,
        "auditor_access_mode": auditor,
    }


def vault_enabled() -> bool:
    return vault_config()["enabled"]


def object_key_for_pack(
    org_id: uuid.UUID,
    account_id: uuid.UUID,
    report_id: str,
    *,
    prefix: str,
) -> str:
    """Immutable key layout: one object per export, never overwrite."""
    base = prefix.rstrip("/")
    parts = [
        base,
        f"orgs/{org_id}",
        f"accounts/{account_id}",
        "packs",
        f"{report_id}.zip",
    ]
    return "/".join(p for p in parts if p)


def plan_vault_upload(
    *,
    org_id: uuid.UUID,
    account_id: uuid.UUID,
    report_id: str,
    framework: str,
    content_sha256: str | None = None,
    generated_at: datetime | None = None,
    customer_s3_uri: str | None = None,
) -> VaultUploadPlan | None:
    """Return upload plan if vault is configured; does not write to S3."""
    cfg = vault_config()
    loc: VaultLocation | None = cfg["location"]
    if customer_s3_uri:
        loc = parse_s3_uri(customer_s3_uri)
    if not loc:
        return None
    if not cfg["enabled"] and not customer_s3_uri:
        return None

    ts = generated_at or datetime.now(timezone.utc)
    key = object_key_for_pack(org_id, account_id, report_id, prefix=loc.prefix)
    return VaultUploadPlan(
        org_id=org_id,
        account_id=account_id,
        report_id=report_id,
        framework=framework,
        object_key=key,
        s3_uri=f"s3://{loc.bucket}/{key}",
        content_sha256=content_sha256,
        retention_days=int(cfg["retention_days"]),
        object_lock_mode=cfg["object_lock_mode"],
        generated_at=ts.isoformat(),
    )


def plan_auditor_access(
    upload: VaultUploadPlan,
    *,
    approved_by: str | None = None,
    ttl_hours: int = 168,
) -> AuditorAccessPlan | None:
    """Future: presigned URL or approved share link for one report_id."""
    cfg = vault_config()
    mode: AuditorAccessMode = cfg["auditor_access_mode"]
    if mode == AuditorAccessMode.NONE:
        return None
    return AuditorAccessPlan(
        report_id=upload.report_id,
        s3_uri=upload.s3_uri,
        mode=mode,
        expires_at=None,
        share_token_placeholder=f"pending-approval:{approved_by or 'unknown'}",
    )


def upload_pack_to_vault(_plan: VaultUploadPlan, _zip_bytes: bytes) -> dict[str, Any]:
    """NOT IMPLEMENTED — raises until S3 Object Lock bucket + IAM exist."""
    raise NotImplementedError(
        "Evidence vault upload is not wired. Set EVIDENCE_VAULT_* env vars and implement "
        "boto3 PutObject with Object Lock when ready."
    )


def org_vault_override(org_settings: dict | None) -> str | None:
    """Future per-org customer bucket: org.settings['evidence_vault']['customer_s3_uri']."""
    if not org_settings:
        return None
    block = org_settings.get("evidence_vault") or {}
    uri = (block.get("customer_s3_uri") or "").strip()
    return uri or None
