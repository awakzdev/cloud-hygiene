import copy
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.aws import verify_account
from app.core.config import get_settings
from app.core.db import get_db
from app.core.iam_usage import (
    unused_services_from_usages,
    used_actions_from_usages,
    used_services_from_usages,
)
from app.core.security import current_principal
from app.models import AwsAccount, IamPermUsage, IamRole, ScanRun
from app.models.cloudtrail import CloudTrailEvent
from app.models.github import IdentityProvider, PullRequest, Repo
from app.models.iam import IamAccessKey, IamUser
from app.models.resources import (
    AccessAnalyzer, CloudTrailTrail, ConfigRecorder, Ec2Instance,
    EbsEncryptionDefault, EbsVolume, GuardDutyDetector, IamPasswordPolicy,
    KmsKey, RdsInstance, S3AccountPublicAccessBlock, S3Bucket, SecurityGroup,
    SecurityHubStatus, Vpc,
)
from app.models.org import Org

router = APIRouter()
settings = get_settings()

CFN_TEMPLATE_URL = (
    "https://amzn-demo-cloud-hygiene.s3.amazonaws.com/hygiene-readonly-role.yaml"
)


class AccountIn(BaseModel):
    label: str = "AWS Account"


class AccountOut(BaseModel):
    id: str
    label: str
    account_id: str | None
    status: str
    external_id: str
    cfn_launch_url: str | None = None
    last_scan_at: datetime | None = None


class VerifyIn(BaseModel):
    role_arn: str


def _launch_url(external_id: str) -> str:
    params = {
        "templateURL": CFN_TEMPLATE_URL,
        "stackName": "VigilReadOnly",
        "param_ExternalId": external_id,
        "param_HygieneAccountPrincipal": settings.TRUST_PRINCIPAL_ARN,
    }
    qs = "&".join(f"{k}={quote(v, safe='')}" for k, v in params.items())
    return f"https://console.aws.amazon.com/cloudformation/home#/stacks/create/review?{qs}"


@router.post("", response_model=AccountOut, status_code=status.HTTP_201_CREATED)
def create_account(body: AccountIn, p=Depends(current_principal), db: Session = Depends(get_db)):
    if not db.get(Org, uuid.UUID(p["org_id"])):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "session expired — please sign in again")
    ext = secrets.token_urlsafe(24)
    acc = AwsAccount(
        id=uuid.uuid4(),
        org_id=uuid.UUID(p["org_id"]),
        label=body.label,
        external_id=ext,
    )
    db.add(acc)
    db.commit()
    return AccountOut(
        id=str(acc.id),
        label=acc.label,
        account_id=acc.account_id,
        status=acc.status,
        external_id=ext,
        cfn_launch_url=_launch_url(ext),
        last_scan_at=acc.last_scan_at,
    )


@router.get("", response_model=list[AccountOut])
def list_accounts(p=Depends(current_principal), db: Session = Depends(get_db)):
    rows = db.scalars(select(AwsAccount).where(AwsAccount.org_id == uuid.UUID(p["org_id"]))).all()
    return [
        AccountOut(
            id=str(a.id),
            label=a.label,
            account_id=a.account_id,
            status=a.status,
            external_id=a.external_id,
            cfn_launch_url=_launch_url(a.external_id),
            last_scan_at=a.last_scan_at,
        )
        for a in rows
    ]


@router.post("/{account_id}/verify", response_model=AccountOut)
def verify(account_id: str, body: VerifyIn, p=Depends(current_principal), db: Session = Depends(get_db)):
    acc = db.get(AwsAccount, uuid.UUID(account_id))
    if not acc or str(acc.org_id) != p["org_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")
    ok, aws_account_id, alias, err = verify_account(body.role_arn, acc.external_id)
    if not ok:
        acc.status = "error"
        acc.last_error = err
        db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"assume role failed: {err}")
    acc.role_arn = body.role_arn
    acc.account_id = aws_account_id
    acc.label = alias or aws_account_id or acc.label
    acc.status = "connected"
    acc.last_error = None
    db.commit()

    from app.worker.tasks import run_scan
    run_scan.delay(str(acc.id))

    return AccountOut(
        id=str(acc.id),
        label=acc.label,
        account_id=acc.account_id,
        status=acc.status,
        external_id=acc.external_id,
        cfn_launch_url=_launch_url(acc.external_id),
        last_scan_at=acc.last_scan_at,
    )


@router.delete("/{account_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_account(account_id: str, p=Depends(current_principal), db: Session = Depends(get_db)):
    acc = db.get(AwsAccount, uuid.UUID(account_id))
    if not acc or str(acc.org_id) != p["org_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")
    db.delete(acc)
    db.commit()


@router.post("/{account_id}/scan")
def trigger_scan(account_id: str, p=Depends(current_principal), db: Session = Depends(get_db)):
    from app.worker.tasks import run_scan
    acc = db.get(AwsAccount, uuid.UUID(account_id))
    if not acc or str(acc.org_id) != p["org_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")
    if acc.status != "connected":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "account not connected")
    job = run_scan.delay(str(acc.id))
    return {"job_id": job.id}


class ScanRunOut(BaseModel):
    id: str
    status: str
    started_at: str
    finished_at: str | None
    error: str | None
    findings_opened: int
    findings_resolved: int


@router.get("/{account_id}/scan-runs/latest", response_model=ScanRunOut | None)
def latest_scan_run(account_id: str, p=Depends(current_principal), db: Session = Depends(get_db)):
    acc = db.get(AwsAccount, uuid.UUID(account_id))
    if not acc or str(acc.org_id) != p["org_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")
    run = db.scalar(
        select(ScanRun)
        .where(ScanRun.account_id == acc.id)
        .order_by(ScanRun.started_at.desc())
        .limit(1)
    )
    if not run:
        return None
    return ScanRunOut(
        id=str(run.id),
        status=run.status,
        started_at=run.started_at.isoformat(),
        finished_at=run.finished_at.isoformat() if run.finished_at else None,
        error=run.error,
        findings_opened=run.findings_opened or 0,
        findings_resolved=run.findings_resolved or 0,
    )


def _actions_for_service(used_actions: list[str], service: str) -> list[str]:
    prefix = f"{service.lower()}:"
    return sorted(a for a in used_actions if a.lower().startswith(prefix))


def _dedupe_actions(actions: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for action in actions:
        key = action.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(action)
    return out


def _clean_policy_doc(
    doc: dict,
    unused_set: set[str],
    used_set: set[str],
    used_actions: list[str],
) -> tuple[dict, int, int]:
    """Return (cleaned_doc, removed_statement_count, modified_statement_count)."""
    doc = copy.deepcopy(doc)
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]

    used_action_keys = {a.lower() for a in used_actions}
    has_action_data = bool(used_actions)

    new_stmts = []
    removed = 0
    modified = 0
    for stmt in stmts:
        if stmt.get("Effect", "Allow") != "Allow":
            new_stmts.append(stmt)
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        if any(a == "*" for a in actions):
            if has_action_data:
                narrowed = list(used_actions)
            elif used_set:
                narrowed = sorted(f"{svc}:*" for svc in used_set)
            else:
                removed += 1
                continue
            stmt = copy.deepcopy(stmt)
            stmt["Action"] = narrowed if len(narrowed) > 1 else narrowed[0]
            new_stmts.append(stmt)
            modified += 1
            continue

        kept: list[str] = []
        for action in actions:
            if action.endswith(":*") and ":" in action:
                svc = action.split(":")[0].lower()
                svc_actions = _actions_for_service(used_actions, svc)
                if svc_actions:
                    kept.extend(svc_actions)
                elif not has_action_data and svc not in unused_set:
                    kept.append(action)
                continue
            svc = action.split(":")[0].lower() if ":" in action else ""
            if has_action_data:
                if action.lower() in used_action_keys:
                    kept.append(action)
            elif svc not in unused_set:
                kept.append(action)

        kept = _dedupe_actions(kept)
        if not kept:
            removed += 1
            continue
        stmt = copy.deepcopy(stmt)
        stmt["Action"] = kept if len(kept) > 1 else kept[0]
        if kept != actions:
            modified += 1
        new_stmts.append(stmt)

    doc["Statement"] = new_stmts
    return doc, removed, modified


@router.get("/{account_id}/roles/generated-policy")
def generate_role_policy(
    account_id: str,
    role_arn: str,
    threshold_days: int = 90,
    p=Depends(current_principal),
    db: Session = Depends(get_db),
):
    acc = db.get(AwsAccount, uuid.UUID(account_id))
    if not acc or str(acc.org_id) != p["org_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")

    role = db.scalar(
        select(IamRole).where(IamRole.account_id == acc.id, IamRole.arn == role_arn)
    )
    if not role:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "role not found — run a scan first")

    usages = db.scalars(
        select(IamPermUsage).where(
            IamPermUsage.account_id == acc.id,
            IamPermUsage.principal_arn == role_arn,
        )
    ).all()

    cutoff = datetime.now(timezone.utc) - timedelta(days=threshold_days)
    unused_set = unused_services_from_usages(usages, cutoff)
    used_set = used_services_from_usages(usages, cutoff)
    used_actions = used_actions_from_usages(usages, cutoff)
    granularity = "action" if used_actions else "service"

    inline = role.inline_policies or {}
    if not inline:
        return {
            "role_arn": role_arn,
            "has_inline_policies": False,
            "unused_services": sorted(unused_set),
            "used_services": sorted(used_set),
            "used_actions": used_actions,
            "granularity": granularity,
            "note": "Role has no inline policies. Permissions come from attached managed policies — review with list-attached-role-policies.",
        }

    cleaned_policies: dict = {}
    total_removed = 0
    total_modified = 0
    for policy_name, doc in inline.items():
        cleaned, removed, modified = _clean_policy_doc(doc, unused_set, used_set, used_actions)
        cleaned_policies[policy_name] = cleaned
        total_removed += removed
        total_modified += modified

    return {
        "role_arn": role_arn,
        "has_inline_policies": True,
        "unused_services": sorted(unused_set),
        "used_services": sorted(used_set),
        "used_actions": used_actions,
        "granularity": granularity,
        "threshold_days": threshold_days,
        "statements_removed": total_removed,
        "statements_modified": total_modified,
        "original_policies": inline,
        "cleaned_policies": cleaned_policies,
    }


@router.get("/{account_id}/blast-radius")
def blast_radius(
    account_id: str,
    resource_arn: str,
    check_id: str,
    p=Depends(current_principal),
    db: Session = Depends(get_db),
):
    """What-if analysis: what depends on this resource, and how safe is remediation?"""
    acc = db.get(AwsAccount, uuid.UUID(account_id))
    if not acc or str(acc.org_id) != p["org_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")

    now = datetime.now(timezone.utc)
    threshold = now - timedelta(days=90)

    # ── IAM Role ────────────────────────────────────────────────────────────
    if check_id.startswith("iam.role."):
        role = db.scalar(
            select(IamRole).where(IamRole.account_id == acc.id, IamRole.arn == resource_arn)
        )
        if not role:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "role not found — run a scan first")

        usages = db.scalars(
            select(IamPermUsage).where(
                IamPermUsage.account_id == acc.id,
                IamPermUsage.principal_arn == resource_arn,
            )
        ).all()

        days_since_assumed = (
            int((now - role.last_assumed).total_seconds() / 86400)
            if role.last_assumed else None
        )

        services = sorted(
            [
                {
                    "name": u.service,
                    "last_used": u.last_authenticated.isoformat() if u.last_authenticated else None,
                    "days_ago": int((now - u.last_authenticated).total_seconds() / 86400) if u.last_authenticated else None,
                    "active": u.last_authenticated is not None and u.last_authenticated >= threshold,
                    "in_policy": any(
                        u.service in str(doc)
                        for doc in (role.inline_policies or {}).values()
                    ),
                }
                for u in usages
            ],
            key=lambda s: (not s["active"], s["name"]),
        )

        active_services = [s for s in services if s["active"]]
        unused_services = [s for s in services if not s["active"]]

        # Extract trust principals from trust policy
        trust_principals: list[str] = []
        for stmt in (role.trust_policy or {}).get("Statement", []):
            p_val = stmt.get("Principal", {})
            if isinstance(p_val, str):
                trust_principals.append(p_val)
            elif isinstance(p_val, dict):
                for v in p_val.values():
                    if isinstance(v, list):
                        trust_principals.extend(v)
                    else:
                        trust_principals.append(v)

        # Confidence: high = safe to remove, low = risky
        if active_services:
            most_recent_days = min(s["days_ago"] for s in active_services if s["days_ago"] is not None)
            confidence = "low" if most_recent_days < 30 else "medium"
        elif days_since_assumed is not None and days_since_assumed < 90:
            confidence = "medium"
        else:
            confidence = "high"

        warnings = []
        for s in active_services:
            warnings.append(f"Service '{s['name']}' was last used {s['days_ago']} days ago — verify before removing")
        if days_since_assumed is not None and days_since_assumed < 90:
            warnings.append(f"Role was assumed {days_since_assumed} days ago — confirm it is no longer needed")

        # Build per-policy unused service overlap
        unused_service_names = {s["name"] for s in unused_services}
        active_service_names = {s["name"] for s in active_services}

        def _services_in_statements(statements: list) -> set[str]:
            """Extract service prefixes (e.g. 's3', 'ec2') from policy statements."""
            found = set()
            for stmt in statements:
                if stmt.get("Effect") != "Allow":
                    continue
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                for action in actions:
                    if action == "*":
                        found.add("*")
                    elif ":" in action:
                        found.add(action.split(":")[0].lower())
            return found

        attached_policy_analysis = []
        for pol in (role.attached_policies or []):
            pol_services = _services_in_statements(pol.get("statements", []))
            removable = sorted(pol_services & unused_service_names - {"*"})
            active_in_pol = sorted(pol_services & active_service_names - {"*"})
            has_wildcard = "*" in pol_services
            attached_policy_analysis.append({
                "policy_arn": pol["policy_arn"],
                "policy_name": pol["policy_name"],
                "policy_type": pol["policy_type"],
                "granted_services": sorted(pol_services - {"*"}),
                "unused_services": removable,
                "active_services": active_in_pol,
                "has_wildcard_action": has_wildcard,
                "action": "detach_and_replace" if pol["policy_type"] == "aws_managed" else "edit",
            })

        return {
            "resource_type": "iam_role",
            "confidence": confidence,
            "days_since_last_assumed": days_since_assumed,
            "trust_principals": trust_principals,
            "services": services,
            "active_service_count": len(active_services),
            "unused_service_count": len(unused_services),
            "has_inline_policies": bool(role.inline_policies),
            "attached_policies": attached_policy_analysis,
            "warnings": warnings,
        }

    # ── IAM Access Key ───────────────────────────────────────────────────────
    if check_id.startswith("iam.access_key."):
        # resource_arn here is the user ARN; key_id is in the finding title/evidence
        keys = db.scalars(
            select(IamAccessKey).where(
                IamAccessKey.account_id == acc.id,
                IamAccessKey.user_arn == resource_arn,
                IamAccessKey.status == "Active",
            )
        ).all()

        key_data = []
        for k in keys:
            days_ago = int((now - k.last_used).total_seconds() / 86400) if k.last_used else None
            key_data.append({
                "key_id": k.key_id,
                "last_used": k.last_used.isoformat() if k.last_used else None,
                "days_ago": days_ago,
                "last_used_service": k.last_used_service,
                "last_used_region": k.last_used_region,
                "active": days_ago is not None and days_ago < 90,
            })

        any_recent = any(k["days_ago"] is not None and k["days_ago"] < 30 for k in key_data)
        any_used_90 = any(k["active"] for k in key_data)
        confidence = "low" if any_recent else ("medium" if any_used_90 else "high")

        warnings = []
        for k in key_data:
            if k["active"]:
                warnings.append(f"Key {k['key_id']} last used {k['days_ago']} days ago via {k['last_used_service'] or 'unknown service'}")

        return {
            "resource_type": "iam_access_key",
            "confidence": confidence,
            "keys": key_data,
            "warnings": warnings,
        }

    # ── IAM User ─────────────────────────────────────────────────────────────
    if check_id.startswith("iam.user."):
        user = db.scalar(
            select(IamUser).where(IamUser.account_id == acc.id, IamUser.arn == resource_arn)
        )
        if not user:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found — run a scan first")

        last_activity = user.password_last_used or user.last_seen_at
        days_inactive = (
            int((now - last_activity).total_seconds() / 86400)
            if last_activity else None
        )

        active_keys = db.scalars(
            select(IamAccessKey).where(
                IamAccessKey.account_id == acc.id,
                IamAccessKey.user_arn == resource_arn,
                IamAccessKey.status == "Active",
            )
        ).all()

        key_summary = [
            {
                "key_id": k.key_id,
                "last_used": k.last_used.isoformat() if k.last_used else None,
                "days_ago": int((now - k.last_used).total_seconds() / 86400) if k.last_used else None,
                "last_used_service": k.last_used_service,
            }
            for k in active_keys
        ]

        recently_active_keys = [k for k in key_summary if k["days_ago"] is not None and k["days_ago"] < 90]
        confidence = "low" if (days_inactive and days_inactive < 30) else ("medium" if recently_active_keys else "high")

        warnings = []
        if recently_active_keys:
            for k in recently_active_keys:
                warnings.append(f"Access key {k['key_id']} used {k['days_ago']} days ago via {k['last_used_service'] or 'unknown'} — deactivate keys before disabling user")

        return {
            "resource_type": "iam_user",
            "confidence": confidence,
            "has_console_password": user.has_console_password,
            "days_inactive": days_inactive,
            "active_key_count": len(active_keys),
            "keys": key_summary,
            "warnings": warnings,
        }

    # ── EC2 Security Group ───────────────────────────────────────────────────
    if check_id.startswith("ec2.security_group."):
        # resource_arn: arn:aws:ec2:{region}:{account}:security-group/{group_id}
        group_id = resource_arn.split("/")[-1] if "/" in resource_arn else None
        sg = db.scalar(
            select(SecurityGroup).where(
                SecurityGroup.account_id == acc.id,
                SecurityGroup.group_id == group_id,
            )
        ) if group_id else None

        if not sg:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "security group not found — run a scan first")

        # Find instances with this SG attached
        all_instances = db.scalars(
            select(Ec2Instance).where(Ec2Instance.account_id == acc.id, Ec2Instance.region == sg.region)
        ).all()
        affected = [i for i in all_instances if sg.group_id in (i.security_group_ids or [])]

        instance_data = [
            {
                "instance_id": i.instance_id,
                "instance_type": i.instance_type,
                "state": i.state,
                "vpc_id": i.vpc_id,
                "name": (i.tags or {}).get("Name", i.instance_id),
            }
            for i in affected
        ]

        running = [i for i in affected if i.state == "running"]
        confidence = "high" if not running else ("low" if len(running) > 3 else "medium")

        warnings = []
        if running:
            warnings.append(f"{len(running)} running instance(s) currently exposed via this security group rule")
        elif sg.is_default and affected:
            warnings.append(
                f"{len(affected)} instance(s) use this default security group — confirm each has an explicit SG before clearing rules"
            )

        return {
            "resource_type": "security_group",
            "confidence": confidence,
            "group_id": sg.group_id,
            "group_name": sg.group_name,
            "vpc_id": sg.vpc_id,
            "region": sg.region,
            "is_default": sg.is_default,
            "affected_instances": instance_data,
            "running_count": len(running),
            "total_count": len(affected),
            "warnings": warnings,
        }

    # ── KMS Key ──────────────────────────────────────────────────────────────
    if check_id.startswith("kms.key."):
        kms_key = db.scalar(
            select(KmsKey).where(KmsKey.account_id == acc.id, KmsKey.arn == resource_arn)
        )
        if not kms_key:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "KMS key not found — run a scan first")

        # Find CloudTrail trails that reference this key
        all_trails = db.scalars(
            select(CloudTrailTrail).where(
                CloudTrailTrail.account_id == acc.id,
                CloudTrailTrail.kms_key_id.isnot(None),
            )
        ).all()
        dependent_trails = [
            t for t in all_trails
            if kms_key.key_id in (t.kms_key_id or "") or kms_key.arn == t.kms_key_id
        ]
        trail_data = [
            {
                "name": t.name,
                "arn": t.arn,
                "region": t.home_region,
                "is_multi_region": t.is_multi_region,
            }
            for t in dependent_trails
        ]

        # Enabling rotation is transparent to applications — AWS retains old key material.
        # confidence=high unless the key is in a state that prevents rotation.
        confidence = "high"
        warnings: list[str] = []

        state_lower = (kms_key.key_state or "").lower()
        if state_lower == "pendingdeletion":
            confidence = "medium"
            warnings.append("Key is pending deletion — rotation cannot be enabled until the deletion is cancelled")
        elif state_lower == "disabled":
            confidence = "medium"
            warnings.append("Key is currently disabled — re-enable the key before enabling rotation")

        return {
            "resource_type": "kms_key",
            "confidence": confidence,
            "key_id": kms_key.key_id,
            "alias": kms_key.alias,
            "key_state": kms_key.key_state,
            "rotation_enabled": kms_key.rotation_enabled,
            "dependent_trails": trail_data,
            "dependent_trail_count": len(dependent_trails),
            "warnings": warnings,
        }

    # ── S3 Bucket ────────────────────────────────────────────────────────────
    if check_id.startswith("s3.bucket."):
        bucket = db.scalar(
            select(S3Bucket).where(S3Bucket.account_id == acc.id, S3Bucket.arn == resource_arn)
        )
        if not bucket:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "S3 bucket not found — run a scan first")

        warnings: list[str] = []
        confidence = "medium"

        if check_id == "s3.bucket.no_kms":
            warnings.append(
                "Any IAM principal writing to this bucket must have kms:GenerateDataKey and kms:Decrypt on the chosen key — verify application IAM policies before enabling"
            )
            if not bucket.encrypted:
                warnings.append("Bucket has no default encryption — enabling SSE-KMS will not re-encrypt existing objects")

        elif check_id == "s3.bucket.no_https_policy":
            confidence = "high"
            # Verdict covers this — no separate warning box (avoids "safe" + amber caution).

        elif check_id == "s3.bucket.public_access_not_blocked":
            if not bucket.public_access_blocked:
                confidence = "low"
                warnings.append(
                    "Blocking public access may break static website hosting or presigned-URL workflows that rely on public bucket ACLs or policies"
                )

        elif check_id == "s3.bucket.no_logging":
            confidence = "high"

        return {
            "resource_type": "s3_bucket",
            "confidence": confidence,
            "bucket_name": bucket.name,
            "arn": bucket.arn,
            "encrypted": bucket.encrypted,
            "kms_encrypted": bucket.kms_encrypted,
            "versioning_enabled": bucket.versioning_enabled,
            "public_access_blocked": bucket.public_access_blocked,
            "https_only": bucket.https_only,
            "logging_enabled": bucket.logging_enabled,
            "warnings": warnings,
        }

    # ── EC2 Instance (IMDSv2) ────────────────────────────────────────────────
    if check_id == "ec2.instance.imdsv2_not_required":
        instance_id = resource_arn.split("/")[-1] if "/" in resource_arn else None
        instance = db.scalar(
            select(Ec2Instance).where(Ec2Instance.account_id == acc.id, Ec2Instance.instance_id == instance_id)
        ) if instance_id else None
        if not instance:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "instance not found — run a scan first")

        warnings: list[str] = [
            "Requiring IMDSv2 breaks applications that call the metadata service without a session token — test in non-prod first"
        ]
        if instance.state == "running":
            warnings.append("Change takes effect immediately on a running instance — no restart needed, but verify application health after applying")

        return {
            "resource_type": "ec2_instance",
            "confidence": "medium",
            "instance_id": instance.instance_id,
            "instance_type": instance.instance_type,
            "state": instance.state,
            "region": instance.region,
            "imdsv2_required": instance.imdsv2_required,
            "warnings": warnings,
        }

    # ── EBS Volume (unencrypted) ─────────────────────────────────────────────
    if check_id == "ec2.ebs.volume_unencrypted":
        volume = db.scalar(
            select(EbsVolume).where(EbsVolume.account_id == acc.id, EbsVolume.arn == resource_arn)
        )
        if not volume:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "EBS volume not found — run a scan first")

        attached_instances = []
        if volume.attached_instance_ids:
            ec2s = db.scalars(
                select(Ec2Instance).where(
                    Ec2Instance.account_id == acc.id,
                    Ec2Instance.instance_id.in_(volume.attached_instance_ids),
                )
            ).all()
            attached_instances = [
                {
                    "instance_id": i.instance_id,
                    "state": i.state,
                    "name": (i.tags or {}).get("Name", i.instance_id),
                    "instance_type": i.instance_type,
                }
                for i in ec2s
            ]

        running = [i for i in attached_instances if i["state"] == "running"]
        confidence = "low" if running else ("medium" if attached_instances else "high")

        warnings = ["Encryption requires a snapshot, an encrypted copy, and a new volume — cannot be done in place"]

        return {
            "resource_type": "ebs_volume",
            "confidence": confidence,
            "volume_id": volume.volume_id,
            "size_gib": volume.size_gib,
            "volume_type": volume.volume_type,
            "state": volume.state,
            "region": volume.region,
            "attached_instances": attached_instances,
            "running_count": len(running),
            "warnings": warnings,
        }

    # ── EBS Encryption Default ───────────────────────────────────────────────
    if check_id == "ec2.ebs.encryption_not_default":
        unencrypted = db.scalars(
            select(EbsVolume).where(EbsVolume.account_id == acc.id, EbsVolume.encrypted == False)  # noqa: E712
        ).all()
        return {
            "resource_type": "ebs_encryption_default",
            "confidence": "high",
            "existing_unencrypted_count": len(unencrypted),
            "warnings": [],
        }

    # ── RDS Instance ─────────────────────────────────────────────────────────
    if check_id.startswith("rds.instance."):
        rds = db.scalar(
            select(RdsInstance).where(RdsInstance.account_id == acc.id, RdsInstance.arn == resource_arn)
        )
        if not rds:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "RDS instance not found — run a scan first")

        warnings = []
        confidence = "medium"

        if check_id == "rds.instance.no_encryption":
            confidence = "low"
            warnings.append(
                "Encryption cannot be enabled on a running instance — requires snapshot → copy with encryption → restore to new instance → update connection strings → delete old instance"
            )
            warnings.append("Plan a maintenance window: this typically causes 5–30 minutes of downtime depending on instance size")

        elif check_id == "rds.instance.publicly_accessible":
            confidence = "medium"
            warnings.append("Disabling public accessibility removes the public endpoint — applications connecting from outside the VPC will lose access")
            warnings.append("Ensure your application connects via private subnet, VPC peering, or a bastion host before applying")

        elif check_id == "rds.instance.no_automated_backup":
            confidence = "high"

        return {
            "resource_type": "rds_instance",
            "confidence": confidence,
            "db_instance_id": rds.db_instance_id,
            "engine": rds.engine,
            "region": rds.region,
            "storage_encrypted": rds.storage_encrypted,
            "publicly_accessible": rds.publicly_accessible,
            "backup_retention_period": rds.backup_retention_period,
            "warnings": warnings,
        }

    # ── CloudTrail ───────────────────────────────────────────────────────────
    if check_id.startswith("cloudtrail.trail."):
        if check_id == "cloudtrail.trail.not_enabled":
            trails = db.scalars(
                select(CloudTrailTrail).where(CloudTrailTrail.account_id == acc.id)
            ).all()
            return {
                "resource_type": "cloudtrail_account",
                "confidence": "high",
                "trail_count": len(trails),
                "existing_trails": [
                    {
                        "name": t.name,
                        "home_region": t.home_region,
                        "is_multi_region": t.is_multi_region,
                        "is_logging": t.is_logging,
                    }
                    for t in trails
                ],
                "warnings": [
                    "Creating a trail stores events in S3 — budget ~$2/month per 100k events for typical startup API call volume",
                ],
            }

        trail = db.scalar(
            select(CloudTrailTrail).where(CloudTrailTrail.account_id == acc.id, CloudTrailTrail.arn == resource_arn)
        )
        if not trail:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "trail not found — run a scan first")

        warnings: list[str] = []
        if check_id == "cloudtrail.trail.no_log_validation":
            confidence = "high"
        elif check_id == "cloudtrail.trail.no_kms":
            confidence = "medium"
            warnings.append("The CloudTrail delivery role must have kms:GenerateDataKey and kms:Decrypt on the chosen key — verify the role policy before applying")
        else:
            confidence = "high"

        return {
            "resource_type": "cloudtrail_trail",
            "confidence": confidence,
            "trail_name": trail.name,
            "home_region": trail.home_region,
            "is_multi_region": trail.is_multi_region,
            "is_logging": trail.is_logging,
            "log_validation_enabled": trail.log_validation_enabled,
            "kms_key_id": trail.kms_key_id,
            "warnings": warnings,
        }

    # ── VPC Flow Logs ────────────────────────────────────────────────────────
    if check_id == "vpc.flow_logs.not_enabled":
        # ARN: arn:aws:ec2:{region}:{account}:vpc/{vpc_id}
        vpc_id = resource_arn.split("/")[-1] if "/" in resource_arn else None
        vpc = db.scalar(
            select(Vpc).where(Vpc.account_id == acc.id, Vpc.vpc_id == vpc_id)
        ) if vpc_id else None
        if not vpc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "VPC not found — run a scan first")

        # Count instances in this VPC
        instance_count = db.scalar(
            select(__import__("sqlalchemy").func.count()).select_from(Ec2Instance).where(
                Ec2Instance.account_id == acc.id,
                Ec2Instance.vpc_id == vpc.vpc_id,
            )
        ) or 0

        return {
            "resource_type": "vpc",
            "confidence": "high",
            "vpc_id": vpc.vpc_id,
            "region": vpc.region,
            "instance_count": instance_count,
            "warnings": [],
        }

    # ── IAM Root ─────────────────────────────────────────────────────────────
    if check_id.startswith("iam.root."):
        if check_id == "iam.root.has_access_keys":
            return {
                "resource_type": "iam_root",
                "confidence": "low",
                "warnings": [
                    "Any process using root access keys will immediately break when the keys are deleted — audit all automation, CI/CD configs, and scripts that may hold root credentials before deleting",
                    "Root keys bypass all IAM policies and cannot be scoped — there is no legitimate use case for keeping them",
                ],
            }
        if check_id == "iam.root.no_mfa":
            return {
                "resource_type": "iam_root",
                "confidence": "high",
                "warnings": ["MFA must be configured via the AWS Console — the CLI cannot enable root MFA directly"],
            }
        if check_id == "iam.root.usage":
            return {
                "resource_type": "iam_root",
                "confidence": "high",
                "warnings": ["This is an informational finding — no remediation breaks anything, but recurring root use indicates a process gap"],
            }

    # ── IAM Password Policy ──────────────────────────────────────────────────
    if check_id == "iam.account.password_policy_weak":
        policy = db.scalar(
            select(IamPasswordPolicy).where(IamPasswordPolicy.account_id == acc.id)
        )
        warnings: list[str] = []
        confidence = "medium"
        if policy and policy.max_age and policy.max_age > 0:
            warnings.append(f"Existing policy has max password age of {policy.max_age} days — if you reduce this, users with older passwords will be forced to reset at next login")
        else:
            confidence = "high"

        return {
            "resource_type": "iam_password_policy",
            "confidence": confidence,
            "min_length": policy.min_length if policy else None,
            "max_age": policy.max_age if policy else None,
            "password_reuse_prevention": policy.password_reuse_prevention if policy else None,
            "warnings": warnings,
        }

    # ── S3 Account Public Access Block ───────────────────────────────────────
    if check_id == "s3.account.public_access_not_blocked":
        block = db.scalar(
            select(S3AccountPublicAccessBlock).where(S3AccountPublicAccessBlock.account_id == acc.id)
        )
        public_buckets = db.scalars(
            select(S3Bucket).where(S3Bucket.account_id == acc.id, S3Bucket.public_access_blocked == False)  # noqa: E712
        ).all() if block else []

        return {
            "resource_type": "s3_account_block",
            "confidence": "low" if public_buckets else "medium",
            "public_bucket_count": len(public_buckets),
            "public_bucket_names": sorted(b.name for b in public_buckets),
            "warnings": [],
        }

    # ── Account-level service enables (GuardDuty, Config, SecurityHub, AccessAnalyzer)
    if check_id == "guardduty.detector.not_enabled":
        disabled_regions = [
            r.region for r in db.scalars(
                select(GuardDutyDetector).where(
                    GuardDutyDetector.account_id == acc.id,
                    GuardDutyDetector.status == "DISABLED",
                )
            ).all()
        ]
        return {
            "resource_type": "guardduty",
            "confidence": "high",
            "disabled_regions": disabled_regions,
            "warnings": [f"GuardDuty costs ~$4–$8/month per account in active regions — scale with data ingestion volume"],
        }

    if check_id == "aws.config.not_enabled":
        return {
            "resource_type": "aws_config",
            "confidence": "high",
            "warnings": ["AWS Config records all configuration changes and stores them in S3 — budget ~$2–$5/month for a typical startup account"],
        }

    if check_id == "aws.securityhub.not_enabled":
        return {
            "resource_type": "securityhub",
            "confidence": "high",
            "warnings": ["Security Hub costs ~$0.001 per check per resource — typically $5–$20/month for a startup-scale account"],
        }

    if check_id == "aws.access_analyzer.not_enabled":
        return {
            "resource_type": "access_analyzer",
            "confidence": "high",
            "warnings": [],
        }

    # ── IAM Policy ───────────────────────────────────────────────────────────
    if check_id == "iam.policy.wildcard_resource":
        # resource_arn is the role ARN; we want to show which roles are affected
        role = db.scalar(
            select(IamRole).where(IamRole.account_id == acc.id, IamRole.arn == resource_arn)
        )
        dangerous_policies: list[str] = []
        if role:
            for pol in (role.attached_policies or []):
                for stmt in pol.get("statements", []):
                    if stmt.get("Effect") == "Allow" and stmt.get("Resource") in ("*", ["*"]):
                        actions = stmt.get("Action", [])
                        if isinstance(actions, str):
                            actions = [actions]
                        if actions:
                            dangerous_policies.append(pol.get("policy_name", "unknown"))
                            break
        return {
            "resource_type": "iam_policy_wildcard_resource",
            "confidence": "medium",
            "role_arn": resource_arn,
            "affected_policies": list(set(dangerous_policies)),
            "warnings": [
                "Scoping Resource: * to specific ARNs requires knowing exactly which resources each action needs — verify application behaviour before changing",
                "If these are AWS-managed policies, detach and replace with customer-managed equivalents scoped to your resources",
            ],
        }

    if check_id == "iam.policy.unattached":
        return {
            "resource_type": "iam_policy_unattached",
            "confidence": "high",
            "warnings": [
                "Deleting an unattached policy is safe — it is not granting access to anyone. Verify it is not intentionally kept as a spare before deleting.",
            ],
        }

    if check_id == "iam.perm.granted_vs_used":
        role = db.scalar(
            select(IamRole).where(IamRole.account_id == acc.id, IamRole.arn == resource_arn)
        )
        if not role:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "role not found — run a scan first")
        usages = db.scalars(
            select(IamPermUsage).where(
                IamPermUsage.account_id == acc.id,
                IamPermUsage.principal_arn == resource_arn,
            )
        ).all()
        threshold = now - timedelta(days=90)
        used_services = sorted({u.service for u in usages if u.last_authenticated and u.last_authenticated >= threshold})
        unused_services = sorted({u.service for u in usages if not u.last_authenticated or u.last_authenticated < threshold})
        return {
            "resource_type": "iam_perm_granted_vs_used",
            "confidence": "high" if not used_services else "medium",
            "used_services": used_services,
            "unused_services": unused_services,
            "warnings": [
                f"Services used in last 90 days: {', '.join(used_services) or 'none — high confidence safe to remove unused grants'}",
                "Use the Generate Policy button to preview the scoped-down policy before applying",
            ] if used_services else [
                "No services recorded as used in 90 days — high confidence removal is safe",
                "Verify application does not use this role before removing",
            ],
        }

    raise HTTPException(status.HTTP_400_BAD_REQUEST, f"blast radius not supported for check: {check_id}")


_TIMELINE_CORRELATION_WINDOW = 3600  # ±60 minutes


@router.get("/{account_id}/timeline")
def get_timeline(
    account_id: str,
    days: int = Query(default=30, ge=1, le=90),
    limit: int = Query(default=100, ge=1, le=500),
    p=Depends(current_principal),
    db: Session = Depends(get_db),
):
    """CloudTrail infrastructure events correlated with GitHub PR merges by timestamp (±60 min)."""
    acc = db.get(AwsAccount, uuid.UUID(account_id))
    if not acc or str(acc.org_id) != p["org_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    ct_events = db.scalars(
        select(CloudTrailEvent)
        .where(CloudTrailEvent.account_id == acc.id, CloudTrailEvent.event_time >= cutoff)
        .order_by(CloudTrailEvent.event_time.desc())
        .limit(limit)
    ).all()

    # Load PRs from all GitHub/GitLab providers for this org
    providers = db.scalars(
        select(IdentityProvider).where(IdentityProvider.org_id == acc.org_id)
    ).all()

    prs: list[PullRequest] = []
    repo_by_id: dict[uuid.UUID, Repo] = {}
    for prov in providers:
        repos = db.scalars(
            select(Repo).where(Repo.provider_id == prov.id)
        ).all()
        for r in repos:
            repo_by_id[r.id] = r
        if repos:
            repo_ids = [r.id for r in repos]
            prs.extend(
                db.scalars(
                    select(PullRequest)
                    .where(
                        PullRequest.repo_id.in_(repo_ids),
                        PullRequest.merged_at.isnot(None),
                        PullRequest.merged_at >= cutoff,
                    )
                    .order_by(PullRequest.merged_at.desc())
                    .limit(500)
                ).all()
            )

    def _correlate(event_time: datetime) -> list[dict]:
        matched = []
        for pr in prs:
            if pr.merged_at is None:
                continue
            delta = int((event_time - pr.merged_at).total_seconds())
            if abs(delta) <= _TIMELINE_CORRELATION_WINDOW:
                repo = repo_by_id.get(pr.repo_id)
                matched.append({
                    "number": pr.number,
                    "repo": repo.name if repo else str(pr.repo_id),
                    "merged_at": pr.merged_at.isoformat(),
                    "merged_by": pr.merged_by,
                    "author": pr.author,
                    "approval_count": pr.approval_count,
                    "required_review_count": pr.required_review_count,
                    "self_merge": pr.self_merge,
                    "delta_seconds": delta,
                })
        matched.sort(key=lambda x: abs(x["delta_seconds"]))
        return matched

    result = []
    for evt in ct_events:
        result.append({
            "type": "cloudtrail",
            "event_id": evt.event_id,
            "event_name": evt.event_name,
            "event_source": evt.event_source,
            "event_time": evt.event_time.isoformat(),
            "actor": evt.actor,
            "source_ip": evt.source_ip,
            "resources": evt.resources or [],
            "correlated_prs": _correlate(evt.event_time),
        })

    return {"events": result, "total": len(result)}
