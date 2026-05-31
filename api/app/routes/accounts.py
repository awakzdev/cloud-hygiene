import copy
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from botocore.exceptions import BotoCoreError, ClientError

from app.core.aws import assume_role, ensure_vigil_role_trust, verify_account
from app.services.policy_generation_messages import (
    POLICY_GEN_ASSUME_FAILED_NOTE,
    POLICY_GEN_NO_CONNECTOR_NOTE,
    POLICY_GEN_NO_JOB_NOTE,
    POLICY_GEN_PASS_ROLE_HINT,
)
from app.services.access_analyzer_policy import (
    apply_aa_resources_to_policy_doc,
    confidence_for,
    derive_advanced_role_arn,
    derive_cloudtrail_access_role_arn,
    fetch_latest_generated_policy,
    latest_policy_generation_status,
    merge_access_analyzer,
    placeholder_resources_from_statements,
    start_policy_generation,
    statements_have_concrete_resources,
)
from app.core.config import get_settings
from app.core.db import get_db
from app.core.iam_usage import (
    augment_used_actions_with_granted_for_service_only,
    filter_stale_wildcard_preservation_warnings,
    remove_service_wildcards_when_specific_actions_exist,
    service_has_tracked_actions_in_window,
    services_with_action_evidence,
    services_with_service_only_evidence,
    unused_services_from_usages,
    used_actions_from_usages,
    used_services_from_usages,
)
from app.core.security import current_principal
from app.services.blast_radius_identity import blast_radius_identity
from app.services.evidence_coverage import compute_evidence_coverage, parse_as_of
from app.services.s3_https_policy import build_https_policy_suggestion
from app.services.compliance_timeline import build_compliance_timeline
from app.services.evidence_diff import build_evidence_diff
from app.models import AssumeRoleAudit, AwsAccount, EvidenceExport, IamPermUsage, IamRole, ScanRun
from app.models.cloudtrail import CloudTrailEvent
from app.models.github import IdentityProvider, PullRequest, Repo
from app.models.iam import IamAccessKey, IamUser
from app.models.resources import (
    AccessAnalyzer, AcmCertificate, CloudTrailTrail, ConfigRecorder, DynamoDbTable, Ec2Ami,
    Ec2Instance, EbsEncryptionDefault, EbsSnapshot, EbsVolume, ElbLoadBalancer,
    GuardDutyDetector, IamPasswordPolicy, KmsKey, LambdaFunction, RdsInstance,
    S3AccountPublicAccessBlock, S3Bucket, SecretsManagerSecret, SecurityGroup,
    SecurityHubStatus, SnsTopic, SsmParameter, SqsQueue, Vpc,
)
from app.data.remediation_modules import (
    REMEDIATION_MODULES,
    remediation_deployed_dict,
    remediation_modules_dict,
    set_remediation_modules,
)
from app.models.org import Org

router = APIRouter()
settings = get_settings()


class RemediationModulesIn(BaseModel):
    security_groups: bool = False
    s3_public_access: bool = False
    iam_access_keys: bool = False
    iam_policies: bool = False
    ssm_parameters: bool = False
    cloudtrail_logging: bool = False


class AccountIn(BaseModel):
    label: str = "AWS Account"
    enable_advanced_policy_generation: bool = False
    remediation_modules: RemediationModulesIn = RemediationModulesIn()


class ConnectionOptionsIn(BaseModel):
    enable_advanced_policy_generation: bool
    remediation_modules: RemediationModulesIn


class AccountOut(BaseModel):
    id: str
    label: str
    account_id: str | None
    status: str
    external_id: str
    role_arn: str | None = None
    enable_advanced_policy_generation: bool = False
    remediation_modules: RemediationModulesIn
    remediation_modules_deployed: RemediationModulesIn
    advanced_policy_generation_deployed: bool = False
    cfn_stack_name: str = "VigilAccountConnector"
    cfn_launch_url: str | None = None
    cfn_update_launch_url: str | None = None
    cfn_template_url: str | None = None
    cfn_cli_command: str | None = None
    cfn_update_cli_command: str | None = None
    remediation_cfn_launch_url: str | None = None
    remediation_cfn_template_url: str | None = None
    remediation_cfn_cli_command: str | None = None
    last_scan_at: datetime | None = None
    last_error: str | None = None


class VerifyIn(BaseModel):
    role_arn: str


def _yes_no(flag: bool) -> str:
    return "Yes" if flag else "No"


def _remediation_modules_in(modules: dict[str, bool]) -> RemediationModulesIn:
    return RemediationModulesIn(**{m.id: bool(modules.get(m.id, False)) for m in REMEDIATION_MODULES})


def _modules_from_body(body: RemediationModulesIn) -> dict[str, bool]:
    return body.model_dump()


def _cfn_stack_params(
    external_id: str,
    *,
    stack_name: str,
    enable_advanced_policy_generation: bool,
    remediation_modules: dict[str, bool],
) -> dict[str, str]:
    s = get_settings()
    params = {
        "templateURL": s.CFN_TEMPLATE_URL,
        "stackName": stack_name,
        "param_ExternalId": external_id,
        "param_VigilAccountPrincipal": s.TRUST_PRINCIPAL_ARN,
        "param_RoleName": s.CFN_SCANNER_ROLE_NAME,
        "param_EnableAdvancedPolicyGeneration": _yes_no(enable_advanced_policy_generation),
    }
    for spec in REMEDIATION_MODULES:
        params[f"param_{spec.cfn_parameter}"] = _yes_no(remediation_modules.get(spec.id, False))
    return params


def _launch_url(
    external_id: str,
    *,
    stack_name: str,
    enable_advanced_policy_generation: bool,
    remediation_modules: dict[str, bool],
) -> str:
    params = _cfn_stack_params(
        external_id,
        stack_name=stack_name,
        enable_advanced_policy_generation=enable_advanced_policy_generation,
        remediation_modules=remediation_modules,
    )
    qs = "&".join(f"{k}={quote(v, safe='')}" for k, v in params.items())
    return f"https://console.aws.amazon.com/cloudformation/home#/stacks/create/review?{qs}"


def _update_launch_url(
    external_id: str,
    *,
    stack_name: str,
    enable_advanced_policy_generation: bool,
    remediation_modules: dict[str, bool],
) -> str:
    params = _cfn_stack_params(
        external_id,
        stack_name=stack_name,
        enable_advanced_policy_generation=enable_advanced_policy_generation,
        remediation_modules=remediation_modules,
    )
    qs = "&".join(f"{k}={quote(v, safe='')}" for k, v in params.items())
    return f"https://console.aws.amazon.com/cloudformation/home#/stacks/update/review?{qs}"


def _cli_command(
    external_id: str,
    *,
    stack_name: str,
    enable_advanced_policy_generation: bool,
    remediation_modules: dict[str, bool],
) -> str:
    s = get_settings()
    lines = [
        "aws cloudformation create-stack \\",
        f"  --stack-name {stack_name} \\",
        f"  --template-url {s.CFN_TEMPLATE_URL} \\",
        "  --parameters \\",
        f"    ParameterKey=ExternalId,ParameterValue={external_id} \\",
        f"    ParameterKey=VigilAccountPrincipal,ParameterValue={s.TRUST_PRINCIPAL_ARN} \\",
        f"    ParameterKey=RoleName,ParameterValue={s.CFN_SCANNER_ROLE_NAME} \\",
        f"    ParameterKey=EnableAdvancedPolicyGeneration,ParameterValue={_yes_no(enable_advanced_policy_generation)} \\",
    ]
    for spec in REMEDIATION_MODULES:
        lines.append(
            f"    ParameterKey={spec.cfn_parameter},ParameterValue={_yes_no(remediation_modules.get(spec.id, False))} \\"
        )
    lines.append("  --capabilities CAPABILITY_NAMED_IAM")
    return "\n".join(lines)


def _update_cli_command(
    external_id: str,
    *,
    stack_name: str,
    enable_advanced_policy_generation: bool,
    remediation_modules: dict[str, bool],
) -> str:
    s = get_settings()
    lines = [
        "aws cloudformation update-stack \\",
        f"  --stack-name {stack_name} \\",
        f"  --template-url {s.CFN_TEMPLATE_URL} \\",
        "  --parameters \\",
        f"    ParameterKey=ExternalId,ParameterValue={external_id} \\",
        f"    ParameterKey=VigilAccountPrincipal,ParameterValue={s.TRUST_PRINCIPAL_ARN} \\",
        f"    ParameterKey=RoleName,ParameterValue={s.CFN_SCANNER_ROLE_NAME} \\",
        f"    ParameterKey=EnableAdvancedPolicyGeneration,ParameterValue={_yes_no(enable_advanced_policy_generation)} \\",
    ]
    for spec in REMEDIATION_MODULES:
        lines.append(
            f"    ParameterKey={spec.cfn_parameter},ParameterValue={_yes_no(remediation_modules.get(spec.id, False))} \\"
        )
    lines.append("  --capabilities CAPABILITY_NAMED_IAM")
    return "\n".join(lines)


def _remediation_launch_url() -> str:
    params = {
        "templateURL": get_settings().CFN_REMEDIATION_SSM_TEMPLATE_URL,
        "stackName": "VigilRemediationSSM",
    }
    qs = "&".join(f"{k}={quote(v, safe='')}" for k, v in params.items())
    return f"https://console.aws.amazon.com/cloudformation/home#/stacks/create/review?{qs}"


def _remediation_cli_command() -> str:
    return (
        "aws cloudformation create-stack \\\n"
        "  --stack-name VigilRemediationSSM \\\n"
        f"  --template-url {get_settings().CFN_REMEDIATION_SSM_TEMPLATE_URL} \\\n"
        "  --capabilities CAPABILITY_NAMED_IAM"
    )


def _create_stack_name() -> str:
    """Launch/create URLs and CLI always target the current connector stack."""
    return settings.CFN_STACK_NAME


def _update_stack_name(acc: AwsAccount) -> str:
    """Update URLs and CLI target the stack already deployed in the account."""
    return acc.cfn_stack_name


def _display_cfn_stack_name(acc: AwsAccount) -> str:
    """UI label: pending legacy rows show current name; connected legacy keeps VigilReadOnly."""
    if acc.status != "connected" and acc.cfn_stack_name == settings.CFN_STACK_NAME_LEGACY:
        return settings.CFN_STACK_NAME
    return acc.cfn_stack_name


def _account_out(acc: AwsAccount) -> AccountOut:
    modules = remediation_modules_dict(acc)
    option_kwargs = dict(
        enable_advanced_policy_generation=acc.enable_advanced_policy_generation,
        remediation_modules=modules,
    )
    create_opts = dict(stack_name=_create_stack_name(), **option_kwargs)
    update_opts = dict(stack_name=_update_stack_name(acc), **option_kwargs)
    return AccountOut(
        id=str(acc.id),
        label=acc.label,
        account_id=acc.account_id,
        status=acc.status,
        external_id=acc.external_id,
        role_arn=acc.role_arn if acc.role_arn and (acc.status == "connected" or acc.account_id) else None,
        last_error=acc.last_error,
        enable_advanced_policy_generation=acc.enable_advanced_policy_generation,
        remediation_modules=_remediation_modules_in(modules),
        remediation_modules_deployed=_remediation_modules_in(remediation_deployed_dict(acc)),
        advanced_policy_generation_deployed=acc.advanced_policy_generation_deployed,
        cfn_stack_name=_display_cfn_stack_name(acc),
        cfn_launch_url=_launch_url(acc.external_id, **create_opts),
        cfn_update_launch_url=_update_launch_url(acc.external_id, **update_opts),
        cfn_template_url=get_settings().CFN_TEMPLATE_URL,
        cfn_cli_command=_cli_command(acc.external_id, **create_opts),
        cfn_update_cli_command=_update_cli_command(acc.external_id, **update_opts),
        remediation_cfn_launch_url=None,
        remediation_cfn_template_url=None,
        remediation_cfn_cli_command=None,
        last_scan_at=acc.last_scan_at,
    )


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
        cfn_stack_name=settings.CFN_STACK_NAME,
        enable_advanced_policy_generation=body.enable_advanced_policy_generation,
    )
    set_remediation_modules(acc, _modules_from_body(body.remediation_modules))
    db.add(acc)
    db.commit()
    return _account_out(acc)


@router.patch("/{account_id}/connection-options", response_model=AccountOut)
def update_connection_options(
    account_id: str,
    body: ConnectionOptionsIn,
    p=Depends(current_principal),
    db: Session = Depends(get_db),
):
    acc = db.get(AwsAccount, uuid.UUID(account_id))
    if not acc or str(acc.org_id) != p["org_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")
    incoming = _modules_from_body(body.remediation_modules)
    current = remediation_modules_dict(acc)
    if (
        acc.enable_advanced_policy_generation
        and not body.enable_advanced_policy_generation
        and acc.advanced_policy_generation_deployed
    ):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Advanced IAM policy generation is verified in your deployed role. "
            "Update your CloudFormation stack with EnableAdvancedPolicyGeneration=No, "
            "run Verify permissions, then turn this off in Vigil.",
        )
    for spec in REMEDIATION_MODULES:
        if (
            current.get(spec.id)
            and not incoming.get(spec.id)
            and getattr(acc, spec.deployed_column)
        ):
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"{spec.label} remediation is verified in your deployed role. "
                f"Update your stack with {spec.cfn_parameter}=No, verify, then disable in Vigil.",
            )
    if body.enable_advanced_policy_generation != acc.enable_advanced_policy_generation:
        acc.advanced_policy_generation_deployed = False
    for spec in REMEDIATION_MODULES:
        if incoming.get(spec.id) != current.get(spec.id):
            setattr(acc, spec.deployed_column, False)
    acc.enable_advanced_policy_generation = body.enable_advanced_policy_generation
    set_remediation_modules(acc, incoming)
    db.commit()
    return _account_out(acc)


def _heal_established_account_after_failed_reverify(acc: AwsAccount) -> bool:
    """Older clients set status=error on failed role update even when the good role_arn was kept."""
    if acc.status == "error" and acc.account_id and acc.role_arn:
        acc.status = "connected"
        return True
    return False


@router.get("", response_model=list[AccountOut])
def list_accounts(p=Depends(current_principal), db: Session = Depends(get_db)):
    rows = db.scalars(select(AwsAccount).where(AwsAccount.org_id == uuid.UUID(p["org_id"]))).all()
    if any(_heal_established_account_after_failed_reverify(a) for a in rows):
        db.commit()
    return [_account_out(a) for a in rows]


@router.get("/{account_id}/evidence-coverage")
def evidence_coverage(
    account_id: str,
    period: int = Query(default=90, ge=7, le=365),
    as_of: str | None = Query(default=None, description="End of audit period (YYYY-MM-DD)"),
    framework: str | None = Query(default=None, description="Include scope_limitations for this framework"),
    p=Depends(current_principal),
    db: Session = Depends(get_db),
):
    from app.data.control_narratives import scope_limitations_for

    acc = db.get(AwsAccount, uuid.UUID(account_id))
    if not acc or str(acc.org_id) != p["org_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")
    end = parse_as_of(as_of) or datetime.now(timezone.utc)
    since = end - timedelta(days=period)
    result = compute_evidence_coverage(db, acc.id, since, end, period)
    if framework:
        result["scope_limitations"] = scope_limitations_for(framework)
    return result


@router.get("/{account_id}/access-roster")
def access_roster(
    account_id: str,
    as_of: str | None = Query(default=None, description="Roster as of date (YYYY-MM-DD); defaults to now"),
    p=Depends(current_principal),
    db: Session = Depends(get_db),
):
    """IAM + Identity Center user roster as of the latest collection before the given date."""
    from app.services.evidence_pack import _build_access_roster

    acc = db.get(AwsAccount, uuid.UUID(account_id))
    if not acc or str(acc.org_id) != p["org_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")
    end = parse_as_of(as_of) or datetime.now(timezone.utc)
    return _build_access_roster(db, acc.id, end)


@router.get("/{account_id}/iam-history")
def iam_history(
    account_id: str,
    as_of: str | None = Query(default=None, description="Point-in-time roster from snapshots (YYYY-MM-DD)"),
    p=Depends(current_principal),
    db: Session = Depends(get_db),
):
    """IAM + Identity Center state from evidence snapshots at or before as_of."""
    from app.services.iam_history import build_iam_history

    acc = db.get(AwsAccount, uuid.UUID(account_id))
    if not acc or str(acc.org_id) != p["org_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")
    end = parse_as_of(as_of) or datetime.now(timezone.utc)
    return build_iam_history(db, acc.id, end)


@router.post("/{account_id}/sync-local-trust", status_code=200)
def sync_local_trust(account_id: str, p=Depends(current_principal), db: Session = Depends(get_db)):
    """Dev helper: add your current AWS caller (e.g. SSO) to VigilReadOnly trust policy."""
    if settings.APP_ENV != "dev":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "only available in dev")
    acc = db.get(AwsAccount, uuid.UUID(account_id))
    if not acc or str(acc.org_id) != p["org_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")
    if not acc.role_arn:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "connect the account first")
    updated = ensure_vigil_role_trust(acc.role_arn, acc.external_id)
    return {"ok": True, "trust_policy_updated": updated}


@router.post("/{account_id}/verify", response_model=AccountOut)
def verify(account_id: str, body: VerifyIn, p=Depends(current_principal), db: Session = Depends(get_db)):
    acc = db.get(AwsAccount, uuid.UUID(account_id))
    if not acc or str(acc.org_id) != p["org_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")
    role_update = acc.status == "connected" and bool(acc.role_arn)
    ok, aws_account_id, alias, err = verify_account(body.role_arn, acc.external_id, aws_account=acc)
    if not ok:
        # Do not demote an established account when a role ARN update fails — keep scanning on the last good role.
        if acc.status != "connected":
            acc.last_error = err
            acc.status = "error"
        else:
            acc.last_error = None
        db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"assume role failed: {err}")
    acc.role_arn = body.role_arn
    acc.account_id = aws_account_id
    acc.label = alias or aws_account_id or acc.label
    acc.status = "connected"
    acc.last_error = None
    from app.services.account_capabilities import apply_capability_verification

    apply_capability_verification(acc)
    db.commit()

    if not role_update:
        from app.worker.tasks import run_scan

        run_scan.delay(str(acc.id))

    return _account_out(acc)


@router.post("/{account_id}/verify-capabilities")
def verify_capabilities(account_id: str, p=Depends(current_principal), db: Session = Depends(get_db)):
    """Confirm optional CFN nested stacks are deployed (assume advanced role, check remediation runner)."""
    from app.services.account_capabilities import apply_capability_verification

    acc = db.get(AwsAccount, uuid.UUID(account_id))
    if not acc or str(acc.org_id) != p["org_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")
    if acc.status != "connected" or not acc.role_arn:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Connect and verify the core scanner role before checking optional capabilities",
        )
    results = apply_capability_verification(acc)
    db.commit()
    verification = results.pop("verification", None)
    return {"account": _account_out(acc), "capabilities": results, "verification": verification}


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

    # Dedup: if a scan is already running for this account and started within the
    # last 30 min, return that one instead of queueing a duplicate. Older runs
    # are presumed stuck (worker restart, etc.) and a fresh scan is allowed.
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=30)
    existing = db.scalar(
        select(ScanRun)
        .where(ScanRun.account_id == acc.id)
        .where(ScanRun.status == "running")
        .where(ScanRun.started_at >= cutoff)
        .order_by(ScanRun.started_at.desc())
    )
    if existing:
        return {"job_id": str(existing.id), "deduped": True}

    job = run_scan.delay(str(acc.id))
    return {"job_id": job.id}


class ScanRunOut(BaseModel):
    id: str
    status: str
    started_at: str
    finished_at: str | None
    error: str | None
    failed_at: str | None = None  # which collector/phase failed (from stats.failed_at)
    error_type: str | None = None  # exception class name
    findings_opened: int
    findings_resolved: int
    progress_step: int | None = None  # worker phase counter (from stats._progress_step)
    progress_total: int | None = None  # total phases (from stats._progress_total)


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
    stats = run.stats or {}
    return ScanRunOut(
        id=str(run.id),
        status=run.status,
        started_at=run.started_at.isoformat(),
        finished_at=run.finished_at.isoformat() if run.finished_at else None,
        error=run.error,
        failed_at=stats.get("failed_at"),
        error_type=stats.get("error_type"),
        findings_opened=run.findings_opened or 0,
        findings_resolved=run.findings_resolved or 0,
        progress_step=stats.get("_progress_step"),
        progress_total=stats.get("_progress_total"),
    )


class AssumeRoleAuditOut(BaseModel):
    id: str
    called_at: str
    purpose: str | None
    session_name: str | None
    success: bool
    error_code: str | None
    error_message: str | None


@router.get("/{account_id}/assume-role-audit", response_model=list[AssumeRoleAuditOut])
def assume_role_audit(
    account_id: str,
    limit: int = Query(100, ge=1, le=500),
    p=Depends(current_principal),
    db: Session = Depends(get_db),
):
    """Customer-facing audit log: every sts:AssumeRole Vigil made against this account.

    Returns the most recent `limit` events newest-first. Read-only.
    """
    acc = db.get(AwsAccount, uuid.UUID(account_id))
    if not acc or str(acc.org_id) != p["org_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")
    rows = db.scalars(
        select(AssumeRoleAudit)
        .where(AssumeRoleAudit.aws_account_id == acc.id)
        .order_by(AssumeRoleAudit.called_at.desc())
        .limit(limit)
    ).all()
    return [
        AssumeRoleAuditOut(
            id=str(r.id),
            called_at=r.called_at.isoformat(),
            purpose=r.purpose,
            session_name=r.session_name,
            success=r.success,
            error_code=r.error_code,
            error_message=r.error_message,
        )
        for r in rows
    ]


def _actions_for_service(used_actions: list[str], service: str) -> list[str]:
    prefix = f"{service.lower()}:"
    return sorted(a for a in used_actions if a.lower().startswith(prefix))


def _allow_actions_from_policy_doc(doc: dict) -> list[str]:
    """All Allow Action values from a policy document (including wildcards)."""
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    out: list[str] = []
    for stmt in stmts:
        if stmt.get("Effect", "Allow") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        out.extend(actions)
    return out


def _granted_allow_actions_for_role(role: IamRole) -> list[str]:
    granted: list[str] = []
    for doc in (role.inline_policies or {}).values():
        granted.extend(_allow_actions_from_policy_doc(doc))
    for pol in role.attached_policies or []:
        stmts = pol.get("statements") or []
        granted.extend(
            action
            for stmt in stmts
            if stmt.get("Effect", "Allow") == "Allow"
            for action in (
                [stmt["Action"]]
                if isinstance(stmt.get("Action"), str)
                else (stmt.get("Action") or [])
            )
        )
    return granted


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


_CONFIDENCE_NOTE = {
    "high": "High confidence — actions and resource ARNs come from a completed CloudTrail policy-generation job.",
    "medium": "Medium confidence — action scope improved; resource scope remains broad.",
    "low": "Low confidence — only service-level evidence is available, so scoping stays broad. "
    "Permissions are preserved (never silently dropped).",
}


def _preserved_service_wildcards(used_actions: list[str], service_only: list[str]) -> list[str]:
    """Service wildcards still present after merge — only when no per-action signal exists."""
    services_with_specific = {
        a.split(":", 1)[0].lower()
        for a in used_actions
        if ":" in a and not a.endswith(":*") and a != "*"
    }
    only = {s.lower() for s in service_only if s}
    return sorted(
        a
        for a in used_actions
        if a.endswith(":*")
        and ":" in a
        and a.split(":")[0].lower() in only
        and a.split(":")[0].lower() not in services_with_specific
    )


def _observed_action_count(used_actions: list[str], preserved: list[str]) -> int:
    preserved_set = {a.lower() for a in preserved}
    return len(
        [
            a
            for a in used_actions
            if a != "*" and a.lower() not in preserved_set and not a.endswith(":*")
        ]
    )


def _consolidate_policy_warnings(
    warnings: list[str],
    preserved_wildcards: list[str],
    *,
    policy_gen_job_completed: bool,
) -> list[str]:
    if preserved_wildcards:
        return []
    if policy_gen_job_completed and len(warnings) > 1:
        return [
            "Some services only returned service-level usage; wildcard permissions were preserved "
            "where needed."
        ]
    return warnings


def _opted_in_aws_regions(sess) -> list[str]:
    ec2 = sess.client("ec2", region_name="us-east-1")
    return [
        r["RegionName"]
        for r in ec2.describe_regions(
            Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
        )["Regions"]
    ]


def _resolve_advanced_policy_generation(
    db: Session, acc: AwsAccount, role_arn: str
) -> dict:
    """Fetch the latest completed CloudTrail policy-generation job for this IAM principal.

    Uses access-analyzer policy-generation APIs (principalArn + CloudTrail). Does not require an
    external/internal/unused Access Analyzer resource analyzer to be enabled. Never raises.
    """
    policy_arn = derive_advanced_role_arn(acc.role_arn) or acc.role_arn
    if not policy_arn:
        return {
            "available": False,
            "reason": "no_advanced_role",
            "note": POLICY_GEN_NO_CONNECTOR_NOTE,
        }
    try:
        sess = assume_role(
            policy_arn,
            acc.external_id,
            session_name="vigil-policy-gen",
            aws_account=acc,
            purpose="generate_role_policy_advanced",
        )
    except (ClientError, BotoCoreError):
        return {
            "available": False,
            "reason": "assume_failed",
            "note": POLICY_GEN_ASSUME_FAILED_NOTE,
        }
    active = db.scalars(
        select(AccessAnalyzer).where(
            AccessAnalyzer.account_id == acc.id,
            AccessAnalyzer.status == "ACTIVE",
        )
    ).all()
    regions = list(dict.fromkeys(a.region for a in active if a.region))
    if not regions:
        try:
            regions = _opted_in_aws_regions(sess)
        except (ClientError, BotoCoreError):
            regions = ["us-east-1"]
    for region in regions:
        try:
            client = sess.client("accessanalyzer", region_name=region)
            result = fetch_latest_generated_policy(client, role_arn)
        except (ClientError, BotoCoreError):
            continue
        if result:
            return {"available": True, "region": region, **result}
        try:
            status = latest_policy_generation_status(client, role_arn)
        except (ClientError, BotoCoreError):
            status = None
        if status and status.get("status") in ("IN_PROGRESS", "RUNNING", "ACTIVE"):
            return {
                "available": False,
                "reason": "in_progress",
                "region": region,
                "job_id": status.get("job_id"),
                "generation_status": status.get("status"),
                "started_on": status.get("started_on"),
                "note": (
                    "CloudTrail policy generation is in progress for this role. "
                    "Rebuild the suggestion in a few minutes."
                ),
            }
    return {
        "available": False,
        "reason": "no_generation",
        "note": POLICY_GEN_NO_JOB_NOTE,
    }


def _policy_generation_meta(
    db: Session,
    account_id: uuid.UUID,
    *,
    threshold_days: int,
    advanced: bool,
    advanced_requested: bool | None = None,
    has_action_data: bool,
    aa: dict | None = None,
) -> dict:
    if advanced_requested is None:
        advanced_requested = advanced
    active_analyzers = db.scalars(
        select(AccessAnalyzer).where(
            AccessAnalyzer.account_id == account_id,
            AccessAnalyzer.status == "ACTIVE",
        )
    ).all()
    aa_on = len(active_analyzers) > 0
    aa_statements = (aa or {}).get("statements") or []
    has_concrete_resources = bool(
        aa and aa.get("available") and (aa.get("has_concrete_resources") or statements_have_concrete_resources(aa_statements))
    )
    policy_gen_job_completed = bool(aa and aa.get("available") and aa.get("job_id"))
    confidence = confidence_for(aa_resource_data=has_concrete_resources, has_action_data=has_action_data)

    if policy_gen_job_completed and has_action_data and not has_concrete_resources:
        confidence_note = _CONFIDENCE_NOTE["medium"]
    elif advanced and not has_concrete_resources and (aa or {}).get("note"):
        confidence_note = aa["note"]
    elif not advanced and has_action_data:
        confidence_note = (
            "Action-level from IAM last accessed. For resource ARNs, enable Advanced IAM policy "
            "generation on the connector and run a CloudTrail policy-generation job for this role."
        )
    else:
        confidence_note = _CONFIDENCE_NOTE[confidence]

    if not advanced:
        advanced_note = None
    elif policy_gen_job_completed and has_concrete_resources:
        advanced_note = "CloudTrail policy generation returned apply-ready resource ARNs."
    elif policy_gen_job_completed:
        advanced_note = None
    else:
        advanced_note = (aa or {}).get("note")

    meta = {
        "coverage": {"actions": has_action_data, "resources": has_concrete_resources},
        "source": "cloudtrail_policy_generation+iam_last_accessed"
        if policy_gen_job_completed
        else "iam_last_accessed",
        "source_label": (
            "IAM last-accessed + CloudTrail policy generation"
            if policy_gen_job_completed
            else f"IAM last accessed ({threshold_days} days)"
        ),
        "access_analyzer_enabled": aa_on,
        "advanced_available": advanced,
        "advanced_requested": advanced_requested,
        "advanced_effective": advanced,
        "advanced_note": advanced_note,
        "confidence": confidence,
        "confidence_note": confidence_note,
    }
    if advanced:
        placeholders = (aa or {}).get("placeholder_resources") or placeholder_resources_from_statements(
            aa_statements
        )
        meta["access_analyzer"] = {
            "available": policy_gen_job_completed,
            "reason": (aa or {}).get("reason"),
            "region": (aa or {}).get("region"),
            "job_id": (aa or {}).get("job_id"),
            "generation_status": (aa or {}).get("generation_status"),
            "completed_on": str((aa or {}).get("completed_on")) if (aa or {}).get("completed_on") else None,
            "resource_statements": aa_statements,
            "placeholder_resources": placeholders,
            "placeholder_resources_ignored": len(placeholders),
            "has_concrete_resources": has_concrete_resources,
        }
        meta["improve_via_cloudtrail"] = confidence != "high" and (
            not policy_gen_job_completed or not has_concrete_resources
        )
    return meta


@router.get("/{account_id}/roles/generated-policy")
def generate_role_policy(
    account_id: str,
    role_arn: str,
    threshold_days: int = 90,
    advanced: bool = Query(default=False),
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
    tracked_actions = used_actions_from_usages(usages, cutoff)
    granted = _granted_allow_actions_for_role(role)
    granularity = "action" if tracked_actions else "service"
    service_only = sorted(services_with_service_only_evidence(usages, cutoff))
    action_evidence = sorted(services_with_action_evidence(usages, cutoff))

    # Advanced: integrate IAM Access Analyzer CloudTrail-derived resource-scoped policy when
    # requested or when the account has policy-generation capability deployed/enabled.
    use_advanced = (
        advanced
        or acc.enable_advanced_policy_generation
        or acc.advanced_policy_generation_deployed
    )
    aa = _resolve_advanced_policy_generation(db, acc, role_arn) if use_advanced else None
    aa_statements = None
    used_actions = list(tracked_actions)
    policy_warnings: list[str] = []
    if aa and aa.get("available") and aa.get("statements"):
        aa_statements = aa["statements"]
        used_actions, policy_warnings = merge_access_analyzer(
            used_actions,
            aa_statements,
            used_set,
            policy_gen_job_completed=bool(aa.get("job_id")),
        )

    augment_actions, augment_warnings = augment_used_actions_with_granted_for_service_only(
        used_actions, usages, cutoff, granted
    )
    used_actions = remove_service_wildcards_when_specific_actions_exist(augment_actions)
    policy_warnings = filter_stale_wildcard_preservation_warnings(
        [*policy_warnings, *augment_warnings], used_actions
    )

    preserved_wildcards = _preserved_service_wildcards(used_actions, service_only)
    policy_gen_done = bool(aa and aa.get("job_id"))
    policy_warnings = _consolidate_policy_warnings(
        policy_warnings,
        preserved_wildcards,
        policy_gen_job_completed=policy_gen_done,
    )
    observed_count = _observed_action_count(used_actions, preserved_wildcards)

    inline = role.inline_policies or {}
    meta = _policy_generation_meta(
        db,
        acc.id,
        threshold_days=threshold_days,
        advanced=use_advanced,
        advanced_requested=advanced,
        has_action_data=bool(tracked_actions),
        aa=aa,
    )

    base_out = {
        "used_services": sorted(used_set),
        "used_services_action_tracked": action_evidence,
        "used_services_service_only": service_only,
        "preserved_service_wildcards": preserved_wildcards,
        "observed_action_count": observed_count,
        "policy_warnings": policy_warnings,
    }

    if not inline:
        return {
            "role_arn": role_arn,
            "has_inline_policies": False,
            "unused_services": sorted(unused_set),
            "used_actions": used_actions,
            "granularity": granularity,
            "note": "Role has no inline policies. Permissions come from attached managed policies — review with list-attached-role-policies.",
            **base_out,
            **meta,
        }

    cleaned_policies: dict = {}
    total_removed = 0
    total_modified = 0
    for policy_name, doc in inline.items():
        cleaned, removed, modified = _clean_policy_doc(doc, unused_set, used_set, used_actions)
        if aa_statements:
            cleaned = apply_aa_resources_to_policy_doc(cleaned, aa_statements)
        cleaned_policies[policy_name] = cleaned
        total_removed += removed
        total_modified += modified

    return {
        "role_arn": role_arn,
        "has_inline_policies": True,
        "unused_services": sorted(unused_set),
        "used_actions": used_actions,
        "granularity": granularity,
        "threshold_days": threshold_days,
        "statements_removed": total_removed,
        "statements_modified": total_modified,
        "original_policies": inline,
        "cleaned_policies": cleaned_policies,
        **base_out,
        **meta,
    }


def _assume_policy_generation_session(acc: AwsAccount):
    policy_arn = derive_advanced_role_arn(acc.role_arn) or acc.role_arn
    if not policy_arn:
        return None, POLICY_GEN_NO_CONNECTOR_NOTE
    try:
        sess = assume_role(
            policy_arn,
            acc.external_id,
            session_name="vigil-policy-gen",
            aws_account=acc,
            purpose="policy_generation_start",
        )
    except (ClientError, BotoCoreError):
        return None, POLICY_GEN_ASSUME_FAILED_NOTE
    return sess, None


def _policy_gen_regions(db: Session, acc: AwsAccount, sess) -> list[str]:
    active = db.scalars(
        select(AccessAnalyzer).where(
            AccessAnalyzer.account_id == acc.id,
            AccessAnalyzer.status == "ACTIVE",
        )
    ).all()
    regions = list(dict.fromkeys(a.region for a in active if a.region))
    if not regions:
        try:
            regions = _opted_in_aws_regions(sess)
        except (ClientError, BotoCoreError):
            regions = ["us-east-1"]
    return regions


@router.post("/{account_id}/roles/policy-generation/start")
def start_role_policy_generation(
    account_id: str,
    role_arn: str,
    p=Depends(current_principal),
    db: Session = Depends(get_db),
):
    """Start AWS CloudTrail policy generation for an IAM role (async; minutes to complete)."""
    acc = db.get(AwsAccount, uuid.UUID(account_id))
    if not acc or str(acc.org_id) != p["org_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")

    role = db.scalar(select(IamRole).where(IamRole.account_id == acc.id, IamRole.arn == role_arn))
    if not role:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "role not found — run a scan first")

    use_advanced = (
        acc.enable_advanced_policy_generation or acc.advanced_policy_generation_deployed
    )
    if not use_advanced:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Enable Advanced IAM policy generation on the connector first.",
        )

    sess, err_note = _assume_policy_generation_session(acc)
    if not sess:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, detail=err_note)

    trails = db.scalars(
        select(CloudTrailTrail).where(
            CloudTrailTrail.account_id == acc.id,
            CloudTrailTrail.is_logging == True,  # noqa: E712
        )
    ).all()
    if not trails:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "No logging CloudTrail trails found. Enable CloudTrail and run a scan, then try again.",
        )
    trail_arns = list(dict.fromkeys(t.arn for t in trails))

    regions = _policy_gen_regions(db, acc, sess)
    last_err: str | None = None
    for region in regions:
        try:
            client = sess.client("accessanalyzer", region_name=region)
            existing = latest_policy_generation_status(client, role_arn)
            if existing and existing.get("status") in ("IN_PROGRESS", "RUNNING", "ACTIVE"):
                return {
                    "job_id": existing.get("job_id"),
                    "status": existing["status"],
                    "region": region,
                    "message": "Policy generation already in progress. Rebuild the suggestion when it completes.",
                }
            access_role = derive_cloudtrail_access_role_arn(acc.role_arn)
            if not access_role:
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    "Could not determine CloudTrail access role ARN for this account.",
                )
            started = start_policy_generation(
                client,
                principal_arn=role_arn,
                trail_arns=trail_arns,
                access_role_arn=access_role,
            )
            return {
                "job_id": started["job_id"],
                "status": "IN_PROGRESS",
                "region": region,
                "message": (
                    "CloudTrail policy generation started. This usually takes several minutes. "
                    "Use “Rebuild suggestion” when the job completes."
                ),
            }
        except ClientError as exc:
            err = str(exc)
            if exc.response.get("Error", {}).get("Code") == "AccessDeniedException" and "PassRole" in err:
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN,
                    detail=f"{err} {POLICY_GEN_PASS_ROLE_HINT}",
                ) from exc
            last_err = err
            continue
        except BotoCoreError as exc:
            last_err = str(exc)
            continue
    raise HTTPException(
        status.HTTP_502_BAD_GATEWAY,
        detail=last_err or "Could not start policy generation in any region.",
    )


@router.get("/{account_id}/roles/policy-generation/status")
def role_policy_generation_status(
    account_id: str,
    role_arn: str,
    p=Depends(current_principal),
    db: Session = Depends(get_db),
):
    acc = db.get(AwsAccount, uuid.UUID(account_id))
    if not acc or str(acc.org_id) != p["org_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")

    sess, err_note = _assume_policy_generation_session(acc)
    if not sess:
        return {"status": "UNAVAILABLE", "detail": err_note}

    for region in _policy_gen_regions(db, acc, sess):
        try:
            client = sess.client("accessanalyzer", region_name=region)
            row = latest_policy_generation_status(client, role_arn)
        except (ClientError, BotoCoreError):
            continue
        if row:
            return {"region": region, **row}
    return {"status": "NONE"}


@router.get("/{account_id}/s3/generated-https-policy")
def generate_s3_https_policy(
    account_id: str,
    bucket_arn: str,
    p=Depends(current_principal),
    db: Session = Depends(get_db),
):
    """Read live bucket policy from AWS and merge DenyInsecureTransport."""
    acc = db.get(AwsAccount, uuid.UUID(account_id))
    if not acc or str(acc.org_id) != p["org_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")
    if not acc.role_arn:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "account not connected — verify the IAM role first")

    bucket = db.scalar(
        select(S3Bucket).where(S3Bucket.account_id == acc.id, S3Bucket.arn == bucket_arn)
    )
    if not bucket:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "bucket not found — run a scan first")

    try:
        sess = assume_role(
            acc.role_arn,
            acc.external_id,
            session_name="vigil-s3-policy",
            aws_account=acc,
            purpose="generate_s3_https_policy",
        )
        s3 = sess.client("s3", region_name="us-east-1")
        return build_https_policy_suggestion(s3, bucket.name)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        msg = exc.response.get("Error", {}).get("Message", str(exc))
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            detail=f"Could not read bucket policy ({code}): {msg}",
        ) from exc


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
                    "action_tracked": (
                        u.last_authenticated is not None
                        and u.last_authenticated >= threshold
                        and service_has_tracked_actions_in_window(u, threshold)
                    ),
                    "service_only_signal": (
                        u.last_authenticated is not None
                        and u.last_authenticated >= threshold
                        and not service_has_tracked_actions_in_window(u, threshold)
                    ),
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
        # iam.access_key.unused_90d uses "{user_arn}#{key_id}"; other key checks use user_arn only
        user_arn = resource_arn
        key_id_filter: str | None = None
        if "#" in resource_arn:
            user_arn, key_id_filter = resource_arn.rsplit("#", 1)

        keys = db.scalars(
            select(IamAccessKey).where(
                IamAccessKey.account_id == acc.id,
                IamAccessKey.user_arn == user_arn,
                IamAccessKey.status == "Active",
            )
        ).all()
        if key_id_filter:
            keys = [k for k in keys if k.key_id == key_id_filter]

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
                if check_id == "iam.user.no_mfa":
                    warnings.append(
                        f"Access key {k['key_id']} had API activity {k['days_ago']} days ago via "
                        f"{k['last_used_service'] or 'unknown'} — enabling MFA does not change keys; rotate separately if needed"
                    )
                else:
                    warnings.append(
                        f"Access key {k['key_id']} used {k['days_ago']} days ago via "
                        f"{k['last_used_service'] or 'unknown'} — deactivate keys before disabling user"
                    )

        return {
            "resource_type": "iam_user",
            "confidence": confidence,
            "has_console_password": user.has_console_password,
            "days_inactive": days_inactive,
            "active_key_count": len(active_keys),
            "keys": key_summary,
            "attached_policies": user.attached_policies or [],
            "inline_policy_names": list((user.inline_policies or {}).keys()),
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

        elif check_id == "s3.bucket.no_default_encryption":
            confidence = "high"
            warnings.append("Default encryption applies to new uploads only — existing objects are not retroactively encrypted")

        elif check_id == "s3.bucket.no_mfa_delete":
            confidence = "high"
            warnings.append("MFA Delete can only be enabled or disabled by the root user — IAM users cannot toggle it")

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
            "mfa_delete_enabled": bucket.mfa_delete_enabled,
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

        elif check_id == "rds.instance.no_deletion_protection":
            confidence = "high"

        elif check_id == "rds.instance.no_multi_az":
            confidence = "medium"
            warnings.append("Enabling Multi-AZ triggers a brief failover (~60s) and doubles instance cost")

        return {
            "resource_type": "rds_instance",
            "confidence": confidence,
            "db_instance_id": rds.db_instance_id,
            "engine": rds.engine,
            "region": rds.region,
            "storage_encrypted": rds.storage_encrypted,
            "publicly_accessible": rds.publicly_accessible,
            "backup_retention_period": rds.backup_retention_period,
            "multi_az": rds.multi_az,
            "deletion_protection": rds.deletion_protection,
            "warnings": warnings,
        }

    # ── DynamoDB Table ───────────────────────────────────────────────────────
    if check_id.startswith("dynamodb.table."):
        table = db.scalar(
            select(DynamoDbTable).where(DynamoDbTable.account_id == acc.id, DynamoDbTable.arn == resource_arn)
        )
        if not table:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "DynamoDB table not found — run a scan first")

        warnings: list[str] = []
        confidence = "high"

        if check_id == "dynamodb.table.no_encryption":
            warnings.append(
                "Encryption is applied in place — no table recreation required. Reads and writes continue during the update."
            )
            warnings.append(
                "If using a customer-managed KMS key, verify application IAM roles have kms:Decrypt and kms:GenerateDataKey on the key"
            )
        elif check_id == "dynamodb.table.no_pitr":
            warnings.append(
                "PITR adds continuous backup storage (~$0.20/GB-month for backup data beyond the free tier)"
            )

        return {
            "resource_type": "dynamodb_table",
            "confidence": confidence,
            "table_name": table.table_name,
            "region": table.region,
            "kms_encrypted": table.kms_encrypted,
            "pitr_enabled": table.pitr_enabled,
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
        elif check_id == "cloudtrail.trail.s3_bucket_public":
            confidence = "low"
            warnings.append("Audit logs may have been exposed while the bucket was public — rotate sensitive credentials")
        elif check_id == "cloudtrail.trail.no_cloudwatch_logs":
            confidence = "high"
            warnings.append("CloudWatch Logs ingestion adds cost (~$0.50/GB) — set a retention period on the log group")
        elif check_id == "cloudtrail.trail.s3_bucket_no_logging":
            confidence = "high"
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
            "s3_bucket_public": trail.s3_bucket_public,
            "cloudwatch_logs_enabled": trail.cloudwatch_logs_enabled,
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

    if check_id == "aws.access_analyzer.not_enabled":
        disabled_regions = sorted(
            r.region
            for r in db.scalars(
                select(AccessAnalyzer).where(
                    AccessAnalyzer.account_id == acc.id,
                    AccessAnalyzer.status != "ACTIVE",
                )
            ).all()
        )
        return {
            "resource_type": "access_analyzer",
            "confidence": "high",
            "disabled_regions": disabled_regions,
            "warnings": [],
        }

    if check_id == "aws.securityhub.not_enabled":
        disabled_regions = sorted(
            s.region
            for s in db.scalars(
                select(SecurityHubStatus).where(
                    SecurityHubStatus.account_id == acc.id,
                    SecurityHubStatus.enabled == False,  # noqa: E712
                )
            ).all()
        )
        return {
            "resource_type": "securityhub",
            "confidence": "high",
            "disabled_regions": disabled_regions,
            "warnings": [
                "Security Hub costs ~$0.001 per check per resource — typically $5–$20/month for a startup-scale account"
            ],
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

    # ── EBS Snapshot ─────────────────────────────────────────────────────────
    if check_id.startswith("ec2.ebs.snapshot"):
        snap = db.scalar(
            select(EbsSnapshot).where(EbsSnapshot.account_id == acc.id, EbsSnapshot.arn == resource_arn)
        )
        if not snap:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "EBS snapshot not found — run a scan first")

        warnings: list[str] = []
        confidence = "high"
        if check_id == "ec2.ebs.snapshot_public":
            confidence = "low"
            warnings.append("Public snapshots may already have been copied by external accounts")
        elif check_id == "ec2.ebs.snapshot_unencrypted":
            warnings.append("Copying and deleting the original snapshot takes time and doubles storage cost temporarily")

        return {
            "resource_type": "ebs_snapshot",
            "confidence": confidence,
            "snapshot_id": snap.snapshot_id,
            "region": snap.region,
            "encrypted": snap.encrypted,
            "is_public": snap.is_public,
            "warnings": warnings,
        }

    # ── EC2 AMI ──────────────────────────────────────────────────────────────
    if check_id == "ec2.ami.public":
        ami = db.scalar(
            select(Ec2Ami).where(Ec2Ami.account_id == acc.id, Ec2Ami.arn == resource_arn)
        )
        if not ami:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "AMI not found — run a scan first")

        return {
            "resource_type": "ec2_ami",
            "confidence": "low",
            "image_id": ami.image_id,
            "name": ami.name,
            "region": ami.region,
            "is_public": ami.is_public,
            "warnings": ["Assume the image may have been copied — rotate secrets baked into the AMI"],
        }

    # ── ACM Certificate ──────────────────────────────────────────────────────
    if check_id == "acm.certificate.expiring":
        cert = db.scalar(
            select(AcmCertificate).where(
                AcmCertificate.account_id == acc.id,
                AcmCertificate.certificate_arn == resource_arn,
            )
        )
        if not cert:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "certificate not found — run a scan first")

        days_left = None
        if cert.expires_at:
            days_left = int((cert.expires_at - now).total_seconds() / 86400)

        confidence = "medium" if days_left is not None and days_left <= 14 else "high"
        warnings: list[str] = []
        if days_left is not None and days_left <= 7:
            confidence = "low"
            warnings.append(f"Certificate expires in {days_left} days — renew immediately to avoid HTTPS outages")

        return {
            "resource_type": "acm_certificate",
            "confidence": confidence,
            "domain_name": cert.domain_name,
            "region": cert.region,
            "expires_at": cert.expires_at.isoformat() if cert.expires_at else None,
            "days_until_expiry": days_left,
            "status": cert.status,
            "warnings": warnings,
        }

    # ── Lambda Function ──────────────────────────────────────────────────────
    if check_id.startswith("lambda.function."):
        fn = db.scalar(
            select(LambdaFunction).where(LambdaFunction.account_id == acc.id, LambdaFunction.arn == resource_arn)
        )
        if not fn:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Lambda function not found — run a scan first")

        warnings: list[str] = []
        confidence = "high"
        if check_id == "lambda.function.deprecated_runtime":
            confidence = "medium"
            warnings.append("Runtime upgrades can break dependencies — test in a staging alias before updating production")
        elif check_id == "lambda.function.no_dlq":
            warnings.append("Adding a DLQ does not affect successful invocations — monitor DLQ depth after enabling")

        return {
            "resource_type": "lambda_function",
            "confidence": confidence,
            "function_name": fn.function_name,
            "region": fn.region,
            "runtime": fn.runtime,
            "has_dlq": fn.has_dlq,
            "warnings": warnings,
        }

    # ── Secrets Manager ──────────────────────────────────────────────────────
    if check_id == "secretsmanager.secret.no_rotation":
        secret = db.scalar(
            select(SecretsManagerSecret).where(
                SecretsManagerSecret.account_id == acc.id,
                SecretsManagerSecret.secret_arn == resource_arn,
            )
        )
        if not secret:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "secret not found — run a scan first")

        return {
            "resource_type": "secrets_manager_secret",
            "confidence": "medium",
            "name": secret.name,
            "region": secret.region,
            "rotation_enabled": secret.rotation_enabled,
            "warnings": ["First rotation updates the live secret — verify apps read from Secrets Manager, not cached values"],
        }

    # ── SSM Parameter ────────────────────────────────────────────────────────
    if check_id == "ssm.parameter.plaintext_secret":
        param_name = resource_arn.split(":parameter", 1)[-1] if ":parameter" in resource_arn else resource_arn
        if param_name and not param_name.startswith("/"):
            param_name = f"/{param_name}"
        param = db.scalar(
            select(SsmParameter).where(
                SsmParameter.account_id == acc.id,
                SsmParameter.parameter_name == param_name,
            )
        )
        if not param:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "SSM parameter not found — run a scan first")

        return {
            "resource_type": "ssm_parameter",
            "confidence": "medium",
            "parameter_name": param.parameter_name,
            "parameter_type": param.parameter_type,
            "region": param.region,
            "warnings": ["Converting to SecureString requires kms:Decrypt on consuming IAM roles"],
        }

    # ── ELB Load Balancer ────────────────────────────────────────────────────
    if check_id.startswith("elb.load_balancer."):
        lb = db.scalar(
            select(ElbLoadBalancer).where(
                ElbLoadBalancer.account_id == acc.id,
                ElbLoadBalancer.load_balancer_arn == resource_arn,
            )
        )
        if not lb:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "load balancer not found — run a scan first")

        warnings: list[str] = []
        confidence = "high"
        if check_id == "elb.load_balancer.weak_tls_policy":
            confidence = "medium"
            warnings.append("Stricter TLS policies break clients still on TLS 1.0/1.1 — test with your oldest production clients")

        return {
            "resource_type": "elb_load_balancer",
            "confidence": confidence,
            "name": lb.name,
            "region": lb.region,
            "lb_type": lb.lb_type,
            "access_logs_enabled": lb.access_logs_enabled,
            "ssl_policy": lb.ssl_policy,
            "warnings": warnings,
        }

    # ── SNS Topic ────────────────────────────────────────────────────────────
    if check_id == "sns.topic.no_encryption":
        topic = db.scalar(
            select(SnsTopic).where(SnsTopic.account_id == acc.id, SnsTopic.topic_arn == resource_arn)
        )
        if not topic:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "SNS topic not found — run a scan first")

        return {
            "resource_type": "sns_topic",
            "confidence": "medium",
            "region": topic.region,
            "kms_encrypted": topic.kms_encrypted,
            "warnings": ["Publishers and subscribers need kms:Decrypt and kms:GenerateDataKey if using a customer-managed key"],
        }

    # ── SQS Queue ──────────────────────────────────────────────────────────
    if check_id == "sqs.queue.no_encryption":
        queue = db.scalar(
            select(SqsQueue).where(SqsQueue.account_id == acc.id, SqsQueue.queue_arn == resource_arn)
        )
        if not queue:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "SQS queue not found — run a scan first")

        return {
            "resource_type": "sqs_queue",
            "confidence": "medium",
            "region": queue.region,
            "kms_encrypted": queue.kms_encrypted,
            "warnings": [
                "Producers and consumers need KMS permissions after enabling encryption — verify publish and subscribe end-to-end after enabling",
            ],
        }

    if check_id.startswith("github.") or check_id.startswith("gitlab."):
        try:
            return blast_radius_identity(db, acc, check_id, resource_arn, now=now)
        except ValueError:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"invalid identity resource_arn: {resource_arn}")

    raise HTTPException(status.HTTP_400_BAD_REQUEST, f"blast radius not supported for check: {check_id}")


@router.get("/{account_id}/timeline")
def get_timeline(
    account_id: str,
    days: int = Query(default=30, ge=1, le=90),
    limit: int = Query(default=100, ge=1, le=500),
    on_date: str | None = Query(
        default=None,
        description="UTC calendar day (YYYY-MM-DD) — returns events on that day only",
    ),
    include_operational_noise: bool = Query(
        default=False,
        description="Include SSM/Lambda churn and other low-signal operational events",
    ),
    p=Depends(current_principal),
    db: Session = Depends(get_db),
):
    """CloudTrail write events from scans (Activity log). Filtered to compliance sources by default."""
    from app.services.timeline_filters import is_compliance_timeline_event
    acc = db.get(AwsAccount, uuid.UUID(account_id))
    if not acc or str(acc.org_id) != p["org_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    day_start: datetime | None = None
    day_end: datetime | None = None
    if on_date:
        try:
            day_start = datetime.fromisoformat(on_date).replace(tzinfo=timezone.utc)
            day_end = day_start + timedelta(days=1)
        except ValueError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "on_date must be YYYY-MM-DD") from exc
        cutoff = day_start

    stmt = select(CloudTrailEvent).where(
        CloudTrailEvent.account_id == acc.id,
        CloudTrailEvent.event_time >= cutoff,
    )
    if day_end is not None:
        stmt = stmt.where(CloudTrailEvent.event_time < day_end)
    ct_events = db.scalars(stmt.order_by(CloudTrailEvent.event_time.desc()).limit(limit)).all()

    result = []
    for evt in ct_events:
        if not include_operational_noise and not is_compliance_timeline_event(evt.event_source):
            continue
        result.append(
            {
                "type": "cloudtrail",
                "event_id": evt.event_id,
                "event_name": evt.event_name,
                "event_source": evt.event_source,
                "event_time": evt.event_time.isoformat(),
                "actor": evt.actor,
                "source_ip": evt.source_ip,
                "resources": evt.resources or [],
                "region": (evt.raw or {}).get("awsRegion"),
            }
        )

    trails = db.scalars(
        select(CloudTrailTrail).where(CloudTrailTrail.account_id == acc.id)
    ).all()
    events_in_account = db.scalar(
        select(func.count())
        .select_from(CloudTrailEvent)
        .where(CloudTrailEvent.account_id == acc.id)
    ) or 0

    logging_active = any(t.is_logging for t in trails) or events_in_account > 0

    from app.services.timeline_finding_links import link_findings_to_timeline_events

    result = link_findings_to_timeline_events(db, acc.id, result)

    return {
        "events": result,
        "total": len(result),
        "meta": {
            "cloudtrail_logging": logging_active,
            "trail_count": len(trails),
            "events_in_account": events_in_account,
            "last_scan_at": acc.last_scan_at.isoformat() if acc.last_scan_at else None,
            "filtered_compliance_only": not include_operational_noise,
        },
    }


@router.get("/{account_id}/remediation-runner/status")
def remediation_runner_status(
    account_id: str,
    p=Depends(current_principal),
    db: Session = Depends(get_db),
):
    """Read-only check: SSM Automation document deployed in REMEDIATION_AUTOMATION_REGION."""
    from app.services.remediation_runner_status import check_remediation_runner

    acc = db.get(AwsAccount, uuid.UUID(account_id))
    if not acc or str(acc.org_id) != p["org_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")
    return check_remediation_runner(acc)


@router.get("/{account_id}/evidence-exports")
def list_evidence_exports(
    account_id: str,
    limit: int = Query(default=15, ge=1, le=50),
    p=Depends(current_principal),
    db: Session = Depends(get_db),
):
    """Recent evidence pack downloads for this account (metadata only — re-generate to download)."""
    acc = db.get(AwsAccount, uuid.UUID(account_id))
    if not acc or str(acc.org_id) != p["org_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")

    rows = db.scalars(
        select(EvidenceExport)
        .where(EvidenceExport.account_id == acc.id)
        .order_by(EvidenceExport.created_at.desc())
        .limit(limit)
    ).all()
    return [
        {
            "id": str(r.id),
            "framework": r.framework,
            "period_days": r.period_days,
            "as_of": r.as_of.isoformat() if r.as_of else None,
            "zip_sha256": r.zip_sha256,
            "file_size_bytes": r.file_size_bytes,
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]


@router.get("/{account_id}/compliance-timeline")
def get_compliance_timeline(
    account_id: str,
    framework: str = Query(default="soc2"),
    days: int = Query(default=90, ge=7, le=365),
    limit: int = Query(default=100, ge=1, le=500),
    p=Depends(current_principal),
    db: Session = Depends(get_db),
):
    """Compliance history: scan-level posture summaries with expandable control diffs."""
    acc = db.get(AwsAccount, uuid.UUID(account_id))
    if not acc or str(acc.org_id) != p["org_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")

    if framework not in {"soc2", "cis_aws_l1", "iso27001"}:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid framework")

    from app.services.compliance_scan_timeline import build_compliance_scan_timeline

    return build_compliance_scan_timeline(db, acc.id, framework, days, limit)


@router.get("/{account_id}/evidence-diff")
def get_evidence_diff(
    account_id: str,
    entity_type: str = Query(...),
    entity_id: str = Query(...),
    at_a: str | None = Query(default=None, description="ISO datetime for earlier snapshot"),
    at_b: str | None = Query(default=None, description="ISO datetime for later snapshot"),
    p=Depends(current_principal),
    db: Session = Depends(get_db),
):
    """Compare collected evidence for an entity between two points in time."""
    acc = db.get(AwsAccount, uuid.UUID(account_id))
    if not acc or str(acc.org_id) != p["org_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")

    def _parse_dt(raw: str | None) -> datetime | None:
        if not raw:
            return None
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"invalid datetime: {raw}") from exc

    return build_evidence_diff(
        db,
        acc.id,
        entity_type,
        entity_id,
        at_a=_parse_dt(at_a),
        at_b=_parse_dt(at_b),
    )
