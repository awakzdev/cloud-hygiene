"""Repo-aware Terraform PR flow (hclpatch scan/patch + terraform validate)."""
from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Finding
from app.models.github import IdentityProvider
from app.services.github_iac_pr import create_terraform_pr
from app.services.github_repo_tf import fetch_terraform_files
from app.services.hcl_patch import hcl_patch_preview, hcl_repo_scan
from app.services.iac_snippets import _TERRAFORM_SNIPPET_CHECKS
from app.services.terraform_fmt_validate import terraform_fmt_validate

# Checks we can open PRs for (declarative patch supported by hclpatch).
PR_PATCH_CHECKS = frozenset(
    {
        "s3.bucket.public_access_not_blocked",
        "kms.key.no_rotation",
    }
)


def _evidence_targets(finding: Finding) -> dict[str, str | None]:
    ev = finding.evidence or {}
    bucket_name = ev.get("bucket_name") or ev.get("bucket")
    if not bucket_name and finding.resource_arn.startswith("arn:aws:s3:::"):
        bucket_name = finding.resource_arn.split(":::")[-1].split("/")[0]
    key_id = ev.get("key_id")
    if not key_id and ":key/" in finding.resource_arn:
        key_id = finding.resource_arn.split("/")[-1]
    return {
        "bucket_name": bucket_name,
        "key_id": key_id,
        "group_id": ev.get("group_id"),
        "group_name": ev.get("group_name"),
    }


def scan_repo_for_finding(
    db: Session,
    *,
    finding: Finding,
    org_id,
    repo_full_name: str,
    base_branch: str | None,
) -> dict[str, Any]:
    gh = db.scalar(
        select(IdentityProvider).where(
            IdentityProvider.org_id == org_id,
            IdentityProvider.type == "github",
            IdentityProvider.status == "connected",
        )
    )
    if not gh:
        raise ValueError("Connect GitHub in Integrations to scan repositories")

    files = fetch_terraform_files(gh, repo_full_name, ref=base_branch)
    if not files:
        return {
            "status": "empty",
            "message": "No .tf or .hcl files found in repository",
            "files_scanned": 0,
        }

    t = _evidence_targets(finding)
    scan = hcl_repo_scan(
        check_id=finding.check_id,
        files=files,
        bucket_name=t["bucket_name"],
        key_id=t["key_id"],
        group_id=t["group_id"],
        group_name=t["group_name"],
    )
    scan["repo"] = repo_full_name
    scan["can_open_pr"] = finding.check_id in PR_PATCH_CHECKS and scan.get("can_patch", False)
    return scan


def build_terraform_pr(
    db: Session,
    *,
    finding: Finding,
    org_id,
    repo_full_name: str,
    file_path: str,
    base_branch: str | None,
) -> dict[str, Any]:
    if finding.check_id not in _TERRAFORM_SNIPPET_CHECKS:
        raise ValueError(f"Terraform PR not supported for check {finding.check_id}")
    if finding.check_id not in PR_PATCH_CHECKS:
        scan = scan_repo_for_finding(
            db, finding=finding, org_id=org_id, repo_full_name=repo_full_name, base_branch=base_branch
        )
        raise ValueError(
            scan.get("message")
            or "Repo match may exist but automatic patch is not supported — use SSM Automation or edit Terraform manually."
        )

    gh = db.scalar(
        select(IdentityProvider).where(
            IdentityProvider.org_id == org_id,
            IdentityProvider.type == "github",
            IdentityProvider.status == "connected",
        )
    )
    if not gh:
        raise ValueError("Connect GitHub in Integrations to open Terraform PRs")

    files = fetch_terraform_files(gh, repo_full_name, ref=base_branch)
    if not files:
        raise ValueError("No .tf/.hcl files found in repository — cannot match resources")

    t = _evidence_targets(finding)
    preview = hcl_patch_preview(
        check_id=finding.check_id,
        files=files,
        bucket_name=t["bucket_name"],
        key_id=t["key_id"],
        group_id=t["group_id"],
        group_name=t["group_name"],
    )
    if preview.get("status") in ("unsupported", "not_found", "error", "repo_context_required"):
        raise ValueError(preview.get("message") or f"Cannot patch: {preview.get('status')}")

    target_path = preview.get("file_path") or file_path
    patched = preview.get("patched_content")
    if not patched:
        raise ValueError("No patched content produced — ambiguous repo match")

    patched_files = []
    replaced = False
    for f in files:
        if f["path"] == target_path:
            patched_files.append({"path": target_path, "content": patched})
            replaced = True
        else:
            patched_files.append(f)
    if not replaced:
        patched_files.append({"path": target_path, "content": patched})

    validation = terraform_fmt_validate(patched_files)
    if not validation.get("ok"):
        raise ValueError(
            f"terraform {validation.get('step', 'validate')} failed: {validation.get('error', '')[:500]}"
        )

    title = f"Vigil: remediate {finding.check_id}"
    body = (
        f"Automated Terraform remediation for finding `{finding.title}`.\n\n"
        f"- Check: `{finding.check_id}`\n"
        f"- Resource: `{finding.resource_arn}`\n"
        f"- Action: {preview.get('action', 'patch')}\n"
    )
    if preview.get("matches"):
        body += f"- Matched {len(preview['matches'])} resource block(s) in repo\n"
    body += "\nGenerated by Vigil (hclpatch + terraform validate). Review before merge."

    pr = create_terraform_pr(
        gh,
        repo_full_name=repo_full_name,
        title=title,
        body=body,
        terraform_hcl=patched,
        file_path=target_path,
        base_branch=base_branch,
    )
    return {
        **pr,
        "preview": preview,
        "validation": validation,
    }
