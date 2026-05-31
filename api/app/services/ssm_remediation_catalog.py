"""SSM Automation mapping for approved remediation.

Prefer AWS-owned runbooks where they fit the finding exactly. Use the Vigil custom
document only where we need extra guardrails such as exact security-group rule matching.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SsmRemediationRunbook:
    check_id: str
    document_name: str
    owner: str
    parameter_mode: str
    note: str


VIGIL_PLAN_DOCUMENT = "Vigil-RemediationPlanExecutor"

RUNBOOKS: dict[str, SsmRemediationRunbook] = {
    "ec2.security_group.unrestricted_ssh": SsmRemediationRunbook(
        check_id="ec2.security_group.unrestricted_ssh",
        document_name=VIGIL_PLAN_DOCUMENT,
        owner="vigil",
        parameter_mode="plan_json",
        note="Custom document preserves exact-match rule revocation from finding evidence.",
    ),
    "ec2.security_group.unrestricted_rdp": SsmRemediationRunbook(
        check_id="ec2.security_group.unrestricted_rdp",
        document_name=VIGIL_PLAN_DOCUMENT,
        owner="vigil",
        parameter_mode="plan_json",
        note="Custom document preserves exact-match rule revocation from finding evidence.",
    ),
    "ssm.parameter.plaintext_secret": SsmRemediationRunbook(
        check_id="ssm.parameter.plaintext_secret",
        document_name=VIGIL_PLAN_DOCUMENT,
        owner="vigil",
        parameter_mode="plan_json",
        note="Custom document rewrites a sensitive String parameter as SecureString after approval.",
    ),
    "s3.bucket.public_access_not_blocked": SsmRemediationRunbook(
        check_id="s3.bucket.public_access_not_blocked",
        document_name="AWSConfigRemediation-ConfigureS3PublicAccessBlock",
        owner="aws",
        parameter_mode="aws_owned",
        note="Prefer AWS-owned S3 public access block remediation when parameters are wired.",
    ),
    "iam.access_key.unused_45d": SsmRemediationRunbook(
        check_id="iam.access_key.unused_45d",
        document_name="AWSConfigRemediation-RevokeUnusedIAMUserCredentials",
        owner="aws",
        parameter_mode="aws_owned",
        note="Prefer AWS-owned IAM credential revocation when parameters are wired.",
    ),
    "cloudtrail.trail.not_enabled": SsmRemediationRunbook(
        check_id="cloudtrail.trail.not_enabled",
        document_name="AWS-EnableCloudTrail",
        owner="aws",
        parameter_mode="aws_owned",
        note="Prefer AWS-owned CloudTrail enablement when parameters are wired.",
    ),
}


def runbook_for_check(check_id: str) -> SsmRemediationRunbook | None:
    return RUNBOOKS.get(check_id)


def automation_parameters_for_plan(plan_json: str, runbook: SsmRemediationRunbook) -> dict[str, list[str]]:
    if runbook.parameter_mode == "plan_json":
        return {"PlanJson": [plan_json]}
    raise ValueError(f"{runbook.check_id} uses AWS-owned runbook parameters that are not wired yet")


def runbook_payload(runbook: SsmRemediationRunbook) -> dict[str, Any]:
    return {
        "check_id": runbook.check_id,
        "document_name": runbook.document_name,
        "owner": runbook.owner,
        "parameter_mode": runbook.parameter_mode,
        "note": runbook.note,
    }
