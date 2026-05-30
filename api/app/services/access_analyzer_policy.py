"""IAM Access Analyzer generated-policy integration for the least-privilege workflow.

IAM Access Analyzer can generate a policy from CloudTrail access activity. Unlike IAM
"last accessed" data (which is action/service granularity only), a generated policy includes
**resource-level ARNs** — the strongest signal for least-privilege scoping.

Generation is asynchronous on the AWS side (``StartPolicyGeneration`` -> minutes -> ``GetGeneratedPolicy``)
and requires the optional advanced policy-generation role (write-level access-analyzer actions,
see infra/cfn/vigil-readonly-role.yaml). The synchronous generated-policy endpoint therefore reads
the *latest already-completed* generation for a principal and merges its resource-scoped statements
into the last-accessed result. It never starts a (slow) generation inline and never blocks the UI.

Design rules (from the IAM accuracy directive):
  * Continue using Last Accessed data; AA augments it, never replaces it.
  * Never silently drop a service that has recorded usage — merge is union-only.
  * If AA is unavailable or has no completed generation, downgrade confidence and explain why.
"""
from __future__ import annotations

import copy
import json
import re

# Confidence tiers surfaced to the UI / FindingDrawer.
CONFIDENCE_HIGH = "high"      # AA CloudTrail-derived action + resource ARNs available
CONFIDENCE_MEDIUM = "medium"  # IAM last-accessed action-level evidence only
CONFIDENCE_LOW = "low"        # service-level evidence only / AA off — broadest scoping


_ROLE_ARN_RE = re.compile(r"^(arn:aws:iam::\d+:role/)(.+)$")
_LEGACY_ADVANCED_SUFFIX = "AdvancedPolicyGen"
_POLICY_GEN_ROLE_NAME = "VigilPolicyGenerationRole"
_SCANNER_ROLE_NAME = "VigilScannerRole"
_LEGACY_SCANNER_ROLE_NAME = "VigilReadOnlyScannerRole"
# Split-stack deploys (before unified connector role).
_LEGACY_SCANNER_TO_POLICY_GEN: dict[str, str] = {
    _LEGACY_SCANNER_ROLE_NAME: _POLICY_GEN_ROLE_NAME,
}


def derive_advanced_role_arn(base_role_arn: str | None) -> str | None:
    """Role ARN used for IAM Access Analyzer policy-generation API calls.

    Unified connector (VigilScannerRole): same ARN as the connected role — policy gen is inline.
    Legacy split-stack: map VigilReadOnlyScannerRole -> VigilPolicyGenerationRole.
    """
    if not base_role_arn:
        return None
    arn = base_role_arn.strip()
    m = _ROLE_ARN_RE.match(arn)
    if not m:
        return None
    prefix, name = m.group(1), m.group(2)
    if name in (_SCANNER_ROLE_NAME, _POLICY_GEN_ROLE_NAME) or name.endswith(_LEGACY_ADVANCED_SUFFIX):
        return arn
    mapped = _LEGACY_SCANNER_TO_POLICY_GEN.get(name)
    if mapped:
        return f"{prefix}{mapped}"
    return arn


def parse_generated_policy(get_generated_policy_response: dict) -> list[dict]:
    """Extract Allow statements (actions + resource ARNs) from a GetGeneratedPolicy response.

    Returns a list of ``{"actions": [...], "resources": [...]}`` dicts. AA embeds each policy as
    a JSON string under ``generatedPolicyResult.generatedPolicies[*].policy``. Malformed or
    non-Allow statements are skipped rather than raising — partial telemetry must not break the flow.
    """
    result = (get_generated_policy_response or {}).get("generatedPolicyResult") or {}
    policies = result.get("generatedPolicies") or []
    out: list[dict] = []
    for entry in policies:
        raw = entry.get("policy")
        if not raw:
            continue
        try:
            doc = json.loads(raw) if isinstance(raw, str) else raw
        except (ValueError, TypeError):
            continue
        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        for st in statements:
            if not isinstance(st, dict) or st.get("Effect", "Allow") != "Allow":
                continue
            actions = st.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            resources = st.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            actions = [a for a in actions if isinstance(a, str)]
            resources = [r for r in resources if isinstance(r, str)]
            if not actions:
                continue
            out.append({"actions": actions, "resources": resources})
    return out


def actions_from_statements(statements: list[dict]) -> list[str]:
    """Distinct action names across AA statements (preserves AWS casing)."""
    seen: dict[str, str] = {}
    for st in statements:
        for a in st.get("actions", []):
            seen.setdefault(a.lower(), a)
    return sorted(seen.values(), key=str.lower)


def merge_access_analyzer(
    last_accessed_actions: list[str],
    aa_statements: list[dict],
    used_services: set[str],
) -> tuple[list[str], list[str]]:
    """Union last-accessed actions with AA CloudTrail-derived actions; never drop a used service.

    Returns ``(merged_actions, warnings)``. AA actions are added (high signal — actually called),
    and a warning is emitted for any used service AA did not cover so the engineer knows it stays
    action-level (no resource ARNs) rather than being silently treated as fully scoped.
    """
    seen: dict[str, str] = {a.lower(): a for a in last_accessed_actions}
    aa_services: set[str] = set()
    for st in aa_statements:
        for a in st.get("actions", []):
            seen.setdefault(a.lower(), a)
            if ":" in a:
                aa_services.add(a.split(":")[0].lower())

    warnings: list[str] = []
    for svc in sorted(s for s in used_services if s):
        if svc.lower() not in aa_services:
            warnings.append(
                f"{svc}: IAM Access Analyzer returned no CloudTrail-derived statements (insufficient "
                f"trail history for this service). Kept last-accessed actions; could not add resource "
                f"ARNs. Scoping for {svc} remains action-level."
            )
    return sorted(seen.values(), key=str.lower), warnings


def fetch_latest_generated_policy(client, principal_arn: str) -> dict | None:
    """Return the parsed latest *completed* generated policy for a principal, or None.

    ``client`` is a boto3 ``accessanalyzer`` client (from the assumed advanced role). Lists policy
    generations for the principal, picks the most recent SUCCEEDED job, fetches and parses it.
    Returns ``{"job_id", "completed_on", "statements"}`` or None when nothing is available.
    Any AWS/parse error is the caller's responsibility to guard — this stays a thin AWS adapter.
    """
    resp = client.list_policy_generations(principalArn=principal_arn)
    generations = resp.get("policyGenerations") or []
    succeeded = [g for g in generations if g.get("status") == "SUCCEEDED"]
    if not succeeded:
        return None
    succeeded.sort(key=lambda g: g.get("completedOn") or g.get("startedOn") or "", reverse=True)
    job = succeeded[0]
    job_id = job.get("jobId")
    if not job_id:
        return None
    detail = client.get_generated_policy(jobId=job_id, includeResourcePlaceholders=True)
    statements = parse_generated_policy(detail)
    if not statements:
        return None
    return {
        "job_id": job_id,
        "completed_on": job.get("completedOn"),
        "statements": statements,
    }


def _resource_is_wildcard(resource) -> bool:
    if isinstance(resource, str):
        return resource == "*"
    if isinstance(resource, list):
        return not resource or all(r == "*" for r in resource)
    return False


def _non_wildcard_aa_resources(aa_statements: list[dict]) -> list[str]:
    seen: dict[str, str] = {}
    for st in aa_statements:
        for r in st.get("resources", []):
            if isinstance(r, str) and r and r != "*":
                seen.setdefault(r, r)
    return sorted(seen.values())


def apply_aa_resources_to_policy_doc(doc: dict, aa_statements: list[dict]) -> dict:
    """Replace wildcard Resource on Allow statements with AA CloudTrail-derived ARNs."""
    aa_resources = _non_wildcard_aa_resources(aa_statements)
    if not aa_resources:
        return doc

    doc = copy.deepcopy(doc)
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]

    new_stmts = []
    for stmt in stmts:
        if stmt.get("Effect", "Allow") != "Allow":
            new_stmts.append(stmt)
            continue
        if _resource_is_wildcard(stmt.get("Resource", "*")):
            stmt = copy.deepcopy(stmt)
            stmt["Resource"] = aa_resources if len(aa_resources) > 1 else aa_resources[0]
        new_stmts.append(stmt)

    doc["Statement"] = new_stmts
    return doc


def confidence_for(*, aa_resource_data: bool, has_action_data: bool) -> str:
    """High when AA resource ARNs are present; medium for action-level; low for service-level."""
    if aa_resource_data:
        return CONFIDENCE_HIGH
    if has_action_data:
        return CONFIDENCE_MEDIUM
    return CONFIDENCE_LOW


# ── IAM Access Analyzer policy *validation* (for the IaC PR hook) ────────────────────────────
# deepsearch v5 §"Terraform/Terragrunt & Automation Integration": "Any Terraform pre-commit / PR
# hook should call IAM Access Analyzer APIs to verify no new unrestricted permissions are granted."
# ValidatePolicy is read-only — AA lints the *passed document text*; it never reads or mutates
# account state. SECURITY_WARNING/ERROR are the signals a PR gate should fail on.
_SECURITY_FINDING_TYPES = {"ERROR", "SECURITY_WARNING"}


def validate_policy(client, policy_document: str, policy_type: str = "IDENTITY_POLICY") -> list[dict]:
    """Call AA ValidatePolicy and return normalized findings (handles nextToken pagination).

    ``client`` is a boto3 ``accessanalyzer`` client. Each finding: ``{finding_type, issue_code,
    detail, learn_more}``. Stays a thin AWS adapter — the caller guards AWS/JSON errors.
    """
    findings: list[dict] = []
    next_token: str | None = None
    while True:
        kwargs = {"policyDocument": policy_document, "policyType": policy_type}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = client.validate_policy(**kwargs)
        for f in resp.get("findings", []) or []:
            findings.append(
                {
                    "finding_type": f.get("findingType"),
                    "issue_code": f.get("issueCode"),
                    "detail": f.get("findingDetails"),
                    "learn_more": f.get("learnMoreLink"),
                }
            )
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return findings


def security_findings_only(findings: list[dict]) -> list[dict]:
    """Keep only ERROR / SECURITY_WARNING — the 'unrestricted permission' signals for a PR gate."""
    return [f for f in findings if (f.get("finding_type") or "").upper() in _SECURITY_FINDING_TYPES]
