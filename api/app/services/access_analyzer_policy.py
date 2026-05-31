"""IAM Access Analyzer generated-policy integration for the least-privilege workflow.

IAM Access Analyzer can generate a policy from CloudTrail access activity. Unlike IAM
"last accessed" data (which is action/service granularity only), a generated policy may
include **resource-level ARNs** — when AWS returns concrete ARNs (not ``${...}`` placeholders).

Generation is asynchronous on the AWS side (``StartPolicyGeneration`` -> minutes -> ``GetGeneratedPolicy``)
and requires the optional advanced policy-generation role. The synchronous endpoint reads the
*latest already-completed* generation for a principal and merges apply-ready output into the
last-accessed result. It never starts generation inline.

Design rules:
  * IAM last-accessed = baseline; CloudTrail policy generation = optional enrichment.
  * Never silently drop a service that has recorded usage — merge is union-only.
  * Placeholder resources (``${BucketName}``) are not apply-ready and do not count as coverage.
  * Resource ARNs are matched to statements by service/action — no global ARN soup.
"""
from __future__ import annotations

import copy
import json
import re
from datetime import datetime, timezone

CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"

_ROLE_ARN_RE = re.compile(r"^(arn:aws:iam::\d+:role/)(.+)$")
_LEGACY_ADVANCED_SUFFIX = "AdvancedPolicyGen"
_POLICY_GEN_ROLE_NAME = "VigilPolicyGenerationRole"
_SCANNER_ROLE_NAME = "VigilScannerRole"
_LEGACY_SCANNER_ROLE_NAME = "VigilReadOnlyScannerRole"
_ACCESS_ANALYZER_MONITOR_SUFFIX = "AccessAnalyzerMonitor"
_IAM_ACTION_RE = re.compile(r"^[a-z0-9-]+:[A-Za-z0-9*?]+$")
_LEGACY_SCANNER_TO_POLICY_GEN: dict[str, str] = {
    _LEGACY_SCANNER_ROLE_NAME: _POLICY_GEN_ROLE_NAME,
}


def derive_advanced_role_arn(base_role_arn: str | None) -> str | None:
    """Role ARN used for IAM Access Analyzer policy-generation API calls."""
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


def derive_cloudtrail_access_role_arn(base_role_arn: str | None) -> str | None:
    """IAM role Access Analyzer assumes to read CloudTrail logs (not the Vigil connector role)."""
    if not base_role_arn:
        return None
    arn = base_role_arn.strip()
    m = _ROLE_ARN_RE.match(arn)
    if not m:
        return None
    prefix, name = m.group(1), m.group(2)
    if name.endswith(_ACCESS_ANALYZER_MONITOR_SUFFIX):
        return arn
    if name.endswith(_LEGACY_ADVANCED_SUFFIX):
        base = name[: -len(_LEGACY_ADVANCED_SUFFIX)]
        return f"{prefix}{base}{_ACCESS_ANALYZER_MONITOR_SUFFIX}"
    return f"{prefix}{name}{_ACCESS_ANALYZER_MONITOR_SUFFIX}"


def is_placeholder_resource(resource: str) -> bool:
    """AWS template placeholders from includeResourcePlaceholders are not apply-ready."""
    return bool(resource) and "${" in resource


def is_valid_iam_action(action: str) -> bool:
    if action == "*":
        return True
    if not isinstance(action, str) or "${" in action:
        return False
    return bool(_IAM_ACTION_RE.match(action))


def split_resources(resources: list[str]) -> tuple[list[str], list[str]]:
    concrete: list[str] = []
    placeholders: list[str] = []
    for r in resources:
        if not isinstance(r, str) or not r or r == "*":
            continue
        if is_placeholder_resource(r):
            placeholders.append(r)
        else:
            concrete.append(r)
    return concrete, placeholders


def normalize_aa_statements(raw: list[dict]) -> list[dict]:
    """Split concrete vs placeholder resources per statement."""
    out: list[dict] = []
    for st in raw:
        concrete, placeholders = split_resources(st.get("resources", []))
        actions = st.get("actions", [])
        if not actions:
            continue
        out.append(
            {
                "actions": actions,
                "resources": concrete,
                "placeholder_resources": placeholders,
            }
        )
    return out


def parse_generated_policy(get_generated_policy_response: dict) -> list[dict]:
    """Extract Allow statements; resources are split into concrete vs placeholders."""
    result = (get_generated_policy_response or {}).get("generatedPolicyResult") or {}
    policies = result.get("generatedPolicies") or []
    raw: list[dict] = []
    for entry in policies:
        policy_raw = entry.get("policy")
        if not policy_raw:
            continue
        try:
            doc = json.loads(policy_raw) if isinstance(policy_raw, str) else policy_raw
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
            actions = [a for a in actions if isinstance(a, str) and is_valid_iam_action(a)]
            resources = [r for r in resources if isinstance(r, str)]
            if not actions:
                continue
            raw.append({"actions": actions, "resources": resources})
    return normalize_aa_statements(raw)


def actions_from_statements(statements: list[dict]) -> list[str]:
    seen: dict[str, str] = {}
    for st in statements:
        for a in st.get("actions", []):
            seen.setdefault(a.lower(), a)
    return sorted(seen.values(), key=str.lower)


def placeholder_resources_from_statements(statements: list[dict]) -> list[str]:
    seen: dict[str, str] = {}
    for st in statements:
        for r in st.get("placeholder_resources", []):
            seen.setdefault(r, r)
    return sorted(seen.values())


def statements_have_concrete_resources(statements: list[dict]) -> bool:
    return any(st.get("resources") for st in statements)


def _service_from_action(action: str) -> str | None:
    if not action or action == "*":
        return None
    if ":" not in action:
        return None
    return action.split(":")[0].lower()


def _arn_matches_service(arn: str, svc: str) -> bool:
    arn_l = arn.lower()
    if svc == "s3":
        return ":s3:" in arn_l or arn_l.startswith("arn:aws:s3")
    return f":{svc}:" in arn_l


def resources_by_service(statements: list[dict]) -> dict[str, list[str]]:
    """Map concrete CloudTrail resource ARNs to IAM services from co-located actions."""
    by_svc: dict[str, dict[str, str]] = {}
    for st in statements:
        resources = list(st.get("resources") or [])
        if not resources:
            continue
        services_in_stmt: set[str] = set()
        for a in st.get("actions", []):
            svc = _service_from_action(a)
            if svc:
                services_in_stmt.add(svc)
        for svc in services_in_stmt:
            bucket = by_svc.setdefault(svc, {})
            for r in resources:
                if _arn_matches_service(r, svc):
                    bucket.setdefault(r, r)
    return {svc: sorted(arns.values()) for svc, arns in by_svc.items()}


def merge_access_analyzer(
    last_accessed_actions: list[str],
    aa_statements: list[dict],
    used_services: set[str],
    *,
    policy_gen_job_completed: bool = False,
) -> tuple[list[str], list[str]]:
    """Union last-accessed actions with CloudTrail-derived actions; never drop a used service."""
    seen: dict[str, str] = {a.lower(): a for a in last_accessed_actions}
    aa_services: set[str] = set()
    for st in aa_statements:
        for a in st.get("actions", []):
            seen.setdefault(a.lower(), a)
            if ":" in a:
                aa_services.add(a.split(":")[0].lower())

    warnings: list[str] = []
    if not policy_gen_job_completed:
        for svc in sorted(s for s in used_services if s):
            if svc.lower() in aa_services:
                continue
            warnings.append(
                f"{svc}: IAM reported service-level use only (no per-action detail). Existing "
                f"permissions are preserved at current scope."
            )
    return sorted(seen.values(), key=str.lower), warnings


def latest_policy_generation_status(client, principal_arn: str) -> dict | None:
    """Most recent generation row for a principal (any status)."""
    resp = client.list_policy_generations(principalArn=principal_arn)
    generations = resp.get("policyGenerations") or []
    if not generations:
        return None
    generations.sort(
        key=lambda g: g.get("completedOn") or g.get("startedOn") or "",
        reverse=True,
    )
    job = generations[0]
    return {
        "job_id": job.get("jobId"),
        "status": job.get("status"),
        "started_on": job.get("startedOn"),
        "completed_on": job.get("completedOn"),
    }


def start_policy_generation(
    client,
    *,
    principal_arn: str,
    trail_arns: list[str],
    access_role_arn: str,
    start_time: datetime | None = None,
) -> dict:
    """Start an AWS CloudTrail policy-generation job (async; poll for SUCCEEDED)."""
    if not trail_arns:
        raise ValueError("no_trails")
    if not access_role_arn:
        raise ValueError("no_access_role")
    when = start_time or datetime.now(timezone.utc)
    resp = client.start_policy_generation(
        policyGenerationDetails={"principalArn": principal_arn},
        cloudTrailDetails={
            "trails": [{"cloudTrailArn": arn} for arn in trail_arns],
            "accessRole": access_role_arn,
            "startTime": when,
        },
    )
    job_id = resp.get("jobId")
    if not job_id:
        raise ValueError("no_job_id")
    return {"job_id": job_id, "status": "IN_PROGRESS"}


def fetch_latest_generated_policy(client, principal_arn: str) -> dict | None:
    """Return the latest completed generation — apply-ready ARNs only (no placeholders)."""
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
    detail = client.get_generated_policy(jobId=job_id, includeResourcePlaceholders=False)
    statements = parse_generated_policy(detail)
    if not statements:
        return None
    placeholders = placeholder_resources_from_statements(statements)
    return {
        "job_id": job_id,
        "completed_on": job.get("completedOn"),
        "statements": statements,
        "placeholder_resources": placeholders,
        "has_concrete_resources": statements_have_concrete_resources(statements),
    }


def _resource_is_wildcard(resource) -> bool:
    if isinstance(resource, str):
        return resource == "*"
    if isinstance(resource, list):
        return not resource or all(r == "*" for r in resource)
    return False


def _actions_list(action_field) -> list[str]:
    if isinstance(action_field, str):
        return [action_field]
    return [a for a in action_field if isinstance(a, str)]


def _resources_for_actions(actions: list[str], by_service: dict[str, list[str]]) -> list[str]:
    seen: dict[str, str] = {}
    for action in actions:
        svc = _service_from_action(action)
        if not svc:
            continue
        for r in by_service.get(svc, []):
            seen.setdefault(r, r)
    return sorted(seen.values())


def apply_aa_resources_to_policy_doc(doc: dict, aa_statements: list[dict]) -> dict:
    """Replace wildcard Resource on Allow statements with service-matched CloudTrail ARNs only."""
    by_service = resources_by_service(aa_statements)
    if not by_service:
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
            actions = _actions_list(stmt.get("Action", []))
            matched = _resources_for_actions(actions, by_service)
            if matched:
                stmt = copy.deepcopy(stmt)
                stmt["Resource"] = matched if len(matched) > 1 else matched[0]
        new_stmts.append(stmt)

    doc["Statement"] = new_stmts
    return doc


def confidence_for(*, aa_resource_data: bool, has_action_data: bool) -> str:
    """High only when concrete (non-placeholder) CloudTrail resource ARNs are in use."""
    if aa_resource_data:
        return CONFIDENCE_HIGH
    if has_action_data:
        return CONFIDENCE_MEDIUM
    return CONFIDENCE_LOW


_SECURITY_FINDING_TYPES = {"ERROR", "SECURITY_WARNING"}


def validate_policy(client, policy_document: str, policy_type: str = "IDENTITY_POLICY") -> list[dict]:
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
    return [f for f in findings if (f.get("finding_type") or "").upper() in _SECURITY_FINDING_TYPES]
