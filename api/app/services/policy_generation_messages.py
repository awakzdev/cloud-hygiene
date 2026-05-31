"""User-facing copy for IAM least-privilege policy generation."""

from __future__ import annotations

from botocore.exceptions import ClientError

# Console path AWS documents for IAM principals.
IAM_POLICY_GEN_CONSOLE_PATH = (
    "IAM → Roles → this role → Permissions → Generate policy based on CloudTrail events"
)

POLICY_GEN_NO_JOB_NOTE = (
    "No completed policy analysis exists for this role yet. "
    "Start analysis in Vigil, or start the same AWS IAM policy-generation job from the IAM role page. "
    "This only reads CloudTrail and IAM last-accessed data; permissions are not changed until you apply a policy."
)

POLICY_GEN_ASSUME_FAILED_NOTE = (
    "Vigil cannot start policy analysis with the connector role. "
    "Update the AWS connector with Advanced IAM policy generation enabled, then verify capabilities again."
)

POLICY_GEN_PASS_ROLE_HINT = (
    "The connector must pass the Vigil Access Analyzer monitor role to access-analyzer.amazonaws.com. "
    "That monitor role is used by AWS to read CloudTrail logs for policy generation; it is not a remediation role."
)

POLICY_GEN_NO_CONNECTOR_NOTE = "Connect the Vigil connector role first."

POLICY_GEN_MONITOR_ROLE_MISSING = (
    "The Access Analyzer monitor role is missing from this account. "
    "Update the Vigil connector with Advanced IAM policy generation enabled, then verify capabilities again."
)

POLICY_GEN_WRONG_REGION_HINT = (
    "AWS could not start policy analysis in the available regions. "
    "Run a scan so Vigil can refresh CloudTrail and Access Analyzer regions, then try again."
)


def _client_error_parts(exc: BaseException) -> tuple[str, str]:
    if isinstance(exc, ClientError):
        err = exc.response.get("Error") or {}
        return str(err.get("Code") or ""), str(err.get("Message") or exc)
    return "", str(exc)


def user_friendly_policy_generation_error(exc: BaseException) -> str:
    """Map AWS/boto errors to copy suitable for end users."""
    code, msg = _client_error_parts(exc)
    lower = f"{code} {msg}".lower()
    compact = lower.replace(" ", "").replace("_", "")

    if "missing regions or allregions" in lower:
        return (
            "CloudTrail is not configured for AWS policy analysis. "
            "Enable at least one logging trail, preferably multi-region, run a scan, then try again."
        )
    if "invalid against requested date format" in lower or "endtime must be after starttime" in lower:
        return "AWS rejected the analysis time window. Try again in a moment."
    if "no logging cloudtrail" in lower or "no_trails" in lower:
        return "No active CloudTrail trail was found. Enable CloudTrail logging, run a scan, then try again."
    if "nosuchentity" in compact and "accessanalyzermonitor" in compact:
        return POLICY_GEN_MONITOR_ROLE_MISSING
    if "passrole" in compact:
        return f"Vigil can start analysis, but AWS blocked the monitor role handoff. {POLICY_GEN_PASS_ROLE_HINT}"
    if "accessanalyzermonitor" in compact and (
        "accessdenied" in lower or "not authorized" in lower or code == "AccessDeniedException"
    ):
        return (
            "The Access Analyzer monitor role exists, but AWS cannot use it to read the CloudTrail logs. "
            "Update the connector and confirm the CloudTrail log bucket/KMS access settings."
        )
    if code == "AccessDeniedException" and "startpolicygeneration" in compact:
        return POLICY_GEN_WRONG_REGION_HINT
    if "accessdenied" in lower or "not authorized" in lower or "unauthorized" in lower:
        return POLICY_GEN_WRONG_REGION_HINT
    if "enable advanced" in lower or "advanced iam policy" in lower:
        return "Turn on Advanced IAM policy generation for this AWS connector, then try again."
    if "could not determine cloudtrail access role" in lower or "cloudtrail reader role" in lower:
        return POLICY_GEN_MONITOR_ROLE_MISSING

    return "Could not start policy analysis right now. Try again in a few minutes."
