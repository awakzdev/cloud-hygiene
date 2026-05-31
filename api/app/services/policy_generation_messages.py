"""User-facing copy for CloudTrail-based IAM policy generation (not external/internal analyzers)."""

from __future__ import annotations

from botocore.exceptions import ClientError

# Console path AWS documents for IAM principals.
IAM_POLICY_GEN_CONSOLE_PATH = (
    "IAM → Roles → this role → Permissions → Generate policy based on CloudTrail events"
)

POLICY_GEN_NO_JOB_NOTE = (
    "No completed policy generation job was found for this role. "
    'Use "Start CloudTrail analysis" in Vigil, or in AWS: '
    f"{IAM_POLICY_GEN_CONSOLE_PATH}. "
    "Analysis is read-only until you apply a policy yourself."
)

POLICY_GEN_ASSUME_FAILED_NOTE = (
    "Connector role is not assumable or lacks policy-generation API permissions "
    "(StartPolicyGeneration, GetGeneratedPolicy, ListPolicyGenerations). "
    "Update the Vigil connector stack with Advanced IAM policy generation enabled."
)

POLICY_GEN_PASS_ROLE_HINT = (
    "Update your Vigil CloudFormation stack (Advanced IAM policy generation enabled) so the connector "
    "can iam:PassRole the VigilAccessAnalyzerMonitor role to access-analyzer.amazonaws.com. "
    "That monitor role reads CloudTrail logs; it is not the VigilScannerRole itself."
)

POLICY_GEN_NO_CONNECTOR_NOTE = "Connect the Vigil connector role first."

POLICY_GEN_MONITOR_ROLE_MISSING = (
    "The CloudTrail reader role for Access Analyzer is not in this account. "
    "Update your Vigil connector stack with Advanced IAM policy generation enabled, "
    "then run Verify permissions again."
)

POLICY_GEN_WRONG_REGION_HINT = (
    "CloudTrail analysis could not be started in any region Vigil tried. "
    "Run a scan so Access Analyzer regions are collected, or retry after enabling "
    "IAM Access Analyzer in your primary AWS region."
)


def _client_error_parts(exc: BaseException) -> tuple[str, str]:
    if isinstance(exc, ClientError):
        err = exc.response.get("Error") or {}
        return str(err.get("Code") or ""), str(err.get("Message") or exc)
    return "", str(exc)


def user_friendly_policy_generation_error(exc: BaseException) -> str:
    """Map AWS/boto errors to copy suitable for end users (no raw API or restart instructions)."""
    code, msg = _client_error_parts(exc)
    lower = f"{code} {msg}".lower()
    compact = lower.replace(" ", "").replace("_", "")

    if "missing regions or allregions" in lower:
        return (
            "CloudTrail is not configured the way AWS expects for this analysis. "
            "Ensure at least one logging trail is enabled (multi-region is best), run a scan, then try again."
        )
    if "invalid against requested date format" in lower or "endtime must be after starttime" in lower:
        return "Could not start CloudTrail analysis due to a timestamp issue. Please try again in a moment."
    if "no logging cloudtrail" in lower or "no_trails" in lower:
        return "No active CloudTrail trails found. Enable CloudTrail logging, run a scan, then try again."
    if "nosuchentity" in compact and "accessanalyzermonitor" in compact:
        return POLICY_GEN_MONITOR_ROLE_MISSING
    if "passrole" in compact:
        return (
            "Vigil can call Access Analyzer APIs but cannot pass the CloudTrail reader role to the service. "
            f"{POLICY_GEN_PASS_ROLE_HINT}"
        )
    if "accessanalyzermonitor" in compact and (
        "accessdenied" in lower or "not authorized" in lower or code == "AccessDeniedException"
    ):
        return (
            "The CloudTrail reader role exists but Access Analyzer cannot use it (trust policy or S3 log access). "
            "Update the connector stack and confirm CloudTrail log bucket settings if your template asks for them."
        )
    if code == "AccessDeniedException" and "startpolicygeneration" in compact:
        return POLICY_GEN_WRONG_REGION_HINT
    if "accessdenied" in lower or "not authorized" in lower or "unauthorized" in lower:
        return POLICY_GEN_WRONG_REGION_HINT
    if "enable advanced" in lower or "advanced iam policy" in lower:
        return "Turn on Advanced IAM policy generation on the AWS connector, then try again."
    if "could not determine cloudtrail access role" in lower or "cloudtrail reader role" in lower:
        return POLICY_GEN_MONITOR_ROLE_MISSING

    return (
        "Could not start CloudTrail analysis right now. Try again in a few minutes, "
        "or ask your administrator if the problem continues."
    )
