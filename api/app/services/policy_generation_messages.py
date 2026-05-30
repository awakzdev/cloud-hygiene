"""User-facing copy for CloudTrail-based IAM policy generation (not external/internal analyzers)."""

# Console path AWS documents for IAM principals.
IAM_POLICY_GEN_CONSOLE_PATH = (
    "IAM → Roles → this role → Permissions → Generate policy based on CloudTrail events"
)

POLICY_GEN_NO_JOB_NOTE = (
    "No completed policy generation job was found for this role. "
    "Start policy generation from Vigil when available, or in AWS: "
    f"{IAM_POLICY_GEN_CONSOLE_PATH}. "
    "This uses CloudTrail activity for the role; it does not modify AWS resources. "
    "External, internal, and unused-access analyzers are separate features."
)

POLICY_GEN_ASSUME_FAILED_NOTE = (
    "Connector role is not assumable or lacks policy-generation API permissions "
    "(StartPolicyGeneration, GetGeneratedPolicy, ListPolicyGenerations). "
    "Update the Vigil connector stack with Advanced IAM policy generation enabled."
)

POLICY_GEN_NO_CONNECTOR_NOTE = "Connect the Vigil connector role first."
