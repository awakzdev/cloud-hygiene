"""User-facing copy for CloudTrail-based IAM policy generation (not external/internal analyzers)."""

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
