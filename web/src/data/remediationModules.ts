/** Remediation modules — must stay aligned with api/app/data/remediation_modules.py */

export type RemediationModuleId =
  | "security_groups"
  | "s3_public_access"
  | "iam_access_keys"
  | "iam_policies"
  | "ssm_parameters"
  | "cloudtrail_logging";

export type RemediationModules = Record<RemediationModuleId, boolean>;

export const DEFAULT_REMEDIATION_MODULES: RemediationModules = {
  security_groups: false,
  s3_public_access: false,
  iam_access_keys: false,
  iam_policies: false,
  ssm_parameters: false,
  cloudtrail_logging: false,
};

export type RemediationModuleSpec = {
  id: RemediationModuleId;
  label: string;
  badgeLabel: string;
  cfnParameter: string;
  summary: string;
  bullets: readonly string[];
  permissions: readonly string[];
  runnerSupported: boolean;
};

export const REMEDIATION_MODULE_SPECS: readonly RemediationModuleSpec[] = [
  {
    id: "security_groups",
    label: "Security Groups",
    badgeLabel: "SG remediation",
    cfnParameter: "EnableSecurityGroupRemediation",
    summary: "Fix open ingress rules",
    bullets: ["Remove open ingress rules", "Restore approved security group configuration"],
    permissions: [
      "ec2:RevokeSecurityGroupIngress",
      "ec2:AuthorizeSecurityGroupIngress",
    ],
    runnerSupported: true,
  },
  {
    id: "s3_public_access",
    label: "S3 public access",
    badgeLabel: "S3 remediation",
    cfnParameter: "EnableS3Remediation",
    summary: "Block public buckets",
    bullets: ["Enforce block public access", "Tighten bucket policies when approved"],
    permissions: ["s3:PutBucketPublicAccessBlock", "s3:PutBucketPolicy"],
    runnerSupported: false,
  },
  {
    id: "iam_access_keys",
    label: "IAM Access Keys",
    badgeLabel: "IAM keys remediation",
    cfnParameter: "EnableIamAccessKeyRemediation",
    summary: "Disable or rotate dormant credentials",
    bullets: ["Disable stale access keys", "Delete unused keys after approval"],
    permissions: ["iam:UpdateAccessKey", "iam:DeleteAccessKey"],
    runnerSupported: false,
  },
  {
    id: "iam_policies",
    label: "IAM policies",
    badgeLabel: "IAM policy remediation",
    cfnParameter: "EnableIamPolicyRemediation",
    summary: "Remove excessive permissions",
    bullets: ["Detach overly broad policies", "Scope inline policies when approved"],
    permissions: [
      "iam:PutRolePolicy",
      "iam:DetachRolePolicy",
      "iam:AttachRolePolicy",
      "iam:CreatePolicyVersion",
      "iam:DeletePolicyVersion",
    ],
    runnerSupported: false,
  },
  {
    id: "ssm_parameters",
    label: "SSM parameters",
    badgeLabel: "SSM remediation",
    cfnParameter: "EnableSsmParameterRemediation",
    summary: "Migrate plaintext secrets",
    bullets: ["Rewrite sensitive String parameters as SecureString", "Run through SSM Automation after approval"],
    permissions: ["ssm:GetParameter", "ssm:PutParameter"],
    runnerSupported: true,
  },
  {
    id: "cloudtrail_logging",
    label: "CloudTrail logging",
    badgeLabel: "CloudTrail remediation",
    cfnParameter: "EnableCloudTrailRemediation",
    summary: "Enable logging if disabled",
    bullets: ["Start logging on trails", "Update trail configuration when approved"],
    permissions: ["cloudtrail:UpdateTrail", "cloudtrail:StartLogging"],
    runnerSupported: false,
  },
];

export function anyRemediationEnabled(modules: RemediationModules): boolean {
  return REMEDIATION_MODULE_SPECS.some((m) => modules[m.id]);
}

export function countRemediationEnabled(modules: RemediationModules): number {
  return REMEDIATION_MODULE_SPECS.filter((m) => modules[m.id]).length;
}
