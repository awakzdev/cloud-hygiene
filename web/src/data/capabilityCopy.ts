import { REMEDIATION_MODULE_SPECS, type RemediationModules } from "./remediationModules";

export const ADVANCED_POLICY_CAPABILITY_LINES = [
  "Generate IAM access reports",
  "Start CloudTrail policy-generation jobs for roles",
  "Cancel in-flight jobs when needed",
  "Retrieve generated least-privilege policies",
] as const;

export const ADVANCED_POLICY_RAW_ACTIONS = [
  "iam:GenerateServiceLastAccessedDetails",
  "access-analyzer:StartPolicyGeneration",
  "access-analyzer:CancelPolicyGeneration",
  "access-analyzer:GetGeneratedPolicy",
  "access-analyzer:ListPolicyGenerations",
  "iam:PassRole",
] as const;

export function countSelectedIamActions(options: {
  enable_advanced_policy_generation: boolean;
  remediation_modules: RemediationModules;
}): number {
  let total = 0;
  if (options.enable_advanced_policy_generation) {
    total += ADVANCED_POLICY_RAW_ACTIONS.length;
  }
  for (const spec of REMEDIATION_MODULE_SPECS) {
    if (options.remediation_modules[spec.id]) {
      total += spec.permissions.length;
    }
  }
  return total;
}
