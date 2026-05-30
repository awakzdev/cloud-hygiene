/** CloudTrail IAM policy generation — not external/internal Access Analyzer dashboards. */

export const IAM_POLICY_GEN_CONSOLE_PATH =
  "IAM → Roles → this role → Permissions → Generate policy based on CloudTrail events";

export const POLICY_GEN_REASON_LABELS: Record<string, string> = {
  no_generation: "No completed CloudTrail policy-generation job for this role yet.",
  in_progress: "CloudTrail policy generation is running — rebuild the suggestion in a few minutes.",
  assume_failed: "Connector lacks policy-generation API permissions.",
  no_advanced_role: "Connect the Vigil connector role first.",
  analyzer_off: "Could not reach policy-generation APIs (check connector permissions).",
};

export function policyGenerationReasonLabel(reason: string | null | undefined): string | null {
  if (!reason) return null;
  return POLICY_GEN_REASON_LABELS[reason] ?? reason;
}
