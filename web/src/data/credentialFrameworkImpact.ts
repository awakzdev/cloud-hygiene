/** IAM credential hygiene checks with different framework inactivity windows. */
export const CREDENTIAL_UNUSED_CHECK_IDS = new Set([
  "iam.user.credentials_unused_45d",
  "iam.access_key.unused_45d",
  "iam.user.inactive_90d",
  "iam.access_key.unused_90d",
]);

export type CredentialFrameworkImpactItem = {
  id: string;
  framework: string;
  control?: string;
  thresholdDays: number;
  tone: "cis" | "soc_iso";
  statusLabel: string;
  isActive: boolean;
};

export const CREDENTIAL_UNUSED_FRAMEWORK_IMPACT: CredentialFrameworkImpactItem[] = [
  {
    id: "cis",
    framework: "CIS",
    control: "1.11",
    thresholdDays: 45,
    tone: "cis",
    statusLabel: "Active trigger",
    isActive: true,
  },
  {
    id: "soc_iso",
    framework: "SOC2 / ISO",
    thresholdDays: 90,
    tone: "soc_iso",
    statusLabel: "Later threshold",
    isActive: false,
  },
];

export function credentialUnusedFrameworkImpact(
  checkId: string,
): readonly CredentialFrameworkImpactItem[] | null {
  return CREDENTIAL_UNUSED_CHECK_IDS.has(checkId) ? CREDENTIAL_UNUSED_FRAMEWORK_IMPACT : null;
}
