/** Drawer Overview tab — short headlines without trailing periods in compact UI. */
export function stripOverviewPeriod(text: string): string {
  return text.replace(/\.\s*$/, "").trim();
}

const CREDENTIAL_HEADLINES: Record<string, string> = {
  "iam.access_key.unused_45d": "Credential inactive for 45+ days",
  "iam.access_key.unused_90d": "Credential inactive for 90+ days",
  "iam.user.credentials_unused_45d": "Console credentials inactive for 45+ days",
  "iam.user.inactive_90d": "Console credentials inactive for 90+ days",
};

const CREDENTIAL_FIX_ARROWS: Record<string, string> = {
  "iam.access_key.unused_45d": "Deactivate → verify → delete",
  "iam.access_key.unused_90d": "Deactivate → verify → delete",
  "iam.user.credentials_unused_45d": "Disable console access → verify → delete",
  "iam.user.inactive_90d": "Disable console access → verify → delete",
};

export function overviewHeadline(checkId: string, fallbackImpact: string): string {
  return CREDENTIAL_HEADLINES[checkId] ?? stripOverviewPeriod(fallbackImpact);
}

export function overviewRecommendedAction(checkId: string, fallbackFix: string): string {
  return CREDENTIAL_FIX_ARROWS[checkId] ?? stripOverviewPeriod(fallbackFix);
}
