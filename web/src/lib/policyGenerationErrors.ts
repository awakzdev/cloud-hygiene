/** End-user copy for CloudTrail policy generation failures (never raw AWS SDK text). */

export function friendlyPolicyGenerationError(raw: string): string {
  const lower = raw.toLowerCase();
  const compact = lower.replace(/\s/g, "").replace(/_/g, "");

  if (lower.includes("missing regions or allregions")) {
    return (
      "CloudTrail is not configured the way AWS expects for this analysis. " +
      "Ensure at least one logging trail is enabled (multi-region is best), run a scan, then try again."
    );
  }
  if (
    lower.includes("invalid against requested date format") ||
    lower.includes("endtime must be after starttime")
  ) {
    return "Could not start CloudTrail analysis due to a timestamp issue. Please try again in a moment.";
  }
  if (lower.includes("no logging cloudtrail") || lower.includes("no_trails")) {
    return "No active CloudTrail trails found. Enable CloudTrail logging, run a scan, then try again.";
  }
  if (lower.includes("cloudtrail reader role") && (lower.includes("missing") || lower.includes("not in this account"))) {
    return raw;
  }
  if (compact.includes("passrole")) {
    return (
      "Vigil can call Access Analyzer APIs but cannot pass the CloudTrail reader role to the service. " +
      "Update the AWS connector with Advanced IAM policy generation enabled, then verify permissions again."
    );
  }
  if (lower.includes("could not be started in any region")) {
    return raw;
  }
  if (lower.includes("accessdenied") || lower.includes("not authorized") || lower.includes("unauthorized")) {
    return (
      "CloudTrail analysis could not be started in the regions Vigil tried. " +
      "Run a full account scan, then try again. Connector API permissions may already be correct."
    );
  }
  if (lower.includes("enable advanced") || lower.includes("advanced iam policy")) {
    return "Turn on Advanced IAM policy generation on the AWS connector, then try again.";
  }
  if (lower.includes("validationexception") || lower.includes("startpolicygeneration")) {
    return (
      "Could not start CloudTrail analysis right now. Try again in a few minutes, " +
      "or ask your administrator if the problem continues."
    );
  }
  if (lower.includes("error") || lower.includes("exception") || lower.includes("failed")) {
    return (
      "Could not start CloudTrail analysis right now. Try again in a few minutes, " +
      "or ask your administrator if the problem continues."
    );
  }

  return raw;
}

export function formatCloudTrailStartFeedback(raw: string): {
  tone: "error" | "success" | "info";
  message: string;
} {
  const lower = raw.toLowerCase();
  if (lower.includes("started") || lower.includes("in progress") || lower.includes("several minutes")) {
    return { tone: "success", message: raw };
  }
  if (lower.includes("error") || lower.includes("exception") || lower.includes("failed") || lower.includes("could not")) {
    return { tone: "error", message: friendlyPolicyGenerationError(raw) };
  }
  return { tone: "info", message: raw };
}
