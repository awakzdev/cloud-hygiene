export type FindingLike = {
  check_id: string;
  resource_arn: string;
  evidence: Record<string, unknown>;
  first_seen: string;
  risk_score: number;
  severity: string;
};

export function resourceName(arn: string): string {
  const parts = arn.split(":");
  const region = parts[3] ?? "";
  const tail = parts.pop() ?? arn;
  const [, rest = tail] = tail.split(/\/(.+)/);
  const [name, suffix] = rest.split("#");
  const label = name || rest;
  const generic = ["detector", "trail", "vpc", "flow-log", "security-group"].includes(label);
  if (generic && region) return region;
  if (!suffix) return label;
  const masked = suffix.length > 12 ? `${suffix.slice(0, 4)}…${suffix.slice(-4)}` : suffix;
  return `${label} · ${masked}`;
}

/** Regional account-level checks (Access Analyzer, GuardDuty, etc.) store regions in evidence. */
export function regionsFromFindingEvidence(ev: Record<string, unknown>): string[] {
  const raw = ev.disabled_regions ?? ev.affected_regions;
  if (!Array.isArray(raw)) return [];
  return raw.filter((r): r is string => typeof r === "string" && r.trim().length > 0);
}

export function resourceDisplayName(f: FindingLike): string {
  const e = f.evidence;
  const regions = regionsFromFindingEvidence(e);
  if (regions.length > 0) {
    const n = typeof e.region_count === "number" ? e.region_count : regions.length;
    return `${n} region${n === 1 ? "" : "s"}`;
  }
  const pick = (...keys: string[]) => {
    for (const k of keys) {
      const v = e[k];
      if (typeof v === "string" && v.trim()) return v;
    }
    return null;
  };
  return (
    pick(
      "user_name",
      "role_name",
      "bucket_name",
      "table_name",
      "key_id",
      "trail_name",
      "group_name",
      "repo_name",
      "instance_id",
      "volume_id",
      "function_name",
      "secret_name",
      "topic_name",
      "queue_name",
      "load_balancer_name",
      "policy_name"
    ) ?? resourceName(f.resource_arn)
  );
}

const RESOURCE_TYPE_LABELS: Record<string, string> = {
  "iam.user": "IAM users",
  "iam.role": "IAM roles",
  "iam.access_key": "Access keys",
  "iam.root": "Root account",
  "iam.policy": "IAM policies",
  "iam.account": "Account settings",
  "iam.perm": "IAM permissions",
  "s3.bucket": "S3 buckets",
  "s3.account": "S3 account",
  "kms.key": "KMS keys",
  "dynamodb.table": "DynamoDB tables",
  "lambda.function": "Lambda functions",
  "ec2.instance": "EC2 instances",
  "ec2.ebs": "EBS volumes",
  "ec2.security_group": "Security groups",
  "rds.instance": "RDS instances",
  "cloudtrail.trail": "CloudTrail trails",
  "github.repo": "Repositories",
  "github.org": "Organizations",
  "gitlab.repo": "Projects",
  "gitlab.org": "Groups",
};

export function resourceTypeLabel(checkId: string): string {
  const match = Object.entries(RESOURCE_TYPE_LABELS).find(([prefix]) => checkId.startsWith(prefix));
  if (match) return match[1];
  const parts = checkId.split(".");
  if (parts.length >= 2) {
    return `${parts[0].toUpperCase()} ${parts[1].replace(/_/g, " ")}s`;
  }
  return "Resources";
}

export function daysAgo(iso: string): string {
  const d = Math.floor((Date.now() - new Date(iso).getTime()) / 86400000);
  if (d <= 0) return "today";
  if (d === 1) return "1 day ago";
  if (d < 30) return `${d} days ago`;
  if (d < 365) return `${Math.floor(d / 30)} mo ago`;
  return `${Math.floor(d / 365)} yr ago`;
}

export function severityLabel(sev: string): string {
  return sev.charAt(0).toUpperCase() + sev.slice(1);
}

/** Comma-separated preview of affected resource names for compact list rows. */
export function affectedResourcesPreview(items: FindingLike[], max = 3): string {
  const names = [...items]
    .sort((a, b) => resourceDisplayName(a).localeCompare(resourceDisplayName(b)))
    .map((f) => resourceDisplayName(f))
    .slice(0, max);
  const rest = items.length - names.length;
  if (rest > 0) return `${names.join(", ")} +${rest} more`;
  return names.join(", ");
}
