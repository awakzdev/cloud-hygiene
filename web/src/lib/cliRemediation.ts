import { api } from "../api";

/** Finding shape needed for CLI placeholder resolution */
export type CliFinding = {
  check_id: string;
  resource_arn: string;
  evidence: Record<string, unknown>;
};

function isPrivateOrLocalIp(ip: string): boolean {
  if (ip === "::1" || ip.startsWith("127.")) return true;
  if (ip.startsWith("10.")) return true;
  if (ip.startsWith("192.168.")) return true;
  const m = /^172\.(\d+)\./.exec(ip);
  if (m) {
    const second = Number(m[1]);
    if (second >= 16 && second <= 31) return true;
  }
  return false;
}

/** Best-effort public IP for security-group / CIDR remediation snippets. */
export async function fetchClientIpForRemediation(): Promise<string | null> {
  try {
    const res = await api<{ ip: string | null }>("/v1/meta/client-ip");
    if (res.ip && !isPrivateOrLocalIp(res.ip)) return res.ip;
  } catch {
    // fall through — e.g. not logged in
  }
  try {
    const res = await fetch("https://api.ipify.org?format=json");
    if (res.ok) {
      const data = (await res.json()) as { ip?: string };
      if (data.ip && !isPrivateOrLocalIp(data.ip)) return data.ip;
    }
  } catch {
    // ignore
  }
  return null;
}

function arnSegment(arn: string, resource: string): string | undefined {
  const re = new RegExp(`:${resource}/([^:/]+)`);
  return arn.match(re)?.[1];
}

function accountFromArn(arn: string): string | undefined {
  return arn.match(/:(\d{12}):/)?.[1];
}

function regionFromArn(arn: string): string | undefined {
  const m = arn.match(/^arn:aws:[^:]+:([^:*]+)/);
  if (!m) return undefined;
  const r = m[1];
  if (r === "aws" || r === "iam" || r === "s3") return undefined;
  return r;
}

/**
 * Resolve `<placeholder>` tokens from finding evidence + resource ARN.
 * Pass `clientIp` when available (public IP for SG restrict rules).
 */
export function buildCliPlaceholders(
  finding: CliFinding,
  clientIp?: string | null,
): Record<string, string> {
  const arn = finding.resource_arn;
  const ev = finding.evidence;
  const checkId = finding.check_id;

  const arnRegion = regionFromArn(arn) ?? "<region>";
  const region =
    (typeof ev.region === "string" && ev.region) ||
    (typeof ev.home_region === "string" && ev.home_region) ||
    arnRegion;
  const accountId =
    (typeof ev.account_id === "string" && ev.account_id) ||
    accountFromArn(arn) ||
    "<account-id>";

  const roleMatch = arn.match(/:role\/(.+)$/);
  const roleName = roleMatch ? (roleMatch[1].split("/").pop() ?? "") : "";

  const userFromArn = arn.match(/:user\/(.+)$/)?.[1]?.split("/").pop() ?? "";
  const userFromKeyArn = arn.includes("#") ? arn.split("/").pop()?.split("#")[0] : "";
  const userName =
    (typeof ev.user_name === "string" && ev.user_name) ||
    userFromKeyArn ||
    userFromArn ||
    "<user>";

  const accessKeyFromArn = arn.includes("#") ? arn.split("#")[1] : "";
  const accessKeyId = checkId.startsWith("iam.access_key.")
    ? (typeof ev.key_id === "string" && ev.key_id) || accessKeyFromArn || "<key-id>"
    : undefined;

  const kmsKeyIdRaw = typeof ev.key_id === "string" ? ev.key_id : undefined;
  const kmsAlias = typeof ev.alias === "string" ? ev.alias : undefined;
  const kmsKeyArn =
    (typeof ev.kms_key_id === "string" && ev.kms_key_id) ||
    (kmsKeyIdRaw && kmsKeyIdRaw.startsWith("arn:") ? kmsKeyIdRaw : undefined) ||
    (kmsKeyIdRaw && checkId.startsWith("kms.")
      ? `arn:aws:kms:${region}:${accountId}:key/${kmsKeyIdRaw}`
      : undefined) ||
    (kmsAlias ? (kmsAlias.startsWith("alias/") ? kmsAlias : `alias/${kmsAlias}`) : undefined) ||
    "<kms-key-arn>";

  const keyId =
    accessKeyId ??
    (checkId.startsWith("kms.") && kmsKeyIdRaw ? kmsKeyIdRaw : undefined) ??
    (typeof ev.key_id === "string" ? ev.key_id : undefined) ??
    "<key-id>";

  const policyArn =
    (typeof ev.policy_arn === "string" && ev.policy_arn) ||
    (arn.includes(":policy/") ? arn : "<policy-arn>");

  const removable = ev.removable_statements as { policy?: string }[] | undefined;
  const removablePolicyNames =
    removable && removable.length > 0
      ? [...new Set(removable.map((s) => s.policy).filter(Boolean) as string[])]
      : [];

  const policyName =
    (removablePolicyNames.length === 1 ? removablePolicyNames[0] : undefined) ||
    (typeof ev.policy_name === "string" && ev.policy_name) ||
    (arn.includes(":policy/") ? arn.split("/").pop() ?? "" : "") ||
    "<policy-name>";

  const bucketName =
    (typeof ev.bucket_name === "string" && ev.bucket_name) ||
    (typeof ev.name === "string" && checkId.startsWith("s3.") ? ev.name : undefined) ||
    arn.match(/^arn:aws:s3:::([^/]+)$/)?.[1] ||
    "<bucket-name>";

  const tableName =
    (typeof ev.table_name === "string" && ev.table_name) ||
    arnSegment(arn, "table") ||
    "<table-name>";

  const instanceId =
    (typeof ev.instance_id === "string" && ev.instance_id) ||
    (typeof ev.db_instance_id === "string" && ev.db_instance_id) ||
    arnSegment(arn, "instance") ||
    arn.match(/:db:([^:/]+)/)?.[1] ||
    "<instance-id>";

  const volumeId =
    (typeof ev.volume_id === "string" && ev.volume_id) ||
    arnSegment(arn, "volume") ||
    "<volume-id>";

  const functionName =
    (typeof ev.function_name === "string" && ev.function_name) ||
    arn.match(/:function:([^:+/]+)/)?.[1] ||
    "<function-name>";

  const snapshotId =
    (typeof ev.snapshot_id === "string" && ev.snapshot_id) ||
    arn.match(/snapshot\/(snap-[a-f0-9]+)/)?.[1] ||
    "<snapshot-id>";

  const imageId =
    (typeof ev.image_id === "string" && ev.image_id) ||
    arn.match(/(ami-[a-f0-9]+)/)?.[1] ||
    "<image-id>";

  const trailName =
    (typeof ev.trail_name === "string" && ev.trail_name) ||
    (typeof ev.name === "string" && checkId.startsWith("cloudtrail.") ? ev.name : undefined) ||
    "<trail-name>";

  const parameterName =
    (typeof ev.parameter_name === "string" && ev.parameter_name) || "<parameter-name>";

  const secretName =
    (typeof ev.name === "string" && checkId.includes("secretsmanager") ? ev.name : undefined) ||
    "<secret-name>";

  const sgId =
    (typeof ev.group_id === "string" && ev.group_id) ||
    arn.match(/security-group\/(sg-[a-f0-9]+)/)?.[1] ||
    "<sg-id>";

  const vpcId =
    (typeof ev.vpc_id === "string" && ev.vpc_id) ||
    arnSegment(arn, "vpc") ||
    "<vpc-id>";

  const yourIp =
    clientIp && !isPrivateOrLocalIp(clientIp) ? clientIp : "<your-ip>";

  const loadBalancerArn = arn.includes(":loadbalancer/") ? arn : "<load-balancer-arn>";
  const domainName = (typeof ev.domain_name === "string" && ev.domain_name) || "<domain-name>";
  const certificateArn = arn.includes(":acm:") ? arn : "<certificate-arn>";
  const topicArn = arn.includes(":sns:") ? arn : "<topic-arn>";

  const queueArnMatch = arn.match(/^arn:aws:sqs:([^:]+):(\d+):(.+)$/);
  const queueUrl = queueArnMatch
    ? `https://sqs.${queueArnMatch[1]}.amazonaws.com/${queueArnMatch[2]}/${queueArnMatch[3]}`
    : "<queue-url>";

  const logBucket =
    (typeof ev.s3_bucket_name === "string" && ev.s3_bucket_name) ||
    (checkId.includes("cloudtrail") && typeof ev.name === "string" ? ev.name : undefined) ||
    `my-access-logs-${accountId}`;

  return {
    "<role-name>": roleName || "<role-name>",
    "<user>": userName,
    "<key-id>": keyId,
    "<kms-key-arn>": kmsKeyArn,
    "<kms-key-id>": kmsKeyArn,
    "<policy-name>": policyName,
    "<policy-arn>": policyArn,
    "<bucket-name>": bucketName,
    "<table-name>": tableName,
    "<region>": region,
    "<instance-id>": instanceId,
    "<volume-id>": volumeId,
    "<function-name>": functionName,
    "<snapshot-id>": snapshotId,
    "<image-id>": imageId,
    "<trail-name>": trailName,
    "<parameter-name>": parameterName,
    "<secret-name>": secretName,
    "<load-balancer-arn>": loadBalancerArn,
    "<domain-name>": domainName,
    "<certificate-arn>": certificateArn,
    "<topic-arn>": topicArn,
    "<queue-url>": queueUrl,
    "<account-id>": accountId,
    "<sg-id>": sgId,
    "<vpc-id>": vpcId,
    "<your-ip>": yourIp,
    "<your-log-bucket>": logBucket,
    "<arn>": arn.includes(":mfa/") ? arn : "<arn>",
  };
}

export function applyCliPlaceholders(template: string, placeholders: Record<string, string>): string {
  let out = template;
  const keys = Object.keys(placeholders).sort((a, b) => b.length - a.length);
  for (const key of keys) {
    out = out.split(key).join(placeholders[key]);
  }
  return out;
}

/** Append --region to EC2 commands when we know the region and the line omits it. */
export function injectEc2RegionFlags(cli: string, region: string): string {
  if (!region || region === "<region>") return cli;
  return cli
    .split("\n")
    .map((line) => {
      const trimmed = line.trim();
      if (!trimmed.startsWith("aws ec2 ")) return line;
      if (trimmed.includes(" --region ")) return line;
      if (trimmed.endsWith("\\")) {
        return line.replace(/\\$/, ` --region ${region} \\`);
      }
      return `${line} --region ${region}`;
    })
    .join("\n");
}

/** Blank line before `# Step N:` comments so multi-step CLI blocks are scannable. */
export function formatCliStepSpacing(cli: string): string {
  return cli.replace(/([^\n])\n(# Step \d+:)/g, "$1\n\n$2");
}
