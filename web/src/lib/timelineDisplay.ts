export interface TimelineEvent {
  type: "cloudtrail";
  event_id: string;
  event_name: string;
  event_source: string;
  event_time: string;
  actor: string | null;
  source_ip: string | null;
  resources: { type: string | null; name: string | null }[];
}

export type EventVerb = "create" | "delete" | "update" | "security";
export type ServiceChip = "IAM" | "S3" | "Network" | "KMS" | "Security" | "CloudFormation" | "Other";
export type ImpactLevel = "high" | "medium" | "low" | "none";

export interface ParsedActor {
  label: string;
  role: string | null;
  user: string | null;
  origin: string;
  fullArn: string | null;
}

const HIGH_IMPACT_EVENTS = new Set([
  "AttachRolePolicy",
  "AttachUserPolicy",
  "PutBucketPolicy",
  "PutBucketAcl",
  "AuthorizeSecurityGroupIngress",
  "StopLogging",
  "DeleteTrail",
  "ScheduleKeyDeletion",
  "DeleteDetector",
  "StopConfigurationRecorder",
]);

const SECURITY_EVENTS = new Set([
  "StopLogging",
  "DeleteTrail",
  "AuthorizeSecurityGroupIngress",
  "AuthorizeSecurityGroupEgress",
  "PutBucketPolicy",
  "PutBucketAcl",
  "AttachRolePolicy",
  "AttachUserPolicy",
  "ScheduleKeyDeletion",
  "DeleteDetector",
]);

const SUMMARY_TEMPLATES: Record<string, string> = {
  CreateUser: "Created IAM user",
  DeleteUser: "Deleted IAM user",
  AttachUserPolicy: "Attached policy to IAM user",
  DetachUserPolicy: "Detached policy from IAM user",
  CreateRole: "Created IAM role",
  DeleteRole: "Deleted IAM role",
  AttachRolePolicy: "Attached policy to IAM role",
  DetachRolePolicy: "Detached policy from IAM role",
  CreatePolicy: "Created IAM policy",
  DeletePolicy: "Deleted IAM policy",
  AddUserToGroup: "Added user to IAM group",
  RemoveUserFromGroup: "Removed user from IAM group",
  AuthorizeSecurityGroupIngress: "Opened inbound security group rule",
  RevokeSecurityGroupIngress: "Revoked inbound security group rule",
  AuthorizeSecurityGroupEgress: "Opened outbound security group rule",
  RevokeSecurityGroupEgress: "Revoked outbound security group rule",
  CreateSecurityGroup: "Created security group",
  DeleteSecurityGroup: "Deleted security group",
  PutBucketPolicy: "Changed S3 bucket policy",
  DeleteBucketPolicy: "Removed S3 bucket policy",
  PutBucketAcl: "Changed S3 bucket ACL",
  PutBucketPublicAccessBlock: "Updated S3 public access block",
  RunInstances: "Launched EC2 instances",
  TerminateInstances: "Terminated EC2 instances",
  CreateKey: "Created KMS key",
  DisableKey: "Disabled KMS key",
  ScheduleKeyDeletion: "Scheduled KMS key deletion",
  StopLogging: "Stopped CloudTrail logging",
  DeleteTrail: "Deleted CloudTrail trail",
  DeleteDetector: "Deleted GuardDuty detector",
  StopConfigurationRecorder: "Stopped AWS Config recorder",
};

export function eventVerb(eventName: string): EventVerb {
  if (SECURITY_EVENTS.has(eventName)) return "security";
  if (/^(Create|Run|Add|Put)/.test(eventName)) return "create";
  if (/^(Delete|Terminate|Remove|Stop|Disable|Schedule|Revoke)/.test(eventName)) return "delete";
  return "update";
}

export function impactLevel(eventName: string): ImpactLevel {
  if (HIGH_IMPACT_EVENTS.has(eventName)) return "high";
  if (/^(Create|Delete)(User|Role|Policy|SecurityGroup|Key)/.test(eventName)) return "medium";
  if (eventName.startsWith("Put") || eventName.startsWith("Attach") || eventName.startsWith("Detach")) return "medium";
  return "low";
}

export function serviceCategory(source: string, eventName: string): ServiceChip {
  const s = source.replace(".amazonaws.com", "").toLowerCase();
  if (s === "iam") return "IAM";
  if (s === "s3") return "S3";
  if (s === "kms") return "KMS";
  if (s === "cloudformation") return "CloudFormation";
  if (s === "ec2" || /securitygroup/i.test(eventName)) return "Network";
  if (s === "cloudtrail" || s === "guardduty" || s === "config") return "Security";
  return "Other";
}

export function serviceLabel(source: string): string {
  const s = source.replace(".amazonaws.com", "");
  const map: Record<string, string> = {
    iam: "IAM",
    s3: "S3",
    ec2: "EC2",
    kms: "KMS",
    cloudtrail: "CloudTrail",
    guardduty: "GuardDuty",
    config: "AWS Config",
  };
  return map[s] || s.toUpperCase() || "AWS";
}

export function parseActor(actor: string | null): ParsedActor {
  if (!actor) {
    return { label: "Unknown actor", role: null, user: null, origin: "Unknown", fullArn: null };
  }
  if (actor.includes(":assumed-role/")) {
    const tail = actor.split(":assumed-role/")[1] ?? "";
    const slash = tail.indexOf("/");
    const role = slash >= 0 ? tail.slice(0, slash) : tail;
    const session = slash >= 0 ? tail.slice(slash + 1) : "";
    // Prefer the session identity (SSO email / username) over the permission set role name.
    const label = session || role || actor;
    return {
      label,
      role: role || null,
      user: session || null,
      origin: "Assumed role session",
      fullArn: actor,
    };
  }
  if (actor.includes(":user/")) {
    const user = actor.split(":user/")[1]?.split("/")[0] ?? actor;
    return { label: user, role: null, user, origin: "IAM user", fullArn: actor };
  }
  if (actor.includes(":role/") && !actor.includes(":assumed-role/")) {
    const role = actor.split(":role/")[1]?.split("/")[0] ?? actor;
    return { label: role, role, user: null, origin: "IAM role", fullArn: actor };
  }
  if (/:root$/.test(actor) || actor.endsWith(":root")) {
    return { label: "Root account", role: null, user: "Root", origin: "AWS account root", fullArn: actor };
  }
  if (actor.includes(".amazonaws.com")) {
    return { label: actor.split("/").pop() || actor, role: null, user: null, origin: "AWS service", fullArn: actor };
  }
  const short = actor.split("/").pop() || actor;
  return { label: short, role: null, user: short, origin: "Principal", fullArn: actor.startsWith("arn:") ? actor : null };
}

export function extractRegion(evt: TimelineEvent): string | null {
  for (const r of evt.resources) {
    const name = r.name || "";
    const m = name.match(/^arn:aws:[^:]+:([a-z0-9-]+):/);
    if (m && m[1] !== "aws") return m[1];
  }
  const src = evt.event_source.replace(".amazonaws.com", "");
  if (src === "ec2" || src === "kms") return null;
  if (src === "s3" || src === "iam") return "global";
  return null;
}

export function primaryResourceName(evt: TimelineEvent): string | null {
  const names = evt.resources.map((r) => r.name || r.type || "").filter(Boolean);
  if (names.length === 0) return null;
  const first = names[0];
  if (first.startsWith("arn:")) {
    const tail = first.split("/").pop() || first.split(":").pop() || first;
    return tail.length > 48 ? `${tail.slice(0, 45)}…` : tail;
  }
  return first.length > 48 ? `${first.slice(0, 45)}…` : first;
}

export function dedupeResources(
  resources: { type: string | null; name: string | null }[],
): { type: string | null; name: string | null }[] {
  const seen = new Set<string>();
  const out: { type: string | null; name: string | null }[] = [];
  for (const r of resources) {
    const display = resourceDisplayName(r.name).toLowerCase();
    const key = `${(r.type || "").toLowerCase()}|${display}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(r);
  }
  return out;
}

/** Collapse repeated CloudTrail writes for the same actor + resource within a window. */
export function dedupeTimelineEvents(events: TimelineEvent[], windowMs = 45 * 60 * 1000): TimelineEvent[] {
  const kept: TimelineEvent[] = [];
  for (const evt of events) {
    const resource = (primaryResourceName(evt) ?? "").toLowerCase();
    const actor = parseActor(evt.actor).label.toLowerCase();
    const t = new Date(evt.event_time).getTime();
    const duplicate = kept.some((k) => {
      if (k.event_name !== evt.event_name) return false;
      if ((primaryResourceName(k) ?? "").toLowerCase() !== resource) return false;
      if (parseActor(k.actor).label.toLowerCase() !== actor) return false;
      return Math.abs(new Date(k.event_time).getTime() - t) <= windowMs;
    });
    if (!duplicate) kept.push(evt);
  }
  return kept;
}

export function eventDisplayName(eventName: string, eventSource?: string): string {
  const base = SUMMARY_TEMPLATES[eventName];
  if (base) return base;
  const verb = eventVerb(eventName);
  const service = eventSource ? serviceLabel(eventSource) : "AWS";
  if (verb === "create") return `Created ${service} resource`;
  if (verb === "delete") return `Deleted ${service} resource`;
  if (verb === "security") return `${service} security change`;
  return `Updated ${service} resource`;
}

export function humanSummary(evt: TimelineEvent): string {
  const base = eventDisplayName(evt.event_name, evt.event_source);
  const resource = primaryResourceName(evt);
  if (resource) return `${base} · ${resource}`;
  if (evt.event_name === "AttachRolePolicy" || evt.event_name === "AttachUserPolicy") {
    return `${base} — review for administrator or wildcard permissions`;
  }
  return base;
}

export function truncateMiddle(value: string, max = 52): string {
  if (value.length <= max) return value;
  const half = Math.floor((max - 1) / 2);
  return `${value.slice(0, half)}…${value.slice(-half)}`;
}

export function isTechnicalString(value: string): boolean {
  return (
    value.startsWith("arn:") ||
    /^[\da-f-]{8,}$/i.test(value) ||
    /^\d{1,3}(\.\d{1,3}){3}$/.test(value) ||
    value.includes(".amazonaws.com")
  );
}

export function resourceDisplayName(name: string | null): string {
  if (!name) return "—";
  if (name.startsWith("arn:")) {
    const tail = name.split("/").pop() || name.split(":").pop() || name;
    return tail;
  }
  return name;
}

export function contextualChips(evt: TimelineEvent): string[] {
  const chips: string[] = [];
  const cat = serviceCategory(evt.event_source, evt.event_name);
  if (cat !== "Other") chips.push(cat);
  if (SECURITY_EVENTS.has(evt.event_name) || cat === "Security") {
    if (!chips.includes("Security")) chips.push("Security");
  }
  if (impactLevel(evt.event_name) === "high") chips.push("High impact");
  return chips;
}

export function verbStyles(verb: EventVerb): { iconBg: string; iconColor: string; border: string } {
  switch (verb) {
    case "create":
      return { iconBg: "bg-emerald-50", iconColor: "text-emerald-700", border: "border-l-emerald-500" };
    case "delete":
      return { iconBg: "bg-red-50", iconColor: "text-red-700", border: "border-l-red-400" };
    case "security":
      return { iconBg: "bg-amber-50", iconColor: "text-amber-800", border: "border-l-amber-500" };
    default:
      return { iconBg: "bg-sky-50", iconColor: "text-sky-700", border: "border-l-sky-400" };
  }
}

export function chipClass(chip: string): string {
  switch (chip) {
    case "IAM":
      return "border-amber-200/80 bg-amber-50 text-amber-800";
    case "S3":
      return "border-sky-200/80 bg-sky-50 text-sky-800";
    case "Network":
      return "border-violet-200/80 bg-violet-50 text-violet-800";
    case "KMS":
      return "border-indigo-200/80 bg-indigo-50 text-indigo-800";
    case "Security":
      return "border-rose-200/80 bg-rose-50 text-rose-800";
    case "CloudFormation":
      return "border-orange-200/80 bg-orange-50 text-orange-800";
    case "High impact":
      return "border-red-200/80 bg-red-50 text-red-800";
    default:
      return "border-zinc-200 bg-zinc-50 text-zinc-600";
  }
}
