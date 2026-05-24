import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api";

type Finding = {
  id: string;
  check_id: string;
  resource_arn: string;
  title: string;
  severity: string;
  risk_score: number;
  status: string;
  evidence: Record<string, unknown>;
  first_seen: string;
  last_seen: string;
};

const sevHeaderBadge: Record<string, string> = {
  critical: "bg-red-50 text-red-700 border-red-100",
  high: "bg-red-50 text-red-600 border-red-100",
  medium: "bg-amber-50 text-amber-700 border-amber-100",
  low: "bg-zinc-50 text-zinc-500 border-zinc-200",
};

const sevWash: Record<string, string> = {
  critical: "from-red-50 to-stone-50",
  high: "from-red-50 to-stone-50",
  medium: "from-amber-50 to-stone-50",
  low: "from-slate-50 to-stone-50",
};

const sevStep: Record<string, string> = {
  critical: "bg-stone-700 text-white",
  high: "bg-stone-700 text-white",
  medium: "bg-stone-700 text-white",
  low: "bg-stone-700 text-white",
};

type Remediation = {
  why: string;
  console: string[];
  cli: string;
  risk: string;
};

const remediations: Record<string, Remediation> = {
  "iam.user.no_mfa": {
    why: "Users without MFA can be fully compromised with only a stolen password. A second factor an attacker must physically control is the single most effective control against credential phishing.",
    console: ["Open IAM → Users → select the user", 'Click "Security credentials" tab', 'Under "Multi-factor authentication", click "Assign MFA device"', "Follow the wizard to register a virtual or hardware MFA"],
    cli: `aws iam create-virtual-mfa-device --virtual-mfa-device-name <name> --outfile /tmp/qr.png --bootstrap-method QRCodePNG

aws iam enable-mfa-device --user-name <user> --serial-number <arn> --authentication-code1 <code1> --authentication-code2 <code2>`,
    risk: "Until MFA is enabled, a leaked password can be enough to sign in to the console.",
  },
  "iam.user.inactive_90d": {
    why: "Inactive accounts have no baseline of normal activity, making compromise invisible. Attackers who obtain credentials can operate undetected for months.",
    console: ["Open IAM → Users → select the user", 'Click "Security credentials" tab', 'Under "Console sign-in", click "Disable console access"', "Confirm with the team, then delete the user if no longer needed"],
    cli: `# Disable console access
aws iam delete-login-profile --user-name <user>

# Or delete the user entirely (remove keys + policies first)
aws iam delete-user --user-name <user>`,
    risk: "Stale console users should be disabled or removed after ownership is confirmed.",
  },
  "iam.access_key.unused_90d": {
    why: "Unused access keys are typically abandoned in scripts, CI config, or developer machines — often forgotten and never rotated. They're persistent credentials with no expiry.",
    console: ["Open IAM → Users → select the user", 'Click "Security credentials" tab', "Find the key under Access Keys", 'Click "Deactivate" first to verify nothing breaks, then "Delete"'],
    cli: `# Deactivate first, confirm nothing breaks, then delete
aws iam update-access-key --access-key-id <key-id> --status Inactive --user-name <user>

aws iam delete-access-key --access-key-id <key-id> --user-name <user>`,
    risk: "Forgotten keys are long-lived credentials. Deactivate first, then delete after confirming nothing still depends on them.",
  },
  "iam.access_key.no_rotation_90d": {
    why: "This access key is older than the configured key-age threshold. Long-lived keys are harder to reason about because they may be stored in old scripts, CI secrets, or developer machines.",
    console: ["Open IAM → Users → select the user", 'Click "Security credentials" tab', "Create a replacement access key for the current workload", "Update the workload secret, then deactivate and delete the old key"],
    cli: `# Create a replacement key, update the workload, then retire the old one
aws iam create-access-key --user-name <user>

aws iam update-access-key --access-key-id <key-id> --status Inactive --user-name <user>

aws iam delete-access-key --access-key-id <key-id> --user-name <user>`,
    risk: "This is a key hygiene finding. Validate where the key is used before rotation or deletion.",
  },
  "iam.access_key.multiple_active": {
    why: "The user has more than one active access key. That can be valid during rotation, but persistent duplicate keys make ownership and cleanup harder.",
    console: ["Open IAM → Users → select the user", 'Click "Security credentials" tab', "Review both active access keys, including creation and last-used dates", "Deactivate and delete the key that is no longer needed"],
    cli: `# Review active keys for the user
aws iam list-access-keys --user-name <user>

# Deactivate the unused key first, then delete it
aws iam update-access-key --access-key-id <key-id> --status Inactive --user-name <user>
aws iam delete-access-key --access-key-id <key-id> --user-name <user>`,
    risk: "Treat this as a review item unless the extra key is clearly stale or unauthorized.",
  },
  "iam.role.unassumed_90d": {
    why: "Roles not assumed in 90+ days are often orphaned. They add attack surface and may carry policies that nobody actively owns.",
    console: ["Open IAM → Roles → select the role", "Review the trust policy and attached policies", "Confirm with the owning team whether the role is still needed", 'If not needed, click "Delete" at the top of the role page'],
    cli: `# Check last activity
aws iam get-role --role-name <role-name> --query 'Role.RoleLastUsed'

# Delete if confirmed unused
aws iam delete-role --role-name <role-name>`,
    risk: "Unused roles should be removed after ownership and service dependencies are confirmed.",
  },
  "iam.role.wildcard_action": {
    why: 'Action: "*" in an inline policy is admin-like unless constrained by resource, condition, or permissions boundary. It should be reviewed and scoped to the actions the role actually needs.',
    console: ["Open IAM → Roles → select the role", 'Click "Permissions" tab → find the inline policy', 'Click "Edit" on the inline policy', 'Replace `"Action": "*"` with the specific actions the role actually needs', "Use IAM Access Analyzer to generate a minimal policy from CloudTrail history"],
    cli: `# Review the inline policy
aws iam get-role-policy --role-name <role-name> --policy-name <policy-name>

# Replace with scoped policy
aws iam put-role-policy --role-name <role-name> --policy-name <policy-name> --policy-document file://scoped-policy.json`,
    risk: "Broad wildcard permissions increase blast radius if the role is compromised or misused.",
  },
  "iam.role.unused_services_90d": {
    why: "This role has permissions to services it has not recently used according to IAM service-last-accessed data. Those permissions may be removable, but should be validated against workload behavior and data freshness.",
    console: ["Open IAM → Roles → select the role", 'Click "Permissions" tab → find inline policies under "Permissions policies"', "Review each inline policy and remove statements for the unused services listed below", "Save the updated policy (or delete it entirely if all its services are unused)"],
    cli: `# List inline policies on the role
aws iam list-role-policies --role-name <role-name>

# Get a specific inline policy
aws iam get-role-policy --role-name <role-name> --policy-name <policy-name>

# Replace with scoped version (unused service statements removed)
aws iam put-role-policy --role-name <role-name> --policy-name <policy-name> --policy-document file://scoped-policy.json

# Or delete entirely if all permissions are unused
aws iam delete-role-policy --role-name <role-name> --policy-name <policy-name>`,
    risk: "Unused service permissions increase blast radius. Removing them improves least privilege after validation.",
  },
  "iam.role.trust_wildcard": {
    why: 'This role trust policy allows any AWS principal. That is high risk unless strong conditions narrow who can assume the role.',
    console: ["Open IAM → Roles → select the role", 'Click "Trust relationships"', "Review the principal and any conditions", "Replace wildcard principals with specific AWS accounts, roles, services, or federated identities"],
    cli: `# Review the role trust policy
aws iam get-role --role-name <role-name> --query 'Role.AssumeRolePolicyDocument'

# Update the trust policy after scoping Principal and Conditions
aws iam update-assume-role-policy --role-name <role-name> --policy-document file://trust-policy.json`,
    risk: "Wildcard trust can expose a role to unintended principals, especially when conditions are missing or weak.",
  },

  "iam.root.has_access_keys": {
    why: "Root account access keys bypass all IAM policies and have unrestricted access to every service and resource. There is no legitimate use case for programmatic root credentials.",
    console: ["Sign in as root", "Open IAM → Security credentials (via account menu top-right)", 'Under "Access keys", delete all active keys', "Create an IAM admin user for any automation that previously used root credentials"],
    cli: `# List root access keys (requires root credentials or AWS Support)
aws iam list-access-keys

# Delete each active root key
aws iam delete-access-key --access-key-id <key-id>`,
    risk: "Root access keys cannot be scoped with policies. Anyone with these credentials has full, unrevokable control of the account.",
  },

  "iam.root.no_mfa": {
    why: "The root account has no IAM policy restrictions. If its password is compromised without MFA, an attacker has unrestricted access to the entire account.",
    console: ["Sign in as root", "Open IAM → Security credentials (via account menu top-right)", 'Under "Multi-factor authentication", click "Assign MFA device"', "Register a hardware MFA device — virtual MFA is acceptable but hardware is preferred for root"],
    cli: `# MFA for root must be configured via the console — the AWS CLI cannot enable root MFA directly.
# Sign in as root and use the Security credentials page.`,
    risk: "Root without MFA is the highest-severity finding possible. Prioritise this above everything else.",
  },

  "s3.bucket.public_access_not_blocked": {
    why: "S3 Block Public Access is an account and bucket-level guard against accidentally making objects public via ACLs or bucket policies. One or more of the four settings is currently off.",
    console: ["Open S3 → select the bucket", 'Click "Permissions" tab', 'Under "Block public access", click "Edit"', "Enable all four settings and save"],
    cli: `# Enable all four Block Public Access settings
aws s3api put-public-access-block \\
  --bucket <bucket-name> \\
  --public-access-block-configuration '{
    "BlockPublicAcls": true,
    "IgnorePublicAcls": true,
    "BlockPublicPolicy": true,
    "RestrictPublicBuckets": true
  }'`,
    risk: "Without this, a misconfigured ACL or bucket policy can silently expose objects to the internet.",
  },

  "s3.bucket.no_https_policy": {
    why: "Without a deny-HTTP bucket policy, clients can request objects over unencrypted HTTP. Data in transit is exposed to interception.",
    console: ["Open S3 → select the bucket", 'Click "Permissions" tab → "Bucket policy"', "Add or update the policy to include a Deny statement with the condition below", "Save the policy"],
    cli: `# Apply an HTTPS-only bucket policy
aws s3api put-bucket-policy --bucket <bucket-name> --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyHTTP",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": [
      "arn:aws:s3:::<bucket-name>",
      "arn:aws:s3:::<bucket-name>/*"
    ],
    "Condition": {
      "Bool": { "aws:SecureTransport": "false" }
    }
  }]
}'`,
    risk: "HTTP requests transmit credentials and data in plaintext. Even internal traffic should be encrypted in transit.",
  },

  "s3.bucket.no_kms": {
    why: "Server-side encryption with KMS (SSE-KMS) uses a customer-managed key, giving you control over key rotation, access policies, and audit logs. SSE-S3 uses an AWS-managed key you cannot audit or revoke.",
    console: ["Open S3 → select the bucket", 'Click "Properties" tab', 'Under "Default encryption", click "Edit"', 'Select "SSE-KMS", choose an existing CMK or create a new one, and save'],
    cli: `# Enable SSE-KMS with an existing CMK
aws s3api put-bucket-encryption --bucket <bucket-name> \\
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "<kms-key-arn>"
      },
      "BucketKeyEnabled": true
    }]
  }'`,
    risk: "SSE-S3 protects data at rest but the key is fully managed by AWS — you cannot restrict, rotate, or audit it independently.",
  },

  "s3.bucket.no_logging": {
    why: "Server access logging records every request made to a bucket — who accessed what, when, and from where. Without it there is no audit trail for forensics or compliance.",
    console: [
      "Create a central logging bucket (e.g. my-access-logs-<account-id>) if one does not exist",
      "On the logging bucket, set ownership to 'Bucket owner preferred' under Object Ownership",
      "Open the source bucket → Properties tab",
      'Under "Server access logging", click Edit',
      "Enable logging and set the target bucket and a prefix (e.g. the source bucket name)",
    ],
    cli: `# 1. Create a dedicated logging bucket (skip if it already exists)
aws s3api create-bucket --bucket my-access-logs-<account-id> --region us-east-1

# 2. Set object ownership so the log delivery service can write
aws s3api put-bucket-ownership-controls \\
  --bucket my-access-logs-<account-id> \\
  --ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerPreferred}]'

# 3. Enable access logging on the source bucket
aws s3api put-bucket-logging \\
  --bucket <bucket-name> \\
  --bucket-logging-status '{
    "LoggingEnabled": {
      "TargetBucket": "my-access-logs-<account-id>",
      "TargetPrefix": "<bucket-name>/"
    }
  }'`,
    risk: "Without access logs you cannot detect data exfiltration, unauthorized access, or misconfigured permissions after the fact.",
  },

  "kms.key.no_rotation": {
    why: "Automatic key rotation replaces the backing key material annually. If the key material is ever exposed, rotation limits the window of exposure.",
    console: ["Open KMS → Customer managed keys", "Select the key", 'Click "Key rotation" tab', 'Enable "Automatically rotate this KMS key every year"'],
    cli: `# Enable annual automatic rotation
aws kms enable-key-rotation --key-id <key-id>

# Confirm rotation is enabled
aws kms get-key-rotation-status --key-id <key-id>`,
    risk: "Keys that never rotate accumulate exposure over time. AWS retains old backing keys so existing ciphertexts remain decryptable after rotation.",
  },
};

const fallbackRemediation: Remediation = {
  why: "Review this finding and take corrective action based on your security policy.",
  console: ["Open the AWS Console", "Navigate to IAM", "Locate the affected resource and review its configuration"],
  cli: "# Review with AWS CLI\naws iam get-user --user-name <user>",
  risk: "Unresolved findings increase your attack surface.",
};

type RemovableStatement = { policy: string; sid: string; actions: string[]; resources: string[] };

function ServicePills({ services }: { services: string[] }) {
  return <div className="flex flex-wrap gap-1.5">{services.map((s) => <span key={s} className="inline-flex items-center rounded border border-amber-200 bg-amber-50 px-2 py-0.5 font-mono text-xs font-medium text-amber-700">{s}</span>)}</div>;
}

function RemovableStatementsBlock({ statements }: { statements: RemovableStatement[] }) {
  if (!statements.length) return null;
  return <div><div className="mb-2 text-xs font-semibold uppercase tracking-wide text-zinc-500">Removable statements<span className="ml-1.5 font-normal normal-case tracking-normal text-zinc-400">from inline policies</span></div><div className="space-y-2">{statements.map((stmt, i) => <div key={i} className="overflow-hidden rounded-lg border border-zinc-200 text-xs"><div className="flex items-center gap-2 border-b border-zinc-200 bg-zinc-50 px-3 py-2"><span className="font-mono font-medium text-zinc-800">{stmt.policy}</span>{stmt.sid && <span className="text-zinc-400">· {stmt.sid}</span>}</div><div className="space-y-2 px-3 py-2.5"><div className="flex flex-wrap gap-1">{stmt.actions.map((a) => <span key={a} className="rounded border border-red-200 bg-red-50 px-1.5 py-0.5 font-mono text-red-700">{a}</span>)}</div><div className="font-mono text-xs text-zinc-400">on: {stmt.resources.join(", ")}</div></div></div>)}</div></div>;
}

function EvidenceSection({ evidence, checkId }: { evidence: Record<string, unknown>; checkId: string }) {
  const skip = new Set(["removable_statements", "unused_services", "role_arn"]);
  const scalar = Object.entries(evidence).filter(([k]) => !skip.has(k));
  const unusedServices = evidence.unused_services as string[] | undefined;
  const removable = evidence.removable_statements as RemovableStatement[] | undefined;
  return <div className="space-y-4">{unusedServices && unusedServices.length > 0 && <div><div className="mb-2 text-xs font-semibold uppercase tracking-wide text-zinc-500">Unused services<span className="ml-1.5 font-normal normal-case tracking-normal text-zinc-400">{unusedServices.length} of {(evidence.total_granted_services as number) ?? "?"} granted</span></div><ServicePills services={unusedServices} /></div>}{scalar.length > 0 && <div className="overflow-hidden rounded-lg border border-zinc-200">{scalar.map(([k, v], i) => <div key={k} className={`flex gap-4 px-4 py-2.5 text-sm ${i % 2 === 0 ? "bg-white" : "bg-zinc-50"}`}><span className="w-32 flex-shrink-0 text-zinc-500">{k.replace(/_/g, " ")}</span><span className="break-all font-mono text-zinc-800">{String(v)}</span></div>)}</div>}{removable && <RemovableStatementsBlock statements={removable} />}</div>;
}

function resolvedCli(finding: Finding): string {
  const arn = finding.resource_arn;
  const roleMatch = arn.match(/:role\/(.+)$/);
  const roleName = roleMatch ? (roleMatch[1].split("/").pop() ?? "") : "";
  const userMatch = arn.match(/:user\/(.+)$/);
  const userName = userMatch ? (userMatch[1].split("/").pop() ?? "") : "";
  const keyId = (finding.evidence.key_id as string | undefined) ?? "<key-id>";
  const removable = finding.evidence.removable_statements as RemovableStatement[] | undefined;
  const hasInline = removable && removable.length > 0;
  if (finding.check_id === "iam.role.unused_services_90d" && !hasInline && roleName) return `# Permissions come from managed/attached policies — inline policies have no matching statements.

# 1. See what's attached
aws iam list-attached-role-policies --role-name ${roleName}

# 2. For each attached policy, review its document
aws iam get-policy-version --policy-arn <policy-arn> --version-id v1

# 3. Use Access Analyzer to generate a least-privilege replacement policy from CloudTrail
aws accessanalyzer start-policy-generation \\
  --policy-generation-details '{"principalArn":"${arn}"}'

# 4. Poll for the generated policy (takes ~30s)
aws accessanalyzer get-generated-policy --job-id <job-id>`;
  const rem = remediations[finding.check_id] ?? fallbackRemediation;
  const policyNames = removable ? [...new Set(removable.map((s) => s.policy))] : [];
  const policyName = policyNames.length === 1 ? policyNames[0] : "<policy-name>";
  const bucketName = (finding.evidence.bucket_name as string | undefined) ?? "<bucket-name>";
  const kmsKeyId = (finding.evidence.key_id as string | undefined) ?? "<key-id>";
  return rem.cli
    .replace(/<role-name>/g, roleName || "<role-name>")
    .replace(/<user>/g, userName || "<user>")
    .replace(/<key-id>/g, kmsKeyId)
    .replace(/<policy-name>/g, policyName)
    .replace(/<bucket-name>/g, bucketName);
}

type Tab = "console" | "cli";
type GeneratedPolicy = { has_inline_policies: boolean; unused_services: string[]; used_services: string[]; statements_removed?: number; original_policies?: Record<string, unknown>; cleaned_policies?: Record<string, unknown>; note?: string };

function GeneratePolicySection({ accountId, finding }: { accountId: string; finding: Finding }) {
  const [enabled, setEnabled] = useState(false);
  const [view, setView] = useState<"cleaned" | "original">("cleaned");
  const { data, isLoading, error } = useQuery<GeneratedPolicy>({ queryKey: ["generated-policy", accountId, finding.resource_arn], queryFn: () => api(`/v1/accounts/${accountId}/roles/generated-policy?role_arn=${encodeURIComponent(finding.resource_arn)}`), enabled, staleTime: Infinity });
  return <div><div className="mb-3 flex items-center justify-between"><div className="text-xs font-semibold uppercase tracking-wide text-zinc-500">Suggested Policy</div>{!enabled && <button onClick={() => setEnabled(true)} className="rounded border border-zinc-300 bg-white px-3 py-1 text-xs font-medium text-zinc-700 transition-colors hover:bg-zinc-50 hover:text-zinc-900">Generate</button>}</div>{!enabled && <p className="text-xs leading-relaxed text-zinc-400">Vigil will strip unused service statements from inline policies and show you the cleaned version, ready to apply.</p>}{enabled && isLoading && <div className="py-3 text-xs text-zinc-400">Generating...</div>}{enabled && error && <div className="py-2 text-xs text-red-500">{String(error)}</div>}{enabled && data && !data.has_inline_policies && <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-xs leading-relaxed text-amber-800">{data.note ?? "No inline policies found. Permissions come from attached managed policies."}</div>}{enabled && data && data.has_inline_policies && data.cleaned_policies && <div className="space-y-3"><div className="flex items-center justify-between"><span className="text-xs text-zinc-500">{data.statements_removed} statement{data.statements_removed !== 1 ? "s" : ""} removed</span><div className="flex gap-1 rounded-lg bg-zinc-100 p-0.5">{(["cleaned", "original"] as const).map((v) => <button key={v} onClick={() => setView(v)} className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${view === v ? "bg-white text-zinc-900 shadow-sm" : "text-zinc-500 hover:text-zinc-700"}`}>{v === "cleaned" ? "Cleaned" : "Original"}</button>)}</div></div><CliBlock code={JSON.stringify(view === "cleaned" ? data.cleaned_policies : data.original_policies, null, 2)} /></div>}</div>;
}

function CliBlock({ code }: { code: string }) {
  const [copied, setCopied] = useState(false);
  function copy() {
    const executable = code
      .split("\n")
      .filter((l) => !l.trimStart().startsWith("#"))
      .join("\n")
      .replace(/\n{3,}/g, "\n\n")
      .trim();
    navigator.clipboard.writeText(executable).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    });
  }
  return (
    <div className="rounded-lg border border-zinc-200 bg-zinc-50 overflow-hidden">
      <div className="flex justify-end border-b border-zinc-200 bg-white px-3 py-1.5">
        <button
          onClick={copy}
          className={`rounded-md border px-2.5 py-1 text-[11px] font-medium transition-all ${
            copied
              ? "border-emerald-200 bg-emerald-50 text-emerald-700"
              : "border-zinc-200 bg-zinc-50 text-zinc-500 hover:border-zinc-300 hover:bg-white hover:text-zinc-800"
          }`}
        >
          {copied ? "✓ Copied" : "Copy"}
        </button>
      </div>
      <pre className="overflow-x-auto whitespace-pre-wrap px-4 py-3 font-mono text-xs leading-relaxed text-zinc-800">{code}</pre>
    </div>
  );
}

export function FindingDrawer({ finding, accountId, onClose, onAction, resolved, verifying }: { finding: Finding | null; accountId: string | null; onClose: () => void; onAction: (id: string, action: "recheck" | "resolve" | "ignore") => void; resolved?: boolean; verifying?: boolean }) {
  const [tab, setTab] = useState<Tab>("console");
  const [countdown, setCountdown] = useState(5);

  useEffect(() => {
    if (!resolved) { setCountdown(5); return; }
    setCountdown(5);
    const tick = setInterval(() => setCountdown((c) => c - 1), 1000);
    const close = setTimeout(onClose, 5000);
    return () => { clearInterval(tick); clearTimeout(close); };
  }, [resolved]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!finding) return null;
  const rem = remediations[finding.check_id] ?? fallbackRemediation;
  const headerBadge = sevHeaderBadge[finding.severity] ?? sevHeaderBadge.low;
  const wash = sevWash[finding.severity] ?? sevWash.low;
  const step = sevStep[finding.severity] ?? sevStep.low;
  const hasEvidence = Object.keys(finding.evidence).length > 0;
  const categoryLabel: Record<string, string> = {
    "iam.root": "Root Account",
    "iam.user": "IAM User",
    "iam.access_key": "Access Key",
    "iam.role": "IAM Role",
    "s3.bucket": "S3 Bucket",
    "kms.key": "KMS Key",
  };
  const category = Object.entries(categoryLabel).find(([prefix]) => finding.check_id.startsWith(prefix))?.[1] ?? "Finding";
  const showPolicyGen = finding.check_id === "iam.role.unused_services_90d" && !!accountId;

  return <><div className="fixed inset-0 z-40 bg-black/25 backdrop-blur-[2px]" onClick={onClose} /><div className="fixed right-0 top-0 z-50 flex h-full w-full max-w-[560px] flex-col overflow-hidden bg-white shadow-2xl">
    <div className={`relative bg-gradient-to-b ${wash} px-7 pb-2 pt-5`}>
      <button onClick={onClose} className="absolute right-5 top-5 rounded-md p-1 text-zinc-300 transition hover:bg-white/70 hover:text-zinc-600"><svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg></button>
      <div className="flex items-center gap-2.5 pr-10"><span className="text-xs font-semibold text-zinc-500">{category}</span><span className="text-zinc-300">·</span><span className={`inline-flex items-center rounded border px-2 py-0.5 text-[11px] font-bold uppercase tracking-wide ${headerBadge}`}>{finding.severity}</span></div>
      <h2 className="mt-2 pr-8 text-lg font-semibold leading-snug tracking-tight text-zinc-950">{finding.title}</h2>
      <div className="mt-3 border-t border-zinc-200/70 pt-3"><div className="text-[10px] font-bold uppercase tracking-[0.18em] text-zinc-400 mb-0.5">Resource</div><p className="break-all font-mono text-[13px] leading-relaxed text-zinc-800">{finding.resource_arn}</p></div>
    </div>
    <div className="flex-1 space-y-6 overflow-y-auto bg-stone-50 px-7 pb-6 pt-2">
      <div className="grid grid-cols-2 gap-3"><div className="rounded-lg border border-zinc-200 bg-white p-4 shadow-sm shadow-zinc-950/[0.025]"><div className="mb-2 text-sm font-semibold text-zinc-800">Finding Context</div><p className="text-sm leading-6 text-zinc-600">{rem.why}</p></div><div className="rounded-lg border border-zinc-200 bg-white p-4 shadow-sm shadow-zinc-950/[0.025]"><div className="mb-2 text-sm font-semibold text-zinc-800">Risk</div><p className="text-sm leading-6 text-zinc-600">{rem.risk}</p></div></div>
      {hasEvidence && <div><div className="mb-3 flex items-center justify-between"><div className="text-xs font-bold uppercase tracking-[0.14em] text-zinc-500">Scan Details</div><span className="text-xs text-zinc-400">Raw values used to produce this finding</span></div><EvidenceSection evidence={finding.evidence} checkId={finding.check_id} /></div>}
      {showPolicyGen && <GeneratePolicySection accountId={accountId!} finding={finding} />}
      <div className="rounded-xl border border-zinc-200 bg-zinc-50 overflow-hidden">
        <div className="flex items-center justify-between border-b border-zinc-100 bg-zinc-50 px-4 py-3">
          <span className="text-xs font-bold uppercase tracking-[0.14em] text-zinc-500">Remediation</span>
          <div className="flex gap-0.5 rounded-full border border-zinc-200 bg-white p-0.5">{(["console", "cli"] as Tab[]).map((t) => <button key={t} onClick={() => setTab(t)} className={`rounded-full px-3.5 py-1 text-[13px] font-medium transition-all ${tab === t ? "bg-zinc-900 text-white shadow-sm" : "text-zinc-400 hover:text-zinc-600"}`}>{t === "cli" ? "AWS CLI" : "Console"}</button>)}</div>
        </div>
        <div className="bg-zinc-100/60 p-4">
          {tab === "console" && <ol className="space-y-2">{rem.console.map((item, i) => <li key={i} className="flex gap-3 text-sm leading-6 text-zinc-700"><span className={`mt-0.5 flex h-5 w-5 flex-shrink-0 items-center justify-center rounded-full text-[11px] font-bold ${step}`}>{i + 1}</span>{item}</li>)}</ol>}
          {tab === "cli" && <CliBlock code={resolvedCli(finding)} />}
        </div>
      </div>
      <div className="flex items-center gap-4 pb-2 text-sm text-zinc-500"><span>First seen {new Date(finding.first_seen).toLocaleDateString()}</span><span className="text-zinc-300">·</span><span>Last seen {new Date(finding.last_seen).toLocaleDateString()}</span><span className="text-zinc-300">·</span><span>Score <span className="font-semibold text-zinc-700">{finding.risk_score}</span></span></div>
    </div>
    <div className="flex gap-2 border-t border-stone-200 bg-stone-50 px-7 py-4">
      <button onClick={() => { onAction(finding.id, "resolve"); onClose(); }} className="flex-1 rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-zinc-700">Resolve</button>
      <button disabled={verifying} onClick={() => onAction(finding.id, "recheck")} className="flex-1 inline-flex items-center justify-center gap-2 rounded-lg border border-zinc-300 bg-white px-4 py-2.5 text-sm font-semibold text-zinc-700 transition hover:bg-zinc-100 disabled:opacity-50">{verifying && <svg className="h-3.5 w-3.5 animate-spin" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>}{verifying ? "Verifying…" : "Verify"}</button>
      <button onClick={() => { onAction(finding.id, "ignore"); onClose(); }} className="rounded-lg border border-zinc-300 bg-white px-4 py-2.5 text-sm font-semibold text-zinc-500 transition hover:bg-zinc-100 hover:text-zinc-700">Ignore</button>
    </div>
    {resolved && (
      <div className="fixed right-0 top-0 z-[60] flex h-full w-full max-w-[560px] flex-col items-center justify-center bg-white/85 backdrop-blur-md">
        <div className="relative flex items-center justify-center">
          <div className="absolute h-36 w-36 animate-ping rounded-full bg-emerald-400 opacity-10" style={{ animationDuration: "1.4s" }} />
          <div className="relative flex h-32 w-32 items-center justify-center rounded-full bg-emerald-500" style={{ boxShadow: "0 0 0 12px rgba(16,185,129,0.12), 0 0 60px rgba(16,185,129,0.45)" }}>
            <svg className="h-16 w-16 text-white" fill="none" stroke="currentColor" strokeWidth={2.5} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
            </svg>
          </div>
        </div>
        <p className="mt-8 text-2xl font-bold tracking-tight text-zinc-900">Issue resolved</p>
        <p className="mt-2 text-sm text-zinc-500">Closing in {countdown}s</p>
        <button
          onClick={onClose}
          className="mt-5 rounded-full border border-zinc-200 bg-white px-5 py-2 text-sm font-medium text-zinc-600 shadow-sm transition hover:bg-zinc-50 hover:text-zinc-900"
        >
          Close now
        </button>
      </div>
    )}
  </div></>;
}
