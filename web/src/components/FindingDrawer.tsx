import { useState } from "react";
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
  critical: "from-red-50 via-white to-white",
  high: "from-red-50 via-white to-white",
  medium: "from-amber-50 via-white to-white",
  low: "from-slate-50 via-white to-white",
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
  return <div className="space-y-4">{unusedServices && unusedServices.length > 0 && <div><div className="mb-2 text-xs font-semibold uppercase tracking-wide text-zinc-500">Unused services<span className="ml-1.5 font-normal normal-case tracking-normal text-zinc-400">{unusedServices.length} of {(evidence.total_granted_services as number) ?? "?"} granted</span></div><ServicePills services={unusedServices} /></div>}{scalar.length > 0 && <div className="overflow-hidden rounded-lg border border-zinc-200">{scalar.map(([k, v], i) => <div key={k} className={`flex gap-4 px-4 py-2.5 text-sm ${i % 2 === 0 ? "bg-white" : "bg-zinc-50"}`}><span className="w-32 flex-shrink-0 text-zinc-400">{k.replace(/_/g, " ")}</span><span className="break-all font-mono text-zinc-800">{String(v)}</span></div>)}</div>}{removable && <RemovableStatementsBlock statements={removable} />}</div>;
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
  return rem.cli.replace(/<role-name>/g, roleName || "<role-name>").replace(/<user>/g, userName || "<user>").replace(/<key-id>/g, keyId).replace(/<policy-name>/g, policyName);
}

type Tab = "console" | "cli";
type GeneratedPolicy = { has_inline_policies: boolean; unused_services: string[]; used_services: string[]; statements_removed?: number; original_policies?: Record<string, unknown>; cleaned_policies?: Record<string, unknown>; note?: string };

function GeneratePolicySection({ accountId, finding }: { accountId: string; finding: Finding }) {
  const [enabled, setEnabled] = useState(false);
  const [view, setView] = useState<"cleaned" | "original">("cleaned");
  const { data, isLoading, error } = useQuery<GeneratedPolicy>({ queryKey: ["generated-policy", accountId, finding.resource_arn], queryFn: () => api(`/v1/accounts/${accountId}/roles/generated-policy?role_arn=${encodeURIComponent(finding.resource_arn)}`), enabled, staleTime: Infinity });
  return <div><div className="mb-3 flex items-center justify-between"><div className="text-xs font-semibold uppercase tracking-wide text-zinc-500">Suggested Policy</div>{!enabled && <button onClick={() => setEnabled(true)} className="rounded border border-zinc-300 bg-white px-3 py-1 text-xs font-medium text-zinc-700 transition-colors hover:bg-zinc-50 hover:text-zinc-900">Generate</button>}</div>{!enabled && <p className="text-xs leading-relaxed text-zinc-400">Vigil will strip unused service statements from inline policies and show you the cleaned version, ready to apply.</p>}{enabled && isLoading && <div className="py-3 text-xs text-zinc-400">Generating...</div>}{enabled && error && <div className="py-2 text-xs text-red-500">{String(error)}</div>}{enabled && data && !data.has_inline_policies && <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-xs leading-relaxed text-amber-800">{data.note ?? "No inline policies found. Permissions come from attached managed policies."}</div>}{enabled && data && data.has_inline_policies && data.cleaned_policies && <div className="space-y-3"><div className="flex items-center justify-between"><span className="text-xs text-zinc-500">{data.statements_removed} statement{data.statements_removed !== 1 ? "s" : ""} removed</span><div className="flex gap-1 rounded-lg bg-zinc-100 p-0.5">{(["cleaned", "original"] as const).map((v) => <button key={v} onClick={() => setView(v)} className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${view === v ? "bg-white text-zinc-900 shadow-sm" : "text-zinc-500 hover:text-zinc-700"}`}>{v === "cleaned" ? "Cleaned" : "Original"}</button>)}</div></div><pre className="max-h-72 overflow-y-auto overflow-x-auto whitespace-pre-wrap rounded-lg bg-zinc-950 px-4 py-4 font-mono text-xs leading-relaxed text-zinc-200">{JSON.stringify(view === "cleaned" ? data.cleaned_policies : data.original_policies, null, 2)}</pre></div>}</div>;
}

export function FindingDrawer({ finding, accountId, onClose, onAction }: { finding: Finding | null; accountId: string | null; onClose: () => void; onAction: (id: string, action: "snooze" | "resolve" | "ignore") => void }) {
  const [tab, setTab] = useState<Tab>("console");
  if (!finding) return null;
  const rem = remediations[finding.check_id] ?? fallbackRemediation;
  const headerBadge = sevHeaderBadge[finding.severity] ?? sevHeaderBadge.low;
  const wash = sevWash[finding.severity] ?? sevWash.low;
  const step = sevStep[finding.severity] ?? sevStep.low;
  const hasEvidence = Object.keys(finding.evidence).length > 0;
  const showPolicyGen = finding.check_id === "iam.role.unused_services_90d" && !!accountId;

  return <><div className="fixed inset-0 z-40 bg-black/25 backdrop-blur-[2px]" onClick={onClose} /><div className="fixed right-0 top-0 z-50 flex h-full w-full max-w-[560px] flex-col overflow-hidden bg-white shadow-2xl">
    <div className={`relative bg-gradient-to-b ${wash} px-7 pb-6 pt-5`}>
      <button onClick={onClose} className="absolute right-5 top-5 rounded-md p-1 text-zinc-300 transition hover:bg-white/70 hover:text-zinc-600"><svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg></button>
      <div className="flex items-center gap-2 pr-10"><span className={`inline-flex items-center rounded border px-2 py-0.5 text-[11px] font-bold uppercase tracking-wide ${headerBadge}`}>{finding.severity}</span><span className="font-mono text-xs text-zinc-500">{finding.check_id}</span></div>
      <h2 className="mt-2 pr-8 text-lg font-semibold leading-snug tracking-tight text-zinc-950">{finding.title}</h2>
      <div className="mt-4 border-t border-zinc-200/70 pt-4"><div className="mb-1 text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-400">Affected Resource</div><p className="break-all font-mono text-xs leading-relaxed text-zinc-700">{finding.resource_arn}</p></div>
    </div>
    <div className="flex-1 space-y-6 overflow-y-auto px-7 py-6">
      <div className="grid grid-cols-2 gap-3"><div className="rounded-lg border border-zinc-200 bg-white p-4 shadow-sm shadow-zinc-950/[0.025]"><div className="mb-2 text-xs font-bold uppercase tracking-[0.16em] text-zinc-400">Finding Context</div><p className="text-sm leading-6 text-zinc-700">{rem.why}</p></div><div className="rounded-lg border border-zinc-200 bg-white p-4 shadow-sm shadow-zinc-950/[0.025]"><div className="mb-2 text-xs font-bold uppercase tracking-[0.16em] text-zinc-400">Risk</div><p className="text-sm leading-6 text-zinc-600">{rem.risk}</p></div></div>
      {hasEvidence && <div><div className="mb-3 flex items-center justify-between"><div className="text-xs font-bold uppercase tracking-[0.14em] text-zinc-500">Scan Details</div><span className="text-xs text-zinc-400">Raw values used to produce this finding</span></div><EvidenceSection evidence={finding.evidence} checkId={finding.check_id} /></div>}
      {showPolicyGen && <GeneratePolicySection accountId={accountId!} finding={finding} />}
      <div><div className="mb-3 flex items-center justify-between"><div className="text-xs font-bold uppercase tracking-[0.14em] text-zinc-500">Remediation</div><span className="text-xs text-zinc-400">Choose console steps or AWS CLI</span></div><div className="mb-4 flex w-fit gap-1 rounded-lg bg-zinc-100 p-1">{(["console", "cli"] as Tab[]).map((t) => <button key={t} onClick={() => setTab(t)} className={`rounded-md px-3 py-1.5 text-xs font-semibold uppercase tracking-wide transition-colors ${tab === t ? "bg-white text-zinc-900 shadow-sm" : "text-zinc-500 hover:text-zinc-700"}`}>{t === "cli" ? "AWS CLI" : "Console"}</button>)}</div>{tab === "console" && <ol className="space-y-2 rounded-lg border border-zinc-200 bg-white p-4 shadow-sm shadow-zinc-950/[0.025]">{rem.console.map((item, i) => <li key={i} className="flex gap-3 text-sm leading-6 text-zinc-700"><span className={`mt-0.5 flex h-5 w-5 flex-shrink-0 items-center justify-center rounded-full text-[11px] font-bold ${step}`}>{i + 1}</span>{item}</li>)}</ol>}{tab === "cli" && <pre className="overflow-x-auto whitespace-pre-wrap rounded-lg bg-zinc-950 px-4 py-4 font-mono text-xs leading-relaxed text-zinc-200">{resolvedCli(finding)}</pre>}</div>
      <div className="flex items-center gap-4 pb-2 text-xs text-zinc-400"><span>First seen {new Date(finding.first_seen).toLocaleDateString()}</span><span>·</span><span>Last seen {new Date(finding.last_seen).toLocaleDateString()}</span><span>·</span><span>Score <span className="font-semibold text-zinc-600">{finding.risk_score}</span></span></div>
    </div>
    <div className="flex gap-2 border-t border-zinc-100 bg-white px-7 py-4"><button onClick={() => { onAction(finding.id, "resolve"); onClose(); }} className="flex-1 rounded-lg bg-stone-800 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-stone-900">Resolve</button><button onClick={() => { onAction(finding.id, "snooze"); onClose(); }} className="flex-1 rounded-lg border border-zinc-300 bg-white px-4 py-2.5 text-sm font-semibold text-zinc-700 transition hover:border-zinc-400 hover:bg-zinc-50">Snooze</button><button onClick={() => { onAction(finding.id, "ignore"); onClose(); }} className="rounded-lg border border-zinc-300 bg-white px-4 py-2.5 text-sm font-semibold text-zinc-700 transition hover:border-zinc-400 hover:bg-zinc-50">Ignore</button></div>
  </div></>;
}
