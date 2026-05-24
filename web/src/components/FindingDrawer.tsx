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
  critical: "bg-red-600 text-white",
  high: "bg-red-500 text-white",
  medium: "bg-amber-500 text-white",
  low: "bg-slate-500 text-white",
};

const severityTheme: Record<string, {
  shell: string;
  badgeGlow: string;
  divider: string;
  eyebrow: string;
  number: string;
  primary: string;
  primaryHover: string;
}> = {
  critical: {
    shell: "linear-gradient(135deg, #4c0519 0%, #881337 42%, #19070d 100%)",
    badgeGlow: "0 0 28px rgba(248,113,113,.45)",
    divider: "border-red-200/20",
    eyebrow: "text-red-100/60",
    number: "bg-red-950 text-white shadow-[0_0_14px_rgba(248,113,113,.35)]",
    primary: "bg-red-950",
    primaryHover: "hover:bg-red-900 hover:shadow-[0_0_22px_rgba(248,113,113,.35)]",
  },
  high: {
    shell: "linear-gradient(135deg, #5f0710 0%, #7f1d1d 46%, #21070b 100%)",
    badgeGlow: "0 0 26px rgba(248,113,113,.42)",
    divider: "border-red-200/20",
    eyebrow: "text-red-100/60",
    number: "bg-red-950 text-white shadow-[0_0_14px_rgba(248,113,113,.32)]",
    primary: "bg-red-950",
    primaryHover: "hover:bg-red-900 hover:shadow-[0_0_22px_rgba(248,113,113,.32)]",
  },
  medium: {
    shell: "linear-gradient(135deg, #451a03 0%, #92400e 46%, #1c1003 100%)",
    badgeGlow: "0 0 24px rgba(251,191,36,.36)",
    divider: "border-amber-100/20",
    eyebrow: "text-amber-100/65",
    number: "bg-amber-900 text-white shadow-[0_0_14px_rgba(251,191,36,.28)]",
    primary: "bg-amber-900",
    primaryHover: "hover:bg-amber-800 hover:shadow-[0_0_22px_rgba(251,191,36,.28)]",
  },
  low: {
    shell: "linear-gradient(135deg, #0f172a 0%, #334155 48%, #020617 100%)",
    badgeGlow: "0 0 20px rgba(148,163,184,.22)",
    divider: "border-slate-100/15",
    eyebrow: "text-slate-100/55",
    number: "bg-slate-800 text-white shadow-[0_0_12px_rgba(148,163,184,.18)]",
    primary: "bg-slate-900",
    primaryHover: "hover:bg-slate-800 hover:shadow-[0_0_18px_rgba(148,163,184,.18)]",
  },
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
    console: [
      "Open IAM → Users → select the user",
      'Click "Security credentials" tab',
      'Under "Multi-factor authentication", click "Assign MFA device"',
      "Follow the wizard to register a virtual or hardware MFA",
    ],
    cli: `aws iam create-virtual-mfa-device --virtual-mfa-device-name <name> --outfile /tmp/qr.png --bootstrap-method QRCodePNG
aws iam enable-mfa-device --user-name <user> --serial-number <arn> --authentication-code1 <code1> --authentication-code2 <code2>`,
    risk: "Until MFA is enabled, a leaked password can be enough to sign in to the console.",
  },
  "iam.user.inactive_90d": {
    why: "Inactive accounts have no baseline of normal activity, making compromise invisible. Attackers who obtain credentials can operate undetected for months.",
    console: [
      "Open IAM → Users → select the user",
      'Click "Security credentials" tab',
      'Under "Console sign-in", click "Disable console access"',
      "Confirm with the team, then delete the user if no longer needed",
    ],
    cli: `# Disable console access
aws iam delete-login-profile --user-name <user>

# Or delete the user entirely (remove keys + policies first)
aws iam delete-user --user-name <user>`,
    risk: "Stale console users should be disabled or removed after ownership is confirmed.",
  },
  "iam.access_key.unused_90d": {
    why: "Unused access keys are typically abandoned in scripts, CI config, or developer machines — often forgotten and never rotated. They're persistent credentials with no expiry.",
    console: [
      "Open IAM → Users → select the user",
      'Click "Security credentials" tab',
      "Find the key under Access Keys",
      'Click "Deactivate" first to verify nothing breaks, then "Delete"',
    ],
    cli: `# Deactivate first, confirm nothing breaks, then delete
aws iam update-access-key --access-key-id <key-id> --status Inactive --user-name <user>
aws iam delete-access-key --access-key-id <key-id> --user-name <user>`,
    risk: "Forgotten keys are long-lived credentials. Deactivate first, then delete after confirming nothing still depends on them.",
  },
  "iam.access_key.no_rotation_90d": {
    why: "This access key is older than the configured key-age threshold. Long-lived keys are harder to reason about because they may be stored in old scripts, CI secrets, or developer machines.",
    console: [
      "Open IAM → Users → select the user",
      'Click "Security credentials" tab',
      "Create a replacement access key for the current workload",
      "Update the workload secret, then deactivate and delete the old key",
    ],
    cli: `# Create a replacement key, update the workload, then retire the old one
aws iam create-access-key --user-name <user>
aws iam update-access-key --access-key-id <key-id> --status Inactive --user-name <user>
aws iam delete-access-key --access-key-id <key-id> --user-name <user>`,
    risk: "This is a key hygiene finding. Validate where the key is used before rotation or deletion.",
  },
  "iam.access_key.multiple_active": {
    why: "The user has more than one active access key. That can be valid during rotation, but persistent duplicate keys make ownership and cleanup harder.",
    console: [
      "Open IAM → Users → select the user",
      'Click "Security credentials" tab',
      "Review both active access keys, including creation and last-used dates",
      "Deactivate and delete the key that is no longer needed",
    ],
    cli: `# Review active keys for the user
aws iam list-access-keys --user-name <user>

# Deactivate the unused key first, then delete it
aws iam update-access-key --access-key-id <key-id> --status Inactive --user-name <user>
aws iam delete-access-key --access-key-id <key-id> --user-name <user>`,
    risk: "Treat this as a review item unless the extra key is clearly stale or unauthorized.",
  },
  "iam.role.unassumed_90d": {
    why: "Roles not assumed in 90+ days are often orphaned. They add attack surface and may carry policies that nobody actively owns.",
    console: [
      "Open IAM → Roles → select the role",
      "Review the trust policy and attached policies",
      "Confirm with the owning team whether the role is still needed",
      'If not needed, click "Delete" at the top of the role page',
    ],
    cli: `# Check last activity
aws iam get-role --role-name <role-name> --query 'Role.RoleLastUsed'

# Delete if confirmed unused
aws iam delete-role --role-name <role-name>`,
    risk: "Unused roles should be removed after ownership and service dependencies are confirmed.",
  },
  "iam.role.wildcard_action": {
    why: 'Action: "*" in an inline policy is admin-like unless constrained by resource, condition, or permissions boundary. It should be reviewed and scoped to the actions the role actually needs.',
    console: [
      "Open IAM → Roles → select the role",
      'Click "Permissions" tab → find the inline policy',
      'Click "Edit" on the inline policy',
      'Replace `"Action": "*"` with the specific actions the role actually needs',
      "Use IAM Access Analyzer to generate a minimal policy from CloudTrail history",
    ],
    cli: `# Review the inline policy
aws iam get-role-policy --role-name <role-name> --policy-name <policy-name>

# Replace with scoped policy
aws iam put-role-policy --role-name <role-name> --policy-name <policy-name> --policy-document file://scoped-policy.json`,
    risk: "Broad wildcard permissions increase blast radius if the role is compromised or misused.",
  },
  "iam.role.unused_services_90d": {
    why: "This role has permissions to services it has not recently used according to IAM service-last-accessed data. Those permissions may be removable, but should be validated against workload behavior and data freshness.",
    console: [
      "Open IAM → Roles → select the role",
      'Click "Permissions" tab → find inline policies under "Permissions policies"',
      "Review each inline policy and remove statements for the unused services listed below",
      "Save the updated policy (or delete it entirely if all its services are unused)",
    ],
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
    console: [
      "Open IAM → Roles → select the role",
      'Click "Trust relationships"',
      "Review the principal and any conditions",
      "Replace wildcard principals with specific AWS accounts, roles, services, or federated identities",
    ],
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

type RemovableStatement = {
  policy: string;
  sid: string;
  actions: string[];
  resources: string[];
};

function ServicePills({ services }: { services: string[] }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {services.map(s => (
        <span key={s} className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium bg-amber-50 text-amber-700 border border-amber-200">
          {s}
        </span>
      ))}
    </div>
  );
}

function RemovableStatementsBlock({ statements }: { statements: RemovableStatement[] }) {
  if (!statements.length) return null;
  return (
    <div>
      <div className="text-xs font-semibold text-zinc-500 uppercase tracking-wide mb-2">
        Removable statements
        <span className="ml-1.5 text-zinc-400 font-normal normal-case tracking-normal">from inline policies</span>
      </div>
      <div className="space-y-2">
        {statements.map((stmt, i) => (
          <div key={i} className="rounded-lg border border-zinc-200 overflow-hidden text-xs">
            <div className="px-3 py-2 bg-zinc-50 border-b border-zinc-200 flex items-center gap-2">
              <span className="font-mono font-medium text-zinc-800">{stmt.policy}</span>
              {stmt.sid && <span className="text-zinc-400">· {stmt.sid}</span>}
            </div>
            <div className="px-3 py-2.5 space-y-2">
              <div className="flex flex-wrap gap-1">
                {stmt.actions.map(a => (
                  <span key={a} className="font-mono bg-red-50 text-red-700 border border-red-200 rounded px-1.5 py-0.5">
                    {a}
                  </span>
                ))}
              </div>
              <div className="font-mono text-zinc-400 text-xs">
                on: {stmt.resources.join(", ")}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function EvidenceSection({ evidence, checkId }: { evidence: Record<string, unknown>; checkId: string }) {
  const skip = new Set(["removable_statements", "unused_services", "role_arn"]);

  const scalar = Object.entries(evidence).filter(([k]) => !skip.has(k));
  const unusedServices = evidence.unused_services as string[] | undefined;
  const removable = evidence.removable_statements as RemovableStatement[] | undefined;

  return (
    <div className="space-y-4">
      {unusedServices && unusedServices.length > 0 && (
        <div>
          <div className="text-xs font-semibold text-zinc-500 uppercase tracking-wide mb-2">
            Unused services
            <span className="ml-1.5 font-normal normal-case tracking-normal text-zinc-400">
              {unusedServices.length} of {(evidence.total_granted_services as number) ?? "?"} granted
            </span>
          </div>
          <ServicePills services={unusedServices} />
        </div>
      )}

      {scalar.length > 0 && (
        <div className="rounded-lg border border-zinc-200 overflow-hidden">
          {scalar.map(([k, v], i) => (
            <div key={k} className={`flex gap-4 px-4 py-2.5 text-xs ${i % 2 === 0 ? "bg-white" : "bg-zinc-50"}`}>
              <span className="text-zinc-400 w-32 flex-shrink-0">{k.replace(/_/g, " ")}</span>
              <span className="font-mono text-zinc-800 break-all">{String(v)}</span>
            </div>
          ))}
        </div>
      )}

      {removable && <RemovableStatementsBlock statements={removable} />}
    </div>
  );
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

  // For unused_services with no inline policy matches → managed policy path
  if (finding.check_id === "iam.role.unused_services_90d" && !hasInline && roleName) {
    return `# Permissions come from managed/attached policies — inline policies have no matching statements.

# 1. See what's attached
aws iam list-attached-role-policies --role-name ${roleName}

# 2. For each attached policy, review its document
aws iam get-policy-version --policy-arn <policy-arn> --version-id v1

# 3. Use Access Analyzer to generate a least-privilege replacement policy from CloudTrail
aws accessanalyzer start-policy-generation \\
  --policy-generation-details '{"principalArn":"${arn}"}'

# 4. Poll for the generated policy (takes ~30s)
aws accessanalyzer get-generated-policy --job-id <job-id>`;
  }

  const rem = remediations[finding.check_id] ?? fallbackRemediation;
  const policyNames = removable ? [...new Set(removable.map(s => s.policy))] : [];
  const policyName = policyNames.length === 1 ? policyNames[0] : "<policy-name>";

  return rem.cli
    .replace(/<role-name>/g, roleName || "<role-name>")
    .replace(/<user>/g, userName || "<user>")
    .replace(/<key-id>/g, keyId)
    .replace(/<policy-name>/g, policyName);
}

type Tab = "console" | "cli";

type GeneratedPolicy = {
  has_inline_policies: boolean;
  unused_services: string[];
  used_services: string[];
  statements_removed?: number;
  original_policies?: Record<string, unknown>;
  cleaned_policies?: Record<string, unknown>;
  note?: string;
};

function GeneratePolicySection({ accountId, finding }: { accountId: string; finding: Finding }) {
  const [enabled, setEnabled] = useState(false);
  const [view, setView] = useState<"cleaned" | "original">("cleaned");

  const { data, isLoading, error } = useQuery<GeneratedPolicy>({
    queryKey: ["generated-policy", accountId, finding.resource_arn],
    queryFn: () =>
      api(`/v1/accounts/${accountId}/roles/generated-policy?role_arn=${encodeURIComponent(finding.resource_arn)}`),
    enabled,
    staleTime: Infinity,
  });

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs font-semibold text-zinc-500 uppercase tracking-wide">Suggested Policy</div>
        {!enabled && (
          <button
            onClick={() => setEnabled(true)}
            className="text-xs font-medium text-zinc-700 hover:text-zinc-900 border border-zinc-300 bg-white hover:bg-zinc-50 px-3 py-1 rounded transition-colors"
          >
            Generate
          </button>
        )}
      </div>

      {!enabled && (
        <p className="text-xs text-zinc-400 leading-relaxed">
          Vigil will strip unused service statements from inline policies and show you the cleaned version, ready to apply.
        </p>
      )}

      {enabled && isLoading && (
        <div className="text-xs text-zinc-400 py-3">Generating...</div>
      )}

      {enabled && error && (
        <div className="text-xs text-red-500 py-2">{String(error)}</div>
      )}

      {enabled && data && !data.has_inline_policies && (
        <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-xs text-amber-800 leading-relaxed">
          {data.note ?? "No inline policies found. Permissions come from attached managed policies."}
        </div>
      )}

      {enabled && data && data.has_inline_policies && data.cleaned_policies && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs text-zinc-500">
              {data.statements_removed} statement{data.statements_removed !== 1 ? "s" : ""} removed
            </span>
            <div className="flex gap-1 bg-zinc-100 rounded-lg p-0.5">
              {(["cleaned", "original"] as const).map(v => (
                <button
                  key={v}
                  onClick={() => setView(v)}
                  className={`px-2.5 py-1 rounded-md text-xs font-medium transition-colors ${
                    view === v ? "bg-white text-zinc-900 shadow-sm" : "text-zinc-500 hover:text-zinc-700"
                  }`}
                >
                  {v === "cleaned" ? "Cleaned" : "Original"}
                </button>
              ))}
            </div>
          </div>
          <pre className="bg-zinc-950 text-zinc-200 rounded-lg px-4 py-4 text-xs font-mono overflow-x-auto whitespace-pre-wrap leading-relaxed max-h-72 overflow-y-auto">
            {JSON.stringify(view === "cleaned" ? data.cleaned_policies : data.original_policies, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

export function FindingDrawer({
  finding,
  accountId,
  onClose,
  onAction,
}: {
  finding: Finding | null;
  accountId: string | null;
  onClose: () => void;
  onAction: (id: string, action: "snooze" | "resolve" | "ignore") => void;
}) {
  const [tab, setTab] = useState<Tab>("console");

  if (!finding) return null;

  const rem = remediations[finding.check_id] ?? fallbackRemediation;
  const headerBadge = sevHeaderBadge[finding.severity] ?? sevHeaderBadge.low;
  const theme = severityTheme[finding.severity] ?? severityTheme.low;
  const hasEvidence = Object.keys(finding.evidence).length > 0;
  const showPolicyGen = finding.check_id === "iam.role.unused_services_90d" && !!accountId;

  return (
    <>
      <div className="fixed inset-0 bg-black/30 z-40 backdrop-blur-sm" onClick={onClose} />

      <div className="fixed right-0 top-0 h-full w-full max-w-[640px] bg-white z-50 shadow-2xl flex flex-col overflow-hidden">
        {/* Header */}
        <div className="px-8 pt-7 pb-7 relative overflow-hidden" style={{ background: theme.shell }}>
          <div className="pointer-events-none absolute -top-24 -right-24 h-72 w-72 rounded-full blur-3xl opacity-70" style={{ background: finding.severity === "medium" ? "rgba(251,191,36,.32)" : finding.severity === "low" ? "rgba(148,163,184,.18)" : "rgba(248,113,113,.38)" }} />
          <div className="pointer-events-none absolute left-0 top-0 h-1.5 w-full" style={{ background: finding.severity === "medium" ? "linear-gradient(90deg,#f59e0b,#fde68a)" : finding.severity === "low" ? "linear-gradient(90deg,#64748b,#cbd5e1)" : "linear-gradient(90deg,#ef4444,#fecaca)" }} />
          <div className="flex items-start justify-between gap-3">
            <div className="space-y-2.5 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className={`inline-flex items-center px-3 py-1 rounded-md text-xs font-bold uppercase tracking-wide ${headerBadge}`} style={{ boxShadow: theme.badgeGlow }}>
                  {finding.severity}
                </span>
                <span className="text-xs font-mono text-zinc-400">{finding.check_id}</span>
              </div>
              <h2 className="text-2xl font-semibold text-white leading-snug tracking-tight">{finding.title}</h2>
            </div>
            <button onClick={onClose} className="text-white/45 hover:text-white transition-colors flex-shrink-0 mt-0.5">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          {/* Affected resource */}
          <div className={`mt-5 pt-5 border-t ${theme.divider}`}>
            <div className={`text-sm font-semibold uppercase tracking-[0.24em] mb-2 ${theme.eyebrow}`}>Affected Resource</div>
            <p className="text-base font-mono text-white/90 break-all leading-relaxed">{finding.resource_arn}</p>
          </div>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-8 py-7 space-y-7">
          {/* Context + Risk side by side */}
          <div className="grid grid-cols-2 gap-3">
            <div className="rounded-xl border border-zinc-200 bg-white px-5 py-5 shadow-sm">
              <div className="text-sm font-semibold text-zinc-400 uppercase tracking-[0.18em] mb-3">Finding Context</div>
              <p className="text-base text-zinc-700 leading-8">{rem.why}</p>
            </div>
            <div className="rounded-xl border border-zinc-200 bg-zinc-50 px-5 py-5 shadow-sm">
              <div className="text-sm font-semibold text-zinc-400 uppercase tracking-[0.18em] mb-3">Risk</div>
              <p className="text-base text-zinc-600 leading-8">{rem.risk}</p>
            </div>
          </div>

          {/* Scan Details */}
          {hasEvidence && (
            <div>
              <div className="flex items-center justify-between mb-3">
                <div className="text-xs font-semibold text-zinc-500 uppercase tracking-wide">Scan Details</div>
                <span className="text-xs text-zinc-400">Raw values used to produce this finding</span>
              </div>
              <EvidenceSection evidence={finding.evidence} checkId={finding.check_id} />
            </div>
          )}

          {/* Suggested policy (unused_services only) */}
          {showPolicyGen && (
            <GeneratePolicySection accountId={accountId!} finding={finding} />
          )}

          {/* Remediation */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <div className="text-xs font-semibold text-zinc-500 uppercase tracking-wide">Remediation</div>
              <span className="text-xs text-zinc-400">Choose console steps or AWS CLI</span>
            </div>
            <div className="flex gap-1 mb-4 bg-zinc-100 rounded-lg p-1 w-fit">
              {(["console", "cli"] as Tab[]).map(t => (
                <button
                  key={t}
                  onClick={() => setTab(t)}
                  className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-colors uppercase tracking-wide ${
                    tab === t ? "bg-white text-zinc-900 shadow-sm" : "text-zinc-500 hover:text-zinc-700"
                  }`}
                >
                  {t === "cli" ? "AWS CLI" : "Console"}
                </button>
              ))}
            </div>

            {tab === "console" && (
              <ol className="space-y-3 rounded-xl border border-zinc-200 bg-white p-5 shadow-sm">
                {rem.console.map((step, i) => (
                  <li key={i} className="flex gap-4 text-base text-zinc-700 leading-7">
                    <span className={`w-7 h-7 rounded-full text-xs font-bold flex items-center justify-center flex-shrink-0 mt-0.5 ${theme.number}`}>
                      {i + 1}
                    </span>
                    {step}
                  </li>
                ))}
              </ol>
            )}

            {tab === "cli" && (
              <pre className="bg-zinc-950 text-zinc-200 rounded-lg px-4 py-4 text-xs font-mono overflow-x-auto whitespace-pre-wrap leading-relaxed">
                {resolvedCli(finding)}
              </pre>
            )}
          </div>

          {/* Meta */}
          <div className="flex items-center gap-4 text-xs text-zinc-400 pb-2">
            <span>First seen {new Date(finding.first_seen).toLocaleDateString()}</span>
            <span>·</span>
            <span>Last seen {new Date(finding.last_seen).toLocaleDateString()}</span>
            <span>·</span>
            <span>Score <span className="font-semibold text-zinc-600">{finding.risk_score}</span></span>
          </div>
        </div>

        {/* Footer */}
        <div className="px-8 py-5 border-t border-zinc-100 flex gap-2">
          <button
            onClick={() => { onAction(finding.id, "resolve"); onClose(); }}
            className={`flex-1 ${theme.primary} ${theme.primaryHover} text-white text-sm font-semibold py-3 rounded-lg transition-all`}
          >
            Resolve
          </button>
          <button
            onClick={() => { onAction(finding.id, "snooze"); onClose(); }}
            className="flex-1 border border-zinc-300 text-zinc-700 hover:bg-zinc-50 hover:border-zinc-500 hover:shadow-md text-sm font-semibold py-3 rounded-lg transition-all"
          >
            Snooze
          </button>
          <button
            onClick={() => { onAction(finding.id, "ignore"); onClose(); }}
            className="px-5 border border-zinc-300 bg-white text-zinc-700 hover:text-zinc-950 hover:border-zinc-500 hover:bg-zinc-50 hover:shadow-md text-sm font-semibold py-3 rounded-lg transition-all"
          >
            Ignore
          </button>
        </div>
      </div>
    </>
  );
}
