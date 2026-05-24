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

const sevBadge: Record<string, string> = {
  critical: "bg-red-50 text-red-700 border border-red-200",
  high:     "bg-red-50 text-red-700 border border-red-200",
  medium:   "bg-amber-50 text-amber-700 border border-amber-200",
  low:      "bg-zinc-100 text-zinc-600 border border-zinc-200",
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
    risk: "Until MFA is enabled, a single credential leak grants full console access.",
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
    risk: "Stale accounts with active credentials remain exploitable indefinitely.",
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
    risk: "Forgotten keys are exfiltrated without detection and never expire.",
  },
  "iam.role.unassumed_90d": {
    why: "Roles not assumed in 90+ days are likely orphaned. They add attack surface and may carry overly broad policies from an earlier, less careful time.",
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
    risk: "Orphaned roles can be assumed by compromised services or used for lateral movement.",
  },
  "iam.role.wildcard_action": {
    why: 'Action: "*" in an inline policy is effectively admin access. It violates least privilege and means any compromise of this role grants unrestricted IAM access.',
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
    risk: "A wildcard role can create users, escalate privileges, exfiltrate data, or destroy infrastructure.",
  },
  "iam.role.unused_services_90d": {
    why: "This role has permissions to services it never calls. Each unused permission is unnecessary blast radius — if this role is compromised via SSRF, metadata endpoint theft, or lateral movement, an attacker can pivot to every service the role can reach.",
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
    risk: "Overly permissive roles violate least privilege. Reducing granted services limits the blast radius of any future compromise.",
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
              <div className="font-mono text-zinc-400 text-[11px]">
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
          <pre className="bg-zinc-950 text-zinc-200 rounded-lg px-4 py-4 text-[11px] font-mono overflow-x-auto whitespace-pre-wrap leading-relaxed max-h-72 overflow-y-auto">
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
  const badge = sevBadge[finding.severity] ?? sevBadge.low;
  const hasEvidence = Object.keys(finding.evidence).length > 0;
  const showPolicyGen = finding.check_id === "iam.role.unused_services_90d" && !!accountId;

  return (
    <>
      <div className="fixed inset-0 bg-black/25 z-40 backdrop-blur-sm" onClick={onClose} />

      <div className="fixed right-0 top-0 h-full w-full max-w-[480px] bg-white z-50 shadow-2xl flex flex-col overflow-hidden">
        {/* Header */}
        <div className="px-6 pt-5 pb-4 border-b border-zinc-100">
          <div className="flex items-start justify-between gap-3">
            <div className="space-y-2 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold ${badge}`}>
                  {finding.severity}
                </span>
                <span className="text-xs font-mono text-zinc-400">{finding.check_id}</span>
              </div>
              <h2 className="text-sm font-semibold text-zinc-900 leading-snug">{finding.title}</h2>
              <p className="text-[11px] font-mono text-zinc-400 break-all leading-relaxed">{finding.resource_arn}</p>
            </div>
            <button onClick={onClose} className="text-zinc-300 hover:text-zinc-500 transition-colors flex-shrink-0 mt-0.5">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">
          {/* Context */}
          <div className="rounded-lg border border-zinc-200 px-4 py-4 space-y-3">
            <p className="text-sm text-zinc-700 leading-relaxed">{rem.why}</p>
            <hr className="border-zinc-100" />
            <p className="text-sm text-zinc-500 leading-relaxed">{rem.risk}</p>
          </div>

          {/* Evidence */}
          {hasEvidence && (
            <div>
              <div className="text-xs font-semibold text-zinc-500 uppercase tracking-wide mb-3">Evidence</div>
              <EvidenceSection evidence={finding.evidence} checkId={finding.check_id} />
            </div>
          )}

          {/* Suggested policy (unused_services only) */}
          {showPolicyGen && (
            <GeneratePolicySection accountId={accountId!} finding={finding} />
          )}

          {/* Remediation */}
          <div>
            <div className="text-xs font-semibold text-zinc-500 uppercase tracking-wide mb-3">Remediation</div>
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
              <ol className="space-y-2.5">
                {rem.console.map((step, i) => (
                  <li key={i} className="flex gap-3 text-sm text-zinc-700 leading-relaxed">
                    <span className="w-5 h-5 rounded-full bg-zinc-900 text-zinc-50 text-[11px] font-semibold flex items-center justify-center flex-shrink-0 mt-0.5">
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
        <div className="px-6 py-4 border-t border-zinc-100 flex gap-2">
          <button
            onClick={() => { onAction(finding.id, "resolve"); onClose(); }}
            className="flex-1 bg-zinc-900 hover:bg-zinc-800 text-white text-sm font-medium py-2 rounded transition-colors"
          >
            Resolve
          </button>
          <button
            onClick={() => { onAction(finding.id, "snooze"); onClose(); }}
            className="flex-1 border border-zinc-200 text-zinc-600 hover:bg-zinc-50 text-sm font-medium py-2 rounded-lg transition-colors"
          >
            Snooze 30d
          </button>
          <button
            onClick={() => { onAction(finding.id, "ignore"); onClose(); }}
            className="px-4 border border-zinc-200 text-zinc-400 hover:bg-zinc-50 text-sm font-medium py-2 rounded-lg transition-colors"
          >
            Ignore
          </button>
        </div>
      </div>
    </>
  );
}
