import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, useEffect } from "react";
import { api } from "../api";

type CheckCfg = { enabled: boolean };
type SettingsData = {
  checks: Record<string, CheckCfg>;
  notifications: {
    email_digest_enabled: boolean;
    digest_email: string | null;
  };
};

const ALL_CHECKS: { id: string; label: string; severity: string; description: string }[] = [
  // Root
  { id: "iam.root.has_access_keys", label: "Root has access keys", severity: "critical", description: "Root account access keys are permanent credentials — delete them." },
  { id: "iam.root.no_mfa", label: "Root MFA not enabled", severity: "critical", description: "Root account without MFA can be compromised with credentials alone." },
  // Users
  { id: "iam.user.no_mfa", label: "MFA not enabled", severity: "high", description: "Require MFA for interactive IAM users." },
  { id: "iam.user.inactive_90d", label: "Inactive user", severity: "medium", description: "Disable or remove dormant IAM users." },
  // Access keys
  { id: "iam.access_key.unused_90d", label: "Unused access key", severity: "high", description: "Deactivate stale access keys, then delete after validation." },
  { id: "iam.access_key.no_rotation_90d", label: "Key not rotated", severity: "medium", description: "Rotate active keys older than 90 days." },
  { id: "iam.access_key.multiple_active", label: "Multiple active access keys", severity: "medium", description: "Each user should have at most one active access key." },
  // Roles
  { id: "iam.role.unassumed_90d", label: "Role unassumed", severity: "medium", description: "Remove or deactivate roles that have never been assumed." },
  { id: "iam.role.wildcard_action", label: "Wildcard action in inline policy", severity: "high", description: "Replace Action: '*' with explicit action lists." },
  { id: "iam.role.unused_services_90d", label: "Unused granted services", severity: "medium", description: "Scope role policies down to services actually used." },
  { id: "iam.role.trust_wildcard", label: "Wildcard trust policy", severity: "critical", description: "Roles that trust '*' can be assumed by anyone." },
  // S3
  { id: "s3.bucket.public_access_not_blocked", label: "Public access not blocked", severity: "high", description: "Enable all four Block Public Access settings." },
  { id: "s3.bucket.no_https_policy", label: "No HTTPS-only policy", severity: "medium", description: "Deny requests where aws:SecureTransport is false." },
  { id: "s3.bucket.no_kms", label: "Not encrypted with KMS", severity: "medium", description: "Use SSE-KMS for encryption at rest." },
  { id: "s3.bucket.no_logging", label: "Access logging disabled", severity: "low", description: "Enable server access logging for audit visibility." },
  // KMS
  { id: "kms.key.no_rotation", label: "Key rotation disabled", severity: "medium", description: "Enable annual automatic rotation for customer-managed keys." },
];

const sevBadge: Record<string, string> = {
  critical: "border-red-200 bg-red-50 text-red-700",
  high: "border-orange-200 bg-orange-50 text-orange-600",
  medium: "border-amber-200 bg-amber-50 text-amber-600",
  low: "border-zinc-200 bg-zinc-50 text-zinc-500",
};

function Toggle({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-6 w-11 flex-shrink-0 rounded-full border-2 border-transparent transition-colors focus:outline-none ${
        checked ? "bg-sky-500" : "bg-zinc-200"
      }`}
    >
      <span
        className={`inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition-transform ${
          checked ? "translate-x-5" : "translate-x-0"
        }`}
      />
    </button>
  );
}

export default function Settings() {
  const qc = useQueryClient();
  const { data, isLoading } = useQuery<SettingsData>({
    queryKey: ["settings"],
    queryFn: () => api("/v1/settings"),
  });

  const [checks, setChecks] = useState<Record<string, boolean>>({});
  const [emailDigestEnabled, setEmailDigestEnabled] = useState(false);
  const [digestEmail, setDigestEmail] = useState("");
  const [saved, setSaved] = useState(false);
  const [testState, setTestState] = useState<"idle" | "sending" | "sent" | "error">("idle");
  const [testError, setTestError] = useState("");

  useEffect(() => {
    if (!data) return;
    const map: Record<string, boolean> = {};
    for (const c of ALL_CHECKS) {
      map[c.id] = data.checks[c.id]?.enabled ?? true;
    }
    setChecks(map);
    setEmailDigestEnabled(data.notifications.email_digest_enabled ?? false);
    setDigestEmail(data.notifications.digest_email ?? "");
  }, [data]);

  const mutation = useMutation({
    mutationFn: (body: Partial<SettingsData>) =>
      api("/v1/settings", { method: "PATCH", body: JSON.stringify(body) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["settings"] });
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    },
  });

  async function sendTest() {
    setTestState("sending");
    setTestError("");
    try {
      await api("/v1/settings/test-digest", { method: "POST" });
      setTestState("sent");
      setTimeout(() => setTestState("idle"), 3000);
    } catch (e) {
      setTestState("error");
      setTestError((e as Error).message);
      setTimeout(() => setTestState("idle"), 4000);
    }
  }

  function save() {
    const checksPayload: Record<string, CheckCfg> = {};
    for (const [id, enabled] of Object.entries(checks)) {
      checksPayload[id] = { enabled };
    }
    mutation.mutate({
      checks: checksPayload,
      notifications: {
        email_digest_enabled: emailDigestEnabled,
        digest_email: digestEmail.trim() || null,
      },
    });
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64 text-zinc-400 text-sm">
        Loading settings…
      </div>
    );
  }

  const grouped = {
    root: ALL_CHECKS.filter((c) => c.id.startsWith("iam.root.")),
    user: ALL_CHECKS.filter((c) => c.id.startsWith("iam.user.")),
    access_key: ALL_CHECKS.filter((c) => c.id.startsWith("iam.access_key.")),
    role: ALL_CHECKS.filter((c) => c.id.startsWith("iam.role.")),
    s3: ALL_CHECKS.filter((c) => c.id.startsWith("s3.")),
    kms: ALL_CHECKS.filter((c) => c.id.startsWith("kms.")),
  };

  return (
    <div className="max-w-3xl space-y-8">
      <div>
        <h1 className="text-2xl font-semibold text-zinc-900">Settings</h1>
        <p className="mt-1 text-sm text-zinc-500">
          Configure which checks run during scans and how you receive alerts.
        </p>
      </div>

      {/* Checks */}
      <section className="space-y-4">
        <h2 className="text-base font-semibold text-zinc-800">Checks</h2>

        {(
          [
            ["Root Account", grouped.root],
            ["IAM Users", grouped.user],
            ["Access Keys", grouped.access_key],
            ["IAM Roles", grouped.role],
            ["S3 Buckets", grouped.s3],
            ["KMS Keys", grouped.kms],
          ] as [string, typeof ALL_CHECKS][]
        ).map(([groupLabel, items]) => (
          <div key={groupLabel} className="rounded-xl border border-zinc-200 bg-white overflow-hidden" style={{ boxShadow: "0 1px 4px 0 rgba(0,0,0,0.06), 0 0 0 1px rgba(0,0,0,0.03)" }}>
            <div className="px-5 py-3 border-b border-zinc-100" style={{ background: "linear-gradient(to bottom, #f9fafb, #f4f5f6)" }}>
              <span className="text-xs font-semibold uppercase tracking-wider text-zinc-400">
                {groupLabel}
              </span>
            </div>
            <div className="divide-y divide-zinc-100">
              {items.map((c) => (
                <div key={c.id} className="group flex items-center gap-4 px-5 py-4 transition-colors hover:bg-zinc-50/70">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-medium text-zinc-900">{c.label}</span>
                      <span
                        className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${
                          sevBadge[c.severity]
                        }`}
                      >
                        {c.severity}
                      </span>
                    </div>
                    <p className="mt-0.5 text-xs text-zinc-500">{c.description}</p>
                  </div>
                  <Toggle
                    checked={checks[c.id] ?? true}
                    onChange={(v) => setChecks((prev) => ({ ...prev, [c.id]: v }))}
                  />
                </div>
              ))}
            </div>
          </div>
        ))}
      </section>

      {/* Notifications */}
      <section className="space-y-4">
        <h2 className="text-base font-semibold text-zinc-800">Notifications</h2>
        <div className="rounded-xl border border-zinc-200 bg-white overflow-hidden" style={{ boxShadow: "0 1px 4px 0 rgba(0,0,0,0.06), 0 0 0 1px rgba(0,0,0,0.03)" }}>
          <div className="flex items-center justify-between px-5 py-4">
            <div>
              <p className="text-sm font-medium text-zinc-900">Weekly email digest</p>
              <p className="text-xs text-zinc-500">Send a findings summary every Monday at 9am UTC.</p>
            </div>
            <Toggle checked={emailDigestEnabled} onChange={setEmailDigestEnabled} />
          </div>
          {emailDigestEnabled && (
            <div className="px-5 pb-4 border-t border-zinc-100">
              <label className="block text-xs font-medium text-zinc-500 mb-1.5 mt-3">
                Recipient email
              </label>
              <input
                type="email"
                value={digestEmail}
                onChange={(e) => setDigestEmail(e.target.value)}
                placeholder="Email address"
                className="w-full max-w-sm rounded-lg border border-zinc-200 bg-zinc-50 px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400 focus:outline-none focus:ring-2 focus:ring-sky-500 focus:border-transparent"
              />
              <p className="mt-1.5 text-xs text-zinc-400">
                Leave blank to send to your account email.
              </p>
              <div className="mt-3 flex items-center gap-3">
                <button
                  type="button"
                  onClick={sendTest}
                  disabled={testState === "sending"}
                  className="rounded-lg border border-zinc-200 bg-white px-3.5 py-2 text-xs font-semibold text-zinc-700 shadow-sm hover:bg-zinc-50 disabled:opacity-50 transition-colors"
                >
                  {testState === "sending" ? "Sending…" : "Send test email"}
                </button>
                {testState === "sent" && (
                  <span className="text-xs text-emerald-600 font-medium">Sent!</span>
                )}
                {testState === "error" && (
                  <span className="text-xs text-red-500">{testError}</span>
                )}
              </div>
            </div>
          )}
        </div>
      </section>

      {/* Save */}
      <div className="flex items-center gap-3">
        <button
          onClick={save}
          disabled={mutation.isPending}
          className="rounded-lg bg-sky-500 px-5 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-sky-600 disabled:opacity-60 transition-colors"
        >
          {mutation.isPending ? "Saving…" : "Save changes"}
        </button>
        {saved && <span className="text-sm text-emerald-600 font-medium">Saved</span>}
        {mutation.isError && (
          <span className="text-sm text-red-500">{(mutation.error as Error).message}</span>
        )}
      </div>
    </div>
  );
}
