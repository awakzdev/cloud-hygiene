import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, useEffect, useMemo } from "react";
import { api } from "../api";

type ScanInterval = "daily" | "weekly" | "custom" | "manual";
type FreqMode = "daily" | "weekly" | "custom";

type SettingsData = {
  scanning: {
    enabled: boolean;
    interval: ScanInterval;
    custom_hours: number | null;
  };
  notifications: {
    email_digest_enabled: boolean;
    digest_email: string | null;
    slack_webhook_url: string | null;
    scan_failure_email_enabled: boolean;
  };
  scan_status: {
    account_connected: boolean;
    last_scan_at: string | null;
    next_scan_at: string | null;
    max_interval: "daily" | "weekly";
    min_custom_hours: number;
  };
};

const cardClass =
  "overflow-hidden rounded-2xl border border-zinc-200 bg-white shadow-sm shadow-zinc-950/[0.04]";

function Toggle({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-6 w-11 shrink-0 rounded-full border-2 border-transparent transition-colors focus:outline-none ${
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

function SettingRow({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-4 px-5 py-3.5">
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium text-zinc-900">{title}</p>
        <p className="mt-0.5 text-xs leading-relaxed text-zinc-500">{description}</p>
      </div>
      <div className="shrink-0 pt-0.5">{children}</div>
    </div>
  );
}

function formatWhen(iso: string | null) {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function formatCustomHours(hours: number) {
  if (hours % 168 === 0) return `about every ${hours / 168} week${hours / 168 === 1 ? "" : "s"}`;
  if (hours % 24 === 0) return `about every ${hours / 24} day${hours / 24 === 1 ? "" : "s"}`;
  return `about every ${hours} hours`;
}

export default function Settings() {
  const qc = useQueryClient();
  const { data, isLoading } = useQuery<SettingsData>({
    queryKey: ["settings"],
    queryFn: () => api("/v1/settings"),
  });

  const [scanEnabled, setScanEnabled] = useState(true);
  const [freqMode, setFreqMode] = useState<FreqMode>("daily");
  const [customHours, setCustomHours] = useState(24);
  const [scanFailureEnabled, setScanFailureEnabled] = useState(true);
  const [emailDigestEnabled, setEmailDigestEnabled] = useState(false);
  const [digestEmail, setDigestEmail] = useState("");
  const [slackWebhookUrl, setSlackWebhookUrl] = useState("");
  const [saved, setSaved] = useState(false);
  const [testState, setTestState] = useState<"idle" | "sending" | "sent" | "error">("idle");
  const [testError, setTestError] = useState("");
  const [slackTestState, setSlackTestState] = useState<"idle" | "sending" | "sent" | "error">("idle");
  const [slackTestError, setSlackTestError] = useState("");

  const minCustomHours = data?.scan_status.min_custom_hours ?? 6;
  const canDaily = data?.scan_status.max_interval === "daily";

  useEffect(() => {
    if (!data) return;
    setScanEnabled(data.scanning.enabled);
    const interval = data.scanning.interval;
    if (interval === "custom") {
      setFreqMode("custom");
      setCustomHours(data.scanning.custom_hours ?? 24);
    } else if (interval === "weekly") {
      setFreqMode("weekly");
    } else {
      setFreqMode(canDaily ? "daily" : "weekly");
    }
    setScanFailureEnabled(data.notifications.scan_failure_email_enabled ?? true);
    setEmailDigestEnabled(data.notifications.email_digest_enabled ?? false);
    setDigestEmail(data.notifications.digest_email ?? "");
    setSlackWebhookUrl(data.notifications.slack_webhook_url ?? "");
  }, [data, canDaily]);

  const scanScheduleLabel = useMemo(() => {
    if (!scanEnabled) return "Manual only — trigger scans from Findings or Compliance.";
    if (freqMode === "weekly") return "Automated scan about every 7 days.";
    if (freqMode === "custom") return `Automated scan ${formatCustomHours(customHours)}.`;
    return "Automated scan about every 24 hours.";
  }, [scanEnabled, freqMode, customHours]);

  const mutation = useMutation({
    mutationFn: (body: { scanning: SettingsData["scanning"]; notifications: SettingsData["notifications"] }) =>
      api("/v1/settings", { method: "PATCH", body: JSON.stringify(body) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["settings"] });
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    },
  });

  async function sendSlackTest() {
    setSlackTestState("sending");
    setSlackTestError("");
    try {
      await api("/v1/settings/test-slack", { method: "POST", body: JSON.stringify({ url: slackWebhookUrl.trim() }) });
      setSlackTestState("sent");
      setTimeout(() => setSlackTestState("idle"), 3000);
    } catch (e) {
      setSlackTestState("error");
      setSlackTestError((e as Error).message);
      setTimeout(() => setSlackTestState("idle"), 4000);
    }
  }

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
    mutation.mutate({
      scanning: {
        enabled: scanEnabled,
        interval: scanEnabled ? (freqMode === "custom" ? "custom" : freqMode) : "manual",
        custom_hours: scanEnabled && freqMode === "custom" ? customHours : null,
      },
      notifications: {
        email_digest_enabled: emailDigestEnabled,
        digest_email: digestEmail.trim() || null,
        slack_webhook_url: slackWebhookUrl.trim() || null,
        scan_failure_email_enabled: scanFailureEnabled,
      },
    });
  }

  if (isLoading) {
    return (
      <div className="mx-auto flex h-64 w-full max-w-2xl items-center justify-center text-sm text-zinc-400">
        Loading settings…
      </div>
    );
  }

  const lastScan = formatWhen(data?.scan_status.last_scan_at ?? null);
  const nextScan = formatWhen(data?.scan_status.next_scan_at ?? null);
  const showAlertEmail = emailDigestEnabled || scanFailureEnabled;

  return (
    <div className="mx-auto w-full max-w-2xl space-y-7 pb-4">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-zinc-950">Settings</h1>
        <p className="mt-2 text-sm text-zinc-500">
          Automated scanning and alert delivery for your organization.
        </p>
      </div>

      <section className="space-y-3">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-zinc-400">Scanning</h2>
        <div className={cardClass}>
          <SettingRow
            title="Automated scans"
            description="Regular scans build your compliance evidence timeline. Turn off to scan manually only."
          >
            <Toggle checked={scanEnabled} onChange={setScanEnabled} />
          </SettingRow>

          {scanEnabled && (
            <div className="border-t border-zinc-100 px-6 pb-5 pt-1">
              <label htmlFor="scan-interval" className="mb-2 mt-4 block text-xs font-medium text-zinc-500">
                Frequency
              </label>
              <select
                id="scan-interval"
                value={freqMode}
                onChange={(e) => setFreqMode(e.target.value as FreqMode)}
                className="w-full rounded-xl border border-zinc-200 bg-zinc-50 px-3 py-2.5 text-sm text-zinc-900 focus:border-transparent focus:outline-none focus:ring-2 focus:ring-sky-500"
              >
                <option value="daily" disabled={!canDaily}>
                  Daily{canDaily ? "" : " (paid plan)"}
                </option>
                <option value="weekly">Weekly</option>
                <option value="custom">Custom interval</option>
              </select>

              {freqMode === "custom" && (
                <div className="mt-3">
                  <label htmlFor="custom-hours" className="mb-2 block text-xs font-medium text-zinc-500">
                    Interval (hours)
                  </label>
                  <input
                    id="custom-hours"
                    type="number"
                    min={minCustomHours}
                    max={720}
                    step={1}
                    value={customHours}
                    onChange={(e) => setCustomHours(Number(e.target.value))}
                    className="w-full rounded-xl border border-zinc-200 bg-zinc-50 px-3 py-2.5 text-sm text-zinc-900 focus:border-transparent focus:outline-none focus:ring-2 focus:ring-sky-500"
                  />
                  <p className="mt-1.5 text-xs text-zinc-400">
                    Between {minCustomHours} and 720 hours
                    {minCustomHours >= 168 ? " (7+ days on Free)" : ""}.
                  </p>
                </div>
              )}

              <p className="mt-3 text-xs text-zinc-400">{scanScheduleLabel}</p>
            </div>
          )}

          <div className="border-t border-zinc-100 bg-zinc-50/70 px-6 py-3.5 text-xs leading-relaxed text-zinc-500">
            {!data?.scan_status.account_connected ? (
              <span>Connect an AWS account to enable automated scanning.</span>
            ) : (
              <span>
                {lastScan ? <>Last scan: {lastScan}</> : "No scan completed yet."}
                {scanEnabled && nextScan && (
                  <>
                    {" · "}
                    Next scan due: {nextScan}
                  </>
                )}
              </span>
            )}
          </div>
        </div>
      </section>

      <section className="space-y-3">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-zinc-400">Notifications</h2>
        <div className={cardClass}>
          <SettingRow
            title="Scan failure email"
            description="Email immediately when an automated or manual scan fails — broken IAM role, collector error, etc."
          >
            <Toggle checked={scanFailureEnabled} onChange={setScanFailureEnabled} />
          </SettingRow>

          <div className="border-t border-zinc-100">
            <SettingRow
              title="Weekly email digest"
              description="Findings summary every Monday at 9am UTC."
            >
              <Toggle checked={emailDigestEnabled} onChange={setEmailDigestEnabled} />
            </SettingRow>
          </div>

          {showAlertEmail && (
            <div className="border-t border-zinc-100 px-6 pb-5">
              <label htmlFor="alert-email" className="mb-2 mt-4 block text-xs font-medium text-zinc-500">
                Alert email
              </label>
              <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
                <input
                  id="alert-email"
                  type="email"
                  value={digestEmail}
                  onChange={(e) => setDigestEmail(e.target.value)}
                  placeholder="Email Address"
                  className="min-w-0 flex-1 rounded-xl border border-zinc-200 bg-zinc-50 px-3 py-2.5 text-sm text-zinc-900 placeholder:text-zinc-400 focus:border-transparent focus:outline-none focus:ring-2 focus:ring-sky-500"
                />
                {emailDigestEnabled && (
                  <button
                    type="button"
                    onClick={sendTest}
                    disabled={testState === "sending"}
                    className="shrink-0 rounded-xl border border-zinc-200 bg-white px-4 py-2.5 text-xs font-semibold text-zinc-700 shadow-sm transition-colors hover:bg-zinc-50 disabled:opacity-50"
                  >
                    {testState === "sending" ? "Sending…" : "Send test digest"}
                  </button>
                )}
              </div>
              <p className="mt-2 text-xs text-zinc-400">
                Used for scan failure alerts{emailDigestEnabled ? " and the weekly digest" : ""}. Leave blank for your account email.
              </p>
              {testState === "sent" && (
                <p className="mt-2 text-xs font-medium text-emerald-600">Test digest sent.</p>
              )}
              {testState === "error" && (
                <p className="mt-2 text-xs text-red-500">{testError}</p>
              )}
            </div>
          )}
        </div>
      </section>

      <section className="space-y-3">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-zinc-400">Slack</h2>
        <div className={`${cardClass} px-6 py-5`}>
          <p className="text-sm font-medium text-zinc-900">Slack webhook</p>
          <p className="mt-1 text-xs leading-relaxed text-zinc-500">
            Post the weekly digest to a Slack channel via an Incoming Webhook.
          </p>
          <div className="mt-4 flex flex-col gap-2 sm:flex-row sm:items-center">
            <input
              type="url"
              value={slackWebhookUrl}
              onChange={(e) => setSlackWebhookUrl(e.target.value)}
              placeholder="https://hooks.slack.com/services/…"
              className="min-w-0 flex-1 rounded-xl border border-zinc-200 bg-zinc-50 px-3 py-2.5 text-sm text-zinc-900 placeholder:text-zinc-400 focus:border-transparent focus:outline-none focus:ring-2 focus:ring-sky-500"
            />
            <button
              type="button"
              onClick={sendSlackTest}
              disabled={slackTestState === "sending" || !slackWebhookUrl.trim()}
              className="shrink-0 rounded-xl border border-zinc-200 bg-white px-4 py-2.5 text-xs font-semibold text-zinc-700 shadow-sm transition-colors hover:bg-zinc-50 disabled:opacity-50"
            >
              {slackTestState === "sending" ? "Sending…" : "Test"}
            </button>
          </div>
          {slackTestState === "sent" && (
            <p className="mt-2 text-xs font-medium text-emerald-600">Message sent to Slack.</p>
          )}
          {slackTestState === "error" && (
            <p className="mt-2 text-xs text-red-500">{slackTestError}</p>
          )}
        </div>
      </section>

      <div className="flex items-center gap-3 pt-2">
        <button
          onClick={save}
          disabled={mutation.isPending}
          className="rounded-xl bg-sky-500 px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-sky-600 disabled:opacity-60"
        >
          {mutation.isPending ? "Saving…" : "Save changes"}
        </button>
        {saved && <span className="text-sm font-medium text-emerald-600">Saved</span>}
        {mutation.isError && (
          <span className="text-sm text-red-500">{(mutation.error as Error).message}</span>
        )}
      </div>
    </div>
  );
}
