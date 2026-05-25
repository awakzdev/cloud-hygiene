import { useQuery } from "@tanstack/react-query";
import { api } from "../api";

type Account = { id: string; label: string; account_id: string | null; status: string };
type Finding = {
  id: string; severity: string; status: string; risk_score: number;
  check_id: string; title: string; resource_arn: string; first_seen: string;
};

type FindingPage = { items: Finding[]; total: number; next_cursor: string | null };
type ScanRun = { id: string; status: string; started_at: string; finished_at: string | null; error: string | null };

const checkLabels: Record<string, string> = {
  "iam.user.no_mfa": "MFA not enabled",
  "iam.user.inactive_90d": "Inactive user",
  "iam.access_key.unused_90d": "Unused access key",
  "iam.access_key.no_rotation_90d": "Long-lived access key",
  "iam.access_key.multiple_active": "Multiple active access keys",
  "iam.role.unassumed_90d": "Role unassumed",
  "iam.role.wildcard_action": "Wildcard action",
  "iam.role.unused_services_90d": "Unused granted services",
  "iam.role.trust_wildcard": "Wildcard trust policy",
  "iam.role.allows_iam_star": "Grants iam:*",
  "iam.role.confused_deputy": "Confused deputy risk",
};

const sevWeight: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

const sevBadge: Record<string, string> = {
  critical: "bg-red-50 text-red-700 border-red-200",
  high: "bg-red-50 text-red-600 border-red-200",
  medium: "bg-amber-50 text-amber-600 border-amber-200",
  low: "bg-zinc-50 text-zinc-500 border-zinc-200",
};

function shortResource(arn: string) {
  const tail = arn.split(":").pop() ?? arn;
  const [, rest = tail] = tail.split(/\/(.+)/);
  const [name, suffix] = rest.split("#");
  if (!suffix) return name || rest;
  const masked = suffix.length > 12 ? `${suffix.slice(0, 4)}…${suffix.slice(-4)}` : suffix;
  return `${name} · ${masked}`;
}

function daysAgo(iso: string): string {
  const d = Math.floor((Date.now() - new Date(iso).getTime()) / 86400000);
  if (d <= 0) return "today";
  if (d === 1) return "1d";
  if (d < 30) return `${d}d`;
  if (d < 365) return `${Math.floor(d / 30)}mo`;
  return `${Math.floor(d / 365)}y`;
}

function lastScanLabel(iso: string): string {
  const date = new Date(iso);
  const sameDay = date.toDateString() === new Date().toDateString();
  const time = date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  return sameDay ? `today at ${time}` : `${date.toLocaleDateString()} at ${time}`;
}

function scoreColor(s: number) {
  if (s >= 80) return "text-green-600";
  if (s >= 60) return "text-amber-500";
  if (s >= 40) return "text-orange-500";
  return "text-red-600";
}

function scoreBarColor(s: number) {
  if (s >= 80) return "bg-green-500";
  if (s >= 60) return "bg-amber-400";
  if (s >= 40) return "bg-orange-400";
  return "bg-red-500";
}

function scoreLabel(s: number) {
  if (s >= 80) return "Good";
  if (s >= 60) return "Fair";
  if (s >= 40) return "Poor";
  return "Critical";
}

export default function Dashboard() {
  const accounts = useQuery({ queryKey: ["accounts"], queryFn: () => api<Account[]>("/v1/accounts") });
  const findings = useQuery({ queryKey: ["dashboard-findings"], queryFn: () => api<FindingPage>("/v1/findings?status=open&limit=500") });

  const connectedAccount = accounts.data?.find((a) => a.status === "connected");

  const scanRun = useQuery({
    queryKey: ["scan-run-latest", connectedAccount?.id],
    queryFn: () =>
      connectedAccount
        ? api<ScanRun | null>(`/v1/accounts/${connectedAccount.id}/scan-runs/latest`)
        : null,
    enabled: !!connectedAccount,
  });

  const rows = findings.data?.items ?? [];
  const isLoading = findings.isLoading || accounts.isLoading;

  const critHigh = rows.filter((f) => f.severity === "critical" || f.severity === "high").length;
  const medium = rows.filter((f) => f.severity === "medium").length;
  const low = rows.filter((f) => f.severity === "low").length;
  const total = rows.length;

  const postureScore = Math.max(0, Math.min(100, Math.round(100 - critHigh * 10 - medium * 3 - low * 1)));

  const topRisks = [...rows]
    .sort((a, b) => (sevWeight[a.severity] ?? 9) - (sevWeight[b.severity] ?? 9) || b.risk_score - a.risk_score)
    .slice(0, 8);

  const mostNeglected = [...rows]
    .sort((a, b) => new Date(a.first_seen).getTime() - new Date(b.first_seen).getTime())
    .slice(0, 3);

  const checkBreakdown = Object.entries(
    rows.reduce<Record<string, { count: number; sev: string }>>((acc, f) => {
      if (!acc[f.check_id]) acc[f.check_id] = { count: 0, sev: f.severity };
      acc[f.check_id].count++;
      if ((sevWeight[f.severity] ?? 9) < (sevWeight[acc[f.check_id].sev] ?? 9)) {
        acc[f.check_id].sev = f.severity;
      }
      return acc;
    }, {}),
  ).sort((a, b) => b[1].count - a[1].count).slice(0, 9);

  const maxCount = Math.max(...checkBreakdown.map(([, v]) => v.count), 1);

  return (
    <div className="space-y-5 max-w-6xl">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-950">Dashboard</h1>
        <p className="text-sm text-zinc-500 mt-1">
          IAM posture overview.
          {scanRun.data?.finished_at && <> Last scan {lastScanLabel(scanRun.data.finished_at)}.</>}
          {scanRun.data?.status === "error" && (
            <span className="text-red-500 ml-2">Last scan failed.</span>
          )}
        </p>
      </div>

      {/* Top row: posture score + severity cards */}
      <div className="grid grid-cols-4 gap-4">
        {/* Posture score */}
        <div className="rounded-2xl border border-zinc-200 bg-white shadow-sm p-6 flex flex-col justify-between">
          <div className="text-xs font-semibold uppercase tracking-wide text-zinc-400">Posture Score</div>
          <div className="my-3">
            <div className={`text-6xl font-bold tabular-nums leading-none ${isLoading ? "text-zinc-200" : scoreColor(postureScore)}`}>
              {isLoading ? "…" : postureScore}
            </div>
            {!isLoading && (
              <div className={`text-sm font-semibold mt-1 ${scoreColor(postureScore)}`}>
                {scoreLabel(postureScore)}
              </div>
            )}
          </div>
          <div>
            <div className="h-1.5 rounded-full bg-zinc-100 overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-700 ${scoreBarColor(postureScore)}`}
                style={{ width: isLoading ? "0%" : `${postureScore}%` }}
              />
            </div>
            <div className="text-xs text-zinc-400 mt-1.5">
              {isLoading ? "" : `${total} open finding${total !== 1 ? "s" : ""}`}
            </div>
          </div>
        </div>

        {/* Critical / High */}
        <div className="rounded-2xl border border-red-100 bg-red-50 p-6">
          <div className="text-xs font-semibold uppercase tracking-wide text-red-400">Critical / High</div>
          <div className="text-5xl font-bold tabular-nums text-red-600 mt-4 leading-none">
            {isLoading ? "…" : critHigh}
          </div>
          <div className="text-sm text-red-400 mt-2">fix first</div>
        </div>

        {/* Medium */}
        <div className="rounded-2xl border border-amber-100 bg-amber-50 p-6">
          <div className="text-xs font-semibold uppercase tracking-wide text-amber-500">Medium</div>
          <div className="text-5xl font-bold tabular-nums text-amber-600 mt-4 leading-none">
            {isLoading ? "…" : medium}
          </div>
          <div className="text-sm text-amber-400 mt-2">reduce backlog</div>
        </div>

        {/* Low */}
        <div className="rounded-2xl border border-zinc-200 bg-zinc-50 p-6">
          <div className="text-xs font-semibold uppercase tracking-wide text-zinc-400">Low</div>
          <div className="text-5xl font-bold tabular-nums text-zinc-600 mt-4 leading-none">
            {isLoading ? "…" : low}
          </div>
          <div className="text-sm text-zinc-400 mt-2">monitor</div>
        </div>
      </div>

      {/* Middle row: top risks + check breakdown */}
      <div className="grid grid-cols-[minmax(0,1fr)_320px] gap-4">
        {/* Top risks */}
        <div className="rounded-2xl border border-zinc-200 bg-white shadow-sm overflow-hidden">
          <div className="px-5 py-4 border-b border-zinc-100">
            <div className="text-sm font-semibold text-zinc-900">Top open risks</div>
            <div className="text-xs text-zinc-400 mt-0.5">Sorted by severity then risk score</div>
          </div>
          <div className="divide-y divide-zinc-100">
            {isLoading && <div className="px-5 py-10 text-sm text-zinc-400">Loading…</div>}
            {!isLoading && topRisks.length === 0 && (
              <div className="px-5 py-10 text-sm text-zinc-400">No open findings.</div>
            )}
            {topRisks.map((f) => (
              <div key={f.id} className="flex items-center gap-3 px-5 py-3.5">
                <span className={`rounded border px-2 py-0.5 text-xs font-semibold uppercase tracking-wide flex-shrink-0 ${sevBadge[f.severity] ?? sevBadge.low}`}>
                  {f.severity}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-zinc-900 truncate">{f.title}</div>
                  <div className="text-xs text-zinc-400 truncate mt-0.5">{shortResource(f.resource_arn)}</div>
                </div>
                <span className="text-sm font-semibold tabular-nums text-zinc-500 flex-shrink-0">{f.risk_score}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Check breakdown */}
        <div className="rounded-2xl border border-zinc-200 bg-white shadow-sm overflow-hidden">
          <div className="px-5 py-4 border-b border-zinc-100">
            <div className="text-sm font-semibold text-zinc-900">Findings by check</div>
            <div className="text-xs text-zinc-400 mt-0.5">Which checks are dragging the score</div>
          </div>
          <div className="px-5 py-4 space-y-3.5">
            {isLoading && <div className="text-sm text-zinc-400">Loading…</div>}
            {!isLoading && checkBreakdown.length === 0 && (
              <div className="text-sm text-zinc-400">No findings.</div>
            )}
            {checkBreakdown.map(([checkId, { count, sev }]) => {
              const bar = sev === "critical" || sev === "high" ? "bg-red-400" : sev === "medium" ? "bg-amber-400" : "bg-zinc-300";
              return (
                <div key={checkId}>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-xs font-medium text-zinc-700 truncate pr-2">
                      {checkLabels[checkId] ?? checkId}
                    </span>
                    <span className="text-xs font-semibold tabular-nums text-zinc-400 flex-shrink-0">{count}</span>
                  </div>
                  <div className="h-1.5 rounded-full bg-zinc-100 overflow-hidden">
                    <div
                      className={`h-full rounded-full ${bar}`}
                      style={{ width: `${Math.round((count / maxCount) * 100)}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Bottom: most neglected */}
      {!isLoading && mostNeglected.length > 0 && (
        <div className="rounded-2xl border border-zinc-200 bg-white shadow-sm overflow-hidden">
          <div className="px-5 py-4 border-b border-zinc-100">
            <div className="text-sm font-semibold text-zinc-900">Most neglected</div>
            <div className="text-xs text-zinc-400 mt-0.5">Oldest open findings — untouched the longest</div>
          </div>
          <div className="grid grid-cols-3 divide-x divide-zinc-100">
            {mostNeglected.map((f) => (
              <div key={f.id} className="px-5 py-4">
                <div className="flex items-center gap-2 mb-2">
                  <span className={`rounded border px-2 py-0.5 text-xs font-semibold uppercase tracking-wide ${sevBadge[f.severity] ?? sevBadge.low}`}>
                    {f.severity}
                  </span>
                  <span className="text-xs text-zinc-400">{daysAgo(f.first_seen)} ago</span>
                </div>
                <div className="text-sm font-medium text-zinc-900 leading-snug">{f.title}</div>
                <div className="text-xs text-zinc-400 mt-1 truncate">{shortResource(f.resource_arn)}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
