import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, useEffect, useRef, useMemo, useCallback } from "react";
import { api, token } from "../api";
import { FindingDrawer } from "../components/FindingDrawer";

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

type Account = { id: string; status: string };

const COLLAPSED_FINDINGS_KEY = "vigil.findings.collapsedGroups";

const sevBadge: Record<string, string> = {
  critical: "border-red-200 bg-red-50 text-red-700",
  high: "border-red-200 bg-red-50 text-red-600",
  medium: "border-amber-200 bg-amber-50 text-amber-600",
  low: "border-zinc-200 bg-zinc-50 text-zinc-500",
};

const sevWeight: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

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

const checkDescriptions: Record<string, string> = {
  "iam.user.no_mfa": "Require MFA for interactive IAM users.",
  "iam.user.inactive_90d": "Disable or remove dormant IAM users.",
  "iam.access_key.unused_90d": "Deactivate stale access keys, then delete after validation.",
  "iam.access_key.no_rotation_90d": "Rotate active keys older than 90 days.",
  "iam.access_key.multiple_active": "Valid during rotation, but persistent duplicates increase exposure.",
  "iam.role.unassumed_90d": "Confirm ownership, then remove roles that are no longer used.",
  "iam.role.wildcard_action": "Replace wildcard permissions with scoped actions.",
  "iam.role.unused_services_90d": "Trim unused service permissions from role policies.",
  "iam.role.trust_wildcard": "Trust policy allows an unrestricted principal.",
  "iam.role.allows_iam_star": "Inline policy grants iam:* — privilege escalation path.",
  "iam.role.confused_deputy": "Cross-account trust without ExternalId — confused deputy risk.",
};

const statusTabs = ["open", "snoozed", "resolved", "all"] as const;
type StatusTab = (typeof statusTabs)[number];
type SeverityFilter = "all" | "critical_high" | "medium" | "low";
type SortKey = "severity" | "score" | "first_seen";

function loadCollapsedGroups(): Record<string, boolean> {
  try {
    const raw = localStorage.getItem(COLLAPSED_FINDINGS_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function resourceName(arn: string): string {
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

function matchesSeverityFilter(f: Finding, filter: SeverityFilter): boolean {
  if (filter === "all") return true;
  if (filter === "critical_high") return f.severity === "critical" || f.severity === "high";
  return f.severity === filter;
}

function sortLabel(k: SortKey): string {
  if (k === "first_seen") return "Age";
  return k.charAt(0).toUpperCase() + k.slice(1);
}

function sortIcon(k: SortKey, active: SortKey, dir: "asc" | "desc"): string {
  if (k !== active) return "";
  return dir === "asc" ? "↑" : "↓";
}

export default function Findings() {
  const qc = useQueryClient();
  const [status, setStatus] = useState<StatusTab>("open");
  const [selected, setSelected] = useState<Finding | null>(null);
  const [sortKey, setSortKey] = useState<SortKey>("severity");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [search, setSearch] = useState("");
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>(() => loadCollapsedGroups());
  const prevScanStatus = useRef<string | null>(null);

  useEffect(() => {
    localStorage.setItem(COLLAPSED_FINDINGS_KEY, JSON.stringify(collapsed));
  }, [collapsed]);

  const downloadCsv = useCallback(async () => {
    const BASE = (import.meta.env.VITE_API_URL as string) || "http://localhost:8000";
    const t = token();
    const res = await fetch(`${BASE}/v1/findings/export/csv?status=${status}`, { headers: t ? { Authorization: `Bearer ${t}` } : {} });
    if (!res.ok) return;
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "vigil-findings.csv";
    a.click();
    URL.revokeObjectURL(url);
  }, [status]);

  const q = useQuery({ queryKey: ["findings", status], queryFn: () => api<Finding[]>(`/v1/findings?status=${status}`) });
  const accounts = useQuery({ queryKey: ["accounts"], queryFn: () => api<Account[]>("/v1/accounts") });
  const connectedId = accounts.data?.find((a) => a.status === "connected")?.id;

  const scanRun = useQuery({
    queryKey: ["scan-run-latest", connectedId],
    queryFn: () => connectedId ? api<{ id: string; status: string; started_at: string; finished_at: string | null; error: string | null } | null>(`/v1/accounts/${connectedId}/scan-runs/latest`) : null,
    enabled: !!connectedId,
    refetchInterval: (query) => query.state.data?.status === "running" ? 5000 : false,
  });

  const scanStatus = scanRun.data?.status ?? null;
  const scanStartedAt = scanRun.data?.started_at ? new Date(scanRun.data.started_at) : null;
  const scanStuck = scanStartedAt ? Date.now() - scanStartedAt.getTime() > 5 * 60 * 1000 : false;
  const isRunning = scanStatus === "running" && !scanStuck;

  useEffect(() => {
    if (prevScanStatus.current === "running" && scanStatus === "ok") qc.invalidateQueries({ queryKey: ["findings"] });
    prevScanStatus.current = scanStatus;
  }, [scanStatus, qc]);

  const scan = useMutation({ mutationFn: (id: string) => api(`/v1/accounts/${id}/scan`, { method: "POST" }), onSuccess: () => setTimeout(() => qc.invalidateQueries({ queryKey: ["scan-run-latest"] }), 1000) });
  const act = useMutation({ mutationFn: ({ id, action }: { id: string; action: "snooze" | "resolve" | "ignore" }) => api(`/v1/findings/${id}/${action}`, { method: "POST", body: action === "snooze" ? JSON.stringify({ days: 30 }) : JSON.stringify({}) }), onSuccess: () => qc.invalidateQueries({ queryKey: ["findings"] }) });

  const findings = q.data ?? [];
  const totals = useMemo(() => {
    const t = { open: 0, critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of findings) {
      t.open++;
      if (f.severity in t) t[f.severity as keyof typeof t]++;
    }
    return t;
  }, [findings]);

  const rows = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const arr = findings.filter((f) => {
      if (!matchesSeverityFilter(f, severityFilter)) return false;
      if (!needle) return true;
      return [f.title, f.check_id, f.resource_arn, checkLabels[f.check_id] ?? "", checkDescriptions[f.check_id] ?? ""].join(" ").toLowerCase().includes(needle);
    });
    arr.sort((a, b) => {
      let cmp = 0;
      if (sortKey === "severity") cmp = (sevWeight[a.severity] ?? 9) - (sevWeight[b.severity] ?? 9) || b.risk_score - a.risk_score;
      else if (sortKey === "score") cmp = b.risk_score - a.risk_score;
      else cmp = new Date(b.first_seen).getTime() - new Date(a.first_seen).getTime();
      return sortDir === "asc" ? cmp : -cmp;
    });
    return arr;
  }, [findings, search, severityFilter, sortKey, sortDir]);

  const grouped = useMemo(() => {
    if (sortKey !== "severity") return null;
    const map = new Map<string, Finding[]>();
    for (const f of rows) {
      const list = map.get(f.check_id) ?? [];
      list.push(f);
      map.set(f.check_id, list);
    }
    return [...map.entries()].sort(([, a], [, b]) => (sevWeight[a[0].severity] ?? 9) - (sevWeight[b[0].severity] ?? 9) || b.length - a.length);
  }, [rows, sortKey]);

  function toggleSort(k: SortKey) {
    if (sortKey === k) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else {
      setSortKey(k);
      setSortDir(k === "severity" ? "asc" : "desc");
    }
  }

  const summaryCards = [
    { key: "all" as SeverityFilter, label: "Open", value: totals.open, tone: "text-zinc-900", hint: "active IAM posture issues", dot: "bg-zinc-400" },
    { key: "critical_high" as SeverityFilter, label: "Critical / High", value: totals.critical + totals.high, tone: "text-red-600", hint: "fix first", dot: "bg-red-500" },
    { key: "medium" as SeverityFilter, label: "Medium", value: totals.medium, tone: "text-amber-600", hint: "reduce backlog", dot: "bg-amber-500" },
    { key: "low" as SeverityFilter, label: "Low", value: totals.low, tone: "text-zinc-500", hint: "monitor", dot: "bg-zinc-300" },
  ];

  return (
    <div className="w-full px-8 py-7">
      <div className="mb-7 flex items-start justify-between gap-6">
        <div className="min-w-0">
          <h1 className="text-2xl font-bold tracking-tight text-zinc-950">Findings</h1>
          <p className="mt-1 text-sm text-zinc-500">IAM posture issues from the latest account scan.{scanRun.data?.finished_at && <> Last scan {lastScanLabel(scanRun.data.finished_at)}.</>}</p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <button onClick={downloadCsv} className="rounded-xl border border-zinc-200 bg-white px-4 py-2.5 text-sm font-semibold text-zinc-600 shadow-sm transition hover:border-zinc-300 hover:bg-zinc-50 hover:text-zinc-950">Export</button>
          <button onClick={() => qc.invalidateQueries({ queryKey: ["findings"] })} className="rounded-xl border border-zinc-200 bg-white px-4 py-2.5 text-sm font-semibold text-zinc-600 shadow-sm transition hover:border-zinc-300 hover:bg-zinc-50 hover:text-zinc-950">Refresh</button>
          {connectedId && <button onClick={() => scan.mutate(connectedId)} disabled={scan.isPending || isRunning} className="rounded-xl bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white shadow-sm shadow-indigo-600/20 transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-50">{isRunning ? "Scanning…" : scan.isPending ? "Triggering…" : "Re-scan"}</button>}
        </div>
      </div>

      {isRunning && <div className="mb-4 rounded-xl border border-indigo-100 bg-indigo-50 px-4 py-3 text-sm font-medium text-indigo-700">Scan running — findings will refresh automatically on completion.</div>}
      {scanStatus === "error" && scanRun.data?.error && <div className="mb-4 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700"><span className="font-semibold">Last scan failed:</span> {scanRun.data.error}</div>}

      <div className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {summaryCards.map((card) => <button key={card.key} onClick={() => setSeverityFilter(card.key)} className={`group relative overflow-hidden rounded-2xl border bg-white px-5 py-5 text-left shadow-sm shadow-zinc-950/[0.04] transition hover:-translate-y-0.5 hover:border-zinc-300 hover:shadow-md ${severityFilter === card.key ? "border-zinc-300 ring-4 ring-zinc-950/[0.04]" : "border-zinc-200"}`}><div className="mb-3 flex items-center justify-between"><span className="text-[11px] font-bold uppercase tracking-[0.18em] text-zinc-400">{card.label}</span><span className={`h-2.5 w-2.5 rounded-full ${card.dot}`} /></div><div className={`text-4xl font-bold tabular-nums leading-none tracking-tight ${card.tone}`}>{card.value}</div><div className="mt-3 text-sm text-zinc-500">{card.hint}</div></button>)}
      </div>

      <div className="mb-5 rounded-2xl border border-zinc-200 bg-white p-2 shadow-sm shadow-zinc-950/[0.03]">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex w-fit items-center gap-1 rounded-xl bg-zinc-100 p-1">{statusTabs.map((s) => <button key={s} onClick={() => setStatus(s)} className={`rounded-lg px-4 py-2 text-sm font-semibold capitalize transition-all ${status === s ? "bg-zinc-950 text-white shadow-sm" : "text-zinc-500 hover:bg-white hover:text-zinc-900"}`}>{s}</button>)}</div>
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center"><input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search findings…" className="h-11 w-full rounded-xl border border-zinc-200 bg-white px-4 text-sm text-zinc-800 outline-none transition placeholder:text-zinc-400 focus:border-zinc-400 focus:ring-4 focus:ring-zinc-950/[0.04] sm:w-80" /><div className="flex h-11 items-center gap-1 rounded-xl border border-zinc-200 bg-zinc-50 p-1"><span className="px-2 text-xs font-bold uppercase tracking-[0.14em] text-zinc-400">Sort</span>{(["severity", "score", "first_seen"] as SortKey[]).map((k) => <button key={k} onClick={() => toggleSort(k)} className={`inline-flex h-8 items-center gap-1 rounded-lg px-3 text-sm font-semibold transition-all ${sortKey === k ? "bg-white text-zinc-950 shadow-sm ring-1 ring-zinc-200" : "text-zinc-500 hover:bg-white/70 hover:text-zinc-900"}`}>{sortLabel(k)}{sortKey === k && <span className="text-xs text-zinc-500">{sortIcon(k, sortKey, sortDir)}</span>}</button>)}</div></div>
        </div>
      </div>

      {q.isLoading && <div className="rounded-2xl border border-zinc-200 bg-white px-4 py-16 text-center text-sm text-zinc-400">Loading…</div>}
      {!q.isLoading && rows.length === 0 && <div className="rounded-2xl border border-zinc-200 bg-white px-4 py-16 text-center"><p className="text-sm font-semibold text-zinc-700">No {status} findings</p><p className="mt-1 text-sm text-zinc-400">{status === "open" ? "Run a scan to check your account for IAM issues." : "Nothing to show here."}</p></div>}

      {rows.length > 0 && <div className="space-y-3 pb-8">{(grouped ?? [["all", rows] as [string, Finding[]]]).map(([key, items]) => {
        const isGrouped = grouped !== null;
        const sev = items[0]?.severity ?? "low";
        const label = checkLabels[key] ?? key;
        const description = checkDescriptions[key];
        const isCollapsed = !!collapsed[key];
        return <div key={key} className="overflow-hidden rounded-2xl border border-zinc-200 bg-white shadow-sm shadow-zinc-950/[0.04] transition-all hover:border-zinc-300 hover:shadow-md">{isGrouped && <button type="button" onClick={() => setCollapsed((prev) => ({ ...prev, [key]: !prev[key] }))} className="grid w-full grid-cols-[auto_auto_minmax(0,1fr)_72px_72px] items-center gap-3 border-b border-zinc-100 bg-gradient-to-r from-zinc-50 to-white px-5 py-4 text-left"><svg className={`h-4 w-4 text-zinc-400 transition-transform ${isCollapsed ? "-rotate-90" : ""}`} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" /></svg><span className={`rounded-lg border px-2.5 py-1 text-[11px] font-bold uppercase tracking-[0.14em] ${sevBadge[sev] ?? sevBadge.low}`}>{sev}</span><div className="min-w-0"><div className="flex items-center gap-2"><span className="text-sm font-bold text-zinc-950">{label}</span><span className="rounded-full bg-zinc-100 px-2 py-0.5 text-xs font-semibold tabular-nums text-zinc-500">{items.length}</span></div>{description && <p className="mt-1 truncate text-sm text-zinc-500">{description}</p>}</div><span className="hidden text-center text-[11px] font-bold uppercase tracking-[0.16em] text-zinc-400 md:block">Score</span><span className="hidden text-center text-[11px] font-bold uppercase tracking-[0.16em] text-zinc-400 md:block">Age</span></button>}{!isCollapsed && <div className="divide-y divide-zinc-100">{items.map((f) => <div key={f.id} onClick={() => setSelected(f)} className="group grid cursor-pointer grid-cols-[minmax(0,1fr)_72px_72px] items-center gap-3 px-5 py-4 transition-colors hover:bg-zinc-50"><div className="min-w-0"><div className="truncate text-sm font-semibold text-zinc-900">{resourceName(f.resource_arn)}</div>{!isGrouped && description && <p className="mt-1.5 truncate text-sm text-zinc-500">{description}</p>}</div><div className="flex justify-center"><span className="inline-flex min-w-10 justify-center rounded-full bg-zinc-100 px-2 py-1 text-sm font-bold tabular-nums text-zinc-800">{f.risk_score}</span></div><div className="text-center"><span className="text-sm tabular-nums text-zinc-500">{daysAgo(f.first_seen)}</span></div></div>)}</div>}</div>;
      })}</div>}

      <FindingDrawer finding={selected} accountId={connectedId ?? null} onClose={() => setSelected(null)} onAction={(id, action) => act.mutate({ id, action })} />
    </div>
  );
}
