import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, useEffect, useRef, useMemo } from "react";
import { api } from "../api";
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

const sevDot: Record<string, string> = {
  critical: "bg-red-600",
  high: "bg-red-500",
  medium: "bg-amber-500",
  low: "bg-zinc-400",
};

const sevWeight: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

const checkLabels: Record<string, string> = {
  "iam.user.no_mfa": "MFA not enabled",
  "iam.user.inactive_90d": "Inactive user",
  "iam.access_key.unused_90d": "Unused access key",
  "iam.role.unassumed_90d": "Role unassumed",
  "iam.role.wildcard_action": "Wildcard action",
  "iam.role.unused_services_90d": "Unused granted services",
};

const statusTabs = ["open", "snoozed", "resolved", "all"] as const;
type StatusTab = (typeof statusTabs)[number];

function shortArn(arn: string): string {
  const tail = arn.split(":").pop() ?? arn;
  if (tail.length <= 56) return tail;
  return `${tail.slice(0, 28)}…${tail.slice(-24)}`;
}

function daysAgo(iso: string): string {
  const d = Math.floor((Date.now() - new Date(iso).getTime()) / 86400000);
  if (d <= 0) return "today";
  if (d === 1) return "1d";
  if (d < 30) return `${d}d`;
  if (d < 365) return `${Math.floor(d / 30)}mo`;
  return `${Math.floor(d / 365)}y`;
}

type SortKey = "severity" | "score" | "first_seen";

export default function Findings() {
  const qc = useQueryClient();
  const [status, setStatus] = useState<StatusTab>("open");
  const [selected, setSelected] = useState<Finding | null>(null);
  const [sortKey, setSortKey] = useState<SortKey>("severity");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const prevScanStatus = useRef<string | null>(null);

  const q = useQuery({
    queryKey: ["findings", status],
    queryFn: () => api<Finding[]>(`/v1/findings?status=${status}`),
  });

  const accounts = useQuery({
    queryKey: ["accounts"],
    queryFn: () => api<Account[]>("/v1/accounts"),
  });

  const connectedId = accounts.data?.find((a) => a.status === "connected")?.id;

  const scanRun = useQuery({
    queryKey: ["scan-run-latest", connectedId],
    queryFn: () =>
      connectedId
        ? api<{
            id: string;
            status: string;
            started_at: string;
            finished_at: string | null;
            error: string | null;
          } | null>(`/v1/accounts/${connectedId}/scan-runs/latest`)
        : null,
    enabled: !!connectedId,
    refetchInterval: (query) => (query.state.data?.status === "running" ? 5000 : false),
  });

  const scanStatus = scanRun.data?.status ?? null;
  const scanStartedAt = scanRun.data?.started_at ? new Date(scanRun.data.started_at) : null;
  const scanStuck = scanStartedAt ? Date.now() - scanStartedAt.getTime() > 5 * 60 * 1000 : false;
  const isRunning = scanStatus === "running" && !scanStuck;

  useEffect(() => {
    if (prevScanStatus.current === "running" && scanStatus === "ok") {
      qc.invalidateQueries({ queryKey: ["findings"] });
    }
    prevScanStatus.current = scanStatus;
  }, [scanStatus, qc]);

  const scan = useMutation({
    mutationFn: (id: string) => api(`/v1/accounts/${id}/scan`, { method: "POST" }),
    onSuccess: () => {
      setTimeout(() => qc.invalidateQueries({ queryKey: ["scan-run-latest"] }), 1000);
    },
  });

  const act = useMutation({
    mutationFn: ({ id, action }: { id: string; action: "snooze" | "resolve" | "ignore" }) =>
      api(`/v1/findings/${id}/${action}`, {
        method: "POST",
        body: action === "snooze" ? JSON.stringify({ days: 30 }) : JSON.stringify({}),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["findings"] }),
  });

  const findings = q.data ?? [];

  const rows = useMemo(() => {
    const arr = [...findings];
    arr.sort((a, b) => {
      let cmp = 0;
      if (sortKey === "severity") {
        const sa = sevWeight[a.severity] ?? 9;
        const sb = sevWeight[b.severity] ?? 9;
        cmp = sa - sb || b.risk_score - a.risk_score;
      } else if (sortKey === "score") {
        cmp = b.risk_score - a.risk_score;
      } else if (sortKey === "first_seen") {
        cmp = new Date(b.first_seen).getTime() - new Date(a.first_seen).getTime();
      }
      return sortDir === "asc" ? cmp : -cmp;
    });
    return arr;
  }, [findings, sortKey, sortDir]);

  const totals = useMemo(() => {
    const t = { open: 0, critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of findings) {
      t.open++;
      t[f.severity as keyof typeof t]++;
    }
    return t;
  }, [findings]);

  function toggleSort(k: SortKey) {
    if (sortKey === k) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else {
      setSortKey(k);
      setSortDir(k === "severity" ? "asc" : "desc");
    }
  }

  return (
    <>
      {/* Top bar */}
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-zinc-900">Findings</h1>
          <p className="text-[13px] text-zinc-500 mt-0.5">
            {totals.open} open
            {totals.critical + totals.high > 0 && (
              <>
                <span className="mx-1.5 text-zinc-300">·</span>
                <span className="text-red-600 font-medium">{totals.critical + totals.high} critical/high</span>
              </>
            )}
            {totals.medium > 0 && (
              <>
                <span className="mx-1.5 text-zinc-300">·</span>
                <span className="text-amber-600">{totals.medium} medium</span>
              </>
            )}
            {scanRun.data?.finished_at && (
              <>
                <span className="mx-1.5 text-zinc-300">·</span>
                <span>last scan {daysAgo(scanRun.data.finished_at)} ago</span>
              </>
            )}
          </p>
        </div>
        <div className="flex items-center gap-1.5">
          <button
            onClick={() => qc.invalidateQueries({ queryKey: ["findings"] })}
            className="flex items-center gap-1.5 border border-zinc-200 bg-white hover:bg-zinc-50 text-zinc-700 text-[13px] font-medium px-2.5 py-1.5 rounded transition-colors"
            title="Refresh"
          >
            <svg
              className={`w-3.5 h-3.5 ${q.isFetching ? "animate-spin" : ""}`}
              fill="none"
              stroke="currentColor"
              strokeWidth={2}
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
              />
            </svg>
            Refresh
          </button>
          {connectedId && (
            <button
              onClick={() => scan.mutate(connectedId)}
              disabled={scan.isPending || isRunning}
              className="flex items-center gap-1.5 bg-zinc-900 hover:bg-zinc-800 text-white text-[13px] font-medium px-3 py-1.5 rounded transition-colors disabled:opacity-50"
            >
              <svg
                className={`w-3.5 h-3.5 ${isRunning || scan.isPending ? "animate-spin" : ""}`}
                fill="none"
                stroke="currentColor"
                strokeWidth={2}
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
                />
              </svg>
              {isRunning ? "Scanning…" : scan.isPending ? "Triggering…" : "Re-scan"}
            </button>
          )}
        </div>
      </div>

      {/* Status strips */}
      {isRunning && (
        <div className="mb-3 border-l-2 border-zinc-900 bg-zinc-50 px-3 py-2 text-[13px] text-zinc-700 flex items-center gap-2">
          <svg className="w-3.5 h-3.5 animate-spin flex-shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
            />
          </svg>
          Scan running — findings refresh on completion.
        </div>
      )}
      {scanStatus === "error" && scanRun.data?.error && (
        <div className="mb-3 border-l-2 border-red-600 bg-red-50 px-3 py-2 text-[13px] text-red-700">
          <span className="font-medium">Last scan failed:</span> {scanRun.data.error}
        </div>
      )}

      {/* Tabs */}
      <div className="flex items-center border-b border-zinc-200 mb-3">
        {statusTabs.map((s) => (
          <button
            key={s}
            onClick={() => setStatus(s)}
            className={`px-3 py-2 text-[13px] font-medium capitalize border-b-2 -mb-px transition-colors ${
              status === s
                ? "border-zinc-900 text-zinc-900"
                : "border-transparent text-zinc-500 hover:text-zinc-700"
            }`}
          >
            {s}
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="border border-zinc-200 rounded bg-white overflow-hidden">
        <div className="grid grid-cols-[24px_140px_220px_minmax(0,1fr)_60px_70px_120px] items-center text-[11px] font-medium text-zinc-500 uppercase tracking-wide px-3 py-2 border-b border-zinc-200 bg-zinc-50">
          <span />
          <button onClick={() => toggleSort("severity")} className="text-left hover:text-zinc-900">
            Severity {sortKey === "severity" && (sortDir === "asc" ? "↑" : "↓")}
          </button>
          <span>Check</span>
          <span>Resource</span>
          <button onClick={() => toggleSort("score")} className="text-right hover:text-zinc-900">
            Score {sortKey === "score" && (sortDir === "asc" ? "↑" : "↓")}
          </button>
          <button onClick={() => toggleSort("first_seen")} className="text-right hover:text-zinc-900">
            Age {sortKey === "first_seen" && (sortDir === "asc" ? "↑" : "↓")}
          </button>
          <span className="text-right pr-1">Actions</span>
        </div>

        {q.isLoading && (
          <div className="px-3 py-10 text-center text-[13px] text-zinc-400">Loading…</div>
        )}
        {!q.isLoading && rows.length === 0 && (
          <div className="px-3 py-12 text-center text-[13px] text-zinc-500">
            No {status} findings.
          </div>
        )}

        <div className="divide-y divide-zinc-100">
          {rows.map((f) => (
            <div
              key={f.id}
              onClick={() => setSelected(f)}
              className="grid grid-cols-[24px_140px_220px_minmax(0,1fr)_60px_70px_120px] items-center px-3 py-2 hover:bg-zinc-50 cursor-pointer text-[13px] group"
            >
              <span className={`w-1.5 h-1.5 rounded-full ${sevDot[f.severity] ?? sevDot.low}`} title={f.severity} />
              <span className="capitalize text-zinc-700">{f.severity}</span>
              <span className="text-zinc-600 truncate" title={f.check_id}>
                {checkLabels[f.check_id] ?? f.check_id}
              </span>
              <span className="font-mono text-[12px] text-zinc-700 truncate" title={f.resource_arn}>
                {shortArn(f.resource_arn)}
              </span>
              <span className="text-right tabular-nums font-medium text-zinc-700">{f.risk_score}</span>
              <span className="text-right tabular-nums text-zinc-500">{daysAgo(f.first_seen)}</span>
              <div className="flex justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    act.mutate({ id: f.id, action: "snooze" });
                  }}
                  className="text-[11px] text-zinc-500 hover:text-zinc-900 px-1.5 py-0.5 rounded hover:bg-zinc-100"
                  title="Snooze 30d"
                >
                  Snooze
                </button>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    act.mutate({ id: f.id, action: "resolve" });
                  }}
                  className="text-[11px] text-zinc-500 hover:text-zinc-900 px-1.5 py-0.5 rounded hover:bg-zinc-100"
                >
                  Resolve
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      <FindingDrawer
        finding={selected}
        accountId={connectedId ?? null}
        onClose={() => setSelected(null)}
        onAction={(id, action) => act.mutate({ id, action })}
      />
    </>
  );
}
