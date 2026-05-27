import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api";

interface Account { id: string; label: string; account_id: string | null; status: string; }

interface CorrelatedPR {
  number: number;
  repo: string;
  merged_at: string;
  merged_by: string | null;
  author: string | null;
  approval_count: number;
  required_review_count: number;
  self_merge: boolean;
  delta_seconds: number;
}

interface TimelineEvent {
  type: "cloudtrail";
  event_id: string;
  event_name: string;
  event_source: string;
  event_time: string;
  actor: string | null;
  source_ip: string | null;
  resources: { type: string | null; name: string | null }[];
  correlated_prs: CorrelatedPR[];
}

interface TimelineResponse {
  events: TimelineEvent[];
  total: number;
}

function fmtDelta(seconds: number): string {
  const abs = Math.abs(seconds);
  if (abs < 60) return `${abs}s`;
  if (abs < 3600) return `${Math.round(abs / 60)}m`;
  return `${Math.round(abs / 3600)}h`;
}

function fmtTime(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function sourceLabel(source: string): string {
  return source.replace(".amazonaws.com", "");
}

function EventRow({ evt }: { evt: TimelineEvent }) {
  const [open, setOpen] = useState(false);
  const hasCorr = evt.correlated_prs.length > 0;

  return (
    <div
      className={`border rounded-xl overflow-hidden transition-all ${
        hasCorr
          ? "border-sky-500/30 bg-sky-950/20"
          : "border-zinc-800/60 bg-zinc-900/30"
      }`}
    >
      <button
        className="w-full text-left px-5 py-4 flex items-start gap-4"
        onClick={() => setOpen(!open)}
      >
        {/* Timeline dot */}
        <div className="flex-shrink-0 mt-1">
          <div
            className={`h-2.5 w-2.5 rounded-full mt-0.5 ${
              hasCorr ? "bg-sky-400 ring-2 ring-sky-400/30" : "bg-zinc-600"
            }`}
          />
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 flex-wrap">
            <span className="font-mono text-sm font-semibold text-zinc-100">{evt.event_name}</span>
            <span className="text-xs text-zinc-500 font-mono">{sourceLabel(evt.event_source)}</span>
            {hasCorr && (
              <span className="inline-flex items-center gap-1 rounded-md bg-sky-500/15 px-2 py-0.5 text-xs font-medium text-sky-300 ring-1 ring-sky-500/25">
                <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                </svg>
                {evt.correlated_prs.length} PR{evt.correlated_prs.length > 1 ? "s" : ""} matched
              </span>
            )}
          </div>
          <div className="mt-1 flex items-center gap-3 flex-wrap text-xs text-zinc-500">
            <span>{fmtTime(evt.event_time)}</span>
            {evt.actor && (
              <span className="truncate max-w-xs font-mono">{evt.actor.split("/").pop()}</span>
            )}
            {evt.resources.length > 0 && (
              <span className="font-mono text-zinc-600 truncate max-w-xs">
                {evt.resources.map(r => r.name || r.type || "").filter(Boolean).join(", ")}
              </span>
            )}
          </div>
        </div>

        <svg
          className={`w-4 h-4 flex-shrink-0 mt-1 text-zinc-600 transition-transform ${open ? "rotate-180" : ""}`}
          fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {open && (
        <div className="px-5 pb-5 pt-1 border-t border-zinc-800/60 space-y-4">
          {/* Event details */}
          <div className="grid grid-cols-2 gap-x-8 gap-y-2 text-xs">
            <div>
              <span className="text-zinc-500 uppercase tracking-wide text-[10px]">Time</span>
              <p className="text-zinc-200 font-mono mt-0.5">{evt.event_time}</p>
            </div>
            {evt.actor && (
              <div>
                <span className="text-zinc-500 uppercase tracking-wide text-[10px]">Actor</span>
                <p className="text-zinc-200 font-mono mt-0.5 break-all">{evt.actor}</p>
              </div>
            )}
            {evt.source_ip && (
              <div>
                <span className="text-zinc-500 uppercase tracking-wide text-[10px]">Source IP</span>
                <p className="text-zinc-200 font-mono mt-0.5">{evt.source_ip}</p>
              </div>
            )}
            {evt.resources.length > 0 && (
              <div className="col-span-2">
                <span className="text-zinc-500 uppercase tracking-wide text-[10px]">Resources</span>
                <ul className="mt-0.5 space-y-0.5">
                  {evt.resources.map((r, i) => (
                    <li key={i} className="text-zinc-300 font-mono">
                      {r.name || "—"}{r.type ? <span className="text-zinc-600"> ({r.type})</span> : null}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {/* Correlated PRs */}
          {evt.correlated_prs.length > 0 && (
            <div>
              <div className="text-xs font-medium text-sky-400 mb-2 flex items-center gap-1.5">
                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                </svg>
                Correlated GitHub PRs (±60 min)
              </div>
              <div className="space-y-2">
                {evt.correlated_prs.map((pr, i) => (
                  <div
                    key={i}
                    className="rounded-lg bg-sky-950/40 border border-sky-500/20 px-4 py-3 text-xs"
                  >
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-semibold text-sky-300">{pr.repo}#{pr.number}</span>
                      <span className="text-zinc-400">merged {fmtTime(pr.merged_at)}</span>
                      <span className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${
                        pr.delta_seconds < 0
                          ? "bg-emerald-500/15 text-emerald-300"
                          : "bg-amber-500/15 text-amber-300"
                      }`}>
                        {pr.delta_seconds < 0 ? "PR merged " : "PR merged "}
                        {fmtDelta(pr.delta_seconds)} {pr.delta_seconds < 0 ? "before" : "after"} event
                      </span>
                      {pr.self_merge && (
                        <span className="rounded px-1.5 py-0.5 text-[10px] font-medium bg-red-500/15 text-red-300">
                          self-merge
                        </span>
                      )}
                    </div>
                    <div className="mt-1.5 flex items-center gap-3 text-zinc-500 flex-wrap">
                      {pr.author && <span>by <span className="text-zinc-300 font-mono">{pr.author}</span></span>}
                      {pr.merged_by && pr.merged_by !== pr.author && (
                        <span>merged by <span className="text-zinc-300 font-mono">{pr.merged_by}</span></span>
                      )}
                      <span>{pr.approval_count} approval{pr.approval_count !== 1 ? "s" : ""}</span>
                      {pr.required_review_count > 0 && (
                        <span className="text-zinc-600">(required: {pr.required_review_count})</span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

const TIMELINE_WINDOWS = [
  { value: 7, label: "Last 7 days" },
  { value: 30, label: "Last 30 days" },
  { value: 90, label: "Last 90 days" },
] as const;

export default function Timeline() {
  const [days, setDays] = useState(30);

  const { data: accounts } = useQuery<Account[]>({
    queryKey: ["accounts"],
    queryFn: () => api("/v1/accounts"),
  });

  const connected = (accounts || []).filter(a => a.status === "connected");
  const [accountId, setAccountId] = useState<string>("");

  // Auto-select first connected account
  const effectiveAccountId = accountId || connected[0]?.id || "";

  const { data, isLoading, error } = useQuery<TimelineResponse>({
    queryKey: ["timeline", effectiveAccountId, days],
    queryFn: () => api(`/v1/accounts/${effectiveAccountId}/timeline?days=${days}&limit=200`),
    enabled: !!effectiveAccountId,
  });

  const correlated = data?.events.filter(e => e.correlated_prs.length > 0) || [];
  const total = data?.total || 0;

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-semibold text-zinc-900">Change Timeline</h1>
        <p className="mt-1 text-sm text-zinc-500">
          CloudTrail infrastructure events correlated with GitHub PR merges within ±60 minutes.
        </p>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          {connected.length > 1 && (
            <select
              value={effectiveAccountId}
              onChange={(e) => setAccountId(e.target.value)}
              aria-label="AWS account"
              className="h-[42px] appearance-none rounded-xl border border-zinc-200 bg-white px-3 pr-8 text-sm font-semibold text-zinc-600 shadow-sm shadow-zinc-950/[0.03] outline-none transition hover:border-zinc-300 focus:border-indigo-300 focus:ring-2 focus:ring-indigo-500/20"
            >
              {connected.map((a) => (
                <option key={a.id} value={a.id}>{a.label}</option>
              ))}
            </select>
          )}

          <div className="relative">
            <select
              value={days}
              onChange={(e) => setDays(Number(e.target.value))}
              aria-label="Timeline window"
              className="h-[42px] appearance-none rounded-xl border border-zinc-200 bg-white pl-3 pr-8 text-sm font-semibold text-zinc-600 shadow-sm shadow-zinc-950/[0.03] outline-none transition hover:border-zinc-300 focus:border-indigo-300 focus:ring-2 focus:ring-indigo-500/20"
            >
              {TIMELINE_WINDOWS.map((window) => (
                <option key={window.value} value={window.value}>
                  {window.label}
                </option>
              ))}
            </select>
            <svg className="pointer-events-none absolute right-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-400" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
            </svg>
          </div>
        </div>

        {data && (
          <span className="text-sm tabular-nums text-zinc-500">
            {total} event{total !== 1 ? "s" : ""} · {correlated.length} correlated
          </span>
        )}
      </div>

      {/* No account */}
      {!effectiveAccountId && (
        <div className="rounded-xl border border-zinc-200 bg-white p-12 text-center">
          <p className="text-zinc-500">No connected AWS account found. Connect an account to view the timeline.</p>
        </div>
      )}

      {/* Loading */}
      {isLoading && (
        <div className="space-y-3">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-16 rounded-xl bg-zinc-100 animate-pulse" />
          ))}
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="rounded-xl border border-red-200 bg-red-50 px-5 py-4 text-sm text-red-700">
          {String(error)}
        </div>
      )}

      {/* Empty */}
      {data && total === 0 && (
        <div className="rounded-xl border border-zinc-200 bg-white p-12 text-center">
          <svg className="mx-auto mb-3 h-10 w-10 text-zinc-300" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <p className="text-zinc-500">No CloudTrail events collected yet.</p>
          <p className="mt-1 text-sm text-zinc-400">Run a scan to collect the last 90 days of infrastructure events.</p>
        </div>
      )}

      {/* Correlation banner */}
      {data && correlated.length > 0 && (
        <div className="rounded-xl border border-sky-500/30 bg-sky-50 px-5 py-3.5 flex items-start gap-3">
          <svg className="w-5 h-5 text-sky-500 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
          </svg>
          <div className="text-sm">
            <span className="font-medium text-sky-800">{correlated.length} event{correlated.length !== 1 ? "s" : ""} matched to GitHub PRs.</span>
            <span className="ml-1.5 text-sky-700">
              Infrastructure changes with an approved PR within ±60 minutes are highlighted.
            </span>
          </div>
        </div>
      )}

      {/* Events list */}
      {data && total > 0 && (
        <div className="space-y-2">
          {data.events.map(evt => (
            <EventRow key={evt.event_id} evt={evt} />
          ))}
        </div>
      )}
    </div>
  );
}
