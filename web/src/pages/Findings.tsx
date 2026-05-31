import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, useEffect, useRef, useMemo, useCallback } from "react";
import { useSearchParams } from "react-router-dom";
import { api, token } from "../api";
import ConnectAwsEmptyState from "../components/ConnectAwsEmptyState";
import {
  FindingDrawer,
  defaultFindingRemediationMode,
  type FindingDrawerTab,
  type FindingRemediationMode,
} from "../components/FindingDrawer";
import { SearchReferenceModal } from "../components/SearchReferenceModal";
import ScanProgressBar from "../components/ScanProgressBar";
import { checkLabels } from "../data/checkLabels";
import { CHECK_FRAMEWORK_MAP } from "../data/checkFrameworkMap";
import { FRAMEWORKS, frameworkLabel, type FrameworkId } from "../data/frameworks";
import { remediationSummaryFor } from "../data/remediationSummaries";
import { affectedResourcesPreview, daysAgo, severityLabel } from "../lib/findingDisplay";
import { useTriggeredScan } from "../hooks/useTriggeredScan";
import { isAccountConnected } from "../lib/accountConnection";
import NotificationsBell from "../components/NotificationsBell";
import {
  useRecheckNotifications,
  type RecheckResponse,
} from "../context/RecheckNotificationsContext";

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
  exception_reason?: string | null;
  exception_approved_by?: string | null;
  exception_expires_at?: string | null;
};

type FindingPage = {
  items: Finding[];
  total: number;
  next_cursor: string | null;
};

type Account = { id: string; status: string; cfn_launch_url?: string };

const COLLAPSED_FINDINGS_KEY = "vigil.findings.collapsedGroups";

const sevBadge: Record<string, string> = {
  critical: "bg-red-50 text-red-700 ring-red-200/70",
  high: "bg-orange-50 text-orange-700 ring-orange-200/70",
  medium: "bg-amber-50 text-amber-800 ring-amber-200/70",
  low: "bg-zinc-100 text-zinc-600 ring-zinc-200/70",
};

const sevBorder: Record<string, string> = {
  critical: "border-l-red-500",
  high: "border-l-orange-500",
  medium: "border-l-amber-400",
  low: "border-l-zinc-300",
};

const sevRiskTone: Record<string, string> = {
  critical: "text-red-700",
  high: "text-orange-700",
  medium: "text-amber-700",
  low: "text-zinc-700",
};

const sevWeight: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

const statusTabs = ["open", "excepted", "resolved", "all"] as const;
type StatusTab = (typeof statusTabs)[number];

const statusTabLabels: Record<StatusTab, string> = {
  open: "Open",
  excepted: "Exceptions",
  resolved: "Resolved",
  all: "All",
};

type SeverityFilter = "all" | "critical_high" | "medium" | "low";
type SortKey = "severity" | "score" | "first_seen";
type BenchmarkFilter = "all" | FrameworkId;

function emptyFindingsLabel(status: StatusTab): string {
  if (status === "all") return "No findings";
  if (status === "excepted") return "No exceptions";
  return `No ${status} findings`;
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
  if (k === "score") return "Risk";
  return "Severity";
}

function sortIcon(k: SortKey, active: SortKey, dir: "asc" | "desc"): string {
  if (k !== active) return "";
  return dir === "asc" ? "↑" : "↓";
}

function frameworksForCheck(checkId: string, apiMap: Record<string, string[]> | undefined): string[] {
  return apiMap?.[checkId] ?? CHECK_FRAMEWORK_MAP[checkId] ?? [];
}

function matchesBenchmarkFilter(
  f: Finding,
  benchmarkFilter: BenchmarkFilter,
  apiMap: Record<string, string[]> | undefined,
): boolean {
  if (benchmarkFilter === "all") return true;
  return frameworksForCheck(f.check_id, apiMap).includes(benchmarkFilter);
}

function FindingIssueCard({
  checkId,
  items,
  onReview,
}: {
  checkId: string;
  items: Finding[];
  onReview: (items: Finding[]) => void;
}) {
  const sev = items[0]?.severity ?? "low";
  const title = checkLabels[checkId] ?? items[0]?.title ?? checkId;
  const ops = remediationSummaryFor(checkId);
  const count = items.length;
  const topRisk = Math.max(...items.map((f) => f.risk_score));
  const oldest = items.reduce((a, b) => (new Date(a.first_seen) < new Date(b.first_seen) ? a : b));
  const affectedPreview = affectedResourcesPreview(items);

  return (
    <article
      role="button"
      tabIndex={0}
      onClick={() => onReview(items)}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onReview(items);
        }
      }}
      className={`group cursor-pointer rounded-xl border border-zinc-200/80 border-l-[3px] bg-white px-4 py-4 transition hover:border-zinc-300 hover:shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500/30 ${sevBorder[sev] ?? sevBorder.low}`}
    >
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2.5">
            <span
              className={`inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-bold uppercase tracking-wide ring-1 ${sevBadge[sev] ?? sevBadge.low}`}
            >
              {severityLabel(sev)}
            </span>
            <span className="text-xs font-medium text-zinc-500">
              {count} resource{count === 1 ? "" : "s"}
            </span>
          </div>
          <h3 className="mt-2 text-[15px] font-semibold leading-snug text-zinc-900">{title}</h3>
        </div>
        <div className="relative shrink-0 self-start">
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              onReview(items);
            }}
            className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3.5 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-700 group-hover:bg-indigo-700 active:scale-[0.98]"
          >
            Review
            <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
            </svg>
          </button>
          <p className="pointer-events-none absolute left-1/2 top-full mt-4 w-max -translate-x-1/2 whitespace-nowrap text-center leading-none">
            <span className="text-xs font-medium text-zinc-400">Risk </span>
            <span className={`text-lg font-bold tabular-nums ${sevRiskTone[sev] ?? sevRiskTone.low}`}>{topRisk}</span>
          </p>
        </div>
      </div>

      <p className="mt-2.5 text-sm leading-relaxed text-zinc-600">{ops.impact}</p>
      <p className="mt-1 text-[13px] leading-relaxed text-zinc-500">{ops.fix}</p>

      <div className="mt-3.5 rounded-lg bg-zinc-50/90 px-3 py-2.5 ring-1 ring-zinc-100/80">
        {affectedPreview ? (
          <p className="truncate font-mono text-[13px] text-zinc-600">{affectedPreview}</p>
        ) : (
          <p className="text-[13px] text-zinc-500">No resource names available</p>
        )}
        <p className="mt-1 text-xs text-zinc-400">First seen {daysAgo(oldest.first_seen)}</p>
      </div>
    </article>
  );
}

function BenchmarkScopeSelect({
  value,
  onChange,
}: {
  value: BenchmarkFilter;
  onChange: (v: BenchmarkFilter) => void;
}) {
  return (
    <div className="relative shrink-0">
      <svg
        className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-indigo-600/75"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
        aria-hidden
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={1.75}
          d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"
        />
      </svg>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value as BenchmarkFilter)}
        aria-label="Findings scope by benchmark"
        className="h-10 min-w-[13rem] cursor-pointer appearance-none rounded-xl border border-zinc-300/90 bg-white pl-9 pr-9 text-sm font-semibold text-zinc-800 shadow-sm outline-none transition hover:border-zinc-400 focus:border-indigo-400 focus:ring-2 focus:ring-indigo-500/20"
      >
        <option value="all">All benchmarks</option>
        {FRAMEWORKS.map((fw) => (
          <option key={fw.id} value={fw.id}>
            {fw.label}
          </option>
        ))}
      </select>
      <svg
        className="pointer-events-none absolute right-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-400"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
        aria-hidden
      >
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
      </svg>
    </div>
  );
}

function metricTileClasses(
  accent: "neutral" | "red" | "amber",
  isActive: boolean,
): string {
  if (accent === "red") {
    return isActive
      ? "bg-red-50 text-red-800 ring-1 ring-red-200/80 shadow-sm shadow-red-100/80"
      : "text-red-700 hover:bg-red-50/70 hover:shadow-md hover:shadow-red-100/60 hover:ring-1 hover:ring-red-200/50";
  }
  if (accent === "amber") {
    return isActive
      ? "bg-amber-50 text-amber-900 ring-1 ring-amber-200/80 shadow-sm shadow-amber-100/80"
      : "text-amber-800 hover:bg-amber-50/70 hover:shadow-md hover:shadow-amber-100/60 hover:ring-1 hover:ring-amber-200/50";
  }
  return isActive
    ? "bg-zinc-100 text-zinc-900 ring-1 ring-zinc-200/90 shadow-sm shadow-zinc-200/50"
    : "text-zinc-800 hover:bg-zinc-50 hover:shadow-md hover:shadow-zinc-200/40 hover:ring-1 hover:ring-zinc-200/60";
}

function MetricSummary({
  totals,
  active,
  onSelect,
  highlightActive = true,
}: {
  totals: { open: number; critical: number; high: number; medium: number; low: number };
  active: SeverityFilter;
  onSelect: (f: SeverityFilter) => void;
  highlightActive?: boolean;
}) {
  const chTotal = totals.critical + totals.high;
  const items: {
    key: SeverityFilter;
    label: string;
    value: number;
    accent: "neutral" | "red" | "amber";
    prominent?: boolean;
  }[] = [
    { key: "all", label: "Open", value: totals.open, accent: "neutral", prominent: true },
    { key: "critical_high", label: "Crit + high", value: chTotal, accent: "red", prominent: true },
    { key: "medium", label: "Medium", value: totals.medium, accent: "amber" },
    { key: "low", label: "Low", value: totals.low, accent: "neutral" },
  ];

  return (
    <div className="inline-flex flex-wrap items-center gap-1">
      {items.map((item) => {
        const isActive = highlightActive && active === item.key;
        return (
          <button
            key={item.key}
            type="button"
            onClick={() => onSelect(item.key)}
            className={`inline-flex min-w-[4.5rem] flex-col items-center rounded-lg border border-transparent px-2.5 py-2 transition ${metricTileClasses(item.accent, isActive)}`}
          >
            <span
              className={`tabular-nums leading-none ${item.prominent ? "text-2xl font-bold" : "text-xl font-semibold"}`}
            >
              {item.value}
            </span>
            <span
              className={`mt-1 uppercase tracking-wide ${
                item.prominent ? "text-[11px] font-semibold opacity-80" : "text-[11px] font-medium opacity-70"
              }`}
            >
              {item.label}
            </span>
          </button>
        );
      })}
    </div>
  );
}

const ALL_CHECK_IDS = Object.keys(checkLabels);

function TagSearchInput({
  tags,
  onTagsChange,
  className,
}: {
  tags: string[];
  onTagsChange: (t: string[]) => void;
  className?: string;
}) {
  const [input, setInput] = useState("");
  const [open, setOpen] = useState(false);
  const [hi, setHi] = useState(0);
  const [helpOpen, setHelpOpen] = useState(false);
  const [refOpen, setRefOpen] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function onMouseDown(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
        setHelpOpen(false);
        setInput("");
      }
    }
    document.addEventListener("mousedown", onMouseDown);
    return () => document.removeEventListener("mousedown", onMouseDown);
  }, []);

  const suggestions = useMemo(() => {
    if (!input.trim()) return [];
    const q = input.toLowerCase();
    return ALL_CHECK_IDS.filter(
      (s) => !tags.includes(s) && (s.includes(q) || (checkLabels[s] ?? "").toLowerCase().includes(q)),
    ).slice(0, 8);
  }, [input, tags]);

  function commit(value: string) {
    const v = value.trim().replace(/,+$/, "");
    if (v && !tags.includes(v)) onTagsChange([...tags, v]);
    setInput("");
    setOpen(false);
    setHi(0);
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "," || e.key === "Enter" || e.key === "Tab") {
      if (!input.trim() && e.key === "Tab") return;
      e.preventDefault();
      commit(suggestions[hi] ?? input);
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      setHi((h) => Math.min(h + 1, Math.max(0, suggestions.length - 1)));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setHi((h) => Math.max(h - 1, 0));
    } else if (e.key === "Backspace" && input === "" && tags.length > 0) {
      onTagsChange(tags.slice(0, -1));
    } else if (e.key === "Escape") {
      setOpen(false);
      setInput("");
    }
  }

  return (
    <div className="relative" ref={containerRef}>
      <div
        className={`flex min-h-10 items-center rounded-xl border border-zinc-200/90 bg-white shadow-sm transition focus-within:border-zinc-300 focus-within:ring-2 focus-within:ring-zinc-950/[0.04] ${className ?? "w-80"}`}
        onClick={() => inputRef.current?.focus()}
      >
        <div className="flex min-w-0 flex-1 flex-wrap items-center gap-1.5 px-3 py-1.5">
          {tags.map((tag) => (
            <span key={tag} className="inline-flex max-w-[10rem] items-center gap-1 rounded-md border border-indigo-200 bg-indigo-50 px-2 py-0.5 text-xs font-mono text-indigo-700">
              <span className="truncate">{tag}</span>
              <button
                type="button"
                className="text-indigo-400 hover:text-indigo-700"
                onClick={(e) => {
                  e.stopPropagation();
                  onTagsChange(tags.filter((t) => t !== tag));
                }}
              >
                ×
              </button>
            </span>
          ))}
          <input
            ref={inputRef}
            value={input}
            onChange={(e) => {
              setInput(e.target.value);
              setOpen(true);
              setHi(0);
            }}
            onKeyDown={handleKeyDown}
            onFocus={() => setOpen(true)}
            placeholder={tags.length === 0 ? "Search findings…" : "Add filter…"}
            className="min-w-28 flex-1 bg-transparent text-sm text-zinc-800 outline-none placeholder:text-zinc-400"
          />
        </div>
        <div className="flex items-center gap-1 pr-2">
          {tags.length === 0 && input.trim() === "" && (
            <button
              type="button"
              aria-label="Search help"
              className="flex h-5 w-5 items-center justify-center rounded-full border border-zinc-200 bg-zinc-50 text-xs font-bold text-zinc-400 transition hover:border-indigo-200 hover:bg-indigo-50 hover:text-indigo-600"
              onClick={(e) => {
                e.stopPropagation();
                setHelpOpen((p) => !p);
                setOpen(false);
              }}
            >
              ?
            </button>
          )}
          {tags.length > 0 && (
            <button
              type="button"
              className="px-0.5 text-base leading-none text-zinc-300 transition hover:text-zinc-500"
              onClick={(e) => {
                e.stopPropagation();
                onTagsChange([]);
              }}
            >
              ×
            </button>
          )}
        </div>
      </div>

      {helpOpen && (
        <div className="absolute right-0 z-20 mt-1 w-80 rounded-xl border border-zinc-200 bg-white p-3 text-left shadow-lg">
          <div className="text-xs font-semibold text-zinc-700">Search lookup</div>
          <p className="mt-1 text-xs leading-relaxed text-zinc-500">
            Search by check, resource, ARN, or resource family. Examples: <span className="font-mono text-zinc-700">iam.root</span>,{" "}
            <span className="font-mono text-zinc-700">s3.bucket</span>, <span className="font-mono text-zinc-700">ec2.instance</span>.
          </p>
          <button
            type="button"
            onClick={() => {
              setHelpOpen(false);
              setRefOpen(true);
            }}
            className="mt-3 inline-flex items-center text-xs font-semibold text-indigo-600 hover:text-indigo-700"
          >
            Open search reference
            <svg className="ml-1 h-3 w-3" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
            </svg>
          </button>
        </div>
      )}

      {refOpen && <SearchReferenceModal onClose={() => setRefOpen(false)} />}

      {open && suggestions.length > 0 && (
        <div className="absolute z-20 mt-1 w-full min-w-80 overflow-hidden rounded-xl border border-zinc-200 bg-white shadow-lg">
          {suggestions.map((s, i) => (
            <button
              key={s}
              type="button"
              className={`flex w-full items-center gap-2 px-3 py-2 text-left transition-colors ${i === hi ? "bg-zinc-100" : "hover:bg-zinc-50"}`}
              onMouseDown={() => commit(s)}
              onMouseEnter={() => setHi(i)}
            >
              <span className="shrink-0 text-xs font-mono font-semibold text-zinc-700">{s}</span>
              {checkLabels[s] && <span className="truncate text-xs text-zinc-400">{checkLabels[s]}</span>}
            </button>
          ))}
          <div className="border-t border-zinc-100 px-3 py-1.5 text-[10px] text-zinc-400">
            Tab / Enter / comma to add. Backspace removes last filter.
          </div>
        </div>
      )}
    </div>
  );
}

function StatusTabs({ status, onChange }: { status: StatusTab; onChange: (status: StatusTab) => void }) {
  return (
    <div className="flex items-center gap-1 rounded-xl border border-zinc-200/80 bg-zinc-100/60 p-1">
      {statusTabs.map((s) => (
        <button
          key={s}
          onClick={() => onChange(s)}
          className={`rounded-lg px-4 py-2 text-sm font-semibold transition ${
            status === s
              ? "bg-white text-zinc-900 shadow-sm ring-1 ring-zinc-200/80"
              : "text-zinc-500 hover:text-zinc-800"
          }`}
        >
          {statusTabLabels[s]}
        </button>
      ))}
    </div>
  );
}

function SortToggle({
  sortKey,
  sortDir,
  onToggle,
}: {
  sortKey: SortKey;
  sortDir: "asc" | "desc";
  onToggle: (key: SortKey) => void;
}) {
  return (
    <div className="flex shrink-0 items-center gap-1 rounded-xl border border-zinc-200/80 bg-zinc-100/60 p-1">
      {(["severity", "score", "first_seen"] as SortKey[]).map((k) => (
        <button
          key={k}
          onClick={() => onToggle(k)}
          className={`inline-flex h-9 items-center gap-1 rounded-lg px-3.5 text-sm font-medium transition ${
            sortKey === k
              ? "bg-white font-semibold text-zinc-900 shadow-sm ring-1 ring-zinc-200/80"
              : "text-zinc-500 hover:text-zinc-700"
          }`}
        >
          {sortLabel(k)}
          {sortKey === k && <span className="text-xs text-zinc-400">{sortIcon(k, sortKey, sortDir)}</span>}
        </button>
      ))}
    </div>
  );
}

export default function Findings() {
  const qc = useQueryClient();
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [searchParams, setSearchParams] = useSearchParams();
  const [status, setStatus] = useState<StatusTab>("open");
  const [selected, setSelected] = useState<Finding | null>(null);
  const [drawerGroup, setDrawerGroup] = useState<Finding[] | null>(null);
  const [drawerTab, setDrawerTab] = useState<FindingDrawerTab>("overview");
  const [remTab, setRemTab] = useState<FindingRemediationMode>("console");
  const [sortKey, setSortKey] = useState<SortKey>("severity");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const {
    pendingRecheck,
    recheckOutcome,
    startRecheck,
    applyRecheckResult,
    failRecheck,
    clearDrawerVerifyFlash,
  } = useRecheckNotifications();
  const [searchTags, setSearchTags] = useState<string[]>(() => {
    const raw = searchParams.get("checks");
    return raw ? raw.split(",").filter(Boolean) : [];
  });
  const [benchmarkFilter, setBenchmarkFilter] = useState<BenchmarkFilter>(() => {
    const fw = searchParams.get("framework");
    if (fw && FRAMEWORKS.some((f) => f.id === fw)) return fw as FrameworkId;
    return "all";
  });

  const frameworkMapQ = useQuery({
    queryKey: ["check-frameworks"],
    queryFn: () => api<{ checks: Record<string, string[]> }>("/v1/controls/check-frameworks"),
    staleTime: 300_000,
  });

  const q = useQuery({
    queryKey: ["findings", status],
    queryFn: () => api<FindingPage>(`/v1/findings?status=${status}&limit=500`),
    refetchInterval: pendingRecheck ? 3000 : false,
  });

  const openMetricsQ = useQuery({
    queryKey: ["findings", "open"],
    queryFn: () => api<FindingPage>("/v1/findings?status=open&limit=500"),
    refetchInterval: pendingRecheck ? 3000 : false,
  });

  const accounts = useQuery({ queryKey: ["accounts"], queryFn: () => api<Account[]>("/v1/accounts") });
  const connectedAccount = accounts.data?.find((a) => isAccountConnected(a));
  const connectedId = connectedAccount?.id;

  const {
    scanRun,
    scanStatus,
    isRunning,
    scanTriggered,
    isScanActive,
    scanProgress,
    triggerScan,
  } = useTriggeredScan(connectedId, {
    onScanComplete: () => qc.invalidateQueries({ queryKey: ["findings"] }),
  });

  useEffect(() => {
    try {
      localStorage.removeItem(COLLAPSED_FINDINGS_KEY);
    } catch {
      /* ignore */
    }
  }, []);

  useEffect(() => {
    if (isRefreshing && !q.isFetching) {
      const t = setTimeout(() => setIsRefreshing(false), 600);
      return () => clearTimeout(t);
    }
  }, [q.isFetching, isRefreshing]);

  const act = useMutation({
    mutationFn: ({ id, action }: { id: string; action: "recheck" | "reopen" }) =>
      api(`/v1/findings/${id}/${action}`, { method: "POST", body: JSON.stringify({}) }),
    onSuccess: (data, { id, action }) => {
      if (action === "recheck") {
        const result = data as RecheckResponse;
        const checkId = selected?.check_id ?? result.check_id ?? "";
        if (!applyRecheckResult(id, checkId, result)) {
          setTimeout(() => qc.invalidateQueries({ queryKey: ["findings"] }), 6000);
        }
      } else {
        qc.invalidateQueries({ queryKey: ["findings"] });
        if (selected) setSelected(data as Finding);
        if (action === "reopen") {
          clearDrawerVerifyFlash();
          setStatus("open");
        }
      }
    },
    onError: (_err, { id, action }) => {
      if (action === "recheck" && selected) {
        failRecheck(id, selected.check_id);
      }
    },
  });

  const downloadCsv = useCallback(async () => {
    const BASE = (import.meta.env.VITE_API_URL as string) || "http://localhost:8000";
    const t = token();
    const res = await fetch(`${BASE}/v1/exports/findings.csv?status=${status}`, {
      headers: t ? { Authorization: `Bearer ${t}` } : {},
    });
    if (!res.ok) return;
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "vigil-findings.csv";
    a.click();
    URL.revokeObjectURL(url);
  }, [status]);

  function openReview(items: Finding[]) {
    const top = items.reduce((best, f) => (f.risk_score > best.risk_score ? f : best), items[0]);
    setDrawerGroup(items.length > 1 ? items : null);
    setSelected(top);
    setDrawerTab("overview");
    setRemTab(defaultFindingRemediationMode(top.check_id));
    clearDrawerVerifyFlash();
  }

  function closeDrawer() {
    setSelected(null);
    setDrawerGroup(null);
    clearDrawerVerifyFlash();
  }

  function handleTagsChange(tags: string[]) {
    setSearchTags(tags);
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      if (tags.length > 0) next.set("checks", tags.join(","));
      else next.delete("checks");
      return next;
    }, { replace: true });
  }

  function handleBenchmarkChange(fw: BenchmarkFilter) {
    setBenchmarkFilter(fw);
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      if (fw === "all") next.delete("framework");
      else next.set("framework", fw);
      return next;
    }, { replace: true });
  }

  function handleRefresh() {
    if (isRefreshing) return;
    qc.invalidateQueries({ queryKey: ["findings"] });
    setIsRefreshing(true);
  }

  function handleMetricSelect(filter: SeverityFilter) {
    setSeverityFilter(filter);
    if (status !== "open") setStatus("open");
  }

  function toggleSort(k: SortKey) {
    if (sortKey === k) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else {
      setSortKey(k);
      setSortDir(k === "severity" ? "asc" : "desc");
    }
  }

  const findings = q.data?.items ?? [];
  const checkFrameworksApi = frameworkMapQ.data?.checks;
  const openFindingsForMetrics = openMetricsQ.data?.items ?? (status === "open" ? findings : []);

  const verifying = !!(selected && pendingRecheck?.findingId === selected.id);
  const verified = !!(
    selected &&
    recheckOutcome?.findingId === selected.id &&
    recheckOutcome.status === "verified"
  );
  const verifyUnchanged = !!(
    selected &&
    recheckOutcome?.findingId === selected.id &&
    recheckOutcome.status === "unchanged"
  );

  const metricBenchmarkScoped = useMemo(
    () => openFindingsForMetrics.filter((f) => matchesBenchmarkFilter(f, benchmarkFilter, checkFrameworksApi)),
    [openFindingsForMetrics, benchmarkFilter, checkFrameworksApi],
  );

  const metricTotals = useMemo(() => {
    const t = { open: 0, critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of metricBenchmarkScoped) {
      t.open++;
      if (f.severity in t) t[f.severity as keyof typeof t]++;
    }
    return t;
  }, [metricBenchmarkScoped]);

  const benchmarkScopedFindings = useMemo(
    () => findings.filter((f) => matchesBenchmarkFilter(f, benchmarkFilter, checkFrameworksApi)),
    [findings, benchmarkFilter, checkFrameworksApi],
  );

  const rows = useMemo(() => {
    const arr = benchmarkScopedFindings.filter((f) => {
      if (status === "open" && !matchesSeverityFilter(f, severityFilter)) return false;
      if (searchTags.length === 0) return true;
      return searchTags.some((tag) => {
        if (f.check_id === tag) return true;
        const haystack = [f.title, f.check_id, f.resource_arn, checkLabels[f.check_id] ?? ""].join(" ").toLowerCase();
        return haystack.includes(tag.toLowerCase());
      });
    });
    arr.sort((a, b) => {
      let cmp = 0;
      if (sortKey === "severity") cmp = (sevWeight[a.severity] ?? 9) - (sevWeight[b.severity] ?? 9) || b.risk_score - a.risk_score;
      else if (sortKey === "score") cmp = b.risk_score - a.risk_score;
      else cmp = new Date(b.first_seen).getTime() - new Date(a.first_seen).getTime();
      return sortDir === "asc" ? cmp : -cmp;
    });
    return arr;
  }, [benchmarkScopedFindings, searchTags, severityFilter, sortKey, sortDir, status]);

  const displayGroups = useMemo(() => {
    const map = new Map<string, Finding[]>();
    for (const f of rows) {
      const list = map.get(f.check_id) ?? [];
      list.push(f);
      map.set(f.check_id, list);
    }
    const entries = [...map.entries()];
    entries.sort(([, a], [, b]) => {
      let cmp = 0;
      if (sortKey === "severity") {
        cmp =
          (sevWeight[a[0].severity] ?? 9) - (sevWeight[b[0].severity] ?? 9) ||
          Math.max(...b.map((f) => f.risk_score)) - Math.max(...a.map((f) => f.risk_score));
      } else if (sortKey === "score") {
        cmp = Math.max(...b.map((f) => f.risk_score)) - Math.max(...a.map((f) => f.risk_score));
      } else {
        const aOldest = Math.min(...a.map((f) => new Date(f.first_seen).getTime()));
        const bOldest = Math.min(...b.map((f) => new Date(f.first_seen).getTime()));
        cmp = bOldest - aOldest;
      }
      return sortDir === "asc" ? cmp : -cmp;
    });
    return entries;
  }, [rows, sortKey, sortDir]);

  const chTotal = metricTotals.critical + metricTotals.high;
  const hasUrgent = chTotal > 0;

  if (!accounts.isLoading && accounts.data && !connectedId) {
    return <ConnectAwsEmptyState />;
  }

  return (
    <div className="w-full px-6 py-6">
      <div className="mb-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="flex min-w-0 flex-wrap items-baseline gap-x-3 gap-y-1">
            <h1 className="text-2xl font-bold tracking-tight text-zinc-950">Findings</h1>
            {scanRun.data?.finished_at && (
              <span className="text-sm text-zinc-500">Last scan {lastScanLabel(scanRun.data.finished_at)}</span>
            )}
            {benchmarkFilter !== "all" && (
              <span className="text-sm font-medium text-indigo-700/90">{frameworkLabel(benchmarkFilter)} scope</span>
            )}
          </div>
          <div className="shrink-0 pt-0.5">
            <NotificationsBell />
          </div>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-3">
          <MetricSummary
            totals={metricTotals}
            active={severityFilter}
            onSelect={handleMetricSelect}
            highlightActive={status === "open"}
          />
          <div className="flex flex-wrap items-center justify-end gap-2 sm:ml-auto">
              <button
                type="button"
                onClick={downloadCsv}
                className="inline-flex items-center rounded-lg border border-zinc-200 bg-white px-3.5 py-2 text-sm font-semibold text-zinc-600 shadow-sm transition hover:border-zinc-300 hover:bg-zinc-50 hover:text-zinc-900"
              >
                Export
              </button>
              <button
                type="button"
                onClick={handleRefresh}
                disabled={isRefreshing}
                className="inline-flex items-center gap-2 rounded-lg border border-zinc-200 bg-white px-3.5 py-2 text-sm font-semibold text-zinc-600 shadow-sm transition hover:border-zinc-300 hover:bg-zinc-50 hover:text-zinc-900 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {isRefreshing && (
                  <svg className="h-3.5 w-3.5 animate-spin" fill="none" viewBox="0 0 24 24" aria-hidden>
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                )}
                Refresh
              </button>
              {connectedId && (
                <button
                  type="button"
                  onClick={() => triggerScan(connectedId)}
                  disabled={scanTriggered || isRunning}
                  className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-3.5 py-2 text-sm font-semibold text-white shadow-sm shadow-indigo-600/20 transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {(scanTriggered || isRunning) && (
                    <svg className="h-3.5 w-3.5 animate-spin" fill="none" viewBox="0 0 24 24" aria-hidden>
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                  )}
                  {isRunning ? "Scanning…" : scanTriggered ? "Starting…" : "Re-scan"}
                </button>
              )}
          </div>
        </div>
      </div>

      {isScanActive && (
        <div className="mb-3">
          <ScanProgressBar
            phase={isRunning ? "running" : "starting"}
            progress={scanProgress.progress}
            elapsedMs={scanProgress.elapsedMs}
            remainingMs={scanProgress.remainingMs}
            finishing={scanProgress.finishing}
            indeterminate={scanProgress.indeterminate}
            progressStep={scanProgress.progressStep}
            progressTotal={scanProgress.progressTotal}
          />
        </div>
      )}

      {scanStatus === "error" && scanRun.data?.error && (
        <div className="mb-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
          <div>
            <span className="font-semibold">Last scan failed</span>
            {scanRun.data.failed_at && (
              <> at step <code className="rounded bg-red-100 px-1 py-0.5 font-mono text-xs">{scanRun.data.failed_at}</code></>
            )}
            {scanRun.data.error_type && <> ({scanRun.data.error_type})</>}
            :
          </div>
          <div className="mt-1 line-clamp-3 break-words text-xs text-red-700/90">{scanRun.data.error}</div>
        </div>
      )}

      <div
        className={`overflow-hidden rounded-xl border bg-white shadow-sm shadow-zinc-950/[0.03] ${
          hasUrgent ? "border-red-200/60" : "border-zinc-200/80"
        }`}
      >
        <div
          className={`flex flex-col gap-3 border-b px-4 py-3 sm:flex-row sm:items-center sm:justify-between ${
            hasUrgent ? "border-red-100/80 bg-gradient-to-r from-red-50/40 via-white to-white" : "border-zinc-100 bg-zinc-50/40"
          }`}
        >
          <StatusTabs status={status} onChange={setStatus} />
          <div className="flex min-w-0 flex-1 flex-wrap items-center gap-3 sm:justify-end">
            <BenchmarkScopeSelect value={benchmarkFilter} onChange={handleBenchmarkChange} />
            <TagSearchInput tags={searchTags} onTagsChange={handleTagsChange} className="min-w-0 flex-1 max-w-md" />
            <SortToggle sortKey={sortKey} sortDir={sortDir} onToggle={toggleSort} />
          </div>
        </div>

        {q.isLoading && (
          <div className="px-4 py-12 text-center text-sm text-zinc-400">Loading…</div>
        )}
        {!q.isLoading && rows.length === 0 && (
          <div className="px-4 py-12 text-center">
            <p className="text-sm font-semibold text-zinc-700">
              {benchmarkFilter !== "all"
                ? `No findings for ${frameworkLabel(benchmarkFilter)}`
                : emptyFindingsLabel(status)}
            </p>
            <p className="mt-1 text-xs text-zinc-400">
              {benchmarkFilter !== "all"
                ? "Try All benchmarks or a different status tab."
                : status === "open"
                  ? "Run a scan to check your account for IAM issues."
                  : "Nothing to show here."}
            </p>
          </div>
        )}
        {rows.length > 0 && (
          <div className="grid gap-3 bg-zinc-50/60 p-3 sm:gap-3.5 sm:p-4">
            {displayGroups.map(([checkId, items]) => (
              <FindingIssueCard key={checkId} checkId={checkId} items={items} onReview={openReview} />
            ))}
          </div>
        )}
      </div>

      <FindingDrawer
        finding={selected}
        relatedFindings={drawerGroup ?? undefined}
        onSelectRelated={(f) => setSelected(f)}
        accountId={connectedId ?? null}
        tab={drawerTab}
        onTabChange={setDrawerTab}
        remTab={remTab}
        onRemTabChange={setRemTab}
        verified={verified}
        verifyUnchanged={verifyUnchanged}
        verifying={verifying}
        onDismissVerifyOutcome={clearDrawerVerifyFlash}
        onClose={closeDrawer}
        onAction={(id, action) => {
          if (action === "recheck") {
            startRecheck(id, selected?.check_id ?? "");
          }
          act.mutate({ id, action });
        }}
      />
    </div>
  );
}
