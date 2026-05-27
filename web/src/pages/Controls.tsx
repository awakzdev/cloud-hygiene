import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { api, token } from "../api";
import ScanProgressBar from "../components/ScanProgressBar";
import { labelForCheck } from "../data/checkLabels";
import { saveScanDurationMs, useScanProgress } from "../hooks/useScanProgress";

const BASE = (import.meta.env.VITE_API_URL as string) || "http://localhost:8000";

type Account = { id: string; label: string; account_id: string | null; status: string; last_scan_at: string | null };

type ControlRow = {
  id: string;
  framework: string;
  control_id: string;
  title: string;
  description: string;
  guidance: string | null;
  narrative: string | null;
  check_ids: string[];
  status: "pass" | "fail" | "no_data";
  finding_count: number;
  open_finding_ids: string[];
};

type EvidencePreview = {
  control_id: string;
  snapshot_count: number;
  period_days: number;
  snapshots: { entity_type: string; taken_at: string }[];
};

const FRAMEWORKS = [
  { id: "soc2", label: "SOC 2", fullLabel: "SOC 2 Trust Services Criteria" },
  { id: "cis_aws_l1", label: "CIS AWS L1", fullLabel: "CIS AWS Foundations Benchmark L1" },
  { id: "iso27001", label: "ISO 27001", fullLabel: "ISO 27001 Annex A" },
];

const AUDIT_WINDOWS = [
  { value: 30, label: "Last 30 days" },
  { value: 90, label: "Last 90 days" },
  { value: 180, label: "Last 180 days" },
  { value: 365, label: "Last 365 days" },
];

type StatusFilter = "all" | "pass" | "fail" | "no_data";

const statusPill: Record<string, string> = {
  pass: "border-emerald-200 bg-emerald-50 text-emerald-700",
  fail: "border-red-200 bg-red-50 text-red-600",
  no_data: "border-zinc-200 bg-zinc-50 text-zinc-500",
};

const statusAccent: Record<string, string> = {
  pass: "border-l-emerald-300/80",
  fail: "border-l-red-300/80",
  no_data: "border-l-zinc-200",
};

const statusExpandedBg: Record<string, string> = {
  pass: "bg-emerald-50/20",
  fail: "bg-red-50/15",
  no_data: "bg-zinc-50/40",
};

function statusPillLabel(status: string) {
  if (status === "no_data") return "N/A";
  return status;
}

function shortFamilyLabel(label: string) {
  const parts = label.split(" ");
  if (parts.length >= 2 && /^(CC\d|CIS|A\.\d)/.test(parts[0])) {
    return parts.slice(0, 2).join(" ");
  }
  return label;
}

function passRateColor(pct: number) {
  if (pct >= 80) return "text-emerald-600";
  if (pct >= 50) return "text-amber-600";
  return "text-red-600";
}

function passRateBarColor(pct: number) {
  if (pct >= 80) return "bg-emerald-500";
  if (pct >= 50) return "bg-amber-500";
  return "bg-red-500";
}

type ControlGroup = {
  key: string;
  label: string;
  rows: ControlRow[];
  passed: number;
  failed: number;
  noData: number;
};

function controlFamily(framework: string, controlId: string) {
  if (framework === "soc2") {
    if (controlId.startsWith("CC6")) return { key: "cc6", label: "CC6 Logical Access" };
    if (controlId.startsWith("CC7")) return { key: "cc7", label: "CC7 System Operations" };
    if (controlId.startsWith("CC8")) return { key: "cc8", label: "CC8 Change Management" };
  }

  if (framework === "cis_aws_l1") {
    const section = controlId.split(".")[0];
    if (section === "1") return { key: "cis-1", label: "CIS 1 Identity and Access" };
    if (section === "2") return { key: "cis-2", label: "CIS 2 Storage and Logging" };
    if (section === "3") return { key: "cis-3", label: "CIS 3 Networking" };
    if (section === "4") return { key: "cis-4", label: "CIS 4 Monitoring" };
  }

  if (framework === "iso27001") {
    if (controlId.startsWith("A.9")) return { key: "iso-a9", label: "A.9 Access Control" };
    if (controlId.startsWith("A.10")) return { key: "iso-a10", label: "A.10 Cryptography" };
    if (controlId.startsWith("A.12")) return { key: "iso-a12", label: "A.12 Operations Security" };
    if (controlId.startsWith("A.13")) return { key: "iso-a13", label: "A.13 Communications Security" };
  }

  return { key: "other", label: "Other Controls" };
}

function groupControls(rows: ControlRow[], framework: string): ControlGroup[] {
  const groups = new Map<string, ControlGroup>();

  for (const row of rows) {
    const family = controlFamily(framework, row.control_id);
    const existing = groups.get(family.key);
    const group = existing ?? {
      key: family.key,
      label: family.label,
      rows: [],
      passed: 0,
      failed: 0,
      noData: 0,
    };

    group.rows.push(row);
    if (row.status === "pass") group.passed += 1;
    if (row.status === "fail") group.failed += 1;
    if (row.status === "no_data") group.noData += 1;
    groups.set(family.key, group);
  }

  return Array.from(groups.values());
}

function shortControlTitle(title: string) {
  const parts = title.split("—");
  return parts.length > 1 ? parts.slice(1).join("—").trim() : title;
}

function findingLabel(count: number) {
  return `${count} finding${count === 1 ? "" : "s"}`;
}

function controlTheme(control: ControlRow) {
  const ids = control.check_ids.join(" ");
  if (/iam|github\.org|gitlab\.org/.test(ids)) return "identity-related";
  if (/github\.repo|gitlab\.repo/.test(ids)) return "change-management";
  if (/cloudtrail|guardduty|securityhub|aws\.config|vpc/.test(ids)) return "monitoring and logging";
  if (/s3|kms|rds|ec2\.ebs/.test(ids)) return "data-protection";
  if (/ec2\.security_group|rds\.instance\.publicly_accessible/.test(ids)) return "network-exposure";
  return "mapped";
}

function controlSummary(control: ControlRow): string {
  if (control.status === "pass") {
    return "Passing — no open findings. Keep in the evidence pack for audit review.";
  }
  if (control.status === "no_data") {
    return "Not evaluated yet — run a scan or connect the required evidence source.";
  }
  const theme = controlTheme(control);
  const action =
    theme === "identity-related"
      ? "Remediate stale or over-permissive identities."
      : theme === "change-management"
        ? "Restore branch protection and review requirements."
        : theme === "monitoring and logging"
          ? "Enable the missing monitoring or audit-log controls."
          : theme === "data-protection"
            ? "Fix encryption, retention, or storage protection gaps."
            : theme === "network-exposure"
              ? "Remove public or unrestricted network exposure."
              : "Remediate the mapped checks blocking this control.";
  return `${control.finding_count} open ${theme} ${control.finding_count === 1 ? "finding" : "findings"}. ${action}`;
}

function formatEvidenceDate(iso: string) {
  return new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}

function lastScanLabel(iso: string) {
  const d = new Date(iso);
  const diff = Date.now() - d.getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 48) return `${hrs}h ago`;
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function LoadingSkeleton() {
  return (
    <div className="animate-pulse space-y-4">
      <div className="h-10 rounded-xl border border-zinc-200 bg-zinc-50" />
      <div className="h-96 rounded-2xl border border-zinc-200 bg-zinc-50" />
    </div>
  );
}

function MappedChecksList({ checkIds }: { checkIds: string[] }) {
  const [open, setOpen] = useState(false);
  const [showIds, setShowIds] = useState(false);

  return (
    <div className="border-t border-zinc-100 pt-4">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center justify-between text-left"
      >
        <p className="vigil-kicker">
          {checkIds.length} mapped check{checkIds.length === 1 ? "" : "s"}
        </p>
        <span className="text-[11px] font-semibold text-zinc-500">{open ? "Hide" : "Show"}</span>
      </button>
      {open && (
        <>
          <div className="mb-2 mt-2 flex justify-end">
            <button
              type="button"
              onClick={() => setShowIds((v) => !v)}
              className="text-[11px] font-semibold text-zinc-500 transition hover:text-zinc-800"
            >
              {showIds ? "Hide IDs" : "Show IDs"}
            </button>
          </div>
          <ul className="space-y-2">
            {checkIds.map((cid) => (
              <li key={cid} className="rounded-lg border border-zinc-100 bg-zinc-50/80 px-3 py-2">
                <p className="text-sm font-medium text-zinc-800">{labelForCheck(cid)}</p>
                {showIds && <code className="mt-1 block font-mono text-[10px] text-zinc-400">{cid}</code>}
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}

function NarrativeBlock({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="rounded-xl border border-violet-200/80 bg-violet-50/40 p-4">
      <div className="mb-2 flex items-center justify-between gap-3">
        <p className="text-[10px] font-semibold uppercase tracking-wider text-violet-600">Audit response draft</p>
        <button
          type="button"
          onClick={copy}
          className="inline-flex items-center gap-1 rounded-lg border border-violet-200 bg-white px-2.5 py-1 text-[11px] font-semibold text-violet-700 transition hover:bg-violet-50"
        >
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <p className="text-sm leading-relaxed text-violet-950/90">{text}</p>
    </div>
  );
}

function EvidencePreviewPanel({
  controlId,
  accountId,
  period,
}: {
  controlId: string;
  accountId: string;
  period: number;
}) {
  const evidence = useQuery({
    queryKey: ["control-evidence", controlId, accountId, period],
    queryFn: () =>
      api<EvidencePreview>(
        `/v1/controls/${encodeURIComponent(controlId)}/evidence?account_id=${accountId}&period=${period}`
      ),
  });

  if (evidence.isLoading) {
    return <p className="text-xs text-zinc-400">Loading evidence snapshots…</p>;
  }

  if (evidence.isError || !evidence.data) {
    return <p className="text-xs text-zinc-400">Evidence preview unavailable.</p>;
  }

  const { snapshot_count, snapshots } = evidence.data;
  const entityTypes = Array.from(new Set(snapshots.map((s) => s.entity_type)));
  const latest = snapshots[0]?.taken_at;

  return (
    <div className="rounded-xl border border-indigo-100 bg-indigo-50/30 p-4">
      <p className="text-[10px] font-semibold uppercase tracking-wider text-indigo-600">Evidence collected</p>
      <p className="mt-1.5 text-sm font-semibold text-zinc-900">
        {snapshot_count === 0
          ? "No snapshots in this audit window"
          : `${snapshot_count} snapshot${snapshot_count === 1 ? "" : "s"} in the last ${period} days`}
      </p>
      {latest && (
        <p className="mt-1 text-xs text-zinc-500">Most recent: {formatEvidenceDate(latest)}</p>
      )}
      {entityTypes.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {entityTypes.slice(0, 8).map((type) => (
            <span key={type} className="rounded-md bg-white/90 px-2 py-0.5 font-mono text-[10px] text-indigo-700 ring-1 ring-indigo-100">
              {type}
            </span>
          ))}
          {entityTypes.length > 8 && (
            <span className="rounded-md px-2 py-0.5 text-[10px] text-zinc-500">+{entityTypes.length - 8} more</span>
          )}
        </div>
      )}
    </div>
  );
}

function useFrameworkPassRate(framework: string, accountId: string | undefined, enabled: boolean) {
  return useQuery({
    queryKey: ["controls", framework, accountId],
    queryFn: () =>
      api<ControlRow[]>(
        `/v1/controls?framework=${framework}${accountId ? `&account_id=${accountId}` : ""}`
      ),
    enabled,
    select: (rows) => {
      const total = rows.length;
      if (total === 0) return null;
      const passed = rows.filter((r) => r.status === "pass").length;
      return Math.round((passed / total) * 100);
    },
  });
}

export default function Controls() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [framework, setFramework] = useState("soc2");
  const [selectedFamilyKey, setSelectedFamilyKey] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [downloading, setDownloading] = useState(false);
  const [period, setPeriod] = useState(90);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [search, setSearch] = useState("");
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [scanTriggered, setScanTriggered] = useState(false);
  const prevScanStatus = useRef<string | null>(null);

  const accounts = useQuery({
    queryKey: ["accounts"],
    queryFn: () => api<Account[]>("/v1/accounts"),
  });

  const connectedAccount = accounts.data?.find((a) => a.status === "connected");
  const hasScanned = !!connectedAccount?.last_scan_at;
  const activeFramework = FRAMEWORKS.find((fw) => fw.id === framework)!;

  const scanRun = useQuery({
    queryKey: ["scan-run-latest", connectedAccount?.id],
    queryFn: () =>
      connectedAccount
        ? api<{
            id: string;
            status: string;
            started_at: string;
            finished_at: string | null;
          } | null>(`/v1/accounts/${connectedAccount.id}/scan-runs/latest`)
        : null,
    enabled: !!connectedAccount,
    refetchInterval: (query) => (query.state.data?.status === "running" ? 5000 : false),
  });

  const scan = useMutation({
    mutationFn: (accountId: string) => api(`/v1/accounts/${accountId}/scan`, { method: "POST", body: "{}" }),
  });

  const scanStatus = scanRun.data?.status ?? null;
  const scanStartedAt = scanRun.data?.started_at ? new Date(scanRun.data.started_at) : null;
  const scanStuck = scanStartedAt ? Date.now() - scanStartedAt.getTime() > 5 * 60 * 1000 : false;
  const isRunning = scanStatus === "running" && !scanStuck;
  const isScanActive = scanTriggered || isRunning;
  const scanProgress = useScanProgress(isScanActive, isRunning ? scanStartedAt : null);

  useEffect(() => {
    if (prevScanStatus.current === "running" && scanStatus === "ok") {
      qc.invalidateQueries({ queryKey: ["controls"] });
      qc.invalidateQueries({ queryKey: ["control-evidence"] });
      if (scanRun.data?.started_at && scanRun.data?.finished_at) {
        saveScanDurationMs(scanRun.data.started_at, scanRun.data.finished_at);
      }
    }
    if (scanStatus === "running") setScanTriggered(false);
    prevScanStatus.current = scanStatus;
  }, [scanStatus, qc, scanRun.data?.started_at, scanRun.data?.finished_at]);

  const controls = useQuery({
    queryKey: ["controls", framework, connectedAccount?.id],
    queryFn: () =>
      api<ControlRow[]>(
        `/v1/controls?framework=${framework}${connectedAccount ? `&account_id=${connectedAccount.id}` : ""}`
      ),
    enabled: !accounts.isLoading,
  });

  useEffect(() => {
    if (isRefreshing && !controls.isFetching) {
      const t = setTimeout(() => setIsRefreshing(false), 600);
      return () => clearTimeout(t);
    }
  }, [isRefreshing, controls.isFetching]);

  const soc2Rate = useFrameworkPassRate("soc2", connectedAccount?.id, hasScanned);
  const cisRate = useFrameworkPassRate("cis_aws_l1", connectedAccount?.id, hasScanned);
  const isoRate = useFrameworkPassRate("iso27001", connectedAccount?.id, hasScanned);

  const rows = controls.data ?? [];
  const passed = rows.filter((r) => r.status === "pass").length;
  const failed = rows.filter((r) => r.status === "fail").length;
  const noData = rows.filter((r) => r.status === "no_data").length;
  const total = rows.length;
  const passRate = total > 0 ? Math.round((passed / total) * 100) : null;

  const filteredRows = useMemo(
    () => (statusFilter === "all" ? rows : rows.filter((r) => r.status === statusFilter)),
    [rows, statusFilter]
  );

  const searchedRows = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return filteredRows;
    return filteredRows.filter(
      (r) =>
        r.control_id.toLowerCase().includes(q) ||
        r.title.toLowerCase().includes(q) ||
        r.description.toLowerCase().includes(q) ||
        (r.narrative?.toLowerCase().includes(q) ?? false)
    );
  }, [filteredRows, search]);

  const groupedRows = useMemo(() => groupControls(searchedRows, framework), [searchedRows, framework]);
  const selectedGroup = groupedRows.find((group) => group.key === selectedFamilyKey) ?? groupedRows[0] ?? null;

  function openControl(ctrl: ControlRow) {
    setSelectedFamilyKey(controlFamily(framework, ctrl.control_id).key);
    setExpanded(ctrl.id);
  }

  const topBlocker = useMemo(() => {
    const failing = rows.filter((row) => row.status === "fail");
    if (failing.length === 0) return null;
    return failing.reduce((worst, row) => (row.finding_count > worst.finding_count ? row : worst));
  }, [rows]);

  async function downloadPack() {
    if (!connectedAccount) return;
    setDownloading(true);
    try {
      const tok = token();
      const res = await fetch(
        `${BASE}/v1/exports/evidence-pack?framework=${framework}&account_id=${connectedAccount.id}&period=${period}`,
        { headers: { Authorization: `Bearer ${tok}` } }
      );
      if (!res.ok) throw new Error(await res.text());
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `vigil-evidence-${framework}-${new Date().toISOString().slice(0, 10)}.zip`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      alert("Download failed: " + String(e));
    } finally {
      setDownloading(false);
    }
  }

  if (!accounts.isLoading && !connectedAccount) {
    return (
      <div className="flex h-full flex-col items-center justify-center px-8 py-20 text-center">
        <div className="mb-5 flex h-14 w-14 items-center justify-center rounded-2xl border border-zinc-200 bg-white shadow-sm">
          <svg className="h-7 w-7 text-zinc-400" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
          </svg>
        </div>
        <h2 className="mb-2 text-lg font-semibold text-zinc-900">Connect AWS to view compliance</h2>
        <p className="mb-6 max-w-sm text-sm leading-relaxed text-zinc-500">
          Map SOC 2, CIS, and ISO 27001 controls to your AWS posture and export auditor-ready evidence packs.
        </p>
        <a href="/accounts" className="rounded-xl bg-indigo-600 px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-700">
          Connect AWS account
        </a>
      </div>
    );
  }

  return (
    <div className="w-full px-8 py-8">
      <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <h1 className="text-2xl font-bold tracking-tight text-zinc-950">Compliance</h1>
          <p className="mt-1.5 text-sm text-zinc-500">
            {activeFramework.fullLabel}
            {connectedAccount?.account_id && (
              <span className="text-zinc-400"> · account {connectedAccount.account_id}</span>
            )}
            {(scanRun.data?.finished_at || connectedAccount?.last_scan_at) && (
              <span className="text-zinc-400">
                {" "}
                · Last scan {lastScanLabel(scanRun.data?.finished_at ?? connectedAccount!.last_scan_at!)}
              </span>
            )}
            {passRate != null && (
              <span className={`font-medium ${passRateColor(passRate)}`}> · {passRate}% passing</span>
            )}
          </p>
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => {
              if (isRefreshing) return;
              qc.invalidateQueries({ queryKey: ["controls"] });
              qc.invalidateQueries({ queryKey: ["control-evidence"] });
              setIsRefreshing(true);
            }}
            disabled={isRefreshing}
            className="inline-flex items-center gap-2 rounded-xl border border-zinc-200 bg-white px-4 py-2.5 text-sm font-semibold text-zinc-600 shadow-sm transition hover:border-zinc-300 hover:bg-zinc-50 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {isRefreshing && (
              <svg className="h-3.5 w-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
            )}
            Refresh
          </button>
          {connectedAccount && (
            <button
              type="button"
              onClick={() => {
                setScanTriggered(true);
                scan.mutate(connectedAccount.id);
              }}
              disabled={scanTriggered || isRunning}
              className="inline-flex items-center gap-2 rounded-xl bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white shadow-sm shadow-indigo-600/20 transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {(scanTriggered || isRunning) && (
                <svg className="h-3.5 w-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
              )}
              {isRunning ? "Scanning…" : scanTriggered ? "Starting…" : "Re-scan"}
            </button>
          )}
        </div>
      </div>

      {isScanActive && (
        <div className="mb-6">
          <ScanProgressBar
            phase={isRunning ? "running" : "starting"}
            progress={scanProgress.progress}
            elapsedMs={scanProgress.elapsedMs}
            remainingMs={scanProgress.remainingMs}
            indeterminate={scanProgress.indeterminate}
            finishing={scanProgress.finishing}
          />
        </div>
      )}

      {!hasScanned && connectedAccount && !controls.isLoading && (
        <div className="mb-6 rounded-2xl border border-amber-200 bg-amber-50/60 px-5 py-4 text-sm text-amber-900">
          <span className="font-semibold">Awaiting first scan.</span> Control pass/fail status appears after your account finishes scanning.
        </div>
      )}

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_288px]">
        <div className="min-w-0 order-2 space-y-5 xl:order-1">
          {/* Summary stats */}
          {controls.isLoading && <LoadingSkeleton />}

          {!controls.isLoading && total > 0 && (
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="inline-flex flex-wrap items-center gap-1 rounded-xl border border-zinc-200 bg-white p-1 shadow-sm shadow-zinc-950/[0.03]">
                {(
                  [
                    { id: "all" as const, label: "All", count: total },
                    { id: "fail" as const, label: "Failing", count: failed },
                    { id: "pass" as const, label: "Passing", count: passed },
                    { id: "no_data" as const, label: "No data", count: noData },
                  ] as const
                ).map((f) => (
                  <button
                    key={f.id}
                    type="button"
                    onClick={() => {
                      setStatusFilter(f.id);
                      setExpanded(null);
                    }}
                    className={`rounded-lg px-3 py-1.5 text-xs font-semibold transition-all ${
                      statusFilter === f.id
                        ? "bg-zinc-900 text-white"
                        : "text-zinc-500 hover:bg-zinc-50 hover:text-zinc-800"
                    }`}
                  >
                    {f.label}
                    <span className={statusFilter === f.id ? "text-white/70" : "text-zinc-400"}> · {f.count}</span>
                  </button>
                ))}
              </div>

              <div className="relative min-w-[200px] sm:max-w-xs sm:flex-1">
                <svg className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-400" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35M11 18a7 7 0 100-14 7 7 0 000 14z" />
                </svg>
                <input
                  type="search"
                  value={search}
                  onChange={(e) => {
                    setSearch(e.target.value);
                    setExpanded(null);
                  }}
                  placeholder="Search controls…"
                  className="w-full rounded-xl border border-zinc-200 bg-white py-2.5 pl-9 pr-3 text-sm text-zinc-800 shadow-sm outline-none transition placeholder:text-zinc-400 focus:border-indigo-300 focus:ring-2 focus:ring-indigo-500/20"
                />
              </div>
            </div>
          )}

          {topBlocker && statusFilter !== "pass" && !controls.isLoading && total > 0 && (
            <p className="text-xs text-zinc-500">
              Top blocker:{" "}
              <button
                type="button"
                onClick={() => {
                  setStatusFilter("fail");
                  openControl(topBlocker);
                }}
                className="font-semibold text-red-600 hover:text-red-700"
              >
                {topBlocker.control_id}
              </button>
              {" "}({findingLabel(topBlocker.finding_count)})
            </p>
          )}

          {/* Control list */}
          <section>
            {!controls.isLoading && rows.length > 0 && searchedRows.length === 0 && (
              <div className="rounded-2xl border border-zinc-200 bg-white px-6 py-12 text-center text-sm text-zinc-400 shadow-sm">
                No controls match your search.
              </div>
            )}

            {!controls.isLoading && rows.length === 0 && (
              <div className="rounded-2xl border border-zinc-200 bg-white px-6 py-16 text-center text-sm text-zinc-400 shadow-sm">
                No controls found for this framework.
              </div>
            )}
            {!controls.isLoading && rows.length > 0 && filteredRows.length === 0 && statusFilter !== "all" && (
              <div className="rounded-2xl border border-zinc-200 bg-white px-6 py-12 text-center text-sm text-zinc-400 shadow-sm">
                No controls match this filter.
              </div>
            )}

            {!controls.isLoading && groupedRows.length > 0 && selectedGroup && (
              <div className="overflow-hidden rounded-2xl border border-zinc-200 bg-white shadow-sm shadow-zinc-950/[0.04]">
                <div className="flex flex-col gap-3 border-b border-zinc-100 px-5 py-3.5 sm:flex-row sm:items-center sm:justify-between">
                  <div
                    className="flex flex-wrap items-center gap-1 rounded-xl border border-zinc-200 bg-white p-1 shadow-sm shadow-zinc-950/[0.03]"
                    role="tablist"
                    aria-label="Control families"
                  >
                    {groupedRows.map((group) => {
                      const isSelected = selectedGroup.key === group.key;
                      return (
                        <button
                          key={group.key}
                          role="tab"
                          aria-selected={isSelected}
                          title={group.label}
                          onClick={() => {
                            setSelectedFamilyKey(group.key);
                            setExpanded(null);
                          }}
                          className={`rounded-lg px-3.5 py-2 text-sm font-semibold transition-all ${
                            isSelected
                              ? "bg-zinc-950 text-white shadow-sm"
                              : "text-zinc-500 hover:bg-zinc-50 hover:text-zinc-900"
                          }`}
                        >
                          {shortFamilyLabel(group.label)}
                          {group.failed > 0 && (
                            <span className={isSelected ? "text-red-200" : "text-red-500"}> · {group.failed}</span>
                          )}
                        </button>
                      );
                    })}
                  </div>
                </div>

                <div className="grid grid-cols-[auto_auto_minmax(0,1fr)_auto] items-center gap-3 border-b border-zinc-100 px-5 py-2.5">
                  <span className="w-3.5" />
                  <span className="w-[52px]" />
                  <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-zinc-400">Control</span>
                  <span className="text-right text-[10px] font-semibold uppercase tracking-[0.12em] text-zinc-400">Findings</span>
                </div>

                <div className="divide-y divide-zinc-100">
                  {selectedGroup.rows.map((ctrl) => {
                    const isExpanded = expanded === ctrl.id;
                    return (
                      <div key={ctrl.id}>
                        <button
                          onClick={() => setExpanded(isExpanded ? null : ctrl.id)}
                          className={`grid w-full grid-cols-[auto_auto_minmax(0,1fr)_auto] items-center gap-3 border-l-2 py-3.5 pl-5 pr-5 text-left transition-colors ${statusAccent[ctrl.status]} ${
                            isExpanded ? statusExpandedBg[ctrl.status] : "hover:bg-zinc-50/80"
                          }`}
                        >
                          <svg
                            className={`h-3.5 w-3.5 shrink-0 transition-transform duration-150 ${isExpanded ? "text-zinc-600" : "-rotate-90 text-zinc-400"}`}
                            fill="none"
                            stroke="currentColor"
                            viewBox="0 0 24 24"
                          >
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                          </svg>

                          <span
                            className={`inline-block w-[52px] shrink-0 rounded border py-0.5 text-center text-[10px] font-semibold uppercase tracking-[0.12em] ${statusPill[ctrl.status]}`}
                          >
                            {statusPillLabel(ctrl.status)}
                          </span>

                          <div className="min-w-0">
                            <div className="truncate text-sm font-semibold text-zinc-900">
                              <span className="font-mono text-xs font-medium text-zinc-500">{ctrl.control_id}</span>
                              <span className="mx-1.5 text-zinc-300">·</span>
                              {shortControlTitle(ctrl.title)}
                            </div>
                          </div>

                          <div className="shrink-0 text-right tabular-nums">
                            {ctrl.status === "fail" ? (
                              <span className={`text-sm font-semibold ${ctrl.finding_count >= 10 ? "text-red-600" : "text-red-500"}`}>
                                {ctrl.finding_count}
                              </span>
                            ) : (
                              <span className="text-xs font-medium text-zinc-300">—</span>
                            )}
                          </div>
                        </button>

                        {isExpanded && (
                          <div className={`border-t border-zinc-100/80 px-5 pb-5 pt-4 sm:pl-[4.75rem] ${statusExpandedBg[ctrl.status]}`}>
                            <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                              <p className="min-w-0 flex-1 text-sm leading-relaxed text-zinc-700">{controlSummary(ctrl)}</p>
                              {ctrl.status === "fail" && ctrl.open_finding_ids.length > 0 && (
                                <button
                                  onClick={() => navigate(`/findings?checks=${ctrl.check_ids.join(",")}`)}
                                  className="inline-flex h-9 shrink-0 items-center gap-1.5 self-start rounded-xl bg-indigo-600 px-4 text-sm font-semibold text-white shadow-sm shadow-indigo-600/20 transition-colors hover:bg-indigo-700"
                                >
                                  View {findingLabel(ctrl.finding_count)}
                                  <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
                                  </svg>
                                </button>
                              )}
                            </div>

                            {ctrl.narrative ? (
                              <div className="mt-4">
                                <NarrativeBlock text={ctrl.narrative} />
                              </div>
                            ) : (
                              <p className="mt-4 text-sm leading-relaxed text-zinc-600">{ctrl.description}</p>
                            )}

                            {connectedAccount && hasScanned && (
                              <div className="mt-4">
                                <EvidencePreviewPanel
                                  controlId={ctrl.control_id}
                                  accountId={connectedAccount.id}
                                  period={period}
                                />
                              </div>
                            )}

                            {ctrl.check_ids.length > 0 && (
                              <div className="mt-4 rounded-xl border border-zinc-200/80 bg-white p-4 shadow-sm shadow-zinc-950/[0.03]">
                                <MappedChecksList checkIds={ctrl.check_ids} />
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </section>
        </div>

        {/* Sidebar — evidence pack first on mobile */}
        <aside className="order-1 space-y-4 xl:order-2 xl:sticky xl:top-8 xl:self-start">
          <div className="rounded-2xl border border-zinc-200 bg-white p-5 shadow-sm shadow-zinc-950/[0.04]">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400">Framework</p>
            <div className="mt-4 space-y-3">
              {[
                { id: "soc2", label: "SOC 2", pct: soc2Rate.data },
                { id: "cis_aws_l1", label: "CIS AWS L1", pct: cisRate.data },
                { id: "iso27001", label: "ISO 27001", pct: isoRate.data },
              ].map(({ id, label, pct }) => (
                <button
                  key={id}
                  type="button"
                  onClick={() => {
                    setFramework(id);
                    setSelectedFamilyKey(null);
                    setExpanded(null);
                  }}
                  className={`flex w-full items-center gap-3 rounded-xl px-2 py-1.5 text-left transition ${
                    framework === id ? "bg-zinc-50 ring-1 ring-zinc-200" : "hover:bg-zinc-50/80"
                  }`}
                >
                  <span className="w-[72px] shrink-0 text-xs font-semibold text-zinc-700">{label}</span>
                  <div className="h-1.5 min-w-0 flex-1 overflow-hidden rounded-full bg-zinc-100">
                    <div
                      className={`h-full rounded-full transition-all ${pct == null ? "bg-zinc-200" : passRateBarColor(pct)}`}
                      style={{ width: `${pct ?? 0}%` }}
                    />
                  </div>
                  <span className={`w-9 shrink-0 text-right text-xs font-bold tabular-nums ${pct == null ? "text-zinc-300" : passRateColor(pct)}`}>
                    {pct == null ? "—" : `${pct}%`}
                  </span>
                </button>
              ))}
            </div>
          </div>

          <div className="rounded-2xl border border-indigo-100 bg-gradient-to-b from-indigo-50/80 to-white p-5 shadow-sm shadow-indigo-950/[0.04]">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-indigo-600">Evidence pack</p>
            <p className="mt-2 text-xs leading-relaxed text-zinc-500">
              {activeFramework.label} ZIP — INDEX.csv, per-control JSON, PDF report.
            </p>

            <label htmlFor="evidence-period" className="mt-4 block text-[10px] font-semibold uppercase tracking-wider text-zinc-400">
              Audit window
            </label>
            <select
              id="evidence-period"
              value={period}
              onChange={(e) => setPeriod(Number(e.target.value))}
              className="mt-1.5 w-full appearance-none rounded-xl border border-zinc-200 bg-white px-3 py-2.5 text-sm font-medium text-zinc-700 outline-none focus:border-indigo-300 focus:ring-2 focus:ring-indigo-500/20"
            >
              {AUDIT_WINDOWS.map((window) => (
                <option key={window.value} value={window.value}>
                  {window.label}
                </option>
              ))}
            </select>

            <button
              onClick={downloadPack}
              disabled={downloading || !connectedAccount}
              className="mt-4 inline-flex w-full items-center justify-center gap-2 rounded-xl bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white shadow-sm shadow-indigo-600/20 transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {downloading ? (
                <>
                  <svg className="h-3.5 w-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  Generating…
                </>
              ) : (
                <>
                  <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                  </svg>
                  Download ZIP
                </>
              )}
            </button>
          </div>
        </aside>
      </div>
    </div>
  );
}
