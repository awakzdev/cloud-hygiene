import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api } from "../api";
import ScanProgressBar from "../components/ScanProgressBar";
import ConfirmDialog from "../components/ConfirmDialog";
import CfnPermissionsBanner from "../components/CfnPermissionsBanner";
import { useTriggeredScan } from "../hooks/useTriggeredScan";

type Account = {
  id: string;
  label: string;
  account_id: string | null;
  status: string;
  external_id: string;
  cfn_launch_url: string;
  last_scan_at: string | null;
};

type Finding = { id: string; account_id: string; severity: string; status: string };

type FindingStats = { critHigh: number; medium: number; open: number };

function AwsIcon({ className = "h-8 w-full" }: { className?: string }) {
  return (
    <img
      src="/aws.png"
      alt="AWS"
      className={`object-contain object-center ${className}`}
    />
  );
}

type ControlRow = { status: string };

function useComplianceScore(framework: string, accountId: string | null, enabled: boolean) {
  return useQuery({
    queryKey: ["controls", framework, accountId],
    queryFn: () =>
      api<ControlRow[]>(
        `/v1/controls?framework=${framework}${accountId ? `&account_id=${accountId}` : ""}`
      ),
    enabled: enabled && !!accountId,
    select: (rows) => {
      const total = rows.length;
      const passed = rows.filter((r) => r.status === "pass").length;
      return total === 0 ? null : Math.round((passed / total) * 100);
    },
  });
}

function formatLastScan(iso: string | null) {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  const ms = Date.now() - d.getTime();
  if (ms < 60_000) return "just now";
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ago`;
  if (ms < 86_400_000) return `${Math.floor(ms / 3_600_000)}h ago`;
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function shortExternalId(value: string): string {
  if (value.length <= 14) return value;
  return `${value.slice(0, 8)}…${value.slice(-4)}`;
}

function CopyableExternalId({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <button
      type="button"
      onClick={copy}
      title={copied ? "Copied!" : value}
      className="font-mono text-indigo-600 underline decoration-indigo-200 underline-offset-2 transition hover:text-indigo-700"
    >
      {copied ? "copied" : shortExternalId(value)}
    </button>
  );
}

const cardClass =
  "overflow-hidden rounded-2xl border border-zinc-200/90 bg-white shadow-sm shadow-zinc-900/[0.03]";

const secondaryBtn =
  "inline-flex items-center rounded-lg border border-zinc-200 bg-white px-3 py-1.5 text-xs font-semibold text-zinc-700 shadow-sm transition hover:border-zinc-300 hover:bg-zinc-50 disabled:cursor-not-allowed disabled:opacity-50";
const cardActionBtn =
  "inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-zinc-200 bg-white text-zinc-500 shadow-sm transition hover:border-zinc-300 hover:bg-zinc-50 hover:text-zinc-700";
const cardRescanBtn =
  "inline-flex h-9 shrink-0 items-center gap-1.5 rounded-xl bg-indigo-600 px-3.5 text-xs font-semibold text-white shadow-sm shadow-indigo-600/15 transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-50";
const dangerBtn =
  "inline-flex items-center rounded-lg border border-red-200 bg-red-50 px-3 py-1.5 text-xs font-semibold text-red-700 transition hover:border-red-300 hover:bg-red-100 disabled:cursor-not-allowed disabled:opacity-50";

function buildStatsMap(items: Finding[] | undefined): Map<string, FindingStats> {
  const map = new Map<string, FindingStats>();
  for (const f of items ?? []) {
    const cur = map.get(f.account_id) ?? { critHigh: 0, medium: 0, open: 0 };
    cur.open += 1;
    if (f.severity === "critical" || f.severity === "high") cur.critHigh += 1;
    if (f.severity === "medium") cur.medium += 1;
    map.set(f.account_id, cur);
  }
  return map;
}

function StatPill({ value, label, href, highlight }: { value: number | string; label: string; href?: string; highlight?: boolean }) {
  const inner = (
    <>
      <div className={`text-base font-medium tabular-nums leading-none ${highlight ? "text-indigo-600" : "text-zinc-900"}`}>
        {value}
      </div>
      <div className="mt-0.5 text-[10px] font-medium uppercase tracking-wide text-zinc-400">{label}</div>
    </>
  );
  const cls = "min-w-[4.5rem] rounded-xl bg-zinc-50 px-3 py-2 text-center ring-1 ring-zinc-100 transition hover:border-indigo-200 hover:bg-indigo-50/50";
  if (href) {
    return <a href={href} className={cls}>{inner}</a>;
  }
  return <div className={cls}>{inner}</div>;
}

function MetricStrip({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className={`flex flex-wrap items-center gap-1.5 rounded-lg border border-zinc-200 bg-white px-2 py-1.5 ${className ?? ""}`}>
      {children}
    </div>
  );
}

function ComplianceBadge({ pct, label }: { pct: number | null | undefined; label: string }) {
  if (pct == null) {
    return (
      <div className="min-w-[3.75rem] rounded-xl border border-zinc-100 bg-zinc-50/50 px-2.5 py-2 text-center">
        <div className="text-sm font-medium tabular-nums leading-none text-zinc-500/40">—</div>
        <div className="mt-0.5 text-[10px] font-medium uppercase tracking-wide text-zinc-400">{label}</div>
      </div>
    );
  }
  return (
    <a
      href="/controls"
      className="min-w-[3.75rem] rounded-xl border border-zinc-200/80 bg-white px-2.5 py-2 text-center shadow-sm transition hover:border-indigo-200 hover:bg-indigo-50/40"
    >
      <div className="text-sm font-medium tabular-nums leading-none text-zinc-800">{pct}%</div>
      <div className="mt-0.5 text-[10px] font-medium uppercase tracking-wide text-zinc-400">{label}</div>
    </a>
  );
}

function AccountCard({
  acc,
  stats,
  expanded,
  onToggle,
}: {
  acc: Account;
  stats: FindingStats | undefined;
  expanded: boolean;
  onToggle: () => void;
}) {
  const qc = useQueryClient();
  const [roleArn, setRoleArn] = useState("");
  const [showUpdateArn, setShowUpdateArn] = useState(false);
  const [showRemoveConfirm, setShowRemoveConfirm] = useState(false);

  const connected = acc.status === "connected";
  const hasScanned = connected && !!acc.last_scan_at;

  const {
    scanRun,
    scanStatus,
    isRunning,
    isScanActive,
    scanProgress,
    triggerScan,
  } = useTriggeredScan(connected ? acc.id : undefined, {
    backgroundPollMs: 5000,
    onScanComplete: () => {
      qc.invalidateQueries({ queryKey: ["findings-snapshot-all"] });
      qc.invalidateQueries({ queryKey: ["controls"] });
      qc.invalidateQueries({ queryKey: ["accounts"] });
    },
  });

  const verify = useMutation({
    mutationFn: () =>
      api<Account>(`/v1/accounts/${acc.id}/verify`, {
        method: "POST",
        body: JSON.stringify({ role_arn: roleArn }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["accounts"] }),
  });

  const soc2 = useComplianceScore("soc2", acc.id, connected && hasScanned);
  const cis = useComplianceScore("cis_aws_l1", acc.id, connected && hasScanned);
  const iso = useComplianceScore("iso27001", acc.id, connected && hasScanned);

  const remove = useMutation({
    mutationFn: () => api(`/v1/accounts/${acc.id}`, { method: "DELETE" }),
    onSuccess: () => {
      setShowRemoveConfirm(false);
      qc.invalidateQueries({ queryKey: ["accounts"] });
    },
  });

  const lastScan = formatLastScan(acc.last_scan_at);
  const critHigh = stats?.critHigh ?? 0;
  const medium = stats?.medium ?? 0;
  const open = stats?.open ?? 0;
  const hasStats = connected && hasScanned;

  return (
    <div
      className={`${cardClass} ${!connected ? "border-l-[3px] border-l-amber-300" : ""} ${expanded ? "ring-2 ring-indigo-500/15" : ""}`}
    >
      <div className="px-4 py-3">
        {/* Header row */}
        <div className="flex items-center gap-2.5">
          <div className="flex h-10 w-20 shrink-0 items-center justify-center rounded-xl bg-white px-2 ring-1 ring-zinc-200/90 shadow-sm">
            <AwsIcon />
          </div>

          <div className="flex min-w-0 flex-1 items-end justify-between gap-2">
            <div className="min-w-0 space-y-2">
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                <h2 className="truncate text-base font-medium leading-snug tracking-[-0.01em] text-zinc-900">
                  {acc.label}
                </h2>
                {!connected && (
                  <span className="inline-flex items-center gap-1.5 rounded-full bg-amber-50 px-2 py-0.5 text-[10px] font-semibold uppercase leading-none tracking-wide text-amber-700">
                    <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
                    Setup needed
                  </span>
                )}
                {isScanActive && (
                  <span className="inline-flex items-center gap-1 rounded-full bg-indigo-50 px-2 py-0.5 text-[10px] font-medium leading-none text-indigo-600">
                    <svg className="h-2.5 w-2.5 animate-spin" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                    {isRunning ? "Scanning" : "Starting"}
                  </span>
                )}
              </div>

              {acc.account_id && (
                <div className="flex min-w-0 flex-wrap items-baseline justify-between gap-x-4 gap-y-0.5 text-xs">
                  <span className="font-mono tabular-nums text-zinc-600">{acc.account_id}</span>
                  {connected &&
                    (isScanActive ? (
                      <span className="shrink-0 font-medium text-indigo-600">
                        {isRunning ? "Scanning now" : "Starting scan"}
                      </span>
                    ) : lastScan ? (
                      <span className="shrink-0 text-zinc-500">Last scan {lastScan}</span>
                    ) : null)}
                </div>
              )}
              {!connected && (
                <p className="text-xs leading-normal text-zinc-500">Deploy the CloudFormation stack to connect.</p>
              )}
            </div>

            <div className="flex shrink-0 items-center gap-2">
              {connected && (
                <button
                  onClick={() => triggerScan(acc.id)}
                  disabled={isScanActive}
                  className={cardRescanBtn}
                >
                  <svg
                    className={`h-3.5 w-3.5 ${isScanActive ? "animate-spin" : ""}`}
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
                    />
                  </svg>
                  {isScanActive ? (isRunning ? "Scanning…" : "Starting…") : "Re-scan"}
                </button>
              )}
              <button
                type="button"
                onClick={onToggle}
                className={cardActionBtn}
                aria-expanded={expanded}
                aria-label={expanded ? "Collapse details" : "Expand details"}
              >
                <svg
                  className={`h-4 w-4 transition-transform ${expanded ? "rotate-180" : ""}`}
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              </button>
            </div>
          </div>
        </div>

        {connected && isScanActive && (
          <ScanProgressBar
            className="mt-2.5"
            phase={isRunning ? "running" : "starting"}
            progress={scanProgress.progress}
            elapsedMs={scanProgress.elapsedMs}
            remainingMs={scanProgress.remainingMs}
            finishing={scanProgress.finishing}
            indeterminate={scanProgress.indeterminate}
          />
        )}

        {connected && !isScanActive && scanRun.data?.cfn_permissions_stale && (
          <CfnPermissionsBanner cfnLaunchUrl={acc.cfn_launch_url} className="mt-2.5" />
        )}

        {/* Posture strip — visible when scanned, no expand needed */}
        {hasStats && (
          <div className="mt-3 flex flex-wrap items-end gap-2 border-t border-zinc-100 pt-3">
            <MetricStrip>
              <StatPill value={critHigh} label="Crit + high" highlight={critHigh > 0} />
              <StatPill value={medium} label="Medium" />
              <StatPill value={open} label="Open" href="/findings" highlight />
            </MetricStrip>
            <MetricStrip>
              <ComplianceBadge pct={soc2.data} label="SOC 2" />
              <ComplianceBadge pct={cis.data} label="CIS" />
              <ComplianceBadge pct={iso.data} label="ISO" />
            </MetricStrip>
          </div>
        )}

        {connected && !hasScanned && (
          <div className="mt-3 rounded-xl border border-dashed border-zinc-200 bg-zinc-50/50 px-4 py-3 text-center text-xs text-zinc-500">
            Run a scan to see findings and compliance scores.
          </div>
        )}
      </div>

      {expanded && (
        <div className="border-t border-zinc-100 bg-zinc-50/60 px-4 py-2.5 text-xs">
          {!connected ? (
            <div className="space-y-4">
              <div className="grid gap-3 sm:grid-cols-3">
                {[
                  {
                    n: 1,
                    title: "Deploy role",
                    body: (
                      <a
                        href={acc.cfn_launch_url}
                        target="_blank"
                        rel="noreferrer"
                        className="mt-1 inline-flex items-center gap-1 font-medium text-indigo-300 hover:text-zinc-800"
                      >
                        Launch stack
                        <svg className="h-3 w-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                        </svg>
                      </a>
                    ),
                  },
                  { n: 2, title: "Copy RoleArn", body: <p className="mt-1 text-zinc-500">From stack Outputs tab</p> },
                  {
                    n: 3,
                    title: "Verify",
                    body: <p className="mt-1 text-zinc-500">Paste RoleArn below</p>,
                  },
                ].map(({ n, title, body }) => (
                  <div key={n} className="rounded-xl border border-zinc-200 bg-white p-3 p-3">
                    <div className="flex h-5 w-5 items-center justify-center rounded-full border border-zinc-200 bg-zinc-50 text-[10px] font-medium text-zinc-500">
                      {n}
                    </div>
                    <div className="mt-2 text-sm font-medium text-zinc-900">{title}</div>
                    {body}
                  </div>
                ))}
              </div>
              <p className="text-xs text-zinc-500">
                External ID for stack: <CopyableExternalId value={acc.external_id} />
              </p>
              <div className="flex gap-2">
                <input
                  className="min-w-0 flex-1 rounded-lg border border-zinc-200 bg-white px-3 py-2 font-mono text-xs focus:outline-none focus:ring-2 focus:ring-indigo-500 min-w-0 flex-1"
                  placeholder="arn:aws:iam::123456789012:role/VigilReadOnly"
                  value={roleArn}
                  onChange={(e) => setRoleArn(e.target.value)}
                />
                <button
                  onClick={() => verify.mutate()}
                  disabled={verify.isPending || !roleArn}
                  className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
                >
                  {verify.isPending ? "Verifying…" : "Verify"}
                </button>
              </div>
              {verify.error && (
                <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-red-700">
                  {(verify.error as Error).message}
                </div>
              )}
              <div className="flex justify-end border-t border-zinc-100 pt-3">
                <button
                  onClick={() => remove.mutate()}
                  disabled={remove.isPending}
                  className={dangerBtn}
                >
                  {remove.isPending ? "Removing…" : "Remove account"}
                </button>
              </div>
            </div>
          ) : (
            <div className="space-y-2">
              {scanStatus === "error" && scanRun.data?.error && (
                <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-red-700">
                  <span className="font-medium">Last scan failed</span>
                  {scanRun.data.error_type && <> ({scanRun.data.error_type})</>}
                  <div className="mt-1 line-clamp-2 break-words">{scanRun.data.error}</div>
                </div>
              )}

              {showUpdateArn ? (
                <div className="rounded-xl border border-zinc-200 bg-white p-3 space-y-2 p-3">
                  <p className="text-zinc-500">
                    Paste the new RoleArn from stack Outputs. External ID:{" "}
                    <CopyableExternalId value={acc.external_id} />.{" "}
                    <a href={acc.cfn_launch_url} target="_blank" rel="noreferrer" className="text-indigo-600 hover:underline">
                      Re-deploy stack
                    </a>
                  </p>
                  <div className="flex gap-2">
                    <input
                      className="min-w-0 flex-1 rounded-lg border border-zinc-200 bg-white px-3 py-2 font-mono text-xs focus:outline-none focus:ring-2 focus:ring-indigo-500 min-w-0 flex-1"
                      placeholder="arn:aws:iam::123456789012:role/VigilReadOnly"
                      value={roleArn}
                      onChange={(e) => setRoleArn(e.target.value)}
                    />
                    <button
                      onClick={() => verify.mutate()}
                      disabled={verify.isPending || !roleArn}
                      className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
                    >
                      {verify.isPending ? "…" : "Verify"}
                    </button>
                    <button
                      onClick={() => { setShowUpdateArn(false); setRoleArn(""); verify.reset(); }}
                      className="rounded-lg px-2 py-2 text-zinc-400 hover:text-zinc-600"
                    >
                      Cancel
                    </button>
                  </div>
                  {verify.isSuccess && <p className="text-emerald-600">Role ARN updated.</p>}
                  {verify.error && (
                    <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-red-700 py-1.5">
                      {(verify.error as Error).message}
                    </div>
                  )}
                </div>
              ) : (
                <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
                  <button
                    type="button"
                    onClick={() => setShowUpdateArn(true)}
                    disabled={isScanActive}
                    className={secondaryBtn}
                  >
                    Update role
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowRemoveConfirm(true)}
                    disabled={remove.isPending}
                    className={dangerBtn}
                  >
                    {remove.isPending ? "Removing…" : "Remove account"}
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      <ConfirmDialog
        open={showRemoveConfirm}
        title="Remove this account?"
        description={`${acc.label} and all associated findings, scan history, and evidence will be permanently deleted. This cannot be undone.`}
        confirmLabel="Remove account"
        variant="danger"
        loading={remove.isPending}
        onCancel={() => !remove.isPending && setShowRemoveConfirm(false)}
        onConfirm={() => remove.mutate()}
      />
    </div>
  );
}

export default function Accounts() {
  const qc = useQueryClient();
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const accounts = useQuery({
    queryKey: ["accounts"],
    queryFn: () => api<Account[]>("/v1/accounts"),
  });

  const create = useMutation({
    mutationFn: () => api<Account>("/v1/accounts", { method: "POST", body: JSON.stringify({}) }),
    onSuccess: (acc) => {
      qc.invalidateQueries({ queryKey: ["accounts"] });
      setExpandedId(acc.id);
    },
  });

  const allFindings = useQuery({
    queryKey: ["findings-snapshot-all"],
    queryFn: () =>
      api<{ items: Finding[]; total: number; next_cursor: string | null }>(
        `/v1/findings?status=open&limit=500`
      ),
    enabled: (accounts.data?.length ?? 0) > 0,
  });

  const statsMap = useMemo(() => buildStatsMap(allFindings.data?.items), [allFindings.data?.items]);

  const accs = accounts.data ?? [];
  const hasPending = accs.some((a) => a.status !== "connected");
  const didAutoExpand = useRef(false);

  // Auto-expand once on first load with a single account
  useEffect(() => {
    if (!didAutoExpand.current && accs.length === 1) {
      setExpandedId(accs[0].id);
      didAutoExpand.current = true;
    }
  }, [accs]);

  return (
    <div className="mx-auto w-full max-w-4xl space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-zinc-950">AWS Accounts</h1>
          <p className="mt-1 text-sm text-zinc-500">
            Manage connected accounts and scan schedules.
          </p>
        </div>
        {accs.length > 0 && (
          <button
            onClick={() => create.mutate()}
            disabled={create.isPending || hasPending}
            title={hasPending ? "Finish setting up the pending account first" : undefined}
            className="inline-flex items-center gap-1.5 rounded-xl border border-zinc-200 bg-white px-4 py-2 text-sm font-semibold text-zinc-700 shadow-sm transition hover:border-zinc-300 hover:bg-zinc-50 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            {create.isPending ? "Adding…" : "Add account"}
          </button>
        )}
      </div>

      {accs.length === 0 && !accounts.isLoading && (
        <div className={`${cardClass} max-w-lg p-6`}>
          <div className="flex h-10 w-20 items-center justify-center rounded-2xl bg-white px-2 ring-1 ring-zinc-200/90 shadow-sm">
            <AwsIcon />
          </div>
          <h2 className="mt-4 text-lg font-medium tracking-[-0.01em] text-zinc-900">Connect your first AWS account</h2>
          <p className="mt-1.5 text-sm leading-relaxed text-zinc-500">
            Deploy a read-only IAM role via CloudFormation. Vigil scans daily and maps findings to SOC 2 and CIS controls.
          </p>
          <button
            onClick={() => create.mutate()}
            disabled={create.isPending}
            className="mt-5 rounded-xl bg-indigo-600 px-5 py-2.5 text-sm font-semibold text-white shadow-sm shadow-indigo-600/15 transition hover:bg-indigo-700 disabled:opacity-50"
          >
            {create.isPending ? "Setting up…" : "Connect account"}
          </button>
        </div>
      )}

      {accs.length > 0 && (
        <div className="space-y-3">
          {accs.map((acc) => (
            <AccountCard
              key={acc.id}
              acc={acc}
              stats={statsMap.get(acc.id)}
              expanded={expandedId === acc.id}
              onToggle={() => setExpandedId((id) => (id === acc.id ? null : acc.id))}
            />
          ))}
        </div>
      )}

      {hasPending && accs.length > 0 && (
        <p className="text-center text-xs text-zinc-500">Finish pending setup before adding another account.</p>
      )}

      {create.error && (
        <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-red-700 text-sm">
          {(create.error as Error).message}
        </div>
      )}
    </div>
  );
}
