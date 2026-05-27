import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { api, token } from "../api";

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

const EVIDENCE_PACK_ITEMS = [
  "README with scan metadata and account context",
  "INDEX.csv — pass/fail per control with finding counts",
  "Per-control JSON evidence snapshots",
  "PDF compliance summary report",
  "exceptions.json for approved deviations",
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

function checkAreas(checkIds: string[]) {
  const areas = checkIds.map((id) => {
    if (id.startsWith("iam.user")) return "IAM users";
    if (id.startsWith("iam.role")) return "IAM roles";
    if (id.startsWith("iam.access_key")) return "Access keys";
    if (id.startsWith("iam.root")) return "Root account";
    if (id.startsWith("iam.policy")) return "IAM policies";
    if (id.includes("dormant_members")) return "Dormant org members";
    if (id.startsWith("github.org")) return "GitHub org access";
    if (id.startsWith("github.repo")) return "GitHub change controls";
    if (id.startsWith("gitlab.org")) return "GitLab group access";
    if (id.startsWith("gitlab.repo")) return "GitLab change controls";
    if (id.startsWith("s3.")) return "S3 buckets";
    if (id.startsWith("cloudtrail.")) return "CloudTrail";
    if (id.startsWith("guardduty.")) return "GuardDuty";
    if (id.startsWith("aws.config")) return "AWS Config";
    if (id.startsWith("aws.securityhub")) return "Security Hub";
    if (id.startsWith("vpc.")) return "VPC flow logs";
    if (id.startsWith("ec2.security_group")) return "Security groups";
    if (id.startsWith("ec2.")) return "EC2";
    if (id.startsWith("rds.")) return "RDS";
    if (id.startsWith("kms.")) return "KMS";
    if (id.startsWith("lambda.")) return "Lambda";
    if (id.startsWith("acm.")) return "ACM certificates";
    if (id.startsWith("dynamodb.")) return "DynamoDB";
    if (id.startsWith("secretsmanager.")) return "Secrets Manager";
    if (id.startsWith("ssm.")) return "SSM parameters";
    if (id.startsWith("elb.")) return "Load balancers";
    if (id.startsWith("sns.")) return "SNS";
    if (id.startsWith("sqs.")) return "SQS";
    return id.split(".")[0]?.toUpperCase() || "Mapped checks";
  });
  return Array.from(new Set(areas));
}

function stripEvidencePrefix(text: string) {
  return text.replace(/^Evidence:\s*/i, "").trim();
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

function failureSummary(control: ControlRow) {
  if (control.status === "pass") return `${control.control_id} is passing with no open findings mapped to this control.`;
  if (control.status === "no_data") return `${control.control_id} cannot be evaluated because scan data is not available yet.`;
  return `${control.control_id} failed because ${control.finding_count} ${controlTheme(control)} ${control.finding_count === 1 ? "finding is" : "findings are"} open.`;
}

function nextStep(control: ControlRow) {
  if (control.status === "pass") return "Keep this control in the evidence package for audit review.";
  if (control.status === "no_data") return "Run a scan or connect the required evidence source to evaluate this control.";
  const theme = controlTheme(control);
  if (theme === "identity-related") return "Review the open findings and remediate stale, untracked, or over-permissive identities.";
  if (theme === "change-management") return "Review the open findings and restore required review, ownership, and branch protection controls.";
  if (theme === "monitoring and logging") return "Review the open findings and enable the missing monitoring or audit-log controls.";
  if (theme === "data-protection") return "Review the open findings and fix missing encryption, retention, or storage protection controls.";
  if (theme === "network-exposure") return "Review the open findings and remove public or unrestricted network exposure.";
  return "Review the open findings and remediate the mapped checks blocking this control.";
}

function formatEvidenceDate(iso: string) {
  return new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
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
  const [framework, setFramework] = useState("soc2");
  const [selectedFamilyKey, setSelectedFamilyKey] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [downloading, setDownloading] = useState(false);
  const [period, setPeriod] = useState(90);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");

  const accounts = useQuery({
    queryKey: ["accounts"],
    queryFn: () => api<Account[]>("/v1/accounts"),
  });

  const connectedAccount = accounts.data?.find((a) => a.status === "connected");
  const hasScanned = !!connectedAccount?.last_scan_at;
  const activeFramework = FRAMEWORKS.find((fw) => fw.id === framework)!;

  const controls = useQuery({
    queryKey: ["controls", framework, connectedAccount?.id],
    queryFn: () =>
      api<ControlRow[]>(
        `/v1/controls?framework=${framework}${connectedAccount ? `&account_id=${connectedAccount.id}` : ""}`
      ),
    enabled: !accounts.isLoading,
  });

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

  const groupedRows = useMemo(() => groupControls(filteredRows, framework), [filteredRows, framework]);
  const selectedGroup = groupedRows.find((group) => group.key === selectedFamilyKey) ?? groupedRows[0] ?? null;

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

  const statusFilters: { id: StatusFilter; label: string; count: number }[] = [
    { id: "all", label: "All", count: total },
    { id: "fail", label: "Failing", count: failed },
    { id: "pass", label: "Passing", count: passed },
    { id: "no_data", label: "No data", count: noData },
  ];

  return (
    <div className="w-full px-8 py-8">
      <div className="mb-6">
        <h1 className="text-2xl font-bold tracking-tight text-zinc-950">Compliance</h1>
        <p className="mt-1.5 text-sm text-zinc-500">
          {activeFramework.fullLabel}
          {connectedAccount?.account_id && (
            <span className="text-zinc-400"> · account {connectedAccount.account_id}</span>
          )}
        </p>
      </div>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_288px]">
        <div className="min-w-0 space-y-5">
          {/* Summary stats */}
          {!controls.isLoading && total > 0 && (
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <div className="rounded-2xl border border-zinc-200 bg-white px-5 py-4 shadow-sm shadow-zinc-950/[0.03]">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400">Pass rate</p>
                <p className={`mt-1 text-3xl font-bold tabular-nums ${passRate == null ? "text-zinc-300" : passRateColor(passRate)}`}>
                  {passRate == null ? "—" : `${passRate}%`}
                </p>
                <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-zinc-100">
                  <div
                    className={`h-full rounded-full transition-all duration-500 ${passRate == null ? "bg-zinc-200" : passRateBarColor(passRate)}`}
                    style={{ width: `${passRate ?? 0}%` }}
                  />
                </div>
              </div>
              <div className="rounded-2xl border border-emerald-100 bg-emerald-50/40 px-5 py-4">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-emerald-600/80">Passing</p>
                <p className="mt-1 text-3xl font-bold tabular-nums text-emerald-700">{passed}</p>
              </div>
              <div className="rounded-2xl border border-red-100 bg-red-50/40 px-5 py-4">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-red-600/80">Failing</p>
                <p className="mt-1 text-3xl font-bold tabular-nums text-red-600">{failed}</p>
              </div>
              <div className="rounded-2xl border border-zinc-200 bg-zinc-50/60 px-5 py-4">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400">No data</p>
                <p className="mt-1 text-3xl font-bold tabular-nums text-zinc-500">{noData}</p>
              </div>
            </div>
          )}

          {/* Toolbar */}
          <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center sm:justify-between">
            <div className="inline-flex flex-wrap items-center gap-2">
              <div className="inline-flex items-center rounded-xl border border-zinc-200 bg-white p-1 shadow-sm shadow-zinc-950/[0.03]" aria-label="Framework">
                {FRAMEWORKS.map((fw) => (
                  <button
                    key={fw.id}
                    onClick={() => {
                      setFramework(fw.id);
                      setSelectedFamilyKey(null);
                      setExpanded(null);
                    }}
                    className={`rounded-lg px-3.5 py-2 text-sm font-semibold transition-all ${
                      framework === fw.id
                        ? "bg-zinc-950 text-white shadow-sm"
                        : "text-zinc-500 hover:bg-zinc-50 hover:text-zinc-900"
                    }`}
                  >
                    {fw.label}
                  </button>
                ))}
              </div>

              <div className="inline-flex flex-wrap items-center gap-1 rounded-xl border border-zinc-200 bg-white p-1 shadow-sm shadow-zinc-950/[0.03]">
                {statusFilters.map((f) => (
                  <button
                    key={f.id}
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
            </div>

            {topBlocker && statusFilter !== "pass" && (
              <p className="text-xs text-zinc-500">
                Top blocker:{" "}
                <button
                  type="button"
                  onClick={() => {
                    setStatusFilter("fail");
                    setExpanded(topBlocker.id);
                  }}
                  className="font-semibold text-red-600 hover:text-red-700"
                >
                  {topBlocker.control_id}
                </button>
                {" "}({findingLabel(topBlocker.finding_count)})
              </p>
            )}
          </div>

          {/* Control list */}
          <section>
            {controls.isLoading && (
              <div className="rounded-2xl border border-zinc-200 bg-white px-6 py-16 text-center text-sm text-zinc-400 shadow-sm">
                Loading controls…
              </div>
            )}
            {!controls.isLoading && rows.length === 0 && (
              <div className="rounded-2xl border border-zinc-200 bg-white px-6 py-16 text-center text-sm text-zinc-400 shadow-sm">
                No controls found.{!connectedAccount && " Connect an AWS account to see compliance status."}
              </div>
            )}
            {!controls.isLoading && rows.length > 0 && filteredRows.length === 0 && (
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
                            <span className={isSelected ? "text-white/70" : "text-red-500"}> · {group.failed}</span>
                          )}
                        </button>
                      );
                    })}
                  </div>
                  <span className="shrink-0 text-xs font-medium text-zinc-400">{selectedGroup.label}</span>
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
                    const areas = checkAreas(ctrl.check_ids);
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
                              <div className="min-w-0 flex-1 space-y-2">
                                <p className="text-sm font-semibold leading-snug text-zinc-900">{failureSummary(ctrl)}</p>
                                <p className="text-sm leading-relaxed text-zinc-600">{nextStep(ctrl)}</p>
                              </div>
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

                            {areas.length > 0 && (
                              <div className="mt-4 flex flex-wrap gap-2">
                                {areas.map((area) => (
                                  <span key={area} className="rounded-md bg-white/80 px-2.5 py-1 text-xs font-medium text-zinc-600 ring-1 ring-zinc-200/80">
                                    {area}
                                  </span>
                                ))}
                              </div>
                            )}

                            {ctrl.narrative && (
                              <div className="mt-4">
                                <NarrativeBlock text={ctrl.narrative} />
                              </div>
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

                            <div className="mt-5 rounded-xl border border-zinc-200/80 bg-white p-5 shadow-sm shadow-zinc-950/[0.03]">
                              <p className="text-sm leading-relaxed text-zinc-600">{ctrl.description}</p>

                              {(ctrl.guidance || ctrl.check_ids.length > 0) && (
                                <div className="mt-4 space-y-4 border-t border-zinc-100 pt-4">
                                  {ctrl.guidance && (
                                    <div>
                                      <p className="vigil-kicker mb-2">Evidence to collect</p>
                                      <p className="text-sm leading-relaxed text-zinc-800">{stripEvidencePrefix(ctrl.guidance)}</p>
                                    </div>
                                  )}

                                  {ctrl.check_ids.length > 0 && (
                                    <div className={ctrl.guidance ? "border-t border-zinc-100 pt-4" : ""}>
                                      <p className="vigil-kicker mb-2.5">
                                        {ctrl.check_ids.length} mapped check{ctrl.check_ids.length === 1 ? "" : "s"}
                                      </p>
                                      <div className="flex flex-wrap gap-1.5">
                                        {ctrl.check_ids.map((cid) => (
                                          <code
                                            key={cid}
                                            className="rounded bg-zinc-100 px-1.5 py-0.5 font-mono text-[11px] leading-5 text-zinc-600"
                                          >
                                            {cid}
                                          </code>
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                </div>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </section>

          {!connectedAccount && !accounts.isLoading && (
            <p className="text-center text-sm text-zinc-400">
              Connect an AWS account and run a scan to see live compliance status.
            </p>
          )}
        </div>

        {/* Sidebar */}
        <aside className="space-y-4 xl:sticky xl:top-8 xl:self-start">
          <div className="rounded-2xl border border-zinc-200 bg-white p-5 shadow-sm shadow-zinc-950/[0.04]">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400">Framework scores</p>
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
            <p className="mt-2 text-sm font-semibold text-zinc-900">Auditor-ready export</p>
            <p className="mt-1 text-xs leading-relaxed text-zinc-500">
              Download a ZIP for {activeFramework.label} covering the selected audit window. Share as-is or sample by date.
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

            <ul className="mt-4 space-y-1.5 border-t border-indigo-100/80 pt-4">
              {EVIDENCE_PACK_ITEMS.map((item) => (
                <li key={item} className="flex gap-2 text-xs leading-relaxed text-zinc-600">
                  <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-indigo-400" />
                  {item}
                </li>
              ))}
            </ul>
          </div>
        </aside>
      </div>
    </div>
  );
}
