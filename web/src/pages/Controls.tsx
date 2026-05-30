import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api, token } from "../api";
import { labelForCheck } from "../data/checkLabels";
import { FRAMEWORKS } from "../data/frameworks";
import ConnectAwsEmptyState from "../components/ConnectAwsEmptyState";
import { EvidencePackExportPanel } from "../components/EvidencePackExportPanel";
import type { EvidenceCoverage } from "../lib/evidenceCoverage";
import {
  controlEvidenceSectionTitle,
  controlEvidenceUsesType2Bar,
  showControlEvidenceSection,
} from "../lib/frameworkEvidenceCoverage";
import { isAccountConnected } from "../lib/accountConnection";

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
  short_answer: string | null;
  long_answer: string | null;
  evidence_refs: string[];
  known_gaps: string[];
  check_ids: string[];
  coverage_tier?: "core" | "extended" | "mixed" | "no_data";
  coverage_label?: string | null;
  extended_check_ids?: string[];
  check_tiers?: Record<string, string>;
  check_evidence_classes?: Record<string, string>;
  status: "pass" | "fail" | "no_data";
  finding_count: number;
  open_finding_ids: string[];
};

type ControlHistory = {
  current_status: string;
  failing_since: string | null;
  days_failing: number | null;
  open_finding_count: number;
  segments: { status: string; from: string; to: string; duration_seconds: number }[];
  events: { timestamp: string; type: string; detail: string }[];
};

const AUDIT_WINDOWS = [
  { value: "last_scan", label: "Last scan (point-in-time)" },
  { value: 30, label: "Last 30 days" },
  { value: 90, label: "Last 90 days" },
  { value: 180, label: "Last 180 days" },
  { value: 365, label: "Last 365 days" },
] as const;

type StatusFilter = "all" | "pass" | "fail" | "no_data";

/** How rows are ordered inside each control domain tab. */
type ControlSortMode = "findings" | "control_id";

const CONTROL_SORT_OPTIONS: { id: ControlSortMode; label: string; title: string }[] = [
  {
    id: "findings",
    label: "Findings",
    title: "Highest open finding count first",
  },
  {
    id: "control_id",
    label: "Control ID",
    title: "Benchmark order (e.g. CC6.1, CC6.2, CC6.3)",
  },
];

const statusAccent: Record<string, string> = {
  pass: "border-l-emerald-300/50",
  fail: "border-l-red-300/50",
  no_data: "border-l-zinc-200/80",
};

const statusExpandedBg: Record<string, string> = {
  pass: "bg-emerald-50/15",
  fail: "bg-red-50/10",
  no_data: "bg-zinc-50/40",
};

type OpenFindingMeta = { id: string; check_id: string; severity: string; resource_arn: string };

function StatusIndicator({ status }: { status: string }) {
  if (status === "pass") {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-50/90 px-2.5 py-1 text-[11px] font-medium text-emerald-700 ring-1 ring-emerald-200/50">
        <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-emerald-500/90" aria-hidden />
        Pass
      </span>
    );
  }
  if (status === "fail") {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full bg-red-50/80 px-2.5 py-1 text-[11px] font-medium text-red-700 ring-1 ring-red-200/45">
        <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-red-500/75" aria-hidden />
        Failing
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full bg-zinc-100/90 px-2.5 py-1 text-[11px] font-medium text-zinc-500 ring-1 ring-zinc-200/70">
      <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-zinc-400/80" aria-hidden />
      No data
    </span>
  );
}

/** Fixed-size findings column badge (56×28px) — width must not vary by digit count. */
function FindingCountBadge({ count, status }: { count: number; status: string }) {
  if (status === "fail") {
    return (
      <span
        className="inline-flex h-7 w-14 items-center justify-center rounded-md bg-red-50 text-sm font-bold tabular-nums leading-none text-red-700 ring-1 ring-red-200/60"
        aria-label={`${count} open findings`}
      >
        {count}
      </span>
    );
  }
  if (status === "pass") {
    return (
      <span
        className="inline-flex h-7 w-14 items-center justify-center rounded-md bg-emerald-50/70 text-[11px] font-semibold text-emerald-600/70 ring-1 ring-emerald-200/50"
        aria-hidden
      >
        —
      </span>
    );
  }
  return (
    <span className="inline-flex h-7 w-14 items-center justify-center text-xs text-zinc-300" aria-hidden>
      —
    </span>
  );
}

function controlRowMetadata(
  ctrl: ControlRow,
  findingMap: Map<string, OpenFindingMeta>,
  lastScanAt: string | null,
): string {
  const parts: string[] = [];
  if (ctrl.check_ids.length > 0) {
    parts.push(`${ctrl.check_ids.length} check${ctrl.check_ids.length === 1 ? "" : "s"} mapped`);
  }
  if (ctrl.status === "fail" && ctrl.open_finding_ids.length > 0) {
    const linked = ctrl.open_finding_ids
      .map((id) => findingMap.get(id))
      .filter((f): f is OpenFindingMeta => !!f);
    const urgent = linked.filter((f) => f.severity === "critical" || f.severity === "high").length;
    if (urgent > 0) parts.push(`${urgent} critical/high`);
    const resources = new Set(linked.map((f) => f.resource_arn)).size;
    if (resources > 0) parts.push(`${resources} resource${resources === 1 ? "" : "s"}`);
  }
  if (lastScanAt) parts.push(`scanned ${lastScanLabel(lastScanAt)}`);
  if (parts.length === 0) {
    return ctrl.check_ids.length === 0 ? "Manual attestation required" : "Awaiting scan data";
  }
  return parts.join(" · ");
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

function controlIdSortKey(controlId: string): (string | number)[] {
  const parts: (string | number)[] = [];
  const re = /(\d+)|(\D+)/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(controlId)) !== null) {
    parts.push(match[1] ? Number.parseInt(match[1], 10) : match[2]);
  }
  return parts;
}

function compareControlIds(a: string, b: string): number {
  const pa = controlIdSortKey(a);
  const pb = controlIdSortKey(b);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i += 1) {
    const va = pa[i];
    const vb = pb[i];
    if (va === undefined) return -1;
    if (vb === undefined) return 1;
    if (typeof va === "number" && typeof vb === "number") {
      if (va !== vb) return va - vb;
    } else {
      const cmp = String(va).localeCompare(String(vb));
      if (cmp !== 0) return cmp;
    }
  }
  return 0;
}

function groupControls(rows: ControlRow[], framework: string, sortMode: ControlSortMode): ControlGroup[] {
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

  for (const group of groups.values()) {
    group.rows.sort((a, b) => {
      if (sortMode === "control_id") {
        const idCmp = compareControlIds(a.control_id, b.control_id);
        if (idCmp !== 0) return idCmp;
        return b.finding_count - a.finding_count;
      }
      const statusRank = (s: ControlRow["status"]) => (s === "fail" ? 0 : s === "no_data" ? 1 : 2);
      const rankDiff = statusRank(a.status) - statusRank(b.status);
      if (rankDiff !== 0) return rankDiff;
      const findingDiff = b.finding_count - a.finding_count;
      if (findingDiff !== 0) return findingDiff;
      return compareControlIds(a.control_id, b.control_id);
    });
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
  if (control.check_ids.length === 0) {
    return "Not automated in Vigil yet — CIS expects this control; map manually or wait for a future check.";
  }
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

function checkGroupLabel(id: string): string {
  if (id.startsWith("github.")) return "GitHub";
  if (id.startsWith("gitlab.")) return "GitLab";
  if (id.startsWith("iam.")) return "IAM";
  if (id.startsWith("s3.")) return "S3";
  if (id.startsWith("kms.")) return "KMS";
  if (id.startsWith("cloudtrail.")) return "CloudTrail";
  if (id.startsWith("ec2.")) return "EC2";
  if (id.startsWith("rds.")) return "RDS";
  if (id.startsWith("guardduty.")) return "GuardDuty";
  if (id.startsWith("aws.")) return "AWS";
  if (id.startsWith("vpc.")) return "VPC";
  if (id.startsWith("lambda.")) return "Lambda";
  if (id.startsWith("dynamodb.")) return "DynamoDB";
  if (id.startsWith("acm.")) return "ACM";
  if (id.startsWith("elb.")) return "ELB";
  if (id.startsWith("secretsmanager.")) return "Secrets";
  if (id.startsWith("ssm.")) return "SSM";
  if (id.startsWith("sns.")) return "SNS";
  if (id.startsWith("sqs.")) return "SQS";
  const prefix = id.split(".")[0] ?? id;
  return prefix.charAt(0).toUpperCase() + prefix.slice(1);
}

const CHECK_GROUP_ORDER = ["IAM", "GitHub", "GitLab", "S3", "KMS", "CloudTrail", "EC2", "RDS", "Lambda", "DynamoDB", "ACM", "ELB", "Secrets", "SSM", "SNS", "SQS", "GuardDuty", "AWS", "VPC"];

function groupCheckIds(checkIds: string[]) {
  const groups = new Map<string, string[]>();
  for (const id of checkIds) {
    const label = checkGroupLabel(id);
    const list = groups.get(label) ?? [];
    list.push(id);
    groups.set(label, list);
  }
  return Array.from(groups.entries()).sort(([a], [b]) => {
    const ai = CHECK_GROUP_ORDER.indexOf(a);
    const bi = CHECK_GROUP_ORDER.indexOf(b);
    if (ai !== -1 || bi !== -1) return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
    return a.localeCompare(b);
  });
}

const EVIDENCE_CLASS_LABELS: Record<string, string> = {
  benchmark: "Benchmark",
  supporting: "Supporting",
  hygiene: "Hygiene",
};

function EvidenceClassBadge({ evidenceClass }: { evidenceClass?: string }) {
  if (!evidenceClass || evidenceClass === "benchmark") return null;
  const label = EVIDENCE_CLASS_LABELS[evidenceClass] ?? evidenceClass;
  const styles =
    evidenceClass === "supporting"
      ? "bg-sky-50 text-sky-800 ring-sky-200/70"
      : "bg-zinc-100 text-zinc-600 ring-zinc-200/80";
  return (
    <span className={`inline-flex items-center rounded-md px-1.5 py-0.5 text-[10px] font-medium ring-1 ring-inset ${styles}`}>
      {label}
    </span>
  );
}

const EMPTY_CHECK_COUNTS = new Map<string, number>();

function MappedChecksList({
  checkIds,
  checkEvidenceClasses = {},
  findingCountByCheck = EMPTY_CHECK_COUNTS,
  findingsOnly = false,
  hideHeader = false,
}: {
  checkIds: string[];
  checkEvidenceClasses?: Record<string, string>;
  findingCountByCheck?: Map<string, number>;
  findingsOnly?: boolean;
  hideHeader?: boolean;
}) {
  const navigate = useNavigate();
  const sortedCheckIds = useMemo(
    () =>
      [...checkIds].sort(
        (a, b) => (findingCountByCheck.get(b) ?? 0) - (findingCountByCheck.get(a) ?? 0),
      ),
    [checkIds, findingCountByCheck],
  );
  const visibleIds = useMemo(
    () =>
      findingsOnly
        ? sortedCheckIds.filter((id) => (findingCountByCheck.get(id) ?? 0) > 0)
        : sortedCheckIds,
    [findingsOnly, sortedCheckIds, findingCountByCheck],
  );
  const grouped = useMemo(() => groupCheckIds(visibleIds), [visibleIds]);

  if (findingsOnly && visibleIds.length === 0) {
    return null;
  }

  const inner = (
      <div className={hideHeader ? "" : "mt-2.5 space-y-2.5"}>
        {grouped.map(([group, ids]) => (
          <div key={group}>
            <p className="mb-1.5 text-xs font-semibold text-zinc-700">{group}</p>
            <ul className="overflow-hidden rounded-lg border border-zinc-200 bg-white divide-y divide-zinc-100">
              {ids.map((cid) => {
                const openCount = findingCountByCheck.get(cid) ?? 0;
                return (
                <li key={cid}>
                  <button
                    type="button"
                    title={cid}
                    onMouseDown={(e) => e.preventDefault()}
                    onClick={() => navigate(`/findings?checks=${encodeURIComponent(cid)}`)}
                    className="group flex w-full items-center gap-3 px-3.5 py-2.5 text-left transition-colors hover:bg-zinc-50/80"
                  >
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-semibold leading-snug text-zinc-900 group-hover:text-indigo-700">
                        {labelForCheck(cid)}
                        {openCount > 0 && (
                          <span className="ml-1.5 tabular-nums text-red-600/90">({openCount})</span>
                        )}
                      </p>
                      <div className="mt-1 flex flex-wrap items-center gap-1.5">
                        <EvidenceClassBadge evidenceClass={checkEvidenceClasses[cid]} />
                      </div>
                    </div>
                    <svg
                      className="h-3.5 w-3.5 shrink-0 text-zinc-400 transition-colors group-hover:text-indigo-500"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth={2}
                      viewBox="0 0 24 24"
                    >
                      <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" />
                    </svg>
                  </button>
                </li>
              );
              })}
            </ul>
          </div>
        ))}
      </div>
  );

  if (hideHeader) return inner;

  return (
    <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/40 p-3.5">
      <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500">Findings</p>
      <p className="mt-0.5 text-[11px] text-zinc-500">Open findings by mapped check · click to filter in Findings</p>
      {inner}
    </div>
  );
}

function themeForAuditorList(label: string): string {
  return label
    .toLowerCase()
    .replace(/\bgithub\b/g, "GitHub")
    .replace(/\bgitlab\b/g, "GitLab");
}

function mappedCheckIdentifiesLine(checkIds: string[], max = 10): string {
  const seen = new Set<string>();
  const themes: string[] = [];
  for (const id of checkIds) {
    const label = labelForCheck(id);
    const key = label.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    themes.push(themeForAuditorList(label));
    if (themes.length >= max) break;
  }
  if (themes.length === 0) return "";
  if (themes.length === 1) return `Vigil identifies ${themes[0]}.`;
  return `Vigil identifies ${themes.slice(0, -1).join(", ")}, and ${themes[themes.length - 1]}.`;
}

function buildAuditorResponseForCopy(control: ControlRow): string {
  if (control.check_ids.length === 0) {
    return [
      `${control.control_id} — ${shortControlTitle(control.title)}`,
      "",
      control.narrative?.trim() ||
        "Vigil does not automate this control. Describe how your organization satisfies it and attach manual evidence.",
    ].join("\n");
  }

  const identifies = mappedCheckIdentifiesLine(control.check_ids);
  if (identifies) {
    return `${identifies} Evidence is collected continuously and retained for the selected audit period.`;
  }
  return "Evidence is collected continuously and retained for the selected audit period.";
}

function CoverageProgressBar({
  coverageDays,
  coverageTotal,
  coveragePct,
  barFillClass,
}: {
  coverageDays: number;
  coverageTotal: number;
  coveragePct: number;
  barFillClass: string;
}) {
  return (
    <div
      className="h-2.5 overflow-hidden rounded bg-zinc-200/60 ring-1 ring-inset ring-zinc-300/25"
      role="progressbar"
      aria-valuenow={coveragePct}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-label={`${coverageDays} of ${coverageTotal} audit days with evidence (${coveragePct}%)`}
    >
      <div
        className={`h-full bg-gradient-to-r ${barFillClass} transition-all`}
        style={{ width: `${Math.max(coveragePct, 2)}%` }}
      />
    </div>
  );
}

function ControlStatusBlock({
  control,
  periodDays,
  coverage,
  controlId,
  framework,
  accountId,
}: {
  control: ControlRow;
  periodDays: number;
  coverage?: EvidenceCoverage;
  controlId: string;
  framework: string;
  accountId: string;
}) {
  const history = useQuery({
    queryKey: ["control-history", controlId, framework, accountId, periodDays],
    queryFn: () =>
      api<ControlHistory>(
        `/v1/controls/${encodeURIComponent(controlId)}/history?framework=${framework}&account_id=${accountId}&days=${periodDays}`,
      ),
    enabled: !!accountId && control.check_ids.length > 0,
  });

  const statusLabel =
    control.status === "pass" ? "Passing" : control.status === "fail" ? "Failing" : "Not evaluated";

  const statusTone =
    control.status === "pass"
      ? "border-emerald-200/80 bg-emerald-50/30"
      : control.status === "fail"
        ? "border-rose-200/80 bg-rose-50/25"
        : "border-zinc-200/80 bg-zinc-50/50";

  const statusValueClass =
    control.status === "pass" ? "text-emerald-700" : control.status === "fail" ? "text-rose-700" : "text-zinc-600";

  const h = history.data;

  const scans = coverage?.successful_scans_in_period;
  const coverageDays = coverage?.days_with_data ?? 0;
  const coverageTotal = coverage?.days_requested ?? periodDays;
  const coveragePct = coverage ? Math.min(100, Math.round(coverage.coverage_ratio * 100)) : 0;

  let statusSubline: string | null = null;
  if (h?.current_status === "fail") {
    if (h.failing_since) statusSubline = `Since ${formatEvidenceDate(h.failing_since)}`;
    else if (h.days_failing != null) {
      statusSubline = `Failing for ${h.days_failing} day${h.days_failing === 1 ? "" : "s"}`;
    }
  } else if (h?.current_status === "pass") {
    statusSubline = "Currently passing";
  }

  const statusMark =
    control.status === "pass" ? "✓" : control.status === "fail" ? "✕" : "○";

  const supportMetrics: { value: string; label: string }[] = [];
  if (control.status === "fail") {
    supportMetrics.push({ value: String(control.finding_count), label: "Findings" });
  } else if (control.status === "pass") {
    supportMetrics.push({ value: "0", label: "Findings" });
  } else if (control.check_ids.length === 0) {
    supportMetrics.push({ value: "—", label: "Manual" });
  } else {
    supportMetrics.push({ value: "—", label: "Pending" });
  }
  if (scans != null) supportMetrics.push({ value: String(scans), label: "Scans" });

  const barFillClass =
    coveragePct >= 80 ? "from-emerald-500/90 to-emerald-600/80" : coveragePct >= 40 ? "from-amber-400/90 to-amber-500/80" : "from-rose-400/90 to-rose-500/80";

  return (
    <div className={`w-full rounded-xl border p-4 ${statusTone}`}>
      <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500">Control status</p>

      <div className="mt-3 flex items-start gap-2.5">
        <span
          className={`w-5 shrink-0 text-center text-xl leading-none ${statusValueClass}`}
          aria-hidden
        >
          {statusMark}
        </span>

        <div className="min-w-0 flex-1 space-y-4">
          <div className="space-y-1">
            <p className={`text-2xl font-bold leading-tight tracking-tight ${statusValueClass}`}>
              {statusLabel}
            </p>
            {statusSubline && <p className="text-sm text-zinc-500">{statusSubline}</p>}
            {supportMetrics.length > 0 && (
              <p className="text-sm leading-relaxed">
                {supportMetrics.map((m, i) => (
                  <span key={m.label}>
                    {i > 0 && <span className="px-2 text-zinc-300">•</span>}
                    <span className="font-semibold tabular-nums text-zinc-900">{m.value}</span>{" "}
                    <span className="text-zinc-600">{m.label}</span>
                  </span>
                ))}
              </p>
            )}
          </div>

          {showControlEvidenceSection(framework) && (
          <div className="max-w-xl space-y-1.5 overflow-visible border-t border-zinc-200/60 pt-4">
            <p className="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">
              {controlEvidenceSectionTitle(framework)}
            </p>

            {coverage ? (
              controlEvidenceUsesType2Bar(framework) ? (
                <div className="space-y-1.5">
                  <div className="flex items-baseline justify-between gap-4">
                    <p className="text-base leading-snug text-zinc-800">
                      <span className="font-semibold tabular-nums text-zinc-900">{coverageDays}</span>
                      <span className="tabular-nums text-zinc-600"> / </span>
                      <span className="font-semibold tabular-nums text-zinc-900">{coverageTotal}</span>
                      {" audit days collected"}
                    </p>
                    <span className="shrink-0 text-sm font-semibold tabular-nums text-zinc-700">{coveragePct}%</span>
                  </div>
                  <CoverageProgressBar
                    coverageDays={coverageDays}
                    coverageTotal={coverageTotal}
                    coveragePct={coveragePct}
                    barFillClass={barFillClass}
                  />
                </div>
              ) : (
                <p className="text-base leading-snug text-zinc-800">
                  <span className="font-semibold tabular-nums text-zinc-900">{coverageDays}</span>
                  {coverageDays === 1 ? " day" : " days"} collected in the selected export period
                </p>
              )
            ) : (
              <p className="text-base font-semibold text-zinc-800">{periodDays}-day export window</p>
            )}
          </div>
          )}
        </div>
      </div>
    </div>
  );
}

function ControlEvaluationBlock({ checkIds }: { checkIds: string[] }) {
  if (checkIds.length === 0) return null;

  const grouped = groupCheckIds(checkIds);

  return (
    <div className="rounded-xl border border-zinc-200/80 bg-white p-3.5">
      <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
        Mapped checks ({checkIds.length})
      </p>
      <div className="mt-3 grid gap-4 sm:grid-cols-2">
        {grouped.map(([group, ids]) => (
          <div key={group}>
            <p className="text-xs font-bold text-zinc-800">
              {group} <span className="font-normal text-zinc-500">({ids.length})</span>
            </p>
            <ul className="mt-1.5 list-disc space-y-1 pl-4 text-sm leading-snug text-zinc-800">
              {ids.map((cid) => (
                <li key={cid} title={cid}>
                  {labelForCheck(cid)}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
}

function ControlFindingsBlock({
  control,
  checkIds,
  checkEvidenceClasses,
  findingCountByCheck,
}: {
  control: ControlRow;
  checkIds: string[];
  checkEvidenceClasses?: Record<string, string>;
  findingCountByCheck: Map<string, number>;
}) {
  const navigate = useNavigate();

  if (control.status === "pass" && control.finding_count === 0) {
    return (
      <div className="rounded-xl border border-emerald-200/70 bg-emerald-50/30 px-4 py-3">
        <p className="text-[10px] font-semibold uppercase tracking-wider text-emerald-800/80">Findings</p>
        <p className="mt-1 text-sm font-medium text-emerald-900">No open findings</p>
      </div>
    );
  }

  const openTotal = control.finding_count;

  return (
    <div className="rounded-xl border border-zinc-200/80 bg-white p-3.5">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500">Findings</p>
        {openTotal > 0 && (
          <button
            type="button"
            onClick={() =>
              navigate(
                `/findings?checks=${encodeURIComponent(checkIds.filter((id) => (findingCountByCheck.get(id) ?? 0) > 0).join(","))}`,
              )
            }
            className="text-xs font-semibold text-indigo-700 hover:text-indigo-900"
          >
            {openTotal} open finding{openTotal === 1 ? "" : "s"} →
          </button>
        )}
      </div>
      {openTotal > 0 ? (
        <div className="mt-2.5">
          <MappedChecksList
            checkIds={checkIds}
            checkEvidenceClasses={checkEvidenceClasses}
            findingCountByCheck={findingCountByCheck}
            findingsOnly
            hideHeader
          />
        </div>
      ) : (
        <p className="mt-2 text-sm text-zinc-600">No open findings in mapped checks.</p>
      )}
    </div>
  );
}

function AuditorResponseBlock({ control }: { control: ControlRow }) {
  const [copied, setCopied] = useState(false);
  const text = useMemo(() => buildAuditorResponseForCopy(control), [control]);

  async function copy() {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="max-w-3xl">
      <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-zinc-500">Auditor response</p>
      <div className="overflow-hidden rounded-xl border border-zinc-200/90 bg-white shadow-sm ring-1 ring-zinc-950/5">
        <div className="px-4 py-3.5">
          <p className="whitespace-pre-wrap text-[13px] leading-[1.65] text-zinc-800">{text}</p>
        </div>
        <div className="flex justify-end border-t border-zinc-100 bg-zinc-50/60 px-4 py-2.5">
          <button
            type="button"
            onClick={() => void copy()}
            className="text-xs font-semibold text-indigo-700 transition hover:text-indigo-900"
          >
            {copied ? "Copied" : "Copy response"}
          </button>
        </div>
      </div>
    </div>
  );
}

type FrameworkStats = {
  passRate: number | null;
  failed: number;
  passed: number;
  total: number;
};

function useFrameworkStats(framework: string, accountId: string | undefined, enabled: boolean) {
  return useQuery({
    queryKey: ["controls", framework, accountId],
    queryFn: () =>
      api<ControlRow[]>(
        `/v1/controls?framework=${framework}${accountId ? `&account_id=${accountId}` : ""}`
      ),
    enabled,
    select: (rows): FrameworkStats => {
      const total = rows.length;
      const passed = rows.filter((r) => r.status === "pass").length;
      const failed = rows.filter((r) => r.status === "fail").length;
      return {
        passRate: total > 0 ? Math.round((passed / total) * 100) : null,
        failed,
        passed,
        total,
      };
    },
  });
}

/** Compact framework switcher + summary strip (revert: git history pre FrameworkNav, or ask for "revert framework checkpoint"). */
function FrameworkNav({
  selectedId,
  statsById,
  framework,
  topBlocker,
  onSelect,
  onOpenTopBlocker,
  exportControl,
}: {
  selectedId: string;
  statsById: Record<string, FrameworkStats | undefined>;
  framework: (typeof FRAMEWORKS)[number];
  topBlocker: ControlRow | null;
  onSelect: (id: string) => void;
  onOpenTopBlocker: () => void;
  exportControl?: ReactNode;
}) {
  const stats = statsById[selectedId];
  const passRate = stats?.passRate ?? null;

  return (
    <header className="mb-2 border-b border-zinc-200/80 pb-3">
      <div
        className="inline-flex rounded-lg border border-zinc-200/80 bg-zinc-100/70 p-0.5"
        role="tablist"
        aria-label="Compliance framework"
      >
        {FRAMEWORKS.map((fw) => {
          const isActive = selectedId === fw.id;
          const tabStats = statsById[fw.id];
          const tabPct = tabStats?.passRate;
          return (
            <button
              key={fw.id}
              type="button"
              role="tab"
              aria-selected={isActive}
              onClick={() => onSelect(fw.id)}
              className={`flex-1 rounded-md px-3 py-1.5 text-xs font-semibold transition-all outline-none focus-visible:ring-2 focus-visible:ring-indigo-500/40 sm:flex-none ${
                isActive
                  ? "bg-white text-zinc-900 shadow-sm"
                  : "text-zinc-600 hover:text-zinc-900"
              }`}
            >
              {fw.label}
              {tabPct != null && (
                <span
                  className={`ml-1.5 tabular-nums font-bold ${
                    isActive ? passRateColor(tabPct) : "text-zinc-400"
                  }`}
                >
                  {tabPct}%
                </span>
              )}
            </button>
          );
        })}
      </div>

      {(stats || exportControl) && (
        <div
          className={`mt-2.5 flex gap-4 ${stats ? "items-end justify-between" : "justify-end"}`}
        >
          {stats && (
            <div className="min-w-0 flex-1">
              <h2 className="flex flex-wrap items-baseline gap-x-2 gap-y-0">
                <span className="text-base font-bold text-zinc-950">{framework.label}</span>
                {passRate != null && (
                  <>
                    <span className={`text-base font-bold tabular-nums ${passRateColor(passRate)}`}>
                      {passRate}%
                    </span>
                    <span className="text-xs font-medium text-zinc-400">passing</span>
                  </>
                )}
              </h2>
              {stats.total === 0 && (
                <p className="mt-1 text-sm text-zinc-500">No controls mapped</p>
              )}
              {passRate != null && stats.total > 0 && (
                <div className="mt-2 flex max-w-xs items-center gap-2">
                  <div className="h-1.5 w-[14rem] shrink-0 overflow-hidden rounded-full bg-zinc-200/90">
                    <div
                      className={`h-full rounded-full transition-all ${passRate > 0 ? passRateBarColor(passRate) : "bg-transparent"}`}
                      style={{ width: `${Math.min(100, Math.max(0, passRate))}%` }}
                    />
                  </div>
                </div>
              )}
              {topBlocker && stats.failed > 0 && (
                <p className="mt-1.5 text-xs leading-snug text-zinc-600">
                  <span className="text-zinc-500">Top blocker: </span>
                  <button
                    type="button"
                    onClick={onOpenTopBlocker}
                    className="font-medium text-indigo-700 hover:text-indigo-900 hover:underline"
                  >
                    <span className="font-mono text-[11px] text-zinc-500">{topBlocker.control_id}</span>
                    {" "}
                    {shortControlTitle(topBlocker.title)}
                    <span className="tabular-nums text-red-600/90"> ({topBlocker.finding_count} findings)</span>
                  </button>
                </p>
              )}
            </div>
          )}
          {exportControl}
        </div>
      )}
    </header>
  );
}

export default function Controls() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const urlFramework = searchParams.get("framework");
  const urlControl = searchParams.get("control");
  const urlAccountId = searchParams.get("account_id");
  const [framework, setFramework] = useState(
    () => (urlFramework && FRAMEWORKS.some((f) => f.id === urlFramework) ? urlFramework : "soc2"),
  );
  const [selectedFamilyKey, setSelectedFamilyKey] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [downloading, setDownloading] = useState(false);
  const [periodKey, setPeriodKey] = useState<string | number>(90);
  const [asOf, setAsOf] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [controlSort, setControlSort] = useState<ControlSortMode>("control_id");
  const [exportOpen, setExportOpen] = useState(false);
  const exportRef = useRef<HTMLDivElement>(null);

  const accounts = useQuery({
    queryKey: ["accounts"],
    queryFn: () => api<Account[]>("/v1/accounts"),
  });

  const connectedAccount = accounts.data?.find((a) => isAccountConnected(a));
  const activeAccount =
    (urlAccountId && accounts.data?.find((a) => a.id === urlAccountId && isAccountConnected(a))) ||
    connectedAccount;
  const hasScanned = !!activeAccount?.last_scan_at;
  const activeFramework = FRAMEWORKS.find((fw) => fw.id === framework)!;

  const controls = useQuery({
    queryKey: ["controls", framework, activeAccount?.id],
    queryFn: () =>
      api<ControlRow[]>(
        `/v1/controls?framework=${framework}${activeAccount ? `&account_id=${activeAccount.id}` : ""}`
      ),
    enabled: !accounts.isLoading,
  });

  const deepLinkDone = useRef(false);
  useEffect(() => {
    deepLinkDone.current = false;
  }, [framework, urlControl]);

  useEffect(() => {
    if (!urlControl || !controls.data?.length || deepLinkDone.current) return;
    const match = controls.data.find((r) => r.control_id === urlControl);
    if (match) {
      deepLinkDone.current = true;
      setSelectedFamilyKey(controlFamily(framework, match.control_id).key);
      setExpanded(match.id);
    }
  }, [controls.data, urlControl, framework]);

  const openFindingsMeta = useQuery({
    queryKey: ["findings", "open", connectedAccount?.id, "controls-meta"],
    queryFn: () =>
      api<{ items: OpenFindingMeta[] }>(`/v1/findings?status=open&limit=500`),
    enabled: !!activeAccount && hasScanned,
    select: (data) => {
      const byId = new Map<string, OpenFindingMeta>();
      const countByCheck = new Map<string, number>();
      for (const f of data.items) {
        byId.set(f.id, f);
        countByCheck.set(f.check_id, (countByCheck.get(f.check_id) ?? 0) + 1);
      }
      return { byId, countByCheck };
    },
  });

  const findingMap = openFindingsMeta.data?.byId ?? new Map<string, OpenFindingMeta>();
  const findingCountByCheck = openFindingsMeta.data?.countByCheck ?? new Map<string, number>();

  const exportWindow = useMemo(() => {
    if (periodKey === "last_scan" && activeAccount?.last_scan_at) {
      return {
        period: 30,
        asOf: activeAccount.last_scan_at.slice(0, 10),
        label: "Last scan",
      };
    }
    const p = Number(periodKey);
    return {
      period: p,
      asOf: asOf.trim() || undefined,
      label: `Last ${p} days`,
    };
  }, [periodKey, asOf, activeAccount?.last_scan_at]);

  const evidenceCoverage = useQuery({
    queryKey: ["evidence-coverage", activeAccount?.id, exportWindow.period, exportWindow.asOf],
    queryFn: () => {
      const params = new URLSearchParams({
        period: String(exportWindow.period),
      });
      if (exportWindow.asOf) params.set("as_of", exportWindow.asOf);
      return api<EvidenceCoverage>(
        `/v1/accounts/${activeAccount!.id}/evidence-coverage?${params}`
      );
    },
    enabled: !!activeAccount && hasScanned,
  });

  useEffect(() => {
    if (!exportOpen) return;
    function handleClick(e: MouseEvent) {
      if (exportRef.current && !exportRef.current.contains(e.target as Node)) {
        setExportOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [exportOpen]);

  const soc2Stats = useFrameworkStats("soc2", connectedAccount?.id, hasScanned);
  const cisStats = useFrameworkStats("cis_aws_l1", connectedAccount?.id, hasScanned);
  const isoStats = useFrameworkStats("iso27001", connectedAccount?.id, hasScanned);

  const frameworkStatsById: Record<string, FrameworkStats | undefined> = {
    soc2: soc2Stats.data,
    cis_aws_l1: cisStats.data,
    iso27001: isoStats.data,
  };

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

  const groupedRows = useMemo(
    () => groupControls(filteredRows, framework, controlSort),
    [filteredRows, framework, controlSort],
  );
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

  async function downloadPack(opts?: { framework?: string; period?: number; asOf?: string }) {
    if (!activeAccount) return;
    setDownloading(true);
    try {
      const tok = token();
      const params = new URLSearchParams({
        framework: opts?.framework ?? framework,
        account_id: activeAccount.id,
        period: String(opts?.period ?? exportWindow.period),
      });
      const asOfVal = opts?.asOf ?? exportWindow.asOf;
      if (asOfVal) params.set("as_of", asOfVal);
      const res = await fetch(`${BASE}/v1/exports/evidence-pack?${params}`, {
        headers: { Authorization: `Bearer ${tok}` },
      });
      if (!res.ok) throw new Error(await res.text());
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `vigil-evidence-${opts?.framework ?? framework}-${(asOfVal ?? new Date().toISOString().slice(0, 10))}.zip`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      alert("Download failed: " + String(e));
    } finally {
      setDownloading(false);
    }
  }

  if (!accounts.isLoading && !connectedAccount) {
    return <ConnectAwsEmptyState />;
  }

  return (
    <div className="min-h-full bg-zinc-100/35">
    <div className="w-full px-8 py-8">
      <div className={`mb-4 ${exportOpen ? "relative z-[100]" : ""}`}>
        <h1 className="text-2xl font-bold tracking-tight text-zinc-950">Compliance</h1>
        <p className="mt-1.5 text-sm text-zinc-500">
          {connectedAccount?.account_id && <span>Account {connectedAccount.account_id}</span>}
          {connectedAccount?.last_scan_at && (
            <span className="text-zinc-400">
              {connectedAccount?.account_id ? " · " : ""}
              Last scan {lastScanLabel(connectedAccount.last_scan_at)}
            </span>
          )}
        </p>
      </div>

      {!hasScanned && connectedAccount && !controls.isLoading && (
        <div className="mb-6 rounded-2xl border border-amber-200 bg-amber-50/60 px-5 py-4 text-sm text-amber-900">
          <span className="font-semibold">Awaiting first scan.</span> Control pass/fail status appears after your account finishes scanning.
        </div>
      )}

      {controls.isLoading && <LoadingSkeleton />}

      {!controls.isLoading && connectedAccount && (
        <FrameworkNav
          selectedId={framework}
          statsById={frameworkStatsById}
          framework={activeFramework}
          topBlocker={topBlocker}
          onSelect={(id) => {
            setFramework(id);
            setSelectedFamilyKey(null);
            setExpanded(null);
          }}
          onOpenTopBlocker={() => {
            if (!topBlocker) return;
            setStatusFilter("fail");
            openControl(topBlocker);
          }}
          exportControl={
            <div ref={exportRef} className={`relative shrink-0 ${exportOpen ? "z-[101]" : ""}`}>
              <button
                type="button"
                onClick={() => setExportOpen((open) => !open)}
                aria-expanded={exportOpen}
                aria-haspopup="dialog"
                className={`inline-flex items-center justify-center gap-2 rounded-lg border px-4 py-2 text-sm font-semibold transition ${
                  exportOpen
                    ? "border-indigo-300 bg-indigo-50 text-indigo-900 ring-1 ring-indigo-200/60"
                    : "border-indigo-200 bg-indigo-50/60 text-indigo-800 hover:border-indigo-300 hover:bg-indigo-50"
                }`}
              >
                <svg className="h-4 w-4 shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                </svg>
                Generate Audit Package
              </button>
              {exportOpen && (
                <>
                  <button
                    type="button"
                    aria-label="Close evidence pack menu"
                    className="fixed inset-0 z-[100] cursor-default bg-zinc-950/15"
                    onClick={() => setExportOpen(false)}
                  />
                  <div
                    role="dialog"
                    aria-label="Generate Audit Package"
                    className="absolute right-0 top-full z-[102] mt-2 rounded-2xl border border-zinc-200/90 bg-white p-5 shadow-lg shadow-zinc-950/10"
                  >
                    <EvidencePackExportPanel
                      frameworkId={framework}
                      frameworkLabel={activeFramework.label}
                      periodKey={periodKey}
                      onPeriodChange={setPeriodKey}
                      asOf={asOf}
                      onAsOfChange={setAsOf}
                      coverage={evidenceCoverage.data}
                      coverageLoading={evidenceCoverage.isFetching}
                      controlsEvaluated={total}
                      openFindings={rows.reduce((sum, r) => sum + r.finding_count, 0)}
                      passingCount={passed}
                      lastScanLabel={
                        activeAccount?.last_scan_at
                          ? lastScanLabel(activeAccount.last_scan_at)
                          : null
                      }
                      downloading={downloading}
                      onDownload={() => void downloadPack()}
                    />
                  </div>
                </>
              )}
            </div>
          }
        />
      )}

      {!controls.isLoading && total > 0 && (
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <div className="inline-flex flex-wrap items-center gap-1 rounded-xl border border-zinc-200/80 bg-white p-1 shadow-sm shadow-zinc-950/[0.03]">
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
                    ? "bg-indigo-50 text-indigo-800 ring-1 ring-indigo-200"
                    : "text-zinc-500 hover:bg-zinc-50 hover:text-zinc-800"
                }`}
              >
                {f.label}
                <span className={statusFilter === f.id ? "text-indigo-500" : "text-zinc-400"}> · {f.count}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      <section className="min-w-0">
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
              <div className="overflow-hidden rounded-2xl border border-zinc-200/80 bg-white shadow-md shadow-zinc-950/[0.05] ring-1 ring-zinc-950/[0.03]">
                <div className="flex flex-wrap items-center justify-between gap-3 border-b border-zinc-100 bg-zinc-50/50 px-5 py-3.5">
                  <div
                    className="inline-flex min-w-0 flex-wrap items-center gap-1 rounded-xl border border-zinc-200/70 bg-white p-1 shadow-sm shadow-zinc-950/[0.02]"
                    role="tablist"
                    aria-label="Control domains"
                  >
                    {groupedRows.map((group) => {
                      const isSelected = selectedGroup.key === group.key;
                      return (
                        <button
                          key={group.key}
                          type="button"
                          role="tab"
                          aria-selected={isSelected}
                          title={group.label}
                          onClick={() => {
                            setSelectedFamilyKey(group.key);
                            setExpanded(null);
                          }}
                          className={`rounded-lg px-3.5 py-2 text-sm font-semibold transition-all ${
                            isSelected
                              ? "bg-indigo-50 text-indigo-900 ring-1 ring-indigo-200/80"
                              : "text-zinc-500 hover:bg-zinc-50 hover:text-zinc-900"
                          }`}
                        >
                          {shortFamilyLabel(group.label)}
                          <span
                            className={
                              group.failed > 0
                                ? "text-red-500/90"
                                : isSelected
                                  ? "text-indigo-500"
                                  : "text-zinc-400"
                            }
                          >
                            {" "}
                            · {group.rows.length}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                  <div
                    className="inline-flex shrink-0 items-center gap-2 rounded-xl border border-zinc-200/80 bg-white px-2 py-1 shadow-sm shadow-zinc-950/[0.03]"
                    role="group"
                    aria-label="Sort controls"
                  >
                    <span className="pl-1 text-[10px] font-semibold uppercase tracking-wide text-zinc-400">Sort by</span>
                    {CONTROL_SORT_OPTIONS.map((opt) => (
                      <button
                        key={opt.id}
                        type="button"
                        title={opt.title}
                        onClick={() => {
                          setControlSort(opt.id);
                          setExpanded(null);
                        }}
                        className={`rounded-lg px-2.5 py-1 text-xs font-semibold transition-all ${
                          controlSort === opt.id
                            ? "bg-zinc-100 text-zinc-900 ring-1 ring-zinc-200/80"
                            : "text-zinc-500 hover:bg-zinc-50 hover:text-zinc-800"
                        }`}
                      >
                        {opt.label}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="hidden grid-cols-[auto_auto_minmax(0,1fr)_3.5rem] items-center gap-4 border-b border-zinc-200 bg-zinc-50/60 px-5 py-2.5 sm:grid">
                  <span className="w-3.5" />
                  <span className="w-[72px] text-[10px] font-semibold uppercase tracking-[0.12em] text-zinc-500">Status</span>
                  <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-zinc-500">Control</span>
                  <span className="text-center text-[10px] font-semibold uppercase tracking-[0.12em] text-zinc-500">
                    Findings
                  </span>
                </div>

                <div className="divide-y divide-zinc-100/90">
                  {selectedGroup.rows.map((ctrl) => {
                    const isExpanded = expanded === ctrl.id;
                    const meta = controlRowMetadata(ctrl, findingMap, connectedAccount?.last_scan_at ?? null);
                    return (
                      <div key={ctrl.id}>
                        <button
                          type="button"
                          onMouseDown={(e) => e.preventDefault()}
                          onClick={() => {
                            const scrollY = window.scrollY;
                            setExpanded(isExpanded ? null : ctrl.id);
                            requestAnimationFrame(() => window.scrollTo(0, scrollY));
                          }}
                          className={`grid w-full grid-cols-1 gap-3 border-l-2 py-4 pl-5 pr-5 text-left transition-colors sm:grid-cols-[auto_auto_minmax(0,1fr)_3.5rem] sm:items-center sm:gap-4 ${statusAccent[ctrl.status]} ${
                            isExpanded ? statusExpandedBg[ctrl.status] : "hover:bg-zinc-50/70"
                          }`}
                        >
                          <svg
                            className={`hidden h-3.5 w-3.5 shrink-0 transition-transform duration-150 sm:block ${isExpanded ? "text-zinc-600" : "-rotate-90 text-zinc-400"}`}
                            fill="none"
                            stroke="currentColor"
                            viewBox="0 0 24 24"
                          >
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                          </svg>

                          <div className="sm:w-[72px]">
                            <StatusIndicator status={ctrl.status} />
                          </div>

                          <div className="min-w-0 flex-1">
                            <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
                              <span className="font-mono text-xs font-semibold text-zinc-500">{ctrl.control_id}</span>
                              <span className="text-sm font-semibold leading-snug text-zinc-900">
                                {shortControlTitle(ctrl.title)}
                              </span>
                            </div>
                            <p className="mt-1.5 line-clamp-2 text-xs leading-relaxed text-zinc-500">{meta}</p>
                          </div>

                          <div className="flex shrink-0 items-center justify-between gap-3 sm:justify-center sm:bg-zinc-50/30">
                            <svg
                              className={`h-3.5 w-3.5 shrink-0 text-zinc-400 sm:hidden ${isExpanded ? "" : "-rotate-90"}`}
                              fill="none"
                              stroke="currentColor"
                              viewBox="0 0 24 24"
                            >
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                            </svg>
                            <FindingCountBadge count={ctrl.finding_count} status={ctrl.status} />
                          </div>
                        </button>

                        {isExpanded && (
                          <div
                            className={`space-y-3 border-t border-zinc-100/80 px-5 pb-5 pt-4 sm:pl-[4.75rem] ${statusExpandedBg[ctrl.status]}`}
                          >
                            <ControlStatusBlock
                              control={ctrl}
                              periodDays={exportWindow.period}
                              coverage={evidenceCoverage.data}
                              controlId={ctrl.control_id}
                              framework={framework}
                              accountId={activeAccount?.id ?? ""}
                            />

                            {ctrl.check_ids.length === 0 ? (
                              <p className="rounded-xl border border-dashed border-zinc-200 bg-zinc-50/60 px-3.5 py-2.5 text-xs leading-relaxed text-zinc-600">
                                No automated Vigil checks map to this control yet — attest manually (e.g. IAM users
                                only inherit access via groups or roles).
                              </p>
                            ) : (
                              <>
                                <ControlEvaluationBlock checkIds={ctrl.check_ids} />
                                <ControlFindingsBlock
                                  control={ctrl}
                                  checkIds={ctrl.check_ids}
                                  checkEvidenceClasses={ctrl.check_evidence_classes}
                                  findingCountByCheck={findingCountByCheck}
                                />
                              </>
                            )}

                            <AuditorResponseBlock control={ctrl} />
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
    </div>
  );
}
