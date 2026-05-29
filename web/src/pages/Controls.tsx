import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { api, token } from "../api";
import { labelForCheck } from "../data/checkLabels";
import { FRAMEWORKS } from "../data/frameworks";

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

type EvidencePreview = {
  control_id: string;
  snapshot_count: number;
  period_days: number;
  snapshots: { id: string; entity_type: string; entity_id: string; taken_at: string; data?: Record<string, unknown> }[];
};

type EvidenceDiff = {
  found: boolean;
  message?: string;
  change_count: number;
  exposure_note: string | null;
  snapshot_a: { taken_at: string | null };
  snapshot_b: { taken_at: string | null };
  changes: { field: string; before: unknown; after: unknown }[];
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
  { value: 30, label: "Last 30 days" },
  { value: 90, label: "Last 90 days" },
  { value: 180, label: "Last 180 days" },
  { value: 365, label: "Last 365 days" },
];

type EvidenceCoverage = {
  coverage_label: string;
  coverage_ratio: number;
  warning: string | null;
  period_start: string;
  period_end: string;
  successful_scans_in_period: number;
};

type StatusFilter = "all" | "pass" | "fail" | "no_data";

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

type OpenFindingMeta = { id: string; severity: string; resource_arn: string };

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

function CoverageTierBadge({ tier, label }: { tier?: string; label?: string | null }) {
  if (!tier || tier === "core" || tier === "no_data") return null;
  const text = label ?? (tier === "extended" ? "Supports control objective" : "Core + extended");
  return (
    <span
      className={`inline-flex items-center rounded-md px-2 py-0.5 text-[10px] font-medium ring-1 ring-inset ${
        tier === "extended"
          ? "bg-sky-50 text-sky-800 ring-sky-200/70"
          : "bg-violet-50 text-violet-800 ring-violet-200/70"
      }`}
    >
      {text}
    </span>
  );
}

function MappedChecksList({
  checkIds,
  checkTiers = {},
  checkEvidenceClasses = {},
}: {
  checkIds: string[];
  checkTiers?: Record<string, string>;
  checkEvidenceClasses?: Record<string, string>;
}) {
  const navigate = useNavigate();
  const grouped = useMemo(() => groupCheckIds(checkIds), [checkIds]);

  return (
    <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/40 p-4">
      <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500">Mapped checks</p>
      <p className="mt-1 text-xs font-medium text-zinc-600">
        {checkIds.length} check{checkIds.length === 1 ? "" : "s"} evaluated for this control
      </p>
      <div className="mt-3.5 space-y-3">
        {grouped.map(([group, ids]) => (
          <div key={group}>
            <p className="mb-1.5 text-xs font-semibold text-zinc-700">{group}</p>
            <ul className="overflow-hidden rounded-lg border border-zinc-200 bg-white divide-y divide-zinc-100">
              {ids.map((cid) => (
                <li key={cid}>
                  <button
                    type="button"
                    onMouseDown={(e) => e.preventDefault()}
                    onClick={() => navigate(`/findings?checks=${encodeURIComponent(cid)}`)}
                    className="group flex w-full items-center gap-3 px-3.5 py-3 text-left transition-colors hover:bg-zinc-50/80"
                  >
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-semibold leading-snug text-zinc-900 group-hover:text-indigo-700">
                        {labelForCheck(cid)}
                      </p>
                      <p className="mt-0.5 truncate font-mono text-[11px] text-zinc-500">{cid}</p>
                      <div className="mt-1 flex flex-wrap items-center gap-1.5">
                        {checkTiers[cid] === "extended" && (
                          <span className="text-[10px] font-medium text-sky-700">Supports control objective</span>
                        )}
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
              ))}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
}

type QuestionnaireDraft = { body: string; notes: string[] };

function buildQuestionnaireDraft(control: ControlRow, periodDays: number): QuestionnaireDraft | null {
  const body = (control.long_answer ?? control.narrative ?? control.description).trim();
  const short = control.short_answer?.trim();
  if (!body && !short) return null;

  const notes: string[] = [];
  if (short && short !== body) {
    notes.push(`Short answer: ${short}`);
  }
  if (control.evidence_refs.length > 0) {
    notes.push(`Evidence: ${control.evidence_refs.slice(0, 3).join("; ")}`);
  }
  if (control.known_gaps.length > 0) {
    notes.push(`Known gaps: ${control.known_gaps.join(" ")}`);
  }

  if (control.check_ids.length === 0) {
    notes.push("Status: Not automated in Vigil — no mapped checks for this CIS control yet.");
    notes.push("Answer manually for auditors (e.g. confirm IAM users have no directly attached policies).");
    return { body: body || short!, notes };
  }

  if (control.status === "no_data") {
    notes.push("Status: Not yet evaluated in Vigil (no scan data for mapped checks, or required sources are not connected).");
    notes.push("Run a scan before submitting this answer to auditors.");
    return { body: body || short!, notes };
  }

  if (control.status === "pass") {
    notes.push(`Status: Passing as of the latest Vigil scan (0 open findings mapped to ${control.control_id} in the last ${periodDays} days).`);
    return { body: body || short!, notes };
  }

  notes.push(`Status: ${findingLabel(control.finding_count)} mapped to ${control.control_id} as of the latest scan.`);
  notes.push("Edit before submitting to auditors — describe remediation in progress, compensating controls, or documented exceptions.");
  notes.push("After remediation, re-scan and export the evidence pack for audit sampling.");
  return { body: body || short!, notes };
}

function questionnaireDraftText(draft: QuestionnaireDraft) {
  return [draft.body, ...draft.notes].join("\n");
}

function questionnaireMeta(control: ControlRow) {
  if (control.check_ids.length === 0) {
    return {
      label: "Questionnaire template",
      hint: "Not automated in Vigil — manual attestation for auditors.",
      box: "border-zinc-200 bg-zinc-50/80",
      labelColor: "text-zinc-600",
      textColor: "text-zinc-800",
      btn: "border-zinc-200 text-zinc-700 hover:bg-zinc-100",
    };
  }
  const status = control.status;
  if (status === "pass") {
    return {
      label: "Questionnaire answer",
      hint: "Adapt for Vanta, Drata, or auditor forms.",
      box: "border-violet-200/80 bg-violet-50/40",
      labelColor: "text-violet-600",
      textColor: "text-violet-950/90",
      btn: "border-violet-200 text-violet-700 hover:bg-violet-50",
    };
  }
  if (status === "fail") {
    return {
      label: "Questionnaire template",
      hint: "Control is failing — add remediation status before submitting.",
      box: "border-amber-200/80 bg-amber-50/40",
      labelColor: "text-amber-800",
      textColor: "text-amber-950/90",
      btn: "border-amber-200 text-amber-800 hover:bg-amber-50",
    };
  }
  return {
    label: "Questionnaire template",
    hint: "Not evaluated yet — run a scan first.",
    box: "border-zinc-200 bg-zinc-50/80",
    labelColor: "text-zinc-600",
    textColor: "text-zinc-800",
    btn: "border-zinc-200 text-zinc-700 hover:bg-zinc-100",
  };
}

function ControlAuditEvidenceBlock({
  control,
  periodDays,
  coverage,
}: {
  control: ControlRow;
  periodDays: number;
  coverage?: EvidenceCoverage;
}) {
  const statusLine =
    control.status === "pass"
      ? `Passing — 0 open findings mapped to ${control.control_id} in the last ${periodDays} days.`
      : control.status === "fail"
        ? `${control.finding_count} open finding(s) mapped to ${control.control_id}.`
        : "Not yet evaluated — run a scan and ensure mapped checks have data.";

  return (
    <div className="mb-4 rounded-xl border border-indigo-200/70 bg-indigo-50/25 p-4">
      <p className="text-[10px] font-semibold uppercase tracking-wider text-indigo-700">Audit evidence summary</p>
      <ol className="mt-3 space-y-3 text-xs leading-relaxed text-zinc-800">
        <li>
          <span className="font-semibold text-zinc-900">1. Control objective — </span>
          {control.title}
          {control.description ? ` — ${control.description}` : ""}
        </li>
        <li>
          <span className="font-semibold text-zinc-900">2. What Vigil collects — </span>
          {control.check_ids.length > 0
            ? `${control.check_ids.length} automated check(s): ${control.check_ids.map((id) => labelForCheck(id)).join(", ")}.`
            : "No automated checks — manual attestation required."}
          {control.evidence_refs.length > 0 && (
            <span className="block mt-1 text-zinc-600">Artifacts: {control.evidence_refs.join("; ")}</span>
          )}
        </li>
        <li>
          <span className="font-semibold text-zinc-900">3. Period completeness — </span>
          {coverage ? (
            <>
              {coverage.coverage_label} ({Math.round(coverage.coverage_ratio * 100)}% of last {periodDays} days with
              successful scans). {coverage.successful_scans_in_period} scan(s) in period.
              {coverage.warning ? ` ${coverage.warning}` : ""}
            </>
          ) : (
            `Evidence pack covers a rolling ${periodDays}-day window from each successful scan.`
          )}
        </li>
        <li>
          <span className="font-semibold text-zinc-900">4. Findings / exceptions — </span>
          {statusLine}
        </li>
        <li>
          <span className="font-semibold text-zinc-900">5. Manual gaps — </span>
          {control.known_gaps.length > 0
            ? control.known_gaps.join(" ")
            : control.check_ids.length === 0
              ? "Entire control requires manual evidence outside Vigil."
              : "None documented for this control."}
        </li>
      </ol>
    </div>
  );
}

function NarrativeDetailBlock({ control }: { control: ControlRow }) {
  if (!control.short_answer && !control.long_answer && !control.narrative) return null;

  return (
    <div className="space-y-3">
      {control.short_answer && (
        <div className="rounded-xl border border-zinc-200/80 bg-white/80 p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500">Short answer</p>
          <p className="mt-1.5 text-sm leading-relaxed text-zinc-800">{control.short_answer}</p>
        </div>
      )}
      {control.evidence_refs.length > 0 && (
        <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/40 p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500">Evidence references</p>
          <ul className="mt-2 space-y-1">
            {control.evidence_refs.map((ref) => (
              <li key={ref} className="text-xs leading-relaxed text-zinc-700">{ref}</li>
            ))}
          </ul>
        </div>
      )}
      {control.known_gaps.length > 0 && (
        <div className="rounded-xl border border-amber-200/80 bg-amber-50/30 p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-amber-800">Known gaps</p>
          <ul className="mt-2 space-y-1">
            {control.known_gaps.map((gap) => (
              <li key={gap} className="text-xs leading-relaxed text-amber-950/90">{gap}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function QuestionnaireAnswerBlock({ control, periodDays }: { control: ControlRow; periodDays: number }) {
  const [copied, setCopied] = useState(false);
  const draft = buildQuestionnaireDraft(control, periodDays);
  const meta = questionnaireMeta(control);

  if (!draft) return null;
  const content = draft;

  async function copy() {
    await navigator.clipboard.writeText(questionnaireDraftText(content));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  const noteDivider =
    control.status === "pass"
      ? "border-violet-200/60"
      : control.status === "fail"
        ? "border-amber-200/60"
        : "border-zinc-200";

  return (
    <div className={`rounded-xl border p-4 ${meta.box}`}>
      <div className="mb-2 flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className={`text-[10px] font-semibold uppercase tracking-wider ${meta.labelColor}`}>{meta.label}</p>
          <p className={`mt-0.5 text-[11px] ${meta.labelColor} opacity-80`}>{meta.hint}</p>
        </div>
        <button
          type="button"
          onClick={copy}
          className={`inline-flex shrink-0 items-center gap-1 rounded-lg border bg-white px-2.5 py-1 text-[11px] font-semibold transition ${meta.btn}`}
        >
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <p className={`text-sm leading-relaxed ${meta.textColor}`}>{content.body}</p>
      {content.notes.length > 0 && (
        <div className={`mt-2.5 space-y-1 border-t pt-2.5 ${noteDivider}`}>
          {content.notes.map((note) => (
            <p key={note} className={`text-xs leading-snug ${meta.textColor} opacity-90`}>
              {note}
            </p>
          ))}
        </div>
      )}
    </div>
  );
}

function formatDuration(seconds: number): string {
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h`;
  return `${Math.round(seconds / 86400)}d`;
}

function ControlHistoryPanel({
  controlId,
  framework,
  accountId,
  period,
}: {
  controlId: string;
  framework: string;
  accountId: string;
  period: number;
}) {
  const navigate = useNavigate();
  const history = useQuery({
    queryKey: ["control-history", controlId, framework, accountId, period],
    queryFn: () =>
      api<ControlHistory>(
        `/v1/controls/${encodeURIComponent(controlId)}/history?framework=${framework}&account_id=${accountId}&days=${period}`
      ),
  });

  if (history.isLoading) {
    return <p className="mt-4 text-xs text-zinc-400">Loading control history…</p>;
  }
  if (history.isError || !history.data) return null;

  const h = history.data;
  const failSegment = h.segments.find((s) => s.status === "fail");

  return (
    <div className="mt-4 rounded-xl border border-zinc-200/80 bg-white p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500">Control history</p>
          {h.current_status === "fail" && h.days_failing != null && (
            <p className="mt-1 text-sm font-semibold text-red-600">
              Failing for {h.days_failing} day{h.days_failing === 1 ? "" : "s"}
              {h.failing_since ? ` · since ${formatEvidenceDate(h.failing_since)}` : ""}
            </p>
          )}
          {h.current_status === "pass" && (
            <p className="mt-1 text-sm font-semibold text-emerald-700">Passing — no open mapped findings</p>
          )}
        </div>
        <p className="text-xs text-zinc-500">
          Pass/fail segments and events above are the compliance history for this control.
        </p>
      </div>
      {failSegment && (
        <p className="mt-2 text-xs text-zinc-600">
          Longest failing window in period: {formatDuration(failSegment.duration_seconds)}
        </p>
      )}
      {h.events.length > 0 && (
        <ul className="mt-3 max-h-40 space-y-1.5 overflow-y-auto border-t border-zinc-100 pt-3">
          {h.events.slice(-5).reverse().map((evt) => (
            <li key={`${evt.timestamp}-${evt.type}`} className="text-xs text-zinc-600">
              <span className="font-mono text-zinc-400">{formatEvidenceDate(evt.timestamp)}</span>
              {" · "}
              <span className="font-medium text-zinc-700">{evt.type.replace(/_/g, " ")}</span>
              {" — "}
              {evt.detail}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function HistoricalDiffPanel({
  accountId,
  snapshots,
  period,
}: {
  accountId: string;
  snapshots: EvidencePreview["snapshots"];
  period: number;
}) {
  const [entityKey, setEntityKey] = useState("");
  const selected = useMemo(() => {
    if (entityKey) {
      return snapshots.find((s) => `${s.entity_type}:${s.entity_id}` === entityKey);
    }
    return snapshots[0];
  }, [entityKey, snapshots]);

  const diff = useQuery({
    queryKey: ["evidence-diff", accountId, selected?.entity_type, selected?.entity_id, period],
    queryFn: () => {
      if (!selected) return Promise.resolve(null);
      const atB = new Date().toISOString();
      const atA = new Date(Date.now() - period * 86400_000).toISOString();
      return api<EvidenceDiff>(
        `/v1/accounts/${accountId}/evidence-diff?entity_type=${encodeURIComponent(selected.entity_type)}&entity_id=${encodeURIComponent(selected.entity_id)}&at_a=${encodeURIComponent(atA)}&at_b=${encodeURIComponent(atB)}`
      );
    },
    enabled: !!selected,
  });

  if (snapshots.length === 0) return null;

  return (
    <div className="mt-4 rounded-xl border border-zinc-200/80 bg-zinc-50/40 p-4">
      <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500">Historical diff</p>
      <p className="mt-1 text-xs text-zinc-600">Compare collected state at start vs end of the {period}-day audit window.</p>
      {snapshots.length > 1 && selected && (
        <select
          value={`${selected.entity_type}:${selected.entity_id}`}
          onChange={(e) => setEntityKey(e.target.value)}
          className="mt-3 w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-xs font-mono text-zinc-700"
        >
          {snapshots.slice(0, 20).map((s) => {
            const key = `${s.entity_type}:${s.entity_id}`;
            return (
              <option key={key} value={key}>
                {s.entity_type} — {s.entity_id.slice(0, 60)}
              </option>
            );
          })}
        </select>
      )}
      {diff.isLoading && <p className="mt-3 text-xs text-zinc-400">Computing diff…</p>}
      {diff.data && !diff.data.found && (
        <p className="mt-3 text-xs text-zinc-500">{diff.data.message ?? "No diff available."}</p>
      )}
      {diff.data?.found && (
        <div className="mt-3 space-y-2">
          {diff.data.exposure_note && (
            <p className="text-xs font-medium text-amber-800">{diff.data.exposure_note}</p>
          )}
          {diff.data.changes.length === 0 ? (
            <p className="text-xs text-emerald-700">No field changes detected in this window.</p>
          ) : (
            <ul className="max-h-48 space-y-2 overflow-y-auto">
              {diff.data.changes.slice(0, 10).map((c) => (
                <li key={c.field} className="rounded-lg border border-zinc-200 bg-white px-3 py-2 text-xs">
                  <p className="font-mono font-semibold text-zinc-800">{c.field}</p>
                  <p className="mt-1 text-red-600 line-through">{String(c.before ?? "—")}</p>
                  <p className="text-emerald-700">{String(c.after ?? "—")}</p>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
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
      <HistoricalDiffPanel accountId={accountId} snapshots={snapshots} period={period} />
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
  const [asOf, setAsOf] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [exportOpen, setExportOpen] = useState(false);
  const exportRef = useRef<HTMLDivElement>(null);

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

  const cisCoverage = useQuery({
    queryKey: ["benchmark-coverage", "cis_aws_l1"],
    queryFn: () =>
      api<{ mapped_control_count: number; cis_v5_level1_total: number }>(
        "/v1/controls/benchmark-coverage/cis_aws_l1"
      ),
    enabled: framework === "cis_aws_l1",
  });

  const openFindingsMeta = useQuery({
    queryKey: ["findings", "open", connectedAccount?.id, "controls-meta"],
    queryFn: () =>
      api<{ items: OpenFindingMeta[] }>(`/v1/findings?status=open&limit=500`),
    enabled: !!connectedAccount && hasScanned,
    select: (data) => {
      const map = new Map<string, OpenFindingMeta>();
      for (const f of data.items) map.set(f.id, f);
      return map;
    },
  });

  const findingMap = openFindingsMeta.data ?? new Map<string, OpenFindingMeta>();

  const evidenceCoverage = useQuery({
    queryKey: ["evidence-coverage", connectedAccount?.id, period, asOf],
    queryFn: () => {
      const params = new URLSearchParams({ period: String(period) });
      if (asOf.trim()) params.set("as_of", asOf.trim());
      return api<EvidenceCoverage>(
        `/v1/accounts/${connectedAccount!.id}/evidence-coverage?${params}`
      );
    },
    enabled: !!connectedAccount && hasScanned,
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
  const totalLinkedFindings = useMemo(
    () => rows.reduce((sum, row) => sum + row.finding_count, 0),
    [rows],
  );

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
      const params = new URLSearchParams({
        framework,
        account_id: connectedAccount.id,
        period: String(period),
      });
      if (asOf.trim()) params.set("as_of", asOf.trim());
      const res = await fetch(`${BASE}/v1/exports/evidence-pack?${params}`, {
        headers: { Authorization: `Bearer ${tok}` },
      });
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
    <div className="min-h-full bg-zinc-100/35">
    <div className="w-full px-8 py-8">
      <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <h1 className="text-2xl font-bold tracking-tight text-zinc-950">Compliance</h1>
          <p className="mt-1.5 text-sm text-zinc-500">
            {activeFramework.fullLabel}
            {connectedAccount?.account_id && (
              <span className="text-zinc-400"> · account {connectedAccount.account_id}</span>
            )}
            {connectedAccount?.last_scan_at && (
              <span className="text-zinc-400">
                {" "}
                · Last scan {lastScanLabel(connectedAccount.last_scan_at)}
              </span>
            )}
            {passRate != null && (
              <span className="text-zinc-400"> · {passed}/{total} controls passing</span>
            )}
          </p>
          {framework === "cis_aws_l1" && cisCoverage.data && (
            <p className="mt-2 max-w-2xl rounded-lg border border-amber-200/80 bg-amber-50/60 px-3 py-2 text-xs text-amber-900">
              Automated coverage: {cisCoverage.data.mapped_control_count} of{" "}
              {cisCoverage.data.cis_v5_level1_total} CIS AWS Foundations v5 Level 1 controls (curated subset).
            </p>
          )}
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-2">
          {connectedAccount && (
            <div ref={exportRef} className="relative">
              <button
                type="button"
                onClick={() => setExportOpen((open) => !open)}
                aria-expanded={exportOpen}
                aria-haspopup="dialog"
                className={`inline-flex items-center gap-2 rounded-xl border px-4 py-2.5 text-sm font-semibold shadow-sm transition ${
                  exportOpen
                    ? "border-indigo-300 bg-indigo-50 text-indigo-800 ring-2 ring-indigo-500/10"
                    : "border-indigo-200 bg-indigo-50/60 text-indigo-700 hover:border-indigo-300 hover:bg-indigo-50"
                }`}
              >
                <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                </svg>
                Evidence pack
              </button>
              {exportOpen && (
                <div
                  role="dialog"
                  aria-label="Evidence pack export"
                  className="absolute right-0 top-full z-50 mt-2 w-72 rounded-2xl border border-indigo-100 bg-gradient-to-b from-indigo-50/70 to-white p-5 shadow-lg shadow-indigo-950/10 ring-1 ring-black/5"
                >
                  <p className="text-[10px] font-semibold uppercase tracking-wider text-indigo-600">Evidence pack</p>
                  <p className="mt-2 text-sm font-semibold text-zinc-900">{activeFramework.label}</p>
                  <p className="mt-1 text-xs leading-relaxed text-zinc-500">
                    Auditor-ready ZIP with INDEX.csv, per-control JSON snapshots, and PDF summary.
                  </p>
                  <div className="mt-5">
                    <label htmlFor="evidence-period" className="block text-[10px] font-semibold uppercase tracking-wider text-zinc-400">
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
                  </div>
                  <div className="mt-4">
                    <label htmlFor="evidence-as-of" className="block text-[10px] font-semibold uppercase tracking-wider text-zinc-400">
                      As of date (optional)
                    </label>
                    <input
                      id="evidence-as-of"
                      type="date"
                      value={asOf}
                      onChange={(e) => setAsOf(e.target.value)}
                      max={new Date().toISOString().slice(0, 10)}
                      className="mt-1.5 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2.5 text-sm font-medium text-zinc-700 outline-none focus:border-indigo-300 focus:ring-2 focus:ring-indigo-500/20"
                    />
                    <p className="mt-1 text-[11px] text-zinc-500">
                      End of audit period for Type II sampling. Leave blank for today (UTC).
                    </p>
                  </div>
                  {evidenceCoverage.data && (
                    <div
                      className={`mt-4 rounded-xl border px-3 py-2.5 text-xs leading-relaxed ${
                        evidenceCoverage.data.warning
                          ? "border-amber-200/80 bg-amber-50/60 text-amber-900"
                          : "border-emerald-200/70 bg-emerald-50/50 text-emerald-900"
                      }`}
                    >
                      <p className="font-medium">
                        Evidence coverage: {evidenceCoverage.data.coverage_label}
                      </p>
                      <p className="mt-0.5 text-[11px] opacity-90">
                        {evidenceCoverage.data.successful_scans_in_period} successful scan
                        {evidenceCoverage.data.successful_scans_in_period === 1 ? "" : "s"} in window
                      </p>
                      {evidenceCoverage.data.warning && (
                        <p className="mt-1.5 text-[11px]">{evidenceCoverage.data.warning}</p>
                      )}
                    </div>
                  )}
                  <button
                    onClick={downloadPack}
                    disabled={downloading}
                    className="mt-5 inline-flex w-full items-center justify-center gap-2 rounded-xl bg-indigo-600 px-4 py-3 text-sm font-semibold text-white shadow-sm shadow-indigo-600/20 transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-50"
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
              )}
            </div>
          )}
        </div>
      </div>

      {!hasScanned && connectedAccount && !controls.isLoading && (
        <div className="mb-6 rounded-2xl border border-amber-200 bg-amber-50/60 px-5 py-4 text-sm text-amber-900">
          <span className="font-semibold">Awaiting first scan.</span> Control pass/fail status appears after your account finishes scanning.
        </div>
      )}

      {controls.isLoading && <LoadingSkeleton />}

      {!controls.isLoading && connectedAccount && (
        <div className="mb-5 grid grid-cols-1 gap-3 sm:grid-cols-3" role="tablist" aria-label="Compliance framework">
          {FRAMEWORKS.map((fw) => {
            const pct =
              fw.id === "soc2" ? soc2Rate.data : fw.id === "cis_aws_l1" ? cisRate.data : isoRate.data;
            const isActive = framework === fw.id;
            const fwFailed = isActive ? failed : null;
            const fwPassed = isActive ? passed : null;
            const fwFindings = isActive ? totalLinkedFindings : null;
            return (
              <button
                key={fw.id}
                type="button"
                role="tab"
                aria-selected={isActive}
                onClick={() => {
                  setFramework(fw.id);
                  setSelectedFamilyKey(null);
                  setExpanded(null);
                }}
                className={`rounded-xl border px-4 py-3.5 text-left transition-all ${
                  isActive
                    ? "border-indigo-200/80 bg-white text-zinc-900 shadow-md shadow-zinc-950/[0.04] ring-1 ring-indigo-500/10"
                    : "border-zinc-200/80 bg-white/80 text-zinc-900 shadow-sm shadow-zinc-950/[0.02] hover:border-indigo-200/60 hover:bg-white hover:shadow-md"
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="text-sm font-bold">{fw.label}</div>
                    <div className="mt-0.5 text-xs text-zinc-500">{fw.fullLabel}</div>
                  </div>
                  <div className={`text-2xl font-bold tabular-nums leading-none ${pct == null ? "text-zinc-300" : passRateColor(pct)}`}>
                    {pct == null ? "—" : `${pct}%`}
                  </div>
                </div>
                {isActive && fwFailed != null && fwPassed != null && (
                  <div className="mt-3 flex flex-wrap gap-x-3 gap-y-1 text-[11px] font-medium text-zinc-500">
                    {fwFailed > 0 && <span className="text-red-600/90">{fwFailed} failing</span>}
                    <span className="text-emerald-600/90">{fwPassed} passing</span>
                    {noData > 0 && <span>{noData} no data</span>}
                    {fwFindings != null && fwFindings > 0 && (
                      <span>{fwFindings} finding{fwFindings === 1 ? "" : "s"} linked</span>
                    )}
                  </div>
                )}
                <div className={`mt-3 h-1.5 overflow-hidden rounded-full ${isActive ? "bg-indigo-100/80" : "bg-zinc-100"}`}>
                  <div
                    className={`h-full rounded-full transition-all ${pct == null ? "bg-zinc-200" : passRateBarColor(pct)}`}
                    style={{ width: `${pct ?? 0}%` }}
                  />
                </div>
              </button>
            );
          })}
        </div>
      )}

      {!controls.isLoading && total > 0 && (
        <div className="mb-5 space-y-3">
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
          {topBlocker && statusFilter !== "pass" && (
            <div className="rounded-xl border border-red-200/60 bg-gradient-to-r from-red-50/40 via-white to-white px-4 py-3.5 shadow-sm shadow-zinc-950/[0.03]">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div className="min-w-0">
                  <p className="text-[10px] font-semibold uppercase tracking-wider text-red-600/90">
                    Highest-impact blocker
                  </p>
                  <p className="mt-1 text-sm font-semibold text-zinc-900">
                    <span className="font-mono text-xs font-medium text-zinc-500">{topBlocker.control_id}</span>
                    <span className="mx-1.5 text-zinc-300">·</span>
                    {shortControlTitle(topBlocker.title)}
                  </p>
                  <p className="mt-1 text-xs text-zinc-600">
                    {findingLabel(topBlocker.finding_count)} blocking this control — address first for fastest audit progress.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setStatusFilter("fail");
                    openControl(topBlocker);
                  }}
                  className="inline-flex shrink-0 items-center gap-1.5 self-start rounded-lg bg-red-600 px-3.5 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-red-700 sm:self-center"
                >
                  Review control
                  <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
                  </svg>
                </button>
              </div>
            </div>
          )}
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
                <div className="flex flex-col gap-3 border-b border-zinc-100 bg-zinc-50/50 px-5 py-3.5 sm:flex-row sm:items-center sm:justify-between">
                  <div
                    className="flex flex-wrap items-center gap-1 rounded-xl border border-zinc-200/70 bg-white p-1 shadow-sm shadow-zinc-950/[0.02]"
                    role="tablist"
                    aria-label="Control domains"
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
                              ? "bg-indigo-50 text-indigo-900 ring-1 ring-indigo-200/80"
                              : "text-zinc-500 hover:bg-zinc-50 hover:text-zinc-900"
                          }`}
                        >
                          {shortFamilyLabel(group.label)}
                          {group.failed > 0 && (
                            <span className="text-red-500/90"> · {group.failed}</span>
                          )}
                        </button>
                      );
                    })}
                  </div>
                </div>

                <div className="border-b border-zinc-100 bg-zinc-50/30 px-5 py-3">
                  <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400">
                    {activeFramework.label}
                  </p>
                  <h2 className="mt-0.5 text-base font-bold text-zinc-900">{selectedGroup.label}</h2>
                  <p className="mt-1 text-xs text-zinc-500">
                    {selectedGroup.rows.length} control{selectedGroup.rows.length === 1 ? "" : "s"}
                    {selectedGroup.failed > 0 && (
                      <span className="text-red-600/90"> · {selectedGroup.failed} failing</span>
                    )}
                    {selectedGroup.passed > 0 && (
                      <span className="text-emerald-600/90"> · {selectedGroup.passed} passing</span>
                    )}
                    {selectedGroup.noData > 0 && (
                      <span> · {selectedGroup.noData} no data</span>
                    )}
                  </p>
                </div>

                <div className="hidden grid-cols-[auto_auto_minmax(0,1fr)_auto] items-center gap-4 border-b border-zinc-100 bg-white px-5 py-2.5 sm:grid">
                  <span className="w-3.5" />
                  <span className="w-[72px] text-[10px] font-semibold uppercase tracking-[0.12em] text-zinc-400">Status</span>
                  <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-zinc-400">Control</span>
                  <span className="text-right text-[10px] font-semibold uppercase tracking-[0.12em] text-zinc-400">Findings</span>
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
                          className={`grid w-full grid-cols-1 gap-3 border-l-2 py-3.5 pl-5 pr-5 text-left transition-colors sm:grid-cols-[auto_auto_minmax(0,1fr)_auto] sm:items-center sm:gap-4 ${statusAccent[ctrl.status]} ${
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
                              <CoverageTierBadge tier={ctrl.coverage_tier} label={ctrl.coverage_label} />
                            </div>
                            <p className="mt-1 truncate text-xs text-zinc-500">{meta}</p>
                          </div>

                          <div className="flex shrink-0 items-center justify-between gap-3 sm:block sm:text-right">
                            <svg
                              className={`h-3.5 w-3.5 shrink-0 text-zinc-400 sm:hidden ${isExpanded ? "" : "-rotate-90"}`}
                              fill="none"
                              stroke="currentColor"
                              viewBox="0 0 24 24"
                            >
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                            </svg>
                            <div className="tabular-nums">
                              {ctrl.status === "fail" ? (
                                <>
                                  <span className={`text-base font-bold ${ctrl.finding_count >= 10 ? "text-red-600" : "text-red-500"}`}>
                                    {ctrl.finding_count}
                                  </span>
                                  <span className="mt-0.5 block text-[10px] font-medium uppercase tracking-wide text-zinc-400">
                                    open
                                  </span>
                                </>
                              ) : ctrl.status === "pass" ? (
                                <span className="text-xs font-medium text-emerald-600/80">Clear</span>
                              ) : (
                                <span className="text-xs font-medium text-zinc-300">—</span>
                              )}
                            </div>
                          </div>
                        </button>

                        {isExpanded && (
                          <div className={`border-t border-zinc-100/80 px-5 pb-5 pt-4 sm:pl-[4.75rem] ${statusExpandedBg[ctrl.status]}`}>
                            <ControlAuditEvidenceBlock
                              control={ctrl}
                              periodDays={period}
                              coverage={evidenceCoverage.data}
                            />
                            <NarrativeDetailBlock control={ctrl} />
                            {(ctrl.narrative || ctrl.description) ? (
                              <div className="mt-4">
                                <QuestionnaireAnswerBlock control={ctrl} periodDays={period} />
                              </div>
                            ) : (
                              <p className="text-sm leading-relaxed text-zinc-700">{controlSummary(ctrl)}</p>
                            )}

                            {connectedAccount && hasScanned && ctrl.check_ids.length > 0 && (
                              <div className={`${ctrl.narrative || ctrl.description ? "mt-4" : "mt-0"}`}>
                                <EvidencePreviewPanel
                                  controlId={ctrl.control_id}
                                  accountId={connectedAccount.id}
                                  period={period}
                                />
                                <ControlHistoryPanel
                                  controlId={ctrl.control_id}
                                  framework={framework}
                                  accountId={connectedAccount.id}
                                  period={period}
                                />
                              </div>
                            )}

                            {ctrl.check_ids.length === 0 && (
                              <p className="mt-4 rounded-xl border border-dashed border-zinc-200 bg-zinc-50/60 px-4 py-3 text-xs leading-relaxed text-zinc-600">
                                No automated Vigil checks map to this CIS control yet — attest manually for auditors
                                (e.g. confirm IAM users have policies only via groups or roles).
                              </p>
                            )}

                            {ctrl.check_ids.length > 0 && (
                              <div className="mt-4">
                                <MappedChecksList
                                  checkIds={ctrl.check_ids}
                                  checkTiers={ctrl.check_tiers}
                                  checkEvidenceClasses={ctrl.check_evidence_classes}
                                />
                              </div>
                            )}

                            {ctrl.status === "fail" && ctrl.open_finding_ids.length > 0 && (
                              <div className="mt-4 border-t border-zinc-200/70 pt-4">
                                <button
                                  type="button"
                                  onClick={() => navigate(`/findings?checks=${ctrl.check_ids.join(",")}`)}
                                  className="inline-flex items-center gap-1.5 text-sm font-semibold text-indigo-600 transition-colors hover:text-indigo-800"
                                >
                                  View {findingLabel(ctrl.finding_count)}
                                  <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
                                  </svg>
                                </button>
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
    </div>
  );
}
