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

const FRAMEWORKS = [
  { id: "soc2", label: "SOC 2", fullLabel: "SOC 2 Trust Services Criteria", postureLabel: "SOC 2 posture" },
  { id: "cis_aws_l1", label: "CIS AWS L1", fullLabel: "CIS AWS Foundations Benchmark L1", postureLabel: "CIS AWS L1 posture" },
  { id: "iso27001", label: "ISO 27001", fullLabel: "ISO 27001 Annex A", postureLabel: "ISO 27001 posture" },
];

const AUDIT_WINDOWS = [
  { value: 30, label: "Last 30 days" },
  { value: 90, label: "Last 90 days" },
  { value: 180, label: "Last 180 days" },
  { value: 365, label: "Last 365 days" },
];

const statusBadge: Record<string, string> = {
  pass: "bg-emerald-50 text-emerald-700 border-emerald-200",
  fail: "bg-red-50 text-red-600 border-red-200",
  no_data: "bg-zinc-50 text-zinc-500 border-zinc-200",
};

const statusLabel: Record<string, string> = {
  pass: "Pass",
  fail: "Fail",
  no_data: "No data",
};

function StatusIcon({ status }: { status: string }) {
  if (status === "pass") {
    return (
      <svg className="w-4 h-4 text-emerald-600" fill="none" stroke="currentColor" strokeWidth={2.5} viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
      </svg>
    );
  }
  if (status === "fail") {
    return (
      <svg className="w-4 h-4 text-red-500" fill="none" stroke="currentColor" strokeWidth={2.5} viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
      </svg>
    );
  }
  return (
    <svg className="w-4 h-4 text-zinc-400" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
    </svg>
  );
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

function totalFindings(group: ControlGroup) {
  return group.rows.reduce((sum, row) => sum + row.finding_count, 0);
}

function findingBadgeClass(count: number) {
  const base = "inline-flex w-[7rem] items-center justify-center rounded-md border px-2.5 py-1 text-xs tabular-nums";
  if (count >= 50) return `${base} border-red-300 bg-red-100 font-bold text-red-700`;
  if (count >= 10) return `${base} border-red-200 bg-red-50 font-semibold text-red-700`;
  return `${base} border-red-100 bg-red-50/70 font-semibold text-red-600`;
}

function familyCardClass(active: boolean, group: ControlGroup) {
  const activeClass = active ? "border-zinc-400 bg-white shadow-sm ring-1 ring-zinc-900/5" : "border-zinc-200 bg-white hover:border-zinc-300 hover:bg-zinc-50/50";
  const accentClass = group.failed > 0 ? "border-l-red-200" : group.noData === group.rows.length ? "border-l-zinc-300" : "border-l-emerald-200";
  return `flex min-h-[10rem] flex-col rounded-xl border border-l-4 ${activeClass} ${accentClass} p-3.5 text-left transition-colors`;
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
    return id.split(".")[0]?.toUpperCase() || "Mapped checks";
  });
  return Array.from(new Set(areas));
}

function compactSentence(text: string | null | undefined, fallback: string) {
  const raw = (text || fallback).replace(/^Evidence:\s*/i, "").trim();
  const first = raw.match(/[^.!?]+[.!?]/)?.[0] ?? raw;
  if (first.length <= 150) return first;
  return `${first.slice(0, 147).trim()}...`;
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

function NarrativeBlock({ text, controlId }: { text: string; controlId: string }) {
  const [copied, setCopied] = useState(false);

  function copy() {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="rounded-lg border border-zinc-200 bg-white px-4 py-3">
      <div className="flex items-center justify-between mb-2">
        <div className="text-xs font-semibold text-zinc-500 uppercase tracking-wide">
          Audit Response — {controlId}
        </div>
        <button
          onClick={copy}
          className="flex items-center gap-1 text-xs text-zinc-500 hover:text-zinc-900 transition-colors"
          title="Copy to clipboard"
        >
          {copied ? (
            <>
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
              </svg>
              Copied
            </>
          ) : (
            <>
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
              </svg>
              Copy
            </>
          )}
        </button>
      </div>
      <p className="text-sm text-zinc-700 leading-relaxed">{text}</p>
    </div>
  );
}

export default function Controls() {
  const navigate = useNavigate();
  const [framework, setFramework] = useState("soc2");
  const [selectedFamilyKey, setSelectedFamilyKey] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [detailsOpen, setDetailsOpen] = useState<string | null>(null);
  const [copiedControlId, setCopiedControlId] = useState<string | null>(null);
  const [downloading, setDownloading] = useState(false);
  const [period, setPeriod] = useState(90);

  const accounts = useQuery({
    queryKey: ["accounts"],
    queryFn: () => api<Account[]>("/v1/accounts"),
  });

  const connectedAccount = accounts.data?.find((a) => a.status === "connected");

  const controls = useQuery({
    queryKey: ["controls", framework, connectedAccount?.id],
    queryFn: () =>
      api<ControlRow[]>(
        `/v1/controls?framework=${framework}${connectedAccount ? `&account_id=${connectedAccount.id}` : ""}`
      ),
    enabled: !accounts.isLoading,
  });

  const rows = controls.data ?? [];
  const passed = rows.filter((r) => r.status === "pass").length;
  const failed = rows.filter((r) => r.status === "fail").length;
  const noData = rows.filter((r) => r.status === "no_data").length;
  const total = rows.length;
  const passRate = total > 0 ? Math.round((passed / total) * 100) : 0;
  const groupedRows = useMemo(() => groupControls(rows, framework), [rows, framework]);
  const selectedGroup = groupedRows.find((group) => group.key === selectedFamilyKey) ?? groupedRows[0] ?? null;
  const selectedFramework = FRAMEWORKS.find((fw) => fw.id === framework) ?? FRAMEWORKS[0];

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

  function copyAuditResponse(control: ControlRow) {
    if (!control.narrative) return;
    navigator.clipboard.writeText(control.narrative);
    setCopiedControlId(control.id);
    setTimeout(() => setCopiedControlId(null), 2000);
  }

  return (
    <div className="w-full space-y-4 px-8 py-5">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-950">Compliance</h1>
          <p className="mt-1 text-sm text-zinc-500">Control status against selected frameworks.</p>
        </div>

        <div className="inline-flex items-center self-start rounded-lg border border-zinc-200 bg-white p-1 shadow-sm" aria-label="Framework">
          {FRAMEWORKS.map((fw) => (
            <button
              key={fw.id}
              onClick={() => {
                setFramework(fw.id);
                setSelectedFamilyKey(null);
                setExpanded(null);
                setDetailsOpen(null);
              }}
              className={`rounded-md px-3.5 py-1.5 text-sm font-medium transition-colors ${
                framework === fw.id
                  ? "bg-zinc-900 text-white shadow-sm"
                  : "text-zinc-500 hover:bg-zinc-50 hover:text-zinc-900"
              }`}
            >
              {fw.label}
            </button>
          ))}
        </div>
      </div>

      <section className="overflow-hidden rounded-xl border border-zinc-200 bg-white shadow-sm">
        <div className="grid lg:grid-cols-[minmax(0,2fr)_minmax(340px,1fr)]">
          <div className="p-4">
            <div className="flex items-start justify-between gap-4">
            <div>
              <h2 className="text-sm font-semibold tracking-tight text-zinc-950">{selectedFramework.postureLabel}</h2>
              <p className="mt-0.5 text-xs text-zinc-500">{selectedFramework.fullLabel} controls evaluated from current evidence.</p>
            </div>
          </div>

            <div className="mt-3 flex flex-col gap-3">
              <div className="flex items-end gap-2">
                <div className="text-3xl font-semibold leading-none tracking-tight text-zinc-950 tabular-nums">
                  {controls.isLoading ? "..." : `${passRate}%`}
                </div>
                <div className="pb-0.5 text-xs font-medium text-zinc-500">pass rate</div>
              </div>

              <div className="h-1.5 overflow-hidden rounded-full bg-zinc-100">
                <div
                  className="h-full rounded-full bg-emerald-500 transition-all duration-700"
                  style={{ width: controls.isLoading ? "0%" : `${passRate}%` }}
                />
              </div>

              <div className="grid grid-cols-2 border-t border-zinc-100 pt-2 sm:grid-cols-4 sm:divide-x sm:divide-zinc-100">
                {[
                  { value: failed, label: "failing controls", valueClass: "text-red-600" },
                  { value: passed, label: "passing controls", valueClass: "text-emerald-700" },
                  { value: noData, label: "no-data controls", valueClass: "text-zinc-600" },
                  { value: total, label: "total controls", valueClass: "text-zinc-900" },
                ].map((item) => (
                  <div key={item.label} className="border-t border-zinc-100 px-3 py-0.5 first:border-t-0 first:pl-0 sm:border-t-0">
                    <div className={`text-base font-semibold tabular-nums ${controls.isLoading ? "text-zinc-300" : item.valueClass}`}>
                      {controls.isLoading ? "..." : item.value}
                    </div>
                    <div className="text-[11px] font-medium text-zinc-500">{item.label}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="border-t border-zinc-100 bg-zinc-50/50 p-4 lg:border-l lg:border-t-0">
            <div>
              <h2 className="text-sm font-semibold text-zinc-950">Audit export</h2>
              <p className="mt-1 text-xs leading-5 text-zinc-500">
                Download an evidence package for the selected audit window. Includes findings, snapshots, and PDF report.
              </p>
            </div>

            <div className="pt-3">
              <label className="block text-[11px] font-semibold uppercase tracking-wide text-zinc-400" htmlFor="audit-window">
                Audit window
              </label>
              <div className="relative mt-1.5">
                <select
                  id="audit-window"
                  value={period}
                  onChange={(e) => setPeriod(Number(e.target.value))}
                  className="h-8 w-full appearance-none rounded-lg border border-zinc-200 bg-white px-3 pr-9 text-sm font-medium text-zinc-800 shadow-sm outline-none transition focus:border-zinc-400 focus:ring-2 focus:ring-zinc-950/[0.06]"
                >
                  {AUDIT_WINDOWS.map((window) => (
                    <option key={window.value} value={window.value}>
                      {window.label}
                    </option>
                  ))}
                </select>
                <svg className="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-400" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                </svg>
              </div>

              <button
                onClick={downloadPack}
                disabled={downloading || !connectedAccount}
                className="mt-3 inline-flex h-8 w-full items-center justify-center gap-2 rounded-lg border border-zinc-900 bg-zinc-900 px-4 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-zinc-800 disabled:cursor-not-allowed disabled:border-zinc-200 disabled:bg-zinc-100 disabled:text-zinc-400"
              >
                {downloading ? (
                  <svg className="h-4 w-4 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                  </svg>
                ) : (
                  <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                  </svg>
                )}
                {downloading ? "Generating package..." : "Download package"}
              </button>
            </div>
          </div>
        </div>
      </section>

      <section className="space-y-3">
        <div>
          <div>
            <h2 className="text-base font-semibold text-zinc-950">Control families</h2>
            <p className="mt-1 text-sm text-zinc-500">{selectedFramework.label} controls grouped by audit area.</p>
          </div>
        </div>

        {controls.isLoading && (
          <div className="rounded-xl border border-zinc-200 bg-white px-6 py-16 text-center text-sm text-zinc-400 shadow-sm">Loading controls...</div>
        )}
        {!controls.isLoading && rows.length === 0 && (
          <div className="rounded-xl border border-zinc-200 bg-white px-6 py-16 text-center text-sm text-zinc-400 shadow-sm">
            No controls found.{!connectedAccount && " Connect an AWS account to see compliance status."}
          </div>
        )}

        {!controls.isLoading && groupedRows.length > 0 && (
          <>
            <div className="grid gap-3 xl:grid-cols-3">
              {groupedRows.map((group) => {
                const isSelected = selectedGroup?.key === group.key;
                const findings = totalFindings(group);
                const previewRows = (group.failed > 0 ? group.rows.filter((row) => row.status === "fail") : group.rows).slice(0, 3);
                return (
                  <button
                    key={group.key}
                    onClick={() => {
                      setSelectedFamilyKey(group.key);
                      setExpanded(null);
                      setDetailsOpen(null);
                    }}
                    className={familyCardClass(isSelected, group)}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <h3 className="text-[15px] font-semibold leading-6 text-zinc-950">{group.label}</h3>
                        <p className="text-xs text-zinc-400">{group.rows.length} controls in scope</p>
                      </div>
                      <span className={`rounded-md border px-2 py-1 text-xs font-semibold ${
                        group.failed > 0
                          ? "border-red-100 bg-red-50 text-red-600"
                          : group.noData === group.rows.length
                            ? "border-zinc-200 bg-zinc-50 text-zinc-500"
                          : "border-emerald-100 bg-emerald-50 text-emerald-700"
                      }`}>
                        {group.failed > 0 ? `${group.failed} failing` : group.noData === group.rows.length ? "No data" : "All clear"}
                      </span>
                    </div>

                    <div className="mt-3 grid grid-cols-3 gap-2 text-left">
                      <div>
                        <div className="text-lg font-semibold tabular-nums text-red-600">{group.failed}</div>
                        <div className="text-xs text-zinc-500">failing</div>
                      </div>
                      <div>
                        <div className="text-lg font-semibold tabular-nums text-emerald-700">{group.passed}</div>
                        <div className="text-xs text-zinc-500">passing</div>
                      </div>
                      <div>
                        <div className="text-lg font-semibold tabular-nums text-zinc-800">{findings}</div>
                        <div className="text-xs text-zinc-500">findings</div>
                      </div>
                    </div>

                    <div className="mt-3 space-y-1.5">
                      {previewRows.map((ctrl) => (
                        <div key={ctrl.id} className="flex items-center justify-between gap-3 text-xs">
                          <span className="truncate text-zinc-700">
                            <span className="font-mono text-xs font-semibold text-zinc-500">{ctrl.control_id}</span>{" "}
                            {shortControlTitle(ctrl.title)}
                          </span>
                          <span className={`shrink-0 font-semibold tabular-nums ${
                            ctrl.status === "fail" ? "text-red-600" : ctrl.status === "pass" ? "text-emerald-700" : "text-zinc-400"
                          }`}>
                            {ctrl.status === "fail" ? ctrl.finding_count : statusLabel[ctrl.status]}
                          </span>
                        </div>
                      ))}
                    </div>
                  </button>
                );
              })}
            </div>

            {selectedGroup && (
              <section className="overflow-hidden rounded-xl border border-zinc-200 bg-white shadow-sm">
                <div className="flex items-start justify-between gap-4 border-b border-zinc-100 bg-white px-4 py-3">
                  <div>
                    <h3 className="text-base font-semibold text-zinc-950">Selected family: {selectedGroup.label}</h3>
                    <p className="mt-1 text-sm text-zinc-500">
                      {selectedGroup.rows.length} controls · {selectedGroup.failed} failing · {selectedGroup.passed} passing · {totalFindings(selectedGroup)} findings
                    </p>
                  </div>
                </div>

                <div className="divide-y divide-zinc-100">
                  {selectedGroup.rows.map((ctrl) => {
                    const isExpanded = expanded === ctrl.id;
                    return (
                      <div key={ctrl.id}>
                        <button
                          onClick={() => {
                            setExpanded(isExpanded ? null : ctrl.id);
                            setDetailsOpen(null);
                          }}
                          className={`grid w-full grid-cols-[1.75rem_4.75rem_minmax(0,1fr)_7rem_1.25rem] items-center gap-2.5 px-4 py-3 text-left transition-colors hover:bg-zinc-50 group ${
                            isExpanded ? "bg-zinc-50/70" : "bg-white"
                          }`}
                        >
                          <div className={`flex h-7 w-7 items-center justify-center rounded-full border ${statusBadge[ctrl.status]}`}>
                            <StatusIcon status={ctrl.status} />
                          </div>

                          <span className="font-mono text-xs font-semibold text-zinc-500">{ctrl.control_id}</span>

                          <div className="min-w-0">
                            <div className="truncate text-sm font-medium leading-6 text-zinc-950">{shortControlTitle(ctrl.title)}</div>
                            <div className="text-xs text-zinc-400">{statusLabel[ctrl.status]}</div>
                          </div>

                          <div className="justify-self-end">
                            {ctrl.status === "fail" && (
                              <span className={findingBadgeClass(ctrl.finding_count)}>{findingLabel(ctrl.finding_count)}</span>
                            )}
                            {ctrl.status === "pass" && (
                              <span className="inline-flex w-[6rem] items-center justify-center rounded-md border border-emerald-100 bg-emerald-50/70 px-2.5 py-1 text-xs font-semibold text-emerald-700">
                                All clear
                              </span>
                            )}
                            {ctrl.status === "no_data" && (
                              <span className="inline-flex w-[6rem] items-center justify-center rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-1 text-xs font-medium text-zinc-400">
                                No data
                              </span>
                            )}
                          </div>

                          <svg
                            className={`h-4 w-4 justify-self-end text-zinc-300 transition-transform group-hover:text-zinc-500 ${isExpanded ? "rotate-180" : ""}`}
                            fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24"
                          >
                            <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                          </svg>
                        </button>

                        {isExpanded && (
                          <div className="border-t border-zinc-100 bg-zinc-50/60 px-4 pb-4 pt-3">
                            <div className={`grid gap-4 ${detailsOpen === ctrl.id ? "2xl:grid-cols-[minmax(0,0.95fr)_minmax(380px,1.05fr)]" : ""}`}>
                              <div className="space-y-3 md:pl-[6.75rem]">
                                <div>
                                  <p className="text-[15px] font-medium leading-6 text-zinc-950">{failureSummary(ctrl)}</p>
                                  <p className="mt-1 text-sm leading-6 text-zinc-600">{nextStep(ctrl)}</p>
                                </div>

                                {checkAreas(ctrl.check_ids).length > 0 && (
                                  <div>
                                    <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-zinc-400">Top affected areas</div>
                                    <div className="flex flex-wrap gap-1.5">
                                      {checkAreas(ctrl.check_ids).slice(0, 6).map((area) => (
                                        <span key={area} className="rounded-md border border-zinc-200 bg-white px-2.5 py-1 text-xs font-medium text-zinc-600">
                                          {area}
                                        </span>
                                      ))}
                                    </div>
                                  </div>
                                )}

                                <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-zinc-500">
                                  <span>
                                    <span className="font-medium text-zinc-700">Evidence expected:</span>{" "}
                                    {compactSentence(ctrl.guidance, ctrl.description)}
                                  </span>
                                  <span>
                                    <span className="font-medium text-zinc-700">Checks mapped:</span>{" "}
                                    {ctrl.check_ids.length}
                                  </span>
                                </div>

                                <div className="flex flex-wrap items-center gap-2">
                                  {ctrl.status === "fail" && ctrl.open_finding_ids.length > 0 && (
                                    <button
                                      onClick={() => navigate(`/findings?checks=${ctrl.check_ids.join(",")}`)}
                                      className="inline-flex h-8 items-center gap-1.5 rounded-lg bg-zinc-900 px-3 text-sm font-semibold text-white transition-colors hover:bg-zinc-800"
                                    >
                                      View {findingLabel(ctrl.finding_count)}
                                      <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
                                      </svg>
                                    </button>
                                  )}
                                  {ctrl.narrative && (
                                    <button
                                      onClick={() => copyAuditResponse(ctrl)}
                                      className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-zinc-200 bg-white px-3 text-sm font-medium text-zinc-700 transition-colors hover:bg-zinc-50 hover:text-zinc-950"
                                    >
                                      {copiedControlId === ctrl.id ? "Copied response" : "Copy audit response"}
                                    </button>
                                  )}
                                  <button
                                    onClick={() => setDetailsOpen(detailsOpen === ctrl.id ? null : ctrl.id)}
                                    className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-zinc-200 bg-white px-3 text-sm font-medium text-zinc-700 transition-colors hover:bg-zinc-50 hover:text-zinc-950"
                                  >
                                    {detailsOpen === ctrl.id ? "Hide details" : "Show details"}
                                    <svg
                                      className={`h-3.5 w-3.5 transition-transform ${detailsOpen === ctrl.id ? "rotate-180" : ""}`}
                                      fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24"
                                    >
                                      <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                                    </svg>
                                  </button>
                                </div>
                              </div>

                              {detailsOpen === ctrl.id && (
                                <aside className="space-y-3 border-t border-zinc-200 pt-4 2xl:border-l 2xl:border-t-0 2xl:pl-5 2xl:pt-0">
                                  <p className="text-sm leading-6 text-zinc-600">{ctrl.description}</p>

                                  {ctrl.guidance && (
                                    <div className="rounded-lg border border-zinc-200 bg-white px-4 py-3">
                                      <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-zinc-500">Full guidance</div>
                                      <p className="text-sm leading-6 text-zinc-700">{ctrl.guidance}</p>
                                    </div>
                                  )}

                                  {ctrl.narrative && (
                                    <NarrativeBlock text={ctrl.narrative} controlId={ctrl.control_id} />
                                  )}

                                  {ctrl.check_ids.length > 0 && (
                                    <div>
                                      <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-zinc-400">Mapped check IDs</div>
                                      <div className="flex flex-wrap gap-1.5">
                                        {ctrl.check_ids.map((cid) => (
                                          <span key={cid} className="rounded-md border border-zinc-200 bg-white px-2 py-0.5 font-mono text-xs text-zinc-600">
                                            {cid}
                                          </span>
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                </aside>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </section>
            )}
          </>
        )}
      </section>

      {!connectedAccount && !accounts.isLoading && (
        <p className="text-center text-sm text-zinc-400">
          Connect an AWS account and run a scan to see live compliance status.
        </p>
      )}
    </div>
  );
}
