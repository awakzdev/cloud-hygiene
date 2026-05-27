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

export default function Controls() {
  const navigate = useNavigate();
  const [framework, setFramework] = useState("soc2");
  const [selectedFamilyKey, setSelectedFamilyKey] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
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
  const passPct = total > 0 ? (passed / total) * 100 : 0;
  const failPct = total > 0 ? (failed / total) * 100 : 0;
  const noDataPct = total > 0 ? (noData / total) * 100 : 0;
  const groupedRows = useMemo(() => groupControls(rows, framework), [rows, framework]);
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

  return (
    <div className="w-full px-8 py-7">
      <div className="mb-6 flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0 flex-1">
          <h1 className="text-2xl font-bold tracking-tight text-zinc-950">Compliance</h1>
          <p className="mt-1 text-sm text-zinc-500">
            {controls.isLoading ? (
              "Loading control status…"
            ) : total === 0 ? (
              "Control status against selected frameworks."
            ) : (
              <>
                <span className="font-medium text-zinc-700">
                  {passed} of {total} passing
                </span>
                {failed > 0 && (
                  <>
                    {" · "}
                    <span className="text-red-600">{failed} failing</span>
                  </>
                )}
                {noData > 0 && (
                  <>
                    {" · "}
                    <span>{noData} no data</span>
                  </>
                )}
                {topBlocker && (
                  <>
                    {" · "}
                    <span className="text-zinc-600">
                      start with {topBlocker.control_id} ({findingLabel(topBlocker.finding_count)})
                    </span>
                  </>
                )}
              </>
            )}
          </p>
          {!controls.isLoading && total > 0 && (
            <div className="mt-2.5 flex h-1 max-w-sm overflow-hidden rounded-full bg-zinc-100">
              {passPct > 0 && (
                <div className="h-full bg-emerald-500 transition-all duration-500" style={{ width: `${passPct}%` }} />
              )}
              {failPct > 0 && (
                <div className="h-full bg-red-400 transition-all duration-500" style={{ width: `${failPct}%` }} />
              )}
              {noDataPct > 0 && (
                <div className="h-full bg-zinc-300 transition-all duration-500" style={{ width: `${noDataPct}%` }} />
              )}
            </div>
          )}
        </div>

        <div className="flex shrink-0 flex-wrap items-center gap-2">
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

          <div className="relative">
            <select
              id="audit-window"
              value={period}
              onChange={(e) => setPeriod(Number(e.target.value))}
              aria-label="Audit window"
              className="h-[42px] appearance-none rounded-xl border border-zinc-200 bg-white pl-3 pr-8 text-sm font-semibold text-zinc-600 shadow-sm shadow-zinc-950/[0.03] outline-none transition hover:border-zinc-300 focus:border-indigo-300 focus:ring-2 focus:ring-indigo-500/20"
            >
              {AUDIT_WINDOWS.map((window) => (
                <option key={window.value} value={window.value}>
                  {window.label}
                </option>
              ))}
            </select>
            <svg className="pointer-events-none absolute right-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-400" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
            </svg>
          </div>

          <button
            onClick={downloadPack}
            disabled={downloading || !connectedAccount}
            className="inline-flex h-[42px] items-center gap-2 rounded-xl bg-indigo-600 px-4 text-sm font-semibold text-white shadow-sm shadow-indigo-600/20 transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {downloading ? (
              <svg className="h-3.5 w-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
            ) : (
              <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
              </svg>
            )}
            {downloading ? "Generating…" : "Download package"}
          </button>
        </div>
      </div>

      <section>
        {controls.isLoading && (
          <div className="rounded-2xl border border-zinc-200 bg-white px-6 py-16 text-center text-sm text-zinc-400 shadow-sm">Loading controls…</div>
        )}
        {!controls.isLoading && rows.length === 0 && (
          <div className="rounded-2xl border border-zinc-200 bg-white px-6 py-16 text-center text-sm text-zinc-400 shadow-sm">
            No controls found.{!connectedAccount && " Connect an AWS account to see compliance status."}
          </div>
        )}

        {!controls.isLoading && groupedRows.length > 0 && selectedGroup && (
          <div className="overflow-hidden rounded-2xl border border-zinc-200 bg-white shadow-sm shadow-zinc-950/[0.04]">
            <div className="flex flex-col gap-3 border-b border-zinc-100 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex flex-wrap items-center gap-1 rounded-xl border border-zinc-200 bg-white p-1 shadow-sm shadow-zinc-950/[0.03]" role="tablist" aria-label="Control families">
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

            <div className="grid grid-cols-[auto_auto_minmax(0,1fr)_auto] items-center gap-3 border-b border-zinc-100 px-4 py-2 sm:px-5">
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
                      className={`grid w-full grid-cols-[auto_auto_minmax(0,1fr)_auto] items-center gap-3 border-l-2 py-3 pl-4 pr-4 text-left transition-colors sm:pl-5 sm:pr-5 ${statusAccent[ctrl.status]} ${
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
                      <div className={`border-t border-zinc-100/80 px-4 pb-4 pt-3 sm:px-5 sm:pb-5 sm:pl-[4.75rem] ${statusExpandedBg[ctrl.status]}`}>
                        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                          <div className="min-w-0 flex-1">
                            <p className="text-sm font-semibold leading-snug text-zinc-900">{failureSummary(ctrl)}</p>
                            <p className="mt-1.5 text-sm leading-relaxed text-zinc-600">{nextStep(ctrl)}</p>
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
                          <div className="mt-3 flex flex-wrap gap-1.5">
                            {areas.map((area) => (
                              <span key={area} className="rounded-md bg-white/80 px-2 py-0.5 text-xs font-medium text-zinc-600 ring-1 ring-zinc-200/80">
                                {area}
                              </span>
                            ))}
                          </div>
                        )}

                        <div className="mt-4 rounded-xl border border-zinc-200/80 bg-white p-4 shadow-sm shadow-zinc-950/[0.03]">
                          <p className="text-sm leading-relaxed text-zinc-600">{ctrl.description}</p>

                          {(ctrl.guidance || ctrl.check_ids.length > 0) && (
                            <div className="mt-3 border-t border-zinc-100 pt-3">
                              {ctrl.guidance && (
                                <>
                                  <p className="vigil-kicker mb-1.5">Evidence to collect</p>
                                  <p className="text-sm leading-relaxed text-zinc-800">{stripEvidencePrefix(ctrl.guidance)}</p>
                                </>
                              )}

                              {ctrl.check_ids.length > 0 && (
                                <div className={ctrl.guidance ? "mt-3 border-t border-zinc-100 pt-3" : ""}>
                                  <p className="vigil-kicker mb-2">
                                    {ctrl.check_ids.length} mapped check{ctrl.check_ids.length === 1 ? "" : "s"}
                                  </p>
                                  <div className="flex flex-wrap gap-1">
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
  );
}
