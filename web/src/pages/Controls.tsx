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

type ControlGroup = { key: string; label: string; rows: ControlRow[]; passed: number; failed: number; noData: number };

function controlFamily(framework: string, controlId: string) {
  if (framework === "soc2") {
    if (controlId.startsWith("CC6")) return { key: "cc6", label: "CC6 — Logical Access" };
    if (controlId.startsWith("CC7")) return { key: "cc7", label: "CC7 — System Operations" };
    if (controlId.startsWith("CC8")) return { key: "cc8", label: "CC8 — Change Management" };
  }
  if (framework === "cis_aws_l1") {
    const s = controlId.split(".")[0];
    if (s === "1") return { key: "cis-1", label: "CIS 1 — Identity and Access" };
    if (s === "2") return { key: "cis-2", label: "CIS 2 — Storage and Logging" };
    if (s === "3") return { key: "cis-3", label: "CIS 3 — Networking" };
    if (s === "4") return { key: "cis-4", label: "CIS 4 — Monitoring" };
  }
  if (framework === "iso27001") {
    if (controlId.startsWith("A.9")) return { key: "iso-a9", label: "A.9 — Access Control" };
    if (controlId.startsWith("A.10")) return { key: "iso-a10", label: "A.10 — Cryptography" };
    if (controlId.startsWith("A.12")) return { key: "iso-a12", label: "A.12 — Operations Security" };
    if (controlId.startsWith("A.13")) return { key: "iso-a13", label: "A.13 — Communications Security" };
  }
  return { key: "other", label: "Other Controls" };
}

function groupControls(rows: ControlRow[], framework: string): ControlGroup[] {
  const groups = new Map<string, ControlGroup>();
  for (const row of rows) {
    const fam = controlFamily(framework, row.control_id);
    const g = groups.get(fam.key) ?? { key: fam.key, label: fam.label, rows: [], passed: 0, failed: 0, noData: 0 };
    g.rows.push(row);
    if (row.status === "pass") g.passed++;
    if (row.status === "fail") g.failed++;
    if (row.status === "no_data") g.noData++;
    groups.set(fam.key, g);
  }
  return Array.from(groups.values());
}

function shortTitle(title: string) {
  const parts = title.split("—");
  return parts.length > 1 ? parts.slice(1).join("—").trim() : title;
}

function totalFindings(g: ControlGroup) {
  return g.rows.reduce((s, r) => s + r.finding_count, 0);
}

function groupBadgeClass(g: ControlGroup) {
  if (g.failed > 0) return "border-red-200 bg-red-50 text-red-600";
  if (g.noData === g.rows.length) return "border-amber-200 bg-amber-50 text-amber-700";
  return "border-emerald-200 bg-emerald-50 text-emerald-700";
}

function groupBadgeLabel(g: ControlGroup) {
  if (g.failed > 0) return `${g.failed} failing`;
  if (g.noData === g.rows.length) return "No evidence";
  return "All clear";
}

function groupSubtitle(g: ControlGroup) {
  if (g.noData === g.rows.length)
    return `${g.rows.length} control${g.rows.length !== 1 ? "s" : ""} · evidence missing`;
  const findings = g.rows.reduce((s, r) => s + r.finding_count, 0);
  const parts = [];
  if (g.failed > 0) parts.push(`${g.failed} failing`);
  if (g.passed > 0) parts.push(`${g.passed} passing`);
  if (findings > 0) parts.push(`${findings} findings`);
  return `${g.rows.length} control${g.rows.length !== 1 ? "s" : ""} · ${parts.join(" · ") || "evaluated"}`;
}

function controlBadgeClass(status: string) {
  if (status === "fail") return "border-red-200 bg-red-50 text-red-600";
  if (status === "pass") return "border-emerald-200 bg-emerald-50 text-emerald-700";
  return "border-zinc-200 bg-zinc-50 text-zinc-400";
}

function controlBadgeLabel(ctrl: ControlRow) {
  if (ctrl.status === "fail") return `${ctrl.finding_count} finding${ctrl.finding_count !== 1 ? "s" : ""}`;
  if (ctrl.status === "pass") return "All clear";
  return "No data";
}

function checkAreas(checkIds: string[]) {
  const areas = checkIds.map((id) => {
    if (id.startsWith("iam.user")) return "IAM users";
    if (id.startsWith("iam.role")) return "IAM roles";
    if (id.startsWith("iam.access_key")) return "Access keys";
    if (id.startsWith("iam.root")) return "Root account";
    if (id.startsWith("iam.policy")) return "IAM policies";
    if (id.includes("dormant_members")) return "Dormant members";
    if (id.startsWith("github.org")) return "GitHub org";
    if (id.startsWith("github.repo")) return "GitHub repos";
    if (id.startsWith("gitlab.org")) return "GitLab group";
    if (id.startsWith("gitlab.repo")) return "GitLab repos";
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
    return id.split(".")[0]?.toUpperCase() ?? "Other";
  });
  return Array.from(new Set(areas));
}

function NarrativeBlock({ text, controlId }: { text: string; controlId: string }) {
  const [copied, setCopied] = useState(false);
  function copy() {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }
  return (
    <div className="rounded-xl border border-zinc-200 bg-white px-4 py-3">
      <div className="mb-2 flex items-center justify-between">
        <span className="text-[11px] font-semibold uppercase tracking-[0.14em] text-zinc-400">Audit Response — {controlId}</span>
        <button onClick={copy} className="flex items-center gap-1 text-xs text-zinc-400 transition-colors hover:text-zinc-800">
          {copied ? (
            <><svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>Copied</>
          ) : (
            <><svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" /></svg>Copy</>
          )}
        </button>
      </div>
      <p className="text-sm leading-relaxed text-zinc-700">{text}</p>
    </div>
  );
}

export default function Controls() {
  const navigate = useNavigate();
  const [framework, setFramework] = useState("soc2");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const [downloading, setDownloading] = useState(false);
  const [period, setPeriod] = useState(90);

  const accounts = useQuery({ queryKey: ["accounts"], queryFn: () => api<Account[]>("/v1/accounts") });
  const connectedAccount = accounts.data?.find((a) => a.status === "connected");

  const controls = useQuery({
    queryKey: ["controls", framework, connectedAccount?.id],
    queryFn: () => api<ControlRow[]>(`/v1/controls?framework=${framework}${connectedAccount ? `&account_id=${connectedAccount.id}` : ""}`),
    enabled: !accounts.isLoading,
  });

  const rows = controls.data ?? [];
  const passed = rows.filter((r) => r.status === "pass").length;
  const failed = rows.filter((r) => r.status === "fail").length;
  const noData = rows.filter((r) => r.status === "no_data").length;
  const total = rows.length;
  const assessed = passed + failed;
  const assessedPassRate = assessed > 0 ? Math.round((passed / assessed) * 100) : 0;
  const isFullyUnassessed = total > 0 && noData === total;
  const groupedRows = useMemo(() => groupControls(rows, framework), [rows, framework]);
  const selectedFramework = FRAMEWORKS.find((fw) => fw.id === framework) ?? FRAMEWORKS[0];

  function toggleCollapsed(key: string) {
    setCollapsed((prev) => ({ ...prev, [key]: !prev[key] }));
  }

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

  const summaryCards = [
    { label: "Assessed", value: assessed, hint: assessed > 0 ? `${assessedPassRate}% passing` : "no evidence yet", dot: assessed > 0 ? "bg-zinc-700" : "bg-zinc-300", tone: assessed > 0 ? "text-zinc-900" : "text-zinc-400" },
    { label: "Passing", value: passed, hint: assessed > 0 ? `${assessedPassRate}% of assessed` : "—", dot: "bg-emerald-500", tone: passed > 0 ? "text-emerald-700" : "text-zinc-400" },
    { label: "Needs evidence", value: noData, hint: noData > 0 ? "no scan data collected" : "all controls evaluated", dot: noData > 0 ? "bg-amber-400" : "bg-zinc-300", tone: noData > 0 ? "text-amber-600" : "text-zinc-400" },
    { label: "Total controls", value: total, hint: selectedFramework.fullLabel, dot: "bg-zinc-400", tone: "text-zinc-900" },
  ];

  return (
    <div className="w-full px-8 py-7">
      {/* Header */}
      <div className="mb-7 flex items-start justify-between gap-6">
        <div className="min-w-0">
          <h1 className="text-2xl font-bold tracking-tight text-zinc-950">Compliance</h1>
          <p className="mt-1 text-sm text-zinc-500">
            Control status against {selectedFramework.fullLabel}.
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <select
            value={period}
            onChange={(e) => setPeriod(Number(e.target.value))}
            className="rounded-xl border border-zinc-200 bg-white px-3 py-2.5 text-sm font-semibold text-zinc-600 shadow-sm transition hover:border-zinc-300 hover:bg-zinc-50 focus:outline-none"
          >
            {AUDIT_WINDOWS.map((w) => (
              <option key={w.value} value={w.value}>{w.label}</option>
            ))}
          </select>
          <button
            onClick={downloadPack}
            disabled={downloading || !connectedAccount}
            className="inline-flex items-center gap-2 rounded-xl border border-zinc-200 bg-white px-4 py-2.5 text-sm font-semibold text-zinc-600 shadow-sm transition hover:border-zinc-300 hover:bg-zinc-50 hover:text-zinc-950 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {downloading && (
              <svg className="h-3.5 w-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
            )}
            {downloading ? "Generating…" : "Evidence pack"}
          </button>
          <div className="flex items-center gap-1 rounded-xl border border-zinc-200 bg-white p-1 shadow-sm shadow-zinc-950/[0.03]">
            {FRAMEWORKS.map((fw) => (
              <button
                key={fw.id}
                onClick={() => { setFramework(fw.id); setExpanded(null); setCollapsed({}); }}
                className={`rounded-lg px-4 py-2 text-sm font-semibold capitalize transition-all ${framework === fw.id ? "bg-zinc-950 text-white shadow-sm" : "text-zinc-500 hover:bg-zinc-50 hover:text-zinc-900"}`}
              >
                {fw.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Stat cards */}
      <div className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {summaryCards.map((card) => (
          <div
            key={card.label}
            className="relative overflow-hidden rounded-2xl border border-zinc-200 bg-white px-5 py-4 shadow-sm shadow-zinc-950/[0.04]"
          >
            <div className="mb-3 flex items-center justify-between">
              <span className="text-[11px] font-semibold uppercase tracking-[0.14em] text-zinc-500">{card.label}</span>
              <span className={`h-2 w-2 rounded-full ${card.dot}`} />
            </div>
            <div className={`text-[2.75rem] font-bold tabular-nums leading-none tracking-tight ${controls.isLoading ? "text-zinc-200" : card.tone}`}>
              {controls.isLoading ? "…" : card.value}
            </div>
            <div className="mt-2.5 text-xs font-medium text-zinc-500 tabular-nums">{card.hint}</div>
          </div>
        ))}
      </div>

      {/* Controls grouped list */}
      {controls.isLoading && (
        <div className="rounded-2xl border border-zinc-200 bg-white px-4 py-16 text-center text-sm text-zinc-400 shadow-sm">
          Loading…
        </div>
      )}
      {!controls.isLoading && rows.length === 0 && (
        <div className="rounded-2xl border border-zinc-200 bg-white px-4 py-16 text-center shadow-sm">
          <p className="text-sm font-semibold text-zinc-700">No controls found</p>
          <p className="mt-1 text-sm text-zinc-400">
            {!connectedAccount ? "Connect an AWS account and run a scan." : "Run a scan to evaluate control status."}
          </p>
        </div>
      )}

      {/* No-evidence state — all controls unassessed */}
      {!controls.isLoading && isFullyUnassessed && (
        <div className="mb-4 overflow-hidden rounded-2xl border border-amber-200 bg-amber-50/60 shadow-sm">
          <div className="px-6 py-5">
            <div className="flex items-start gap-4">
              <div className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-full border border-amber-200 bg-amber-100">
                <svg className="h-4 w-4 text-amber-600" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                </svg>
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-sm font-semibold text-amber-900">
                  {selectedFramework.label} has not been evaluated yet
                </p>
                <p className="mt-1 text-sm text-amber-800">
                  {total} control{total !== 1 ? "s" : ""} are in scope, but no evidence has been collected for this framework.
                  {!connectedAccount?.last_scan_at
                    ? " Connect an AWS account and run a scan to start collecting evidence."
                    : " Run a scan or connect additional evidence sources to begin evaluation."}
                </p>
                <div className="mt-4 flex flex-wrap gap-2">
                  {connectedAccount ? (
                    <button
                      onClick={() => navigate("/accounts")}
                      className="inline-flex h-8 items-center gap-1.5 rounded-lg bg-amber-700 px-3 text-sm font-semibold text-white transition-colors hover:bg-amber-800"
                    >
                      Run scan
                    </button>
                  ) : (
                    <button
                      onClick={() => navigate("/accounts")}
                      className="inline-flex h-8 items-center gap-1.5 rounded-lg bg-amber-700 px-3 text-sm font-semibold text-white transition-colors hover:bg-amber-800"
                    >
                      Connect AWS account
                    </button>
                  )}
                  <button
                    onClick={() => navigate("/integrations")}
                    className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-amber-300 bg-white px-3 text-sm font-medium text-amber-800 transition-colors hover:bg-amber-50"
                  >
                    Connect evidence sources
                  </button>
                  <button
                    onClick={downloadPack}
                    disabled={downloading || !connectedAccount}
                    className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-amber-300 bg-white px-3 text-sm font-medium text-amber-800 transition-colors hover:bg-amber-50 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    Export evidence package
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {!controls.isLoading && groupedRows.length > 0 && (
        <div className="space-y-2.5 pb-8">
          {groupedRows.map((group) => {
            const isCollapsed = !!collapsed[group.key];
            return (
              <div
                key={group.key}
                className="overflow-hidden rounded-2xl border border-zinc-200 bg-white shadow-sm shadow-zinc-950/[0.04] transition-shadow hover:border-zinc-300 hover:shadow-md"
              >
                {/* Group header */}
                <button
                  type="button"
                  onClick={() => toggleCollapsed(group.key)}
                  className="grid w-full grid-cols-[auto_auto_minmax(0,1fr)_72px_72px] items-center gap-3 bg-gradient-to-r from-zinc-50/80 to-white py-3.5 pl-5 pr-3 text-left transition-colors hover:from-zinc-100/60"
                >
                  <svg
                    className={`h-3.5 w-3.5 transition-transform duration-150 ${isCollapsed ? "-rotate-90 text-zinc-600" : "text-zinc-500"}`}
                    fill="none" stroke="currentColor" viewBox="0 0 24 24"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                  <span className={`inline-block w-[80px] rounded border py-0.5 text-center text-[10px] font-semibold uppercase tracking-[0.12em] ${groupBadgeClass(group)}`}>
                    {groupBadgeLabel(group)}
                  </span>
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-[15px] font-semibold text-zinc-900">{group.label}</span>
                      <span className="rounded-full bg-zinc-100 px-2 py-0.5 text-[11px] font-semibold tabular-nums text-zinc-500">
                        {group.rows.length}
                      </span>
                    </div>
                    <p className="mt-0.5 text-xs font-medium text-zinc-500">{groupSubtitle(group)}</p>
                  </div>
                  <span className="hidden text-center text-[10px] font-semibold uppercase tracking-[0.1em] text-zinc-500 md:block">Controls</span>
                  <span className="hidden text-center text-[10px] font-semibold uppercase tracking-[0.1em] text-zinc-500 md:block">Findings</span>
                </button>

                {/* Animated accordion */}
                <div
                  className="grid transition-[grid-template-rows] duration-[140ms] ease-out"
                  style={{ gridTemplateRows: isCollapsed ? "0fr" : "1fr" }}
                >
                  <div className="overflow-hidden">
                    <div className="divide-y divide-zinc-100 border-t border-zinc-100">
                      {group.rows.map((ctrl) => {
                        const isExpanded = expanded === ctrl.id;
                        return (
                          <div key={ctrl.id}>
                            <button
                              type="button"
                              onClick={() => setExpanded(isExpanded ? null : ctrl.id)}
                              className="grid w-full grid-cols-[minmax(0,1fr)_72px_72px] items-center gap-3 py-2.5 pl-10 pr-3 text-left transition-colors duration-[120ms] hover:bg-zinc-100/50"
                            >
                              <div className="flex min-w-0 items-center gap-3">
                                <span className={`shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.1em] ${controlBadgeClass(ctrl.status)}`}>
                                  {ctrl.status === "pass" ? "Pass" : ctrl.status === "fail" ? "Fail" : "—"}
                                </span>
                                <span className="font-mono text-xs font-semibold text-zinc-400">{ctrl.control_id}</span>
                                <span className="truncate text-sm font-medium text-zinc-700">{shortTitle(ctrl.title)}</span>
                              </div>
                              <div className="flex justify-center">
                                <span className="text-xs font-medium tabular-nums text-zinc-500">{group.rows.length > 0 ? "" : ""}</span>
                              </div>
                              <div className="flex justify-center">
                                {ctrl.status === "fail" && (
                                  <span className="rounded-md border border-red-100 bg-red-50/70 px-2 py-0.5 text-xs font-semibold tabular-nums text-red-600">
                                    {ctrl.finding_count}
                                  </span>
                                )}
                              </div>
                            </button>

                            {/* Expanded detail */}
                            {isExpanded && (
                              <div className="border-t border-zinc-100 bg-zinc-50/60 px-5 pb-4 pt-3">
                                <div className="pl-[calc(2rem+0.75rem)] space-y-3">
                                  <p className="text-sm leading-relaxed text-zinc-600">{ctrl.description}</p>

                                  {checkAreas(ctrl.check_ids).length > 0 && (
                                    <div className="flex flex-wrap gap-1.5">
                                      {checkAreas(ctrl.check_ids).slice(0, 6).map((area) => (
                                        <span key={area} className="rounded-md border border-zinc-200 bg-white px-2.5 py-0.5 text-xs font-medium text-zinc-600">
                                          {area}
                                        </span>
                                      ))}
                                    </div>
                                  )}

                                  {ctrl.guidance && (
                                    <p className="text-xs text-zinc-500">
                                      <span className="font-semibold text-zinc-600">Evidence expected: </span>
                                      {ctrl.guidance}
                                    </p>
                                  )}

                                  {ctrl.narrative && (
                                    <NarrativeBlock text={ctrl.narrative} controlId={ctrl.control_id} />
                                  )}

                                  <div className="flex flex-wrap items-center gap-2 pt-1">
                                    {ctrl.status === "fail" && ctrl.open_finding_ids.length > 0 && (
                                      <button
                                        onClick={() => navigate(`/findings?checks=${ctrl.check_ids.join(",")}`)}
                                        className="inline-flex h-8 items-center gap-1.5 rounded-lg bg-zinc-900 px-3 text-sm font-semibold text-white transition-colors hover:bg-zinc-800"
                                      >
                                        View {ctrl.finding_count} finding{ctrl.finding_count !== 1 ? "s" : ""}
                                        <svg className="h-3 w-3" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                                          <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
                                        </svg>
                                      </button>
                                    )}
                                  </div>
                                </div>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {!connectedAccount && !accounts.isLoading && (
        <p className="text-center text-sm text-zinc-400">
          Connect an AWS account and run a scan to see live compliance status.
        </p>
      )}
    </div>
  );
}
