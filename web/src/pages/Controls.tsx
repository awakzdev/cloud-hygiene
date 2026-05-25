import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, token } from "../api";

const BASE = (import.meta.env.VITE_API_URL as string) || "http://localhost:8000";

type Account = { id: string; label: string; account_id: string | null; status: string };

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
  { id: "soc2", label: "SOC 2" },
  { id: "cis_aws_l1", label: "CIS AWS L1" },
];

const statusBadge: Record<string, string> = {
  pass: "bg-green-50 text-green-700 border-green-200 ring-green-100",
  fail: "bg-red-50 text-red-700 border-red-200 ring-red-100",
  no_data: "bg-zinc-50 text-zinc-500 border-zinc-200 ring-zinc-100",
};

const statusLabel: Record<string, string> = {
  pass: "Pass",
  fail: "Fail",
  no_data: "No data",
};

const statusDot: Record<string, string> = {
  pass: "bg-green-500",
  fail: "bg-red-500",
  no_data: "bg-zinc-300",
};

function StatusIcon({ status }: { status: string }) {
  if (status === "pass") {
    return (
      <svg className="w-4 h-4 text-green-600" fill="none" stroke="currentColor" strokeWidth={2.5} viewBox="0 0 24 24">
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

export default function Controls() {
  const [framework, setFramework] = useState("soc2");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [downloading, setDownloading] = useState(false);

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

  async function downloadPack() {
    if (!connectedAccount) return;
    setDownloading(true);
    try {
      const tok = token();
      const res = await fetch(
        `${BASE}/v1/exports/evidence-pack?framework=${framework}&account_id=${connectedAccount.id}&period=90`,
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
    <div className="space-y-6 max-w-5xl">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-950">Compliance</h1>
          <p className="text-sm text-zinc-500 mt-1">
            Control status against {framework === "soc2" ? "SOC 2 Trust Services Criteria" : "CIS AWS Foundations Benchmark L1"}.
          </p>
        </div>

        {/* Framework toggle + download */}
        <div className="flex items-center gap-3 flex-shrink-0">
          <div className="flex items-center gap-1 rounded-full border border-zinc-200 bg-white p-1 shadow-sm">
            {FRAMEWORKS.map((fw) => (
              <button
                key={fw.id}
                onClick={() => setFramework(fw.id)}
                className={`rounded-full px-4 py-1.5 text-sm font-medium transition-all ${
                  framework === fw.id
                    ? "bg-zinc-900 text-white shadow-sm"
                    : "text-zinc-500 hover:text-zinc-800"
                }`}
              >
                {fw.label}
              </button>
            ))}
          </div>

          <button
            onClick={downloadPack}
            disabled={downloading || !connectedAccount}
            className="flex items-center gap-2 rounded-xl border border-zinc-200 bg-white px-4 py-2 text-sm font-medium text-zinc-700 shadow-sm transition-all hover:bg-zinc-50 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {downloading ? (
              <svg className="w-4 h-4 animate-spin text-zinc-400" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
              </svg>
            ) : (
              <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
              </svg>
            )}
            {downloading ? "Generating…" : "Evidence Pack"}
          </button>
        </div>
      </div>

      {/* Summary bar */}
      {!controls.isLoading && total > 0 && (
        <div className="rounded-2xl border border-zinc-200 bg-white shadow-sm p-5">
          <div className="flex items-center gap-6">
            <div>
              <div className="text-3xl font-bold tabular-nums leading-none text-zinc-900">{passRate}%</div>
              <div className="text-xs text-zinc-400 mt-1 font-medium">pass rate</div>
            </div>
            <div className="flex-1 h-2 rounded-full bg-zinc-100 overflow-hidden">
              <div
                className="h-full rounded-full bg-green-500 transition-all duration-700"
                style={{ width: `${passRate}%` }}
              />
            </div>
            <div className="flex items-center gap-5 text-sm">
              <span className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-green-500" />
                <span className="font-semibold text-zinc-800">{passed}</span>
                <span className="text-zinc-400">pass</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-red-500" />
                <span className="font-semibold text-zinc-800">{failed}</span>
                <span className="text-zinc-400">fail</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-zinc-300" />
                <span className="font-semibold text-zinc-800">{noData}</span>
                <span className="text-zinc-400">no data</span>
              </span>
              <span className="text-zinc-300">|</span>
              <span className="text-zinc-400">{total} controls</span>
            </div>
          </div>
        </div>
      )}

      {/* Control list */}
      <div className="rounded-2xl border border-zinc-200 bg-white shadow-sm overflow-hidden">
        {controls.isLoading && (
          <div className="px-6 py-16 text-center text-sm text-zinc-400">Loading controls…</div>
        )}
        {!controls.isLoading && rows.length === 0 && (
          <div className="px-6 py-16 text-center text-sm text-zinc-400">
            No controls found.{!connectedAccount && " Connect an AWS account to see compliance status."}
          </div>
        )}
        {rows.map((ctrl, idx) => {
          const isExpanded = expanded === ctrl.id;
          return (
            <div key={ctrl.id} className={idx > 0 ? "border-t border-zinc-100" : ""}>
              <button
                onClick={() => setExpanded(isExpanded ? null : ctrl.id)}
                className="w-full flex items-center gap-4 px-5 py-4 text-left hover:bg-zinc-50/80 transition-colors group"
              >
                {/* Status icon */}
                <div className={`flex-shrink-0 w-7 h-7 rounded-full border flex items-center justify-center ${statusBadge[ctrl.status]}`}>
                  <StatusIcon status={ctrl.status} />
                </div>

                {/* Control ID */}
                <div className="flex-shrink-0 w-20">
                  <span className="text-xs font-mono font-semibold text-zinc-500">{ctrl.control_id}</span>
                </div>

                {/* Title */}
                <div className="flex-1 min-w-0">
                  <span className="text-sm font-medium text-zinc-900 leading-snug">{ctrl.title}</span>
                </div>

                {/* Finding count */}
                {ctrl.status === "fail" && (
                  <span className="flex-shrink-0 rounded-full bg-red-50 border border-red-200 px-2.5 py-0.5 text-xs font-semibold text-red-600">
                    {ctrl.finding_count} finding{ctrl.finding_count !== 1 ? "s" : ""}
                  </span>
                )}
                {ctrl.status === "pass" && (
                  <span className="flex-shrink-0 text-xs text-green-600 font-medium">All clear</span>
                )}
                {ctrl.status === "no_data" && (
                  <span className="flex-shrink-0 text-xs text-zinc-400">—</span>
                )}

                {/* Chevron */}
                <svg
                  className={`w-4 h-4 flex-shrink-0 text-zinc-300 group-hover:text-zinc-400 transition-transform ${isExpanded ? "rotate-180" : ""}`}
                  fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24"
                >
                  <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                </svg>
              </button>

              {/* Expanded detail */}
              {isExpanded && (
                <div className="px-5 pb-5 pt-1 border-t border-zinc-100 bg-zinc-50/50 space-y-4">
                  <div className="pl-11 space-y-3">
                    <p className="text-sm text-zinc-600 leading-relaxed">{ctrl.description}</p>

                    {ctrl.guidance && (
                      <div className="rounded-xl border border-blue-100 bg-blue-50/60 px-4 py-3">
                        <div className="text-xs font-semibold text-blue-600 uppercase tracking-wide mb-1">Guidance</div>
                        <p className="text-sm text-blue-800 leading-relaxed">{ctrl.guidance}</p>
                      </div>
                    )}

                    {ctrl.check_ids.length > 0 && (
                      <div>
                        <div className="text-xs font-semibold text-zinc-400 uppercase tracking-wide mb-2">Checks</div>
                        <div className="flex flex-wrap gap-1.5">
                          {ctrl.check_ids.map((cid) => (
                            <span key={cid} className="rounded-md bg-zinc-100 border border-zinc-200 px-2 py-0.5 text-xs font-mono text-zinc-600">
                              {cid}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {ctrl.status === "fail" && ctrl.open_finding_ids.length > 0 && (
                      <div>
                        <div className="text-xs font-semibold text-zinc-400 uppercase tracking-wide mb-2">
                          Open findings ({ctrl.finding_count})
                        </div>
                        <a
                          href="/findings"
                          className="inline-flex items-center gap-1.5 text-sm text-red-600 hover:text-red-700 font-medium"
                        >
                          View in Findings
                          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
                          </svg>
                        </a>
                      </div>
                    )}

                    {ctrl.status === "no_data" && (
                      <p className="text-xs text-zinc-400 italic">
                        {!connectedAccount
                          ? "No AWS account connected. Connect an account and run a scan."
                          : "No scan data available for this control. Run a scan to evaluate status."}
                      </p>
                    )}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {!connectedAccount && !accounts.isLoading && (
        <p className="text-center text-sm text-zinc-400">
          Connect an AWS account and run a scan to see live compliance status.
        </p>
      )}
    </div>
  );
}
