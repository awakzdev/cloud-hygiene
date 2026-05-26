import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { api } from "../api";

type Account = {
  id: string;
  label: string;
  account_id: string | null;
  status: string;
  external_id: string;
  cfn_launch_url: string;
  last_scan_at: string | null;
};

type Finding = { id: string; severity: string; status: string };

function AwsProviderIcon() {
  return (
    <img
      src="https://www.google.com/s2/favicons?domain=aws.amazon.com&sz=64"
      alt="AWS"
      className="h-6 w-6 object-contain"
    />
  );
}

type ControlRow = { status: string };

function useComplianceScore(framework: string, enabled: boolean) {
  return useQuery({
    queryKey: ["controls", framework],
    queryFn: () => api<ControlRow[]>(`/v1/controls?framework=${framework}`),
    enabled,
    select: (rows) => {
      const total = rows.length;
      const passed = rows.filter((r) => r.status === "pass").length;
      return total === 0 ? null : Math.round((passed / total) * 100);
    },
  });
}

function scoreColor(pct: number | null | undefined): string {
  if (pct == null) return "bg-zinc-300";
  if (pct >= 80) return "bg-emerald-600";
  if (pct >= 50) return "bg-emerald-500";
  return "bg-emerald-400";
}

function AccountCard({ acc, findingsData, onRemoved }: {
  acc: Account;
  findingsData: { items: Finding[] } | undefined;
  onRemoved: () => void;
}) {
  const qc = useQueryClient();
  const [roleArn, setRoleArn] = useState("");
  const [scanQueued, setScanQueued] = useState(false);
  const [showUpdateArn, setShowUpdateArn] = useState(false);
  const snapshotRef = useRef<HTMLDivElement>(null);
  const [lockedHeight, setLockedHeight] = useState<number | null>(null);

  function toggleUpdateArn() {
    if (!showUpdateArn && snapshotRef.current) {
      setLockedHeight(snapshotRef.current.offsetHeight);
    } else {
      setLockedHeight(null);
    }
    setShowUpdateArn((v) => !v);
  }

  const verify = useMutation({
    mutationFn: () => api<Account>(`/v1/accounts/${acc.id}/verify`, { method: "POST", body: JSON.stringify({ role_arn: roleArn }) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["accounts"] }),
  });
  const scan = useMutation({
    mutationFn: () => api(`/v1/accounts/${acc.id}/scan`, { method: "POST" }),
    onSuccess: () => setScanQueued(true),
  });
  const remove = useMutation({
    mutationFn: () => api(`/v1/accounts/${acc.id}`, { method: "DELETE" }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["accounts"] }); onRemoved(); },
  });

  const critHigh = findingsData?.items.filter(f => f.severity === "critical" || f.severity === "high").length ?? 0;
  const medium = findingsData?.items.filter(f => f.severity === "medium").length ?? 0;
  const totalOpen = findingsData?.items.length ?? 0;
  const hasScanned = acc.status === "connected" && !!acc.last_scan_at;
  const soc2 = useComplianceScore("soc2", hasScanned);
  const cis = useComplianceScore("cis_aws_l1", hasScanned);
  const iso = useComplianceScore("iso27001", hasScanned);

  return (
    <div className="grid grid-cols-[1fr_280px] gap-4 items-stretch">
      {/* Main card */}
      <div className="bg-white rounded-xl border border-zinc-200 shadow-sm overflow-hidden">
        {/* Account header */}
        <div className="px-6 py-5 border-b border-zinc-100 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-orange-50 ring-1 ring-orange-100 flex items-center justify-center flex-shrink-0">
              <AwsProviderIcon />
            </div>
            <div>
              <div className="font-semibold text-zinc-900 text-base">{acc.label}</div>
              {acc.account_id && <div className="text-xs text-zinc-400 font-mono mt-0.5">{acc.account_id}</div>}
            </div>
          </div>
          <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold ${
            acc.status === "connected" ? "bg-green-50 text-green-700" : "bg-amber-50 text-amber-700"
          }`}>
            <span className={`w-1.5 h-1.5 rounded-full ${acc.status === "connected" ? "bg-green-500" : "bg-amber-500"}`} />
            {acc.status}
          </span>
        </div>

        {/* Setup steps (not connected) */}
        {acc.status !== "connected" && (
          <div className="px-6 py-5 space-y-5">
            <div className="space-y-4">
              {[
                {
                  n: 1,
                  label: "Deploy IAM role via CloudFormation",
                  content: (
                    <a href={acc.cfn_launch_url} target="_blank" rel="noreferrer"
                      className="inline-flex items-center gap-1.5 text-sm text-indigo-600 font-medium hover:text-indigo-700">
                      Launch CloudFormation stack
                      <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                      </svg>
                    </a>
                  ),
                },
                { n: 2, label: "Copy the RoleArn from stack Outputs", content: null },
                {
                  n: 3,
                  label: "Paste and verify",
                  content: (
                    <div className="space-y-2">
                      <div className="text-xs text-zinc-400">
                        ExternalId: <code className="font-mono bg-zinc-100 px-1.5 py-0.5 rounded">{acc.external_id}</code>
                      </div>
                      <div className="flex gap-2">
                        <input
                          className="flex-1 border border-zinc-200 rounded-lg px-3 py-2 font-mono text-xs focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                          placeholder="arn:aws:iam::123456789012:role/VigilReadOnly"
                          value={roleArn}
                          onChange={e => setRoleArn(e.target.value)}
                        />
                        <button
                          onClick={() => verify.mutate()}
                          disabled={verify.isPending || !roleArn}
                          className="bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors disabled:opacity-50"
                        >
                          {verify.isPending ? "Verifying…" : "Verify"}
                        </button>
                      </div>
                      {verify.error && (
                        <div className="text-xs text-red-600 bg-red-50 border border-red-200 rounded px-3 py-2">
                          {(verify.error as Error).message}
                        </div>
                      )}
                    </div>
                  ),
                },
              ].map(({ n, label, content }) => (
                <div key={n} className="flex gap-3">
                  <div className="w-6 h-6 rounded-full bg-zinc-100 flex items-center justify-center text-xs font-bold text-zinc-500 flex-shrink-0 mt-0.5">
                    {n}
                  </div>
                  <div className="flex-1 space-y-2">
                    <div className="text-sm font-medium text-zinc-700">{label}</div>
                    {content}
                  </div>
                </div>
              ))}
            </div>
            <div className="flex items-center justify-end pt-2 border-t border-zinc-100">
              <button
                onClick={() => remove.mutate()}
                disabled={remove.isPending}
                className="text-sm font-medium text-zinc-400 hover:text-red-500 transition-colors disabled:opacity-50"
              >
                {remove.isPending ? "Removing…" : "Remove account"}
              </button>
            </div>
          </div>
        )}

        {/* Connected state */}
        {acc.status === "connected" && (
          <div className="relative px-6 py-5 space-y-4">
            {/* Info tiles */}
            <div className="grid grid-cols-2 gap-3">
              <div className="rounded-lg border border-zinc-200 bg-zinc-50 px-4 py-3">
                <div className="text-xs text-zinc-400 uppercase tracking-wide font-medium mb-1">Open findings</div>
                <div className="font-semibold text-sm text-zinc-800">{findingsData ? totalOpen : "…"}</div>
              </div>
              <div className="rounded-lg border border-zinc-200 bg-zinc-50 px-4 py-3">
                <div className="text-xs text-zinc-400 uppercase tracking-wide font-medium mb-1">External ID</div>
                <div className="font-mono text-xs text-zinc-600 truncate" title={acc.external_id}>{acc.external_id}</div>
              </div>
            </div>

            {showUpdateArn && (
              <div className="rounded-lg border border-zinc-200 bg-zinc-50 px-4 py-4 space-y-2">
                <div className="text-xs text-zinc-500">
                  Paste the new RoleArn from your CloudFormation stack Outputs.{" "}
                  <a href={acc.cfn_launch_url} target="_blank" rel="noreferrer" className="text-indigo-600 hover:underline">Re-deploy stack</a>
                  {" "}if you need to update permissions.
                </div>
                <div className="text-xs text-zinc-400">
                  ExternalId: <code className="font-mono bg-white border border-zinc-200 px-1.5 py-0.5 rounded">{acc.external_id}</code>
                </div>
                <div className="flex gap-2">
                  <input
                    className="flex-1 border border-zinc-200 rounded-lg px-3 py-2 font-mono text-xs bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                    placeholder="arn:aws:iam::123456789012:role/VigilReadOnly"
                    value={roleArn}
                    onChange={(e) => setRoleArn(e.target.value)}
                  />
                  <button
                    onClick={() => verify.mutate()}
                    disabled={verify.isPending || !roleArn}
                    className="bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors disabled:opacity-50"
                  >
                    {verify.isPending ? "Verifying…" : "Verify"}
                  </button>
                </div>
                {verify.isSuccess && <p className="text-xs text-emerald-600">Role ARN updated.</p>}
                {verify.error && (
                  <div className="text-xs text-red-600 bg-red-50 border border-red-200 rounded px-3 py-2">
                    {(verify.error as Error).message}
                  </div>
                )}
              </div>
            )}

            {/* Actions */}
            <div className="flex items-center justify-between gap-3 border-t border-zinc-100 pt-4">
              <div className="flex flex-wrap items-center gap-2">
                <button
                  onClick={() => { setScanQueued(false); scan.mutate(); }}
                  disabled={scan.isPending}
                  className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors disabled:opacity-50"
                >
                  <svg className={`w-4 h-4 ${scan.isPending ? "animate-spin" : ""}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                  </svg>
                  {scan.isPending ? "Triggering…" : "Run scan now"}
                </button>
                <button
                  onClick={() => { toggleUpdateArn(); setRoleArn(""); verify.reset(); }}
                  className="flex items-center gap-1.5 border border-zinc-200 bg-white hover:bg-zinc-50 text-zinc-700 text-sm font-medium px-4 py-2 rounded-lg transition-colors"
                >
                  Update role ARN
                  <svg className={`w-3 h-3 transition-transform ${showUpdateArn ? "rotate-180" : ""}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </button>
              </div>

              <div className="flex items-center gap-2">
                {scanQueued && (
                  <div className="inline-flex items-center rounded-full border border-emerald-200 bg-emerald-50/70 px-2 py-0.5 text-[11px] font-medium text-emerald-700">
                    Scan queued
                  </div>
                )}
                <button
                  onClick={() => { if (confirm("Remove this account? All findings will be deleted.")) remove.mutate(); }}
                  disabled={remove.isPending}
                  className="rounded-lg border border-red-200 bg-white px-4 py-2 text-sm font-medium text-red-600 transition-colors hover:border-red-300 hover:bg-red-50 hover:text-red-700 disabled:opacity-50"
                >
                  {remove.isPending ? "Removing…" : "Remove account"}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Posture snapshot sidebar */}
      <div ref={snapshotRef} className="bg-white rounded-xl border border-zinc-200 shadow-sm px-5 py-5 flex flex-col" style={lockedHeight ? { height: lockedHeight } : undefined}>
        <div className="text-xs font-semibold text-zinc-400 uppercase tracking-widest mb-3">Posture Snapshot</div>
        {hasScanned ? (
          <>
            <div className="grid grid-cols-2 gap-2.5 mb-3">
              <div className="rounded-lg border border-red-100 bg-red-50 px-3 py-4 flex flex-col items-center justify-center text-center">
                <div className="text-4xl font-bold text-red-600 tabular-nums">{findingsData ? critHigh : "…"}</div>
                <div className="text-xs text-red-500 font-medium mt-1">critical · high</div>
              </div>
              <div className="rounded-lg border border-amber-100 bg-amber-50 px-3 py-4 flex flex-col items-center justify-center text-center">
                <div className="text-4xl font-bold text-amber-600 tabular-nums">{findingsData ? medium : "…"}</div>
                <div className="text-xs text-amber-500 font-medium mt-1">medium</div>
              </div>
            </div>
            <div className="flex-1" />
            <div className="space-y-3 pt-2">
              {[
                { label: "SOC 2", pct: soc2.data },
                { label: "CIS AWS L1", pct: cis.data },
                { label: "ISO 27001", pct: iso.data },
              ].map(({ label, pct }) => (
                <div key={label} className="flex items-center gap-2.5">
                  <span className="text-xs font-medium text-zinc-600 w-[72px] shrink-0">{label}</span>
                  <div className="flex-1 h-2 rounded-full overflow-hidden bg-emerald-100">
                    <div className={`h-full rounded-full transition-all duration-500 ${scoreColor(pct)}`} style={{ width: `${pct ?? 0}%` }} />
                  </div>
                  <span className="text-xs font-semibold tabular-nums text-zinc-700 w-8 text-right shrink-0">
                    {pct == null ? "—" : `${pct}%`}
                  </span>
                </div>
              ))}
            </div>
          </>
        ) : (
          <div className="flex flex-col gap-2.5">
            <div className="grid grid-cols-2 gap-2.5">
              <div className="rounded-lg border border-dashed border-zinc-200 bg-zinc-50/60 px-3 py-2 text-center">
                <div className="text-xl font-bold text-zinc-300 tabular-nums">—</div>
                <div className="text-[11px] text-zinc-300 font-medium mt-0.5">critical · high</div>
              </div>
              <div className="rounded-lg border border-dashed border-zinc-200 bg-zinc-50/60 px-3 py-2 text-center">
                <div className="text-xl font-bold text-zinc-300 tabular-nums">—</div>
                <div className="text-[11px] text-zinc-300 font-medium mt-0.5">medium</div>
              </div>
            </div>
            <p className="text-[12px] text-zinc-400 leading-relaxed">
              {acc.status === "connected"
                ? "Run a scan to see posture data."
                : "Awaiting verification — posture data will appear after the first scan."}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

export default function Accounts() {
  const qc = useQueryClient();
  const accounts = useQuery({ queryKey: ["accounts"], queryFn: () => api<Account[]>("/v1/accounts") });

  const create = useMutation({
    mutationFn: () => api<Account>("/v1/accounts", { method: "POST", body: JSON.stringify({}) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["accounts"] }),
  });

  const allFindings = useQuery({
    queryKey: ["findings-snapshot-all"],
    queryFn: () => api<{ items: Finding[]; total: number; next_cursor: string | null }>(`/v1/findings?status=open&limit=500`),
    enabled: (accounts.data?.length ?? 0) > 0,
  });

  const accs = accounts.data ?? [];
  const hasPending = accs.some((a) => a.status !== "connected");

  return (
    <div className="space-y-6 max-w-5xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">AWS Accounts</h1>
          <p className="text-sm text-zinc-500 mt-1">Connect your AWS accounts to start scanning.</p>
        </div>
        {accs.length > 0 && (
          <div className="flex flex-col items-end gap-1">
            <button
              onClick={() => create.mutate()}
              disabled={create.isPending || hasPending}
              title={hasPending ? "Finish setting up the pending account first" : undefined}
              className="flex items-center gap-1.5 rounded-xl border border-zinc-200 bg-white px-4 py-2 text-sm font-semibold text-zinc-700 shadow-sm hover:border-zinc-300 hover:bg-zinc-50 transition-colors disabled:cursor-not-allowed disabled:opacity-40"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
              {create.isPending ? "Adding…" : "Add account"}
            </button>
            {hasPending && (
              <span className="text-[11px] text-zinc-400">Finish pending setup first</span>
            )}
          </div>
        )}
      </div>

      {accs.length === 0 && !accounts.isLoading && (
        <div className="bg-white rounded-xl border border-zinc-200 shadow-sm p-6 max-w-md">
          <h2 className="font-semibold text-zinc-900 mb-1">Connect an AWS account</h2>
          <p className="text-sm text-zinc-500 mb-4">Deploy a read-only IAM role and start scanning for security issues.</p>
          <button
            onClick={() => create.mutate()}
            disabled={create.isPending}
            className="bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors disabled:opacity-50"
          >
            {create.isPending ? "Setting up…" : "Connect account"}
          </button>
        </div>
      )}

      {accs.map((acc) => (
        <AccountCard
          key={acc.id}
          acc={acc}
          findingsData={acc.status === "connected" ? allFindings.data : undefined}
          onRemoved={() => {}}
        />
      ))}

      {create.error && (
        <div className="max-w-md text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2">
          {(create.error as Error).message}
        </div>
      )}
    </div>
  );
}
