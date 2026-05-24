import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "../api";

type Account = {
  id: string;
  label: string;
  account_id: string | null;
  status: string;
  external_id: string;
  cfn_launch_url: string;
};

export default function Accounts() {
  const qc = useQueryClient();
  const accounts = useQuery({ queryKey: ["accounts"], queryFn: () => api<Account[]>("/v1/accounts") });
  const [roleArn, setRoleArn] = useState("");
  const [scanQueued, setScanQueued] = useState(false);

  const create = useMutation({
    mutationFn: () => api<Account>("/v1/accounts", { method: "POST", body: JSON.stringify({}) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["accounts"] }),
  });
  const verify = useMutation({
    mutationFn: (id: string) => api<Account>(`/v1/accounts/${id}/verify`, { method: "POST", body: JSON.stringify({ role_arn: roleArn }) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["accounts"] }),
  });
  const scan = useMutation({
    mutationFn: (id: string) => api(`/v1/accounts/${id}/scan`, { method: "POST" }),
    onSuccess: () => setScanQueued(true),
  });

  const acc = accounts.data?.[0];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-zinc-900">AWS Accounts</h1>
        <p className="text-sm text-zinc-500 mt-0.5">Connect your AWS account to start scanning</p>
      </div>

      {!acc && (
        <div className="bg-white rounded-xl border border-zinc-200 shadow-sm p-6 max-w-md">
          <h2 className="font-semibold text-zinc-900 mb-1">Connect an AWS account</h2>
          <p className="text-sm text-zinc-500 mb-4">Deploy a read-only IAM role and start scanning for IAM issues.</p>
          <button
            onClick={() => create.mutate()}
            disabled={create.isPending}
            className="bg-zinc-900 hover:bg-zinc-800 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors disabled:opacity-50"
          >
            {create.isPending ? "Setting up…" : "Connect account"}
          </button>
        </div>
      )}

      {acc && (
        <div className="bg-white rounded-xl border border-zinc-200 shadow-sm overflow-hidden max-w-2xl">
          {/* Account header */}
          <div className="px-6 py-4 border-b border-zinc-100 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-orange-100 flex items-center justify-center">
                <svg className="w-4 h-4 text-orange-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" />
                </svg>
              </div>
              <div>
                <div className="font-semibold text-zinc-900">{acc.label}</div>
                {acc.account_id && <div className="text-xs text-zinc-400 font-mono">{acc.account_id}</div>}
              </div>
            </div>
            <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold ${
              acc.status === "connected"
                ? "bg-green-50 text-green-700"
                : "bg-amber-50 text-amber-700"
            }`}>
              <span className={`w-1.5 h-1.5 rounded-full ${acc.status === "connected" ? "bg-green-500" : "bg-amber-500"}`} />
              {acc.status}
            </span>
          </div>

          {/* Setup steps (not connected) */}
          {acc.status !== "connected" && (
            <div className="px-6 py-5 space-y-5">
              <div className="space-y-3">
                {[
                  {
                    n: 1,
                    label: "Deploy IAM role via CloudFormation",
                    content: (
                      <a href={acc.cfn_launch_url} target="_blank" rel="noreferrer"
                        className="inline-flex items-center gap-1.5 text-sm text-zinc-600 font-medium hover:text-zinc-700">
                        Launch CloudFormation stack
                        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                        </svg>
                      </a>
                    ),
                  },
                  {
                    n: 2,
                    label: "Copy the RoleArn from stack Outputs",
                    content: null,
                  },
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
                            className="flex-1 border border-zinc-200 rounded-lg px-3 py-2 font-mono text-xs focus:outline-none focus:ring-2 focus:ring-zinc-900 focus:border-transparent"
                            placeholder="arn:aws:iam::123456789012:role/CloudHygieneReadOnly"
                            value={roleArn}
                            onChange={e => setRoleArn(e.target.value)}
                          />
                          <button
                            onClick={() => verify.mutate(acc.id)}
                            disabled={verify.isPending || !roleArn}
                            className="bg-zinc-900 hover:bg-zinc-800 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors disabled:opacity-50"
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
            </div>
          )}

          {/* Connected — scan */}
          {acc.status === "connected" && (
            <div className="px-6 py-5 space-y-3">
              <p className="text-sm text-zinc-500">Account connected. Run a scan to detect IAM issues.</p>
              <div className="flex items-center gap-3">
                <button
                  onClick={() => { setScanQueued(false); scan.mutate(acc.id); }}
                  disabled={scan.isPending}
                  className="flex items-center gap-2 bg-zinc-900 hover:bg-zinc-800 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors disabled:opacity-50"
                >
                  <svg className={`w-4 h-4 ${scan.isPending ? "animate-spin" : ""}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                  </svg>
                  {scan.isPending ? "Triggering…" : "Run scan now"}
                </button>
                {scanQueued && (
                  <span className="text-sm text-zinc-500">Scan queued — check Findings in ~30s</span>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
