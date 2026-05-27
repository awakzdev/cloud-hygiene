import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { GITHUB_SYNC_KEY, useIntegrationSyncState } from "../hooks/useIntegrationSyncState";
import { useAccountScanRun } from "../hooks/useAccountScanRun";

type GitHubProvider = {
  id: string;
  status: string;
  login: string | null;
  org_login: string | null;
  org_logins: string[];
  last_synced_at: string | null;
  identity_users: number;
  repos: number;
  protected_branches: number;
  pull_requests: number;
  selected_repos: string[];
};

type SyncStats = {
  identity_users: number;
  repos: number;
  repo_protections: number;
  pull_requests: number;
};

function formatCollectionTime(value: string | null | undefined) {
  if (!value) return "No collection run yet";
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(value));
}

function pluralize(count: number, singular: string, plural = `${singular}s`) {
  return count === 1 ? singular : plural;
}

function GitHubMark({ className = "h-5 w-5" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" aria-hidden="true" fill="currentColor">
      <path d="M12 2C6.477 2 2 6.593 2 12.253c0 4.526 2.862 8.368 6.839 9.724.5.095.683-.222.683-.494 0-.244-.009-.89-.014-1.747-2.782.62-3.369-1.375-3.369-1.375-.455-1.184-1.11-1.5-1.11-1.5-.908-.636.069-.623.069-.623 1.004.072 1.532 1.057 1.532 1.057.892 1.566 2.341 1.114 2.91.852.091-.662.349-1.114.635-1.37-2.221-.259-4.555-1.139-4.555-5.068 0-1.12.39-2.034 1.029-2.751-.103-.26-.446-1.302.098-2.714 0 0 .84-.276 2.75 1.051A9.358 9.358 0 0 1 12 6.949c.85.004 1.705.118 2.504.346 1.909-1.327 2.747-1.051 2.747-1.051.546 1.412.203 2.454.1 2.714.64.717 1.027 1.631 1.027 2.751 0 3.939-2.337 4.806-4.565 5.06.359.318.679.945.679 1.904 0 1.374-.013 2.483-.013 2.82 0 .274.18.594.688.493C19.14 20.617 22 16.778 22 12.253 22 6.593 17.523 2 12 2Z" />
    </svg>
  );
}

function ChevronRight({ className = "h-4 w-4" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 20 20" aria-hidden="true" fill="none">
      <path d="m7.5 4.5 5 5.5-5 5.5" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export default function GitHubIntegration() {
  const qc = useQueryClient();
  const [lastSync, setLastSync] = useState<SyncStats | null>(null);
  const params = useMemo(() => new URLSearchParams(window.location.search), []);
  const connected = params.get("connected") === "1";
  const error = params.get("error");

  const provider = useQuery({
    queryKey: ["github-provider"],
    queryFn: () => api<GitHubProvider | null>("/v1/integrations/github"),
  });

  const accounts = useQuery({
    queryKey: ["accounts"],
    queryFn: () => api<{ id: string; status: string }[]>("/v1/accounts"),
  });
  const connectedAccountId = accounts.data?.find((a) => a.status === "connected")?.id;
  const { isSyncing } = useIntegrationSyncState("github");
  const { isRunning: awsScanRunning } = useAccountScanRun(connectedAccountId);

  const sync = useMutation({
    mutationKey: GITHUB_SYNC_KEY,
    mutationFn: async () =>
      api<SyncStats>("/v1/integrations/github/sync", {
        method: "POST",
        body: JSON.stringify({ org_login: null }),
      }),
    onSuccess: (stats) => {
      setLastSync(stats);
      qc.invalidateQueries({ queryKey: ["github-provider"] });
      setTimeout(() => qc.invalidateQueries({ queryKey: ["scan-run-latest"] }), 300);
    },
  });

  const disconnect = useMutation({
    mutationFn: () => api<void>("/v1/integrations/github", { method: "DELETE" }),
    onSuccess: () => {
      setLastSync(null);
      qc.invalidateQueries({ queryKey: ["github-provider"] });
    },
  });

  const connect = useMutation({
    mutationFn: () => api<{ url: string }>("/v1/integrations/github/connect-url"),
    onSuccess: ({ url }) => {
      window.location.href = url;
    },
  });

  const p = provider.data;
  const connectedLabel = p ? "Connected" : "Not connected";
  const syncTargets = p?.org_logins?.length ? p.org_logins : p?.org_login ? [p.org_login] : p?.login ? [p.login] : [];
  const syncTarget = syncTargets.length > 1 ? `${syncTargets.length} sources` : syncTargets[0] || "No source selected";
  const selectedRepoCount = p?.selected_repos?.length || 0;
  const scannedRepoCount = p?.repos || 0;
  const currentScopeCount = selectedRepoCount || scannedRepoCount;
  const scopeLabel = selectedRepoCount ? `${selectedRepoCount} selected repositories` : "All repositories";
  const hasScopeDrift = !!p?.last_synced_at && selectedRepoCount > 0 && scannedRepoCount > 0 && selectedRepoCount !== scannedRepoCount;
  const scopeDriftCount = Math.abs(selectedRepoCount - scannedRepoCount);
  const evidenceItems = (p?.repos || 0) + (p?.pull_requests || 0);
  const lastSyncAgeMs = p?.last_synced_at ? Date.now() - new Date(p.last_synced_at).getTime() : null;
  const syncState = !p?.last_synced_at
    ? "Pending"
    : hasScopeDrift
      ? "Needs refresh"
      : lastSyncAgeMs && lastSyncAgeMs > 7 * 24 * 60 * 60 * 1000
        ? "Stale"
        : "Synced";
  const syncStateClass =
    syncState === "Synced"
      ? "bg-emerald-50 text-emerald-700 ring-emerald-200"
      : syncState === "Stale" || syncState === "Needs refresh"
        ? "bg-amber-50 text-amber-700 ring-amber-200"
        : "bg-zinc-100 text-zinc-600 ring-zinc-200";
  const lastCollectionLabel = formatCollectionTime(p?.last_synced_at);
  const protectedRepos = p?.protected_branches || 0;
  const hasProtectionGap = !!p && p.repos > 0 && protectedRepos === 0;
  const missingProtections = Math.max((p?.repos || 0) - protectedRepos, 0);
  const protectedCoverageLabel = p?.repos ? `${protectedRepos} / ${p.repos}` : "0";
  const protectedCoveragePercent = p?.repos ? Math.round((protectedRepos / p.repos) * 100) : 0;
  const scopeDriftSummary = selectedRepoCount < scannedRepoCount
    ? `${scopeDriftCount} ${pluralize(scopeDriftCount, "repository")} excluded after latest collection.`
    : `${scopeDriftCount} ${pluralize(scopeDriftCount, "repository")} added after latest collection.`;

  return (
    <div className="mx-auto max-w-6xl space-y-8">
      <div>
        <p className="text-sm font-medium text-sky-700">Integrations / Evidence source</p>
        <h1 className="mt-1 text-3xl font-semibold tracking-tight text-zinc-950">GitHub evidence</h1>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-zinc-600">
          Sync GitHub identity, repository controls, and pull request activity into audit-ready compliance evidence.
        </p>
        {!p && (
          <>
            <button
              onClick={() => connect.mutate()}
              disabled={connect.isPending}
              className="mt-4 rounded-lg bg-zinc-950 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 disabled:opacity-60"
            >
              {connect.isPending ? "Connecting..." : "Connect GitHub"}
            </button>
            {connect.isError && (
              <div className="mt-3 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
                {(connect.error as Error).message}
              </div>
            )}
          </>
        )}
      </div>

      {connected && (
        <div className="rounded-lg border border-zinc-200 bg-white px-4 py-3 text-sm text-zinc-600">
          GitHub is connected. Review the repository scope or sync evidence from the current source.
        </div>
      )}
      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
          GitHub connection failed: {error}
        </div>
      )}

      {lastSync && (
        <div className="rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">
          Sync complete — {lastSync.identity_users} identity records, {lastSync.repos} repositories, {lastSync.repo_protections} protected branches, {lastSync.pull_requests} merged pull requests.
        </div>
      )}

      {(isSyncing || awsScanRunning) && (
        <div className="overflow-hidden rounded-xl border border-indigo-100 bg-indigo-50/80">
          <div className="flex items-center gap-2.5 px-4 py-2.5 text-sm text-indigo-800">
            <svg className="h-4 w-4 shrink-0 animate-spin text-indigo-500" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            <span className="font-semibold">
              {isSyncing && awsScanRunning
                ? "Syncing GitHub and running AWS scan"
                : isSyncing
                  ? "Syncing GitHub evidence"
                  : "AWS compliance scan running"}
            </span>
            <span className="text-indigo-600/75">— safe to leave this page</span>
          </div>
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-[1.18fr_0.82fr]">
        <div className="rounded-lg border border-zinc-200 bg-white p-6 shadow-sm">
          <div className="flex flex-wrap items-start justify-between gap-5">
            <div>
              <div className="flex items-center gap-3">
                <span className="flex h-10 w-10 items-center justify-center rounded-lg bg-zinc-950 text-white">
                  <GitHubMark className="h-6 w-6" />
                </span>
                <div>
                  <h2 className="text-xl font-semibold text-zinc-950">GitHub connection</h2>
                  <p className="mt-1 text-sm text-zinc-500">
                    {p ? `Authenticated as ${p.login || "GitHub user"}` : "Connect GitHub before evidence can be collected."}
                  </p>
                </div>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <span
                className={`rounded-full px-3 py-1 text-xs font-medium ${
                  p ? "bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200" : "bg-zinc-100 text-zinc-600"
                }`}
              >
                {connectedLabel}
              </span>
            </div>
          </div>

          <div className="mt-8 grid gap-5 border-t border-zinc-200 pt-6 md:grid-cols-3">
            <div>
              <div className="text-xs font-medium uppercase tracking-wide text-zinc-500">Source</div>
              <div className="mt-2 text-sm font-medium text-zinc-950">{syncTarget}</div>
            </div>
            <div>
              <div className="text-xs font-medium uppercase tracking-wide text-zinc-500">Repository scope</div>
              <div className="mt-2 text-sm font-medium text-zinc-950">{scopeLabel}</div>
            </div>
            <div>
              <div className="text-xs font-medium uppercase tracking-wide text-zinc-500">Last sync</div>
              <div className="mt-2 text-sm font-medium text-zinc-950">
                {lastCollectionLabel}
              </div>
            </div>
          </div>

          {p && (
            <div className="mt-8 border-t border-zinc-200 pt-6">
              <div className="flex flex-wrap items-center justify-between gap-4 rounded-lg border border-zinc-200 bg-zinc-50 px-5 py-3.5">
                <div className="min-w-0">
                  <div className="text-sm font-medium text-zinc-950">Collection scope</div>
                  <div className="mt-1 text-sm text-zinc-600">
                    {p.selected_repos?.length
                      ? `${p.selected_repos.length} repositories included for ${syncTarget}.`
                      : `All repositories under ${syncTarget} are included.`}
                  </div>
                </div>
                <div className="ml-auto flex flex-wrap items-center justify-end gap-3">
                  <Link
                    to="/integrations/github/edit"
                    className="rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm font-medium text-zinc-700 hover:bg-zinc-50"
                  >
                    Edit scope
                  </Link>
                  <button
                    onClick={() => sync.mutate()}
                    disabled={isSyncing || syncTargets.length === 0}
                    className="rounded-lg bg-zinc-950 px-5 py-2 text-sm font-medium text-white hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {isSyncing ? "Syncing…" : "Sync"}
                  </button>
                </div>
              </div>
            </div>
          )}

          {sync.error && (
            <div className="mt-5 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
              {(sync.error as Error).message}
            </div>
          )}

          {p && (
            <div className="mt-8 flex flex-wrap items-center justify-between gap-3 border-t border-zinc-200 pt-5">
              <div>
                <div className="text-sm font-medium text-zinc-950">Connection administration</div>
                <div className="mt-1 text-xs text-zinc-500">Disconnecting stops future GitHub evidence collection for this workspace.</div>
              </div>
              <button
                onClick={() => disconnect.mutate()}
                disabled={disconnect.isPending}
                className="rounded-lg border border-red-200 bg-white px-4 py-2 text-sm font-medium text-red-700 hover:bg-red-50 disabled:opacity-60"
              >
                {disconnect.isPending ? "Disconnecting..." : "Disconnect"}
              </button>
            </div>
          )}
        </div>

        <div className="flex flex-col rounded-lg border border-zinc-200 bg-white p-6 text-zinc-950 shadow-sm">
          <div className="flex items-center justify-between gap-3">
            <p className="text-sm font-medium text-zinc-800">Evidence health</p>
            <span className={`rounded-full px-3 py-1 text-xs font-medium ring-1 ${syncStateClass}`}>{syncState}</span>
          </div>
          <div className="mt-5 grid grid-cols-3 gap-3">
            {[
              { label: "Members", value: p?.identity_users ?? "—" },
              { label: "Repos", value: p?.repos ?? "—" },
              { label: "PRs", value: p?.pull_requests ?? "—" },
            ].map((s) => (
              <div key={s.label} className="rounded-lg border border-zinc-100 bg-zinc-50 px-3 py-2.5 text-center">
                <div className="text-lg font-semibold tabular-nums text-zinc-900">{s.value}</div>
                <div className="mt-0.5 text-[10px] font-medium uppercase tracking-wide text-zinc-500">{s.label}</div>
              </div>
            ))}
          </div>
          <div className="mt-5 space-y-3 border-y border-zinc-200 py-3 text-sm">
            <div className="flex items-center justify-between gap-4">
              <div className="font-medium text-zinc-700">Last collection</div>
              <div className="shrink-0 whitespace-nowrap text-right font-semibold text-zinc-950">{lastCollectionLabel}</div>
            </div>
            <div className="flex items-center justify-between gap-4">
              <div className="font-medium text-zinc-700">Current scope</div>
              <div className="shrink-0 whitespace-nowrap text-right font-semibold text-zinc-950">
                {currentScopeCount ? `${currentScopeCount} repositories` : "Not collected"}
              </div>
            </div>
            {hasScopeDrift && (
              <div className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs leading-5 text-amber-800">
                Coverage changed after the latest sync. Run sync to refresh evidence metrics.
              </div>
            )}
          </div>
          <div className="mt-3.5 space-y-2.5 text-sm">
            <div className="flex items-center justify-between gap-3">
              <span className="text-zinc-500">Access review</span>
              <span className="font-medium text-zinc-700">{p?.last_synced_at ? "Collected" : "—"}</span>
            </div>
            <div className="flex items-center justify-between gap-3">
              <span className="text-zinc-500">Pull request approvals</span>
              <span className="font-medium text-zinc-700">{p?.last_synced_at ? "Collected" : "—"}</span>
            </div>
            <div className="flex items-center justify-between gap-3">
              <span className="text-zinc-500">Self-merge checks</span>
              <span className="font-medium text-zinc-700">{p?.last_synced_at ? "Collected" : "—"}</span>
            </div>
            <div className="flex items-center justify-between gap-3">
              <span className="text-zinc-500">Branch protections</span>
              <span className={`font-medium ${!p?.last_synced_at ? "text-zinc-400" : missingProtections ? "text-amber-700" : "text-zinc-700"}`}>
                {!p?.last_synced_at ? "—" : missingProtections ? "Needs review" : "Collected"}
              </span>
            </div>
          </div>
          <div className="mt-auto pt-4 border-t border-zinc-200">
            {/* check IDs below are the planned GitHub check slugs — filter activates automatically once checks ship */}
            <Link
              to="/findings?checks=github.org.mfa_not_enforced,github.org.dormant_members,github.repo.no_branch_protection,github.repo.self_merge_allowed,github.repo.insufficient_reviews"
              className="inline-flex w-full items-center justify-center rounded-lg border border-sky-200 bg-white px-3 py-2 text-sm font-medium text-sky-800 hover:bg-sky-50"
            >
              View findings <ChevronRight className="ml-2 h-4 w-4" />
            </Link>
          </div>
        </div>
      </div>

      <div className="rounded-lg border border-zinc-200 bg-white p-6">
        <div>
          <h2 className="text-lg font-semibold text-zinc-950">Branch protection</h2>
          <p className="mt-1 max-w-2xl text-sm leading-6 text-zinc-600">
            Protected branch rules help enforce review controls required for change-management evidence.
          </p>
        </div>
        {hasScopeDrift && (
          <div className="mt-5 rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
            Coverage changed after the latest sync. {scopeDriftSummary} Run sync to refresh branch-protection metrics.
          </div>
        )}
        <div className="mt-5 grid gap-4 md:grid-cols-[0.8fr_1.2fr]">
          <div className="rounded-lg border border-zinc-200 bg-zinc-50 px-5 py-4">
            <div className={`text-2xl font-semibold ${missingProtections ? "text-amber-800" : "text-zinc-950"}`}>
              {protectedRepos} / {p?.repos || 0}
            </div>
            <div className="mt-1 text-sm font-medium text-zinc-800">repositories protected during last scan</div>
            <div className="mt-4 h-2 overflow-hidden rounded-full bg-zinc-200">
              <div
                className={`h-full rounded-full ${missingProtections ? "bg-amber-700" : "bg-emerald-600"}`}
                style={{ width: `${protectedCoveragePercent}%` }}
              />
            </div>
            <div className="mt-3 text-sm leading-6 text-zinc-600">
              {!p?.repos
                ? "No data collected yet."
                : hasScopeDrift
                  ? `Latest evidence was collected from ${scannedRepoCount} repositories. The current scope contains ${currentScopeCount}.`
                  : missingProtections
                    ? `${missingProtections} repositories are missing branch protection.`
                    : "All analyzed repositories have branch protection evidence."}
            </div>
          </div>
          <div className="divide-y divide-zinc-200 rounded-lg border border-zinc-200 bg-zinc-50 text-sm">
            <div className="flex items-center justify-between gap-4 px-5 py-4">
              <span className="font-semibold text-zinc-800">Current scope</span>
              <span className="font-semibold text-zinc-950">{scopeLabel}</span>
            </div>
            <div className="flex items-center justify-between gap-4 px-5 py-4">
              <span className="font-semibold text-zinc-800">Last synced scope</span>
              <span className="font-semibold text-zinc-950">{scannedRepoCount || 0} repositories</span>
            </div>
            <div className="flex items-center justify-between gap-4 px-5 py-4">
              <span className="font-semibold text-zinc-800">Remediation state</span>
              <span className={`font-semibold ${!p?.repos ? "text-zinc-500" : hasScopeDrift || missingProtections ? "text-amber-800" : "text-emerald-700"}`}>
                {!p?.repos ? "—" : hasScopeDrift ? "Needs refresh" : missingProtections ? "Needs review" : "Complete"}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
