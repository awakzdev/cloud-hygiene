import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";

type GitLabProvider = {
  id: string;
  status: string;
  username: string | null;
  group_id: string | null;
  group_ids: string[];
  base_url: string | null;
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

function GitLabMark({ className = "h-5 w-5" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" aria-hidden="true" fill="currentColor">
      <path d="M22.65 14.39L12 22.13 1.35 14.39a.84.84 0 0 1-.3-.94l1.22-3.78 2.44-7.51A.42.42 0 0 1 4.82 2a.43.43 0 0 1 .58 0 .42.42 0 0 1 .11.18l2.44 7.49h8.1l2.44-7.51a.42.42 0 0 1 .11-.18.43.43 0 0 1 .58 0 .42.42 0 0 1 .11.18l2.44 7.51L23 13.45a.84.84 0 0 1-.35.94z" />
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

export default function GitLabIntegration() {
  const qc = useQueryClient();
  const [lastSync, setLastSync] = useState<SyncStats | null>(null);
  const [baseUrlInput, setBaseUrlInput] = useState("");
  const params = useMemo(() => new URLSearchParams(window.location.search), []);
  const connected = params.get("connected") === "1";
  const error = params.get("error");

  const provider = useQuery({
    queryKey: ["gitlab-provider"],
    queryFn: () => api<GitLabProvider | null>("/v1/integrations/gitlab"),
  });

  const sync = useMutation({
    mutationFn: async () =>
      api<SyncStats>("/v1/integrations/gitlab/sync", {
        method: "POST",
        body: JSON.stringify({ group_id: null }),
      }),
    onSuccess: (stats) => {
      setLastSync(stats);
      qc.invalidateQueries({ queryKey: ["gitlab-provider"] });
    },
  });

  const disconnect = useMutation({
    mutationFn: () => api<void>("/v1/integrations/gitlab", { method: "DELETE" }),
    onSuccess: () => {
      setLastSync(null);
      qc.invalidateQueries({ queryKey: ["gitlab-provider"] });
    },
  });

  const connect = useMutation({
    mutationFn: () => {
      const base = baseUrlInput.trim() || undefined;
      const qs = base ? `?base_url=${encodeURIComponent(base)}` : "";
      return api<{ url: string }>(`/v1/integrations/gitlab/connect-url${qs}`);
    },
    onSuccess: ({ url }) => {
      window.location.href = url;
    },
  });

  const p = provider.data;
  const syncTargets = p?.group_ids?.length ? p.group_ids : p?.group_id ? [p.group_id] : [];
  const syncTarget = syncTargets.length > 1 ? `${syncTargets.length} groups` : syncTargets[0] || "No group selected";
  const selectedRepoCount = p?.selected_repos?.length || 0;
  const scannedRepoCount = p?.repos || 0;
  const currentScopeCount = selectedRepoCount || scannedRepoCount;
  const scopeLabel = selectedRepoCount ? `${selectedRepoCount} selected repositories` : "All repositories";
  const hasScopeDrift = !!p?.last_synced_at && selectedRepoCount > 0 && scannedRepoCount > 0 && selectedRepoCount !== scannedRepoCount;
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
  const missingProtections = Math.max((p?.repos || 0) - protectedRepos, 0);
  const protectedCoverageLabel = p?.repos ? `${protectedRepos} / ${p.repos}` : "0";
  const protectedCoveragePercent = p?.repos ? Math.round((protectedRepos / p.repos) * 100) : 0;
  const instanceLabel = p?.base_url ? p.base_url.replace(/^https?:\/\//, "") : "gitlab.com";

  return (
    <div className="mx-auto max-w-6xl space-y-8">
      <div>
        <p className="text-sm font-medium text-sky-700">
          <Link to="/integrations" className="hover:underline">Integrations</Link>
          {" / "}Evidence source
        </p>
        <h1 className="mt-1 text-3xl font-semibold tracking-tight text-zinc-950">GitLab evidence</h1>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-zinc-600">
          Sync GitLab identity, repository controls, and merge request activity into audit-ready compliance evidence.
        </p>
        {!p && (
          <div className="mt-4 space-y-3">
            <div className="flex max-w-sm items-center gap-3">
              <input
                type="url"
                value={baseUrlInput}
                onChange={(e) => setBaseUrlInput(e.target.value)}
                placeholder="https://gitlab.com  (or self-hosted URL)"
                className="flex-1 rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm text-zinc-950 outline-none placeholder:text-zinc-400 focus:border-sky-500 focus:ring-2 focus:ring-sky-100"
              />
            </div>
            <button
              onClick={() => connect.mutate()}
              disabled={connect.isPending}
              className="rounded-lg bg-[#e24329] px-4 py-2 text-sm font-medium text-white hover:bg-[#c93a22] disabled:opacity-60"
            >
              {connect.isPending ? "Connecting..." : "Connect GitLab"}
            </button>
            {connect.isError && (
              <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
                {(connect.error as Error).message}
              </div>
            )}
          </div>
        )}
      </div>

      {connected && (
        <div className="rounded-lg border border-zinc-200 bg-white px-4 py-3 text-sm text-zinc-600">
          GitLab is connected. Review the repository scope or sync evidence from the current source.
        </div>
      )}
      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
          GitLab connection failed: {error}
        </div>
      )}

      {lastSync && (
        <div className="rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">
          Sync complete — {lastSync.identity_users} identity records, {lastSync.repos} repositories, {lastSync.repo_protections} protected branches, {lastSync.pull_requests} merge requests.
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-[1.18fr_0.82fr]">
        <div className="rounded-lg border border-zinc-200 bg-white p-6 shadow-sm">
          <div className="flex flex-wrap items-start justify-between gap-5">
            <div className="flex items-center gap-3">
              <span className="flex h-10 w-10 items-center justify-center rounded-lg bg-[#e24329] text-white">
                <GitLabMark className="h-6 w-6" />
              </span>
              <div>
                <h2 className="text-xl font-semibold text-zinc-950">GitLab connection</h2>
                <p className="mt-1 text-sm text-zinc-500">
                  {p
                    ? `Authenticated as ${p.username || "GitLab user"} on ${instanceLabel}`
                    : "Connect GitLab before evidence can be collected."}
                </p>
              </div>
            </div>
            <span
              className={`rounded-full px-3 py-1 text-xs font-medium ${
                p ? "bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200" : "bg-zinc-100 text-zinc-600"
              }`}
            >
              {p ? "Connected" : "Not connected"}
            </span>
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
              <div className="mt-2 text-sm font-medium text-zinc-950">{lastCollectionLabel}</div>
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
                    to="/integrations/gitlab/edit"
                    className="rounded-lg border border-transparent px-3 py-2 text-sm font-medium text-zinc-600 hover:border-zinc-200 hover:bg-white hover:text-zinc-950"
                  >
                    Edit scope
                  </Link>
                  <button
                    onClick={() => sync.mutate()}
                    disabled={sync.isPending || syncTargets.length === 0}
                    className="rounded-lg bg-[#e24329] px-5 py-2 text-sm font-medium text-white hover:bg-[#c93a22] disabled:opacity-60"
                  >
                    {sync.isPending ? "Syncing..." : "Sync"}
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
                <div className="mt-1 text-xs text-zinc-500">Disconnecting stops future GitLab evidence collection for this workspace.</div>
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
          <div className="mt-5">
            <div className="text-xl font-semibold text-zinc-950">{evidenceItems}</div>
            <div className="mt-1 text-xs font-medium uppercase tracking-wide text-zinc-500">Evidence records</div>
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
              <span className="text-zinc-500">MR approvals</span>
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
            {/* check IDs below are the planned GitLab check slugs — filter activates automatically once checks ship */}
            <Link
              to="/findings?checks=gitlab.group.mfa_not_enforced,gitlab.group.dormant_members,gitlab.repo.no_branch_protection,gitlab.repo.self_merge_allowed,gitlab.repo.insufficient_reviews"
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
              <span className={`font-semibold ${!p?.repos ? "text-zinc-500" : missingProtections ? "text-amber-800" : "text-emerald-700"}`}>
                {!p?.repos ? "—" : missingProtections ? "Needs review" : "Complete"}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
