import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../api";

type ProviderSummary = {
  id: string;
  status: string;
  last_synced_at: string | null;
  repos: number;
  pull_requests: number;
};

function formatSync(value: string | null | undefined) {
  if (!value) return "Never synced";
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(value));
}

function GitHubMark({ className = "h-6 w-6" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" aria-hidden="true" fill="currentColor">
      <path d="M12 2C6.477 2 2 6.593 2 12.253c0 4.526 2.862 8.368 6.839 9.724.5.095.683-.222.683-.494 0-.244-.009-.89-.014-1.747-2.782.62-3.369-1.375-3.369-1.375-.455-1.184-1.11-1.5-1.11-1.5-.908-.636.069-.623.069-.623 1.004.072 1.532 1.057 1.532 1.057.892 1.566 2.341 1.114 2.91.852.091-.662.349-1.114.635-1.37-2.221-.259-4.555-1.139-4.555-5.068 0-1.12.39-2.034 1.029-2.751-.103-.26-.446-1.302.098-2.714 0 0 .84-.276 2.75 1.051A9.358 9.358 0 0 1 12 6.949c.85.004 1.705.118 2.504.346 1.909-1.327 2.747-1.051 2.747-1.051.546 1.412.203 2.454.1 2.714.64.717 1.027 1.631 1.027 2.751 0 3.939-2.337 4.806-4.565 5.06.359.318.679.945.679 1.904 0 1.374-.013 2.483-.013 2.82 0 .274.18.594.688.493C19.14 20.617 22 16.778 22 12.253 22 6.593 17.523 2 12 2Z" />
    </svg>
  );
}

function GitLabMark({ className = "h-6 w-6" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" aria-hidden="true" fill="currentColor">
      <path d="M22.65 14.39L12 22.13 1.35 14.39a.84.84 0 0 1-.3-.94l1.22-3.78 2.44-7.51A.42.42 0 0 1 4.82 2a.43.43 0 0 1 .58 0 .42.42 0 0 1 .11.18l2.44 7.49h8.1l2.44-7.51a.42.42 0 0 1 .11-.18.43.43 0 0 1 .58 0 .42.42 0 0 1 .11.18l2.44 7.51L23 13.45a.84.84 0 0 1-.35.94z"/>
    </svg>
  );
}

type IntegrationCardProps = {
  name: string;
  description: string;
  icon: React.ReactNode;
  iconBg: string;
  href: string;
  provider: ProviderSummary | null | undefined;
  isLoading: boolean;
};

function IntegrationCard({ name, description, icon, iconBg, href, provider, isLoading }: IntegrationCardProps) {
  const connected = !!provider;
  return (
    <div className="flex flex-col rounded-lg border border-zinc-200 bg-white p-6 shadow-sm">
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-center gap-4">
          <span className={`flex h-12 w-12 items-center justify-center rounded-xl text-white ${iconBg}`}>
            {icon}
          </span>
          <div>
            <h2 className="text-lg font-semibold text-zinc-950">{name}</h2>
            <p className="mt-0.5 text-sm text-zinc-500">{description}</p>
          </div>
        </div>
        <span
          className={`mt-0.5 shrink-0 rounded-full px-2.5 py-1 text-xs font-medium ring-1 ${
            connected
              ? "bg-emerald-50 text-emerald-700 ring-emerald-200"
              : "bg-zinc-100 text-zinc-500 ring-zinc-200"
          }`}
        >
          {isLoading ? "—" : connected ? "Connected" : "Not connected"}
        </span>
      </div>

      {connected && provider && (
        <div className="mt-5 grid grid-cols-3 gap-4 border-t border-zinc-100 pt-4 text-sm">
          <div>
            <div className="text-xs font-medium uppercase tracking-wide text-zinc-400">Last sync</div>
            <div className="mt-1 font-medium text-zinc-700">{formatSync(provider.last_synced_at)}</div>
          </div>
          <div>
            <div className="text-xs font-medium uppercase tracking-wide text-zinc-400">Repos</div>
            <div className="mt-1 font-medium text-zinc-700">{provider.repos}</div>
          </div>
          <div>
            <div className="text-xs font-medium uppercase tracking-wide text-zinc-400">MRs / PRs</div>
            <div className="mt-1 font-medium text-zinc-700">{provider.pull_requests}</div>
          </div>
        </div>
      )}

      <div className="mt-auto pt-5">
        <Link
          to={href}
          className="inline-flex w-full items-center justify-center rounded-lg border border-zinc-200 bg-white px-4 py-2 text-sm font-medium text-zinc-700 hover:bg-zinc-50"
        >
          {connected ? "Manage" : "Connect"}
        </Link>
      </div>
    </div>
  );
}

export default function Integrations() {
  const github = useQuery({
    queryKey: ["github-provider"],
    queryFn: () => api<ProviderSummary | null>("/v1/integrations/github"),
  });

  const gitlab = useQuery({
    queryKey: ["gitlab-provider"],
    queryFn: () => api<ProviderSummary | null>("/v1/integrations/gitlab"),
  });

  return (
    <div className="mx-auto max-w-6xl space-y-8">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight text-zinc-950">Integrations</h1>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-zinc-600">
          Connect identity and change-management sources to collect compliance evidence alongside AWS.
        </p>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <IntegrationCard
          name="GitHub"
          description="Identity, branch protection, PR approvals, self-merge detection."
          icon={<GitHubMark />}
          iconBg="bg-zinc-950"
          href="/integrations/github"
          provider={github.data ?? null}
          isLoading={github.isLoading}
        />
        <IntegrationCard
          name="GitLab"
          description="Identity, protected branches, MR approvals, self-merge detection."
          icon={<GitLabMark />}
          iconBg="bg-[#e24329]"
          href="/integrations/gitlab"
          provider={gitlab.data ?? null}
          isLoading={gitlab.isLoading}
        />
      </div>
    </div>
  );
}
