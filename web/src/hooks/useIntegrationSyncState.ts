import { useMutationState } from "@tanstack/react-query";

export const GITHUB_SYNC_KEY = ["integration-sync", "github"] as const;
export const GITLAB_SYNC_KEY = ["integration-sync", "gitlab"] as const;

export function useIntegrationSyncState(provider: "github" | "gitlab") {
  const mutationKey = provider === "github" ? GITHUB_SYNC_KEY : GITLAB_SYNC_KEY;
  const pending = useMutationState({
    filters: { mutationKey: [...mutationKey], status: "pending" },
  });
  return { isSyncing: pending.length > 0 };
}
