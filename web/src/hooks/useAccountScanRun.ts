import { useQuery } from "@tanstack/react-query";
import { api } from "../api";

export type ScanRun = {
  id: string;
  status: string;
  started_at: string;
  finished_at: string | null;
  error: string | null;
  failed_at?: string | null;
  error_type?: string | null;
  findings_opened?: number;
  findings_resolved?: number;
};

export function useAccountScanRun(accountId: string | null | undefined) {
  const scanRun = useQuery({
    queryKey: ["scan-run-latest", accountId],
    queryFn: () => (accountId ? api<ScanRun | null>(`/v1/accounts/${accountId}/scan-runs/latest`) : null),
    enabled: !!accountId,
    refetchInterval: (query) => (query.state.data?.status === "running" ? 5000 : false),
  });

  const scanStatus = scanRun.data?.status ?? null;
  const scanStartedAt = scanRun.data?.started_at ? new Date(scanRun.data.started_at) : null;
  const scanStuck = scanStartedAt ? Date.now() - scanStartedAt.getTime() > 5 * 60 * 1000 : false;
  const isRunning = scanStatus === "running" && !scanStuck;

  return { scanRun, scanStatus, isRunning, scanStuck };
}
