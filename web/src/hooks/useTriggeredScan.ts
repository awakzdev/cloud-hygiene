import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { saveScanDurationMs, useScanProgress } from "./useScanProgress";

export type ScanRunLatest = {
  id: string;
  status: string;
  started_at: string;
  finished_at: string | null;
  error?: string | null;
  failed_at?: string | null;
  error_type?: string | null;
};

const STARTING_TIMEOUT_MS = 3 * 60 * 1000;
const SCAN_STUCK_MS = 5 * 60 * 1000;

/** In-memory pending scans survive SPA navigation; sessionStorage survives refresh. */
const pendingScanAtMs = new Map<string, number>();

function pendingScanKey(accountId: string) {
  return `vigil:scan-pending:${accountId}`;
}

export function readPendingScan(accountId: string): Date | null {
  let ms = pendingScanAtMs.get(accountId);
  if (ms == null) {
    try {
      const raw = sessionStorage.getItem(pendingScanKey(accountId));
      if (raw) ms = parseInt(raw, 10);
    } catch {
      /* sessionStorage unavailable */
    }
  }
  if (ms == null || !Number.isFinite(ms) || Date.now() - ms > STARTING_TIMEOUT_MS) {
    clearPendingScan(accountId);
    return null;
  }
  pendingScanAtMs.set(accountId, ms);
  return new Date(ms);
}

function writePendingScan(accountId: string, at: Date) {
  pendingScanAtMs.set(accountId, at.getTime());
  try {
    sessionStorage.setItem(pendingScanKey(accountId), String(at.getTime()));
  } catch {
    /* sessionStorage unavailable */
  }
}

export function clearPendingScan(accountId: string) {
  pendingScanAtMs.delete(accountId);
  try {
    sessionStorage.removeItem(pendingScanKey(accountId));
  } catch {
    /* sessionStorage unavailable */
  }
}

function pendingMatchesRun(pendingAt: Date, run: ScanRunLatest): boolean {
  const pendingMs = pendingAt.getTime();
  if (run.status === "running") {
    return new Date(run.started_at).getTime() >= pendingMs - 2000;
  }
  if (run.status === "ok" || run.status === "error") {
    if (!run.finished_at) return false;
    return new Date(run.finished_at).getTime() >= pendingMs - 2000;
  }
  return false;
}

type UseTriggeredScanOptions = {
  onScanComplete?: () => void;
  /** Poll while idle (e.g. Accounts page) to catch scans started on other pages. */
  backgroundPollMs?: number;
};

export function useTriggeredScan(accountId: string | undefined, options?: UseTriggeredScanOptions) {
  const qc = useQueryClient();
  const [scanTriggered, setScanTriggered] = useState(false);
  const [localScanStartedAt, setLocalScanStartedAt] = useState<Date | null>(null);
  const prevScanStatus = useRef<string | null>(null);
  const onScanCompleteRef = useRef(options?.onScanComplete);
  onScanCompleteRef.current = options?.onScanComplete;
  const backgroundPollMs = options?.backgroundPollMs;

  const scanRun = useQuery({
    queryKey: ["scan-run-latest", accountId],
    queryFn: () =>
      accountId ? api<ScanRunLatest | null>(`/v1/accounts/${accountId}/scan-runs/latest`) : null,
    enabled: !!accountId,
    refetchOnMount: "always",
    refetchInterval: () => {
      if (!accountId) return false;
      const pending = readPendingScan(accountId);
      const status = qc.getQueryData<ScanRunLatest | null>(["scan-run-latest", accountId])?.status;
      if (pending || status === "running") return 3000;
      return backgroundPollMs ?? false;
    },
  });

  const scanStatus = scanRun.data?.status ?? null;
  const scanStartedAt = scanRun.data?.started_at ? new Date(scanRun.data.started_at) : null;
  const scanStuck = scanStartedAt ? Date.now() - scanStartedAt.getTime() > SCAN_STUCK_MS : false;
  const pendingFromStorage = accountId ? readPendingScan(accountId) : null;
  const pendingAt = localScanStartedAt ?? pendingFromStorage;
  const isRunning =
    scanStatus === "running" &&
    !scanStuck &&
    !!scanRun.data &&
    (!pendingAt || pendingMatchesRun(pendingAt, scanRun.data));
  const isQueuePending = (scanTriggered || !!pendingFromStorage) && !isRunning;
  const isScanActive = isQueuePending || isRunning;
  const effectiveScanStartedAt = isRunning
    ? scanStartedAt
    : isQueuePending
      ? pendingAt
      : null;
  const scanProgress = useScanProgress(isScanActive, effectiveScanStartedAt);

  useEffect(() => {
    if (!accountId) return;
    const pending = readPendingScan(accountId);
    if (!pending) return;
    setScanTriggered(true);
    setLocalScanStartedAt((cur) => cur ?? pending);
  }, [accountId]);

  useEffect(() => {
    const run = scanRun.data;
    const pending = pendingAt;

    if (prevScanStatus.current === "running" && scanStatus === "ok") {
      onScanCompleteRef.current?.();
      if (run?.started_at && run?.finished_at) {
        saveScanDurationMs(run.started_at, run.finished_at);
      }
    }

    if (run && pending && accountId) {
      if (run.status === "running" && pendingMatchesRun(pending, run)) {
        clearPendingScan(accountId);
        setScanTriggered(false);
      } else if (
        (run.status === "ok" || run.status === "error") &&
        pendingMatchesRun(pending, run)
      ) {
        clearPendingScan(accountId);
        setScanTriggered(false);
        setLocalScanStartedAt(null);
      }
    } else if ((scanStatus === "ok" || scanStatus === "error") && !pending && !scanTriggered) {
      setLocalScanStartedAt(null);
    }

    prevScanStatus.current = scanStatus;
  }, [accountId, scanStatus, scanTriggered, pendingAt, scanRun.data]);

  useEffect(() => {
    if (!pendingAt || isRunning) return;
    const remaining = STARTING_TIMEOUT_MS - (Date.now() - pendingAt.getTime());
    if (remaining <= 0) {
      if (accountId) clearPendingScan(accountId);
      setScanTriggered(false);
      setLocalScanStartedAt(null);
      return;
    }
    const id = setTimeout(() => {
      if (accountId) clearPendingScan(accountId);
      setScanTriggered(false);
      setLocalScanStartedAt(null);
    }, remaining);
    return () => clearTimeout(id);
  }, [accountId, isRunning, pendingAt]);

  const scan = useMutation({
    mutationFn: (id: string) => api(`/v1/accounts/${id}/scan`, { method: "POST" }),
    onSuccess: () => {
      setTimeout(() => qc.invalidateQueries({ queryKey: ["scan-run-latest"] }), 300);
    },
    onError: (_err, id) => {
      clearPendingScan(id);
      setScanTriggered(false);
      setLocalScanStartedAt(null);
    },
  });

  function triggerScan(id: string) {
    const at = new Date();
    writePendingScan(id, at);
    setScanTriggered(true);
    setLocalScanStartedAt(at);
    scan.mutate(id);
  }

  return {
    scanRun,
    scanStatus,
    isRunning,
    scanTriggered,
    isScanActive,
    scanProgress,
    scanStuck,
    triggerScan,
  };
}
