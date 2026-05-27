import { useEffect, useState } from "react";

const LAST_SCAN_DURATION_KEY = "vigil:lastScanDurationMs";
const DEFAULT_SCAN_DURATION_MS = 120_000;

export function loadExpectedScanDurationMs(): number {
  const raw = localStorage.getItem(LAST_SCAN_DURATION_KEY);
  const n = raw ? parseInt(raw, 10) : NaN;
  return Number.isFinite(n) && n >= 15_000 ? n : DEFAULT_SCAN_DURATION_MS;
}

export function saveScanDurationMs(startedAt: string, finishedAt: string) {
  const ms = new Date(finishedAt).getTime() - new Date(startedAt).getTime();
  if (ms >= 15_000) localStorage.setItem(LAST_SCAN_DURATION_KEY, String(ms));
}

export function formatScanDuration(ms: number): string {
  const sec = Math.max(1, Math.ceil(ms / 1000));
  if (sec < 60) return `${sec}s`;
  const min = Math.floor(sec / 60);
  const rem = sec % 60;
  return rem > 0 ? `${min}m ${rem}s` : `${min}m`;
}

type ScanProgress = {
  progress: number;
  elapsedMs: number;
  remainingMs: number | null;
  expectedMs: number;
  indeterminate: boolean;
  finishing: boolean;
};

export function useScanProgress(active: boolean, startedAt: Date | null): ScanProgress {
  const [now, setNow] = useState(Date.now());
  const expectedMs = loadExpectedScanDurationMs();

  useEffect(() => {
    if (!active) return;
    setNow(Date.now());
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [active]);

  if (!active) {
    return { progress: 0, elapsedMs: 0, remainingMs: null, expectedMs, indeterminate: false, finishing: false };
  }

  if (!startedAt) {
    return { progress: 0, elapsedMs: 0, remainingMs: null, expectedMs, indeterminate: true, finishing: false };
  }

  const elapsedMs = Math.max(0, now - startedAt.getTime());
  const finishing = elapsedMs >= expectedMs;
  const progress = finishing ? 95 : Math.min(95, (elapsedMs / expectedMs) * 100);
  const remainingMs = finishing ? null : expectedMs - elapsedMs;

  return { progress, elapsedMs, remainingMs, expectedMs, indeterminate: false, finishing };
}
