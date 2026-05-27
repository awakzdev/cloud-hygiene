import { formatScanDuration } from "../hooks/useScanProgress";

type ScanProgressBarProps = {
  phase: "starting" | "running";
  progress: number;
  elapsedMs: number;
  remainingMs: number | null;
  finishing: boolean;
  indeterminate: boolean;
};

export default function ScanProgressBar({
  phase,
  progress,
  elapsedMs,
  remainingMs,
  finishing,
  indeterminate,
}: ScanProgressBarProps) {
  const label = phase === "starting" ? "Starting scan" : "Scanning account";
  const detail =
    phase === "starting"
      ? "Queued — usually takes a couple of minutes"
      : finishing
        ? `${formatScanDuration(elapsedMs)} elapsed · finishing up`
        : remainingMs != null
          ? `${formatScanDuration(elapsedMs)} elapsed · ~${formatScanDuration(remainingMs)} left (estimated)`
          : `${formatScanDuration(elapsedMs)} elapsed`;

  return (
    <div className="mb-4 overflow-hidden rounded-xl border border-indigo-100 bg-indigo-50/80">
      <div className="flex items-center justify-between gap-3 px-4 py-2.5">
        <div className="flex min-w-0 items-center gap-2.5 text-sm text-indigo-800">
          <svg className="h-4 w-4 shrink-0 animate-spin text-indigo-500" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          <div className="min-w-0">
            <span className="font-semibold">{label}</span>
            <span className="hidden text-indigo-600/80 sm:inline"> — {detail}</span>
          </div>
        </div>
        {!indeterminate && (
          <span className="shrink-0 text-xs font-semibold tabular-nums text-indigo-600">{Math.round(progress)}%</span>
        )}
      </div>
      <p className="px-4 pb-2 text-xs text-indigo-600/80 sm:hidden">{detail}</p>
      <div className="h-1 overflow-hidden bg-indigo-100">
        {indeterminate ? (
          <div className="h-full w-1/3 animate-scan-indeterminate rounded-full bg-indigo-400" />
        ) : (
          <div
            className="h-full rounded-full bg-indigo-500 transition-[width] duration-1000 ease-out"
            style={{ width: `${progress}%` }}
          />
        )}
      </div>
    </div>
  );
}
