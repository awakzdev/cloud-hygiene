import type {
  CurrentSummary,
  HistoryEvent,
  PeriodSummary,
  ScanCadenceDay,
} from "../lib/complianceHistory";
import { ComplianceTrendChart } from "./ComplianceTrendChart";

function DashboardMetric({
  label,
  value,
  detail,
  tone = "neutral",
}: {
  label: string;
  value: string | number;
  detail: string;
  tone?: "neutral" | "good" | "bad";
}) {
  const toneClass =
    tone === "good" ? "text-emerald-700" : tone === "bad" ? "text-rose-700" : "text-zinc-950";
  return (
    <div className="min-w-0 rounded-lg border border-zinc-200 bg-white px-4 py-3 shadow-sm shadow-zinc-950/[0.03]">
      <p className="truncate text-[10px] font-semibold uppercase text-zinc-500">{label}</p>
      <p className={`mt-2 text-2xl font-bold tabular-nums tracking-tight ${toneClass}`}>{value}</p>
      <p className="mt-1 truncate text-xs text-zinc-500">{detail}</p>
    </div>
  );
}

function ControlStatusRow({ summary }: { summary: CurrentSummary }) {
  const total = summary.controls_passed + summary.controls_failed + summary.controls_no_data;
  if (total === 0) return null;

  const pct = (n: number) => `${((n / total) * 100).toFixed(0)}%`;

  return (
    <div className="rounded-lg border border-zinc-200 bg-white px-4 py-3.5 shadow-sm shadow-zinc-950/[0.03]">
      <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
        Current control status
      </p>

      {/* Bar */}
      <div className="mt-3 flex h-2.5 w-full overflow-hidden rounded-full bg-zinc-100">
        {summary.controls_passed > 0 && (
          <div
            className="bg-emerald-500 transition-all"
            style={{ width: `${(summary.controls_passed / total) * 100}%` }}
            title={`Passing: ${summary.controls_passed}`}
          />
        )}
        {summary.controls_failed > 0 && (
          <div
            className="bg-rose-500 transition-all"
            style={{ width: `${(summary.controls_failed / total) * 100}%` }}
            title={`Failing: ${summary.controls_failed}`}
          />
        )}
        {summary.controls_no_data > 0 && (
          <div
            className="bg-zinc-300 transition-all"
            style={{ width: `${(summary.controls_no_data / total) * 100}%` }}
            title={`No data: ${summary.controls_no_data}`}
          />
        )}
      </div>

      {/* Legend */}
      <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-xs">
        <span>
          <span className="font-semibold tabular-nums text-emerald-700">{summary.controls_passed}</span>
          <span className="text-zinc-500"> passing ({pct(summary.controls_passed)})</span>
        </span>
        <span>
          <span className="font-semibold tabular-nums text-rose-700">{summary.controls_failed}</span>
          <span className="text-zinc-500"> failing ({pct(summary.controls_failed)})</span>
        </span>
        {summary.controls_no_data > 0 && (
          <span>
            <span className="font-semibold tabular-nums text-zinc-500">{summary.controls_no_data}</span>
            <span className="text-zinc-400"> no data ({pct(summary.controls_no_data)})</span>
          </span>
        )}
      </div>
    </div>
  );
}

function ScanCadence({ cadence, days }: { cadence: ScanCadenceDay[]; days: number }) {
  const visible = cadence.slice(-18);
  if (visible.length === 0) return null;
  const maxScans = Math.max(1, ...visible.map((d) => d.scan_count));

  return (
    <div className="rounded-lg border border-zinc-200 bg-white px-4 py-3.5 shadow-sm shadow-zinc-950/[0.03]">
      <div className="flex items-baseline justify-between gap-3">
        <p className="text-[10px] font-semibold uppercase text-zinc-500">Scan cadence</p>
        <p className="text-[11px] text-zinc-400">Last {Math.min(days, visible.length)} scan days</p>
      </div>
      <div className="mt-3 grid grid-cols-[repeat(18,minmax(0,1fr))] gap-1.5">
        {visible.map((d) => {
          const intensity = d.scan_count / maxScans;
          const cls =
            d.posture_change_count > 0
              ? "bg-indigo-600"
              : intensity > 0.66
                ? "bg-emerald-600"
                : intensity > 0.33
                  ? "bg-emerald-400"
                  : "bg-emerald-200";
          return (
            <div
              key={d.date}
              className={`h-8 rounded-md ${cls}`}
              title={`${d.date}: ${d.scan_count} scan${d.scan_count === 1 ? "" : "s"}${
                d.posture_change_count > 0 ? `, ${d.posture_change_count} posture change${d.posture_change_count === 1 ? "" : "s"}` : ""
              }`}
            />
          );
        })}
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-zinc-500">
        <span><span className="mr-1 inline-block h-2 w-2 rounded-sm bg-emerald-400" />Scanned</span>
        <span><span className="mr-1 inline-block h-2 w-2 rounded-sm bg-indigo-600" />Posture changed</span>
      </div>
    </div>
  );
}

export function HistoryDashboard({
  events,
  days,
  currentScore,
  currentSummary,
  periodSummary,
  scanCount,
  scanCadence = [],
  onSelectSnapshot,
}: {
  events: HistoryEvent[];
  days: number;
  currentScore: number | null | undefined;
  currentSummary?: CurrentSummary | null;
  periodSummary?: PeriodSummary;
  scanCount?: number;
  scanCadence?: ScanCadenceDay[];
  onSelectSnapshot?: (scanRunId: string) => void;
}) {
  const failing = currentSummary?.controls_failed ?? 0;
  const passed = currentSummary?.controls_passed ?? 0;
  const noData = currentSummary?.controls_no_data ?? 0;
  const changed = (periodSummary?.controls_regressed ?? 0) + (periodSummary?.controls_improved ?? 0);

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <DashboardMetric
          label="Current posture"
          value={currentScore != null ? `${currentScore}%` : "No data"}
          detail={`${passed} passing, ${failing} failing`}
          tone={failing > 0 ? "bad" : currentScore != null ? "good" : "neutral"}
        />
        <DashboardMetric
          label="Failing controls"
          value={failing}
          detail={noData > 0 ? `${noData} controls without data` : "All mapped controls have data"}
          tone={failing > 0 ? "bad" : "good"}
        />
        <DashboardMetric
          label="Scans recorded"
          value={scanCount ?? 0}
          detail={`In the last ${days} days`}
        />
        <DashboardMetric
          label="Controls changed"
          value={changed}
          detail={`${periodSummary?.controls_improved ?? 0} improved, ${periodSummary?.controls_regressed ?? 0} regressed`}
          tone={(periodSummary?.controls_regressed ?? 0) > 0 ? "bad" : changed > 0 ? "good" : "neutral"}
        />
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.15fr)_minmax(18rem,0.85fr)]">
        {currentSummary && <ControlStatusRow summary={currentSummary} />}
        <ScanCadence cadence={scanCadence} days={days} />
      </div>

      {/* Trend chart — hero element. Score movement + story + clickable points */}
      {events.length > 0 && (
        <ComplianceTrendChart
          events={events}
          currentScore={currentScore}
          days={days}
          periodSummary={periodSummary}
          onSelectSnapshot={onSelectSnapshot}
        />
      )}

      {events.length === 0 && currentScore != null && (
        <div className="rounded-2xl border border-zinc-200/90 bg-white px-5 py-5 shadow-sm shadow-zinc-950/[0.04]">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500">
            Compliance posture
          </p>
          <p className="mt-3 text-4xl font-bold tabular-nums tracking-tight text-zinc-950">
            {currentScore}%
          </p>
          <p className="mt-2 text-sm text-zinc-500">
            Posture held steady — {scanCount ?? 0} scan{(scanCount ?? 0) === 1 ? "" : "s"} in the last {days} days
            with no control pass/fail changes.
          </p>
        </div>
      )}
    </div>
  );
}
