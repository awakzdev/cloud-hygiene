import { useEffect, useMemo, useRef, useState } from "react";
import type { EvidenceCoverage } from "../lib/evidenceCoverage";
import {
  exportAsOfSectionLabel,
  exportAsOfShowsType2Hint,
  exportScopeSectionLabel,
  frameworkEvidenceUi,
  type EvidenceTone,
  type FrameworkEvidenceUi,
} from "../lib/frameworkEvidenceCoverage";

const WINDOW_OPTIONS = [
  { value: "last_scan" as const, label: "Last scan" },
  { value: 30 as const, label: "30d" },
  { value: 90 as const, label: "90d" },
  { value: 180 as const, label: "180d" },
  { value: 365 as const, label: "365d" },
];

const readinessStyles: Record<
  EvidenceTone,
  { badge: string; dot: string; bar: string; headline: string }
> = {
  ready: {
    badge: "bg-emerald-50 text-emerald-900 ring-emerald-200/80",
    dot: "bg-emerald-500",
    bar: "bg-emerald-500",
    headline: "text-emerald-900",
  },
  partial: {
    badge: "bg-amber-50/90 text-amber-950 ring-amber-200/70",
    dot: "bg-amber-400",
    bar: "bg-amber-400",
    headline: "text-amber-950",
  },
  limited: {
    badge: "bg-zinc-100 text-zinc-800 ring-zinc-200/80",
    dot: "bg-zinc-400",
    bar: "bg-zinc-500",
    headline: "text-zinc-800",
  },
  insufficient: {
    badge: "bg-rose-50/80 text-rose-900 ring-rose-200/60",
    dot: "bg-rose-500",
    bar: "bg-rose-400",
    headline: "text-zinc-900",
  },
  snapshot: {
    badge: "bg-indigo-50 text-indigo-900 ring-indigo-200/80",
    dot: "bg-indigo-500",
    bar: "bg-indigo-500",
    headline: "text-indigo-900",
  },
  neutral: {
    badge: "bg-zinc-100 text-zinc-800 ring-zinc-200/80",
    dot: "bg-zinc-500",
    bar: "bg-zinc-500",
    headline: "text-zinc-900",
  },
};

function EvidenceCoverageSection({
  ui,
  loading,
}: {
  ui: FrameworkEvidenceUi;
  loading?: boolean;
}) {
  const styles = readinessStyles[ui.tone];
  return (
    <>
      <div className="flex flex-wrap items-center gap-2">
        <span
          className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ${styles.badge}`}
        >
          <span className={`h-1.5 w-1.5 rounded-full ${styles.dot}`} aria-hidden />
          {ui.badgeLabel}
        </span>
        {loading && <span className="text-[11px] text-zinc-400">Updating…</span>}
      </div>

      {ui.headline && (
        <p className={`mt-3 text-sm font-semibold tabular-nums ${styles.headline}`}>{ui.headline}</p>
      )}

      {ui.showProgressBar && (
        <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-zinc-200/90">
          <div
            className={`h-full rounded-full transition-all duration-300 ${ui.progressPct > 0 ? styles.bar : "bg-transparent"}`}
            style={{ width: `${Math.min(100, Math.max(0, ui.progressPct))}%` }}
            role="progressbar"
            aria-valuenow={ui.progressPct}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-label={ui.progressAriaLabel ?? "Days with scan evidence"}
          />
        </div>
      )}

      {ui.detailLine && (
        <p className="mt-2.5 text-sm leading-relaxed text-zinc-600">{ui.detailLine}</p>
      )}

      {ui.guidanceLine && (
        <div
          className="mt-2.5 flex items-start gap-2 rounded-md border border-amber-200/60 bg-amber-50/90 px-2.5 py-2 text-xs font-medium leading-snug text-amber-950"
          role="note"
        >
          <span
            className="mt-px flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded-full bg-amber-100 text-[9px] font-semibold leading-none text-amber-800 ring-1 ring-amber-200/70"
            aria-hidden
          >
            i
          </span>
          <span>{ui.guidanceLine}</span>
        </div>
      )}
    </>
  );
}

function CompactStatsRow({
  items,
}: {
  items: { label: string; value: string }[];
}) {
  return (
    <dl className="grid grid-cols-[1fr_auto] gap-x-6 gap-y-1.5 text-xs">
      {items.map((item) => (
        <div key={item.label} className="contents">
          <dt className="font-medium text-zinc-500">{item.label}</dt>
          <dd className="text-right font-semibold tabular-nums text-zinc-900">{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

function toIsoDate(d: Date): string {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${y}-${m}-${day}`;
}

function parseIso(iso: string): Date {
  return new Date(`${iso}T12:00:00`);
}

function formatDisplayDate(iso: string): string {
  return parseIso(iso).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

function AuditAsOfPicker({
  value,
  onChange,
  maxIso,
}: {
  value: string;
  onChange: (iso: string) => void;
  maxIso: string;
}) {
  const todayIso = maxIso;
  const selectedIso = value.trim() || todayIso;
  const [open, setOpen] = useState(false);
  const [mode, setMode] = useState<"day" | "month" | "year">("day");
  const [view, setView] = useState(() => {
    const d = parseIso(selectedIso);
    return { year: d.getFullYear(), month: d.getMonth() };
  });
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const d = parseIso(selectedIso);
    setView({ year: d.getFullYear(), month: d.getMonth() });
    setMode("day");
  }, [open, selectedIso]);

  useEffect(() => {
    if (!open) return;
    function onDoc(e: MouseEvent) {
      if (!rootRef.current?.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);

  const cells = useMemo(() => {
    const first = new Date(view.year, view.month, 1);
    const startPad = first.getDay();
    const daysInMonth = new Date(view.year, view.month + 1, 0).getDate();
    const grid: { iso: string; day: number; inMonth: boolean; disabled: boolean }[] = [];
    for (let i = 0; i < startPad; i++) {
      const d = new Date(view.year, view.month, -startPad + i + 1);
      grid.push({
        iso: toIsoDate(d),
        day: d.getDate(),
        inMonth: false,
        disabled: toIsoDate(d) > maxIso,
      });
    }
    for (let day = 1; day <= daysInMonth; day++) {
      const d = new Date(view.year, view.month, day);
      const iso = toIsoDate(d);
      grid.push({ iso, day, inMonth: true, disabled: iso > maxIso });
    }
    while (grid.length % 7 !== 0) {
      const d = new Date(view.year, view.month + 1, grid.length - startPad - daysInMonth + 1);
      const iso = toIsoDate(d);
      grid.push({
        iso,
        day: d.getDate(),
        inMonth: false,
        disabled: iso > maxIso,
      });
    }
    return grid;
  }, [view.month, view.year, maxIso]);

  const monthLabel = new Date(view.year, view.month, 1).toLocaleDateString(undefined, {
    month: "long",
    year: "numeric",
  });
  const maxDate = parseIso(maxIso);
  const maxYear = maxDate.getFullYear();
  const maxMonth = maxDate.getMonth();
  const yearBlockStart = view.year - (((view.year % 12) + 12) % 12);
  const headerLabel =
    mode === "day"
      ? monthLabel
      : mode === "month"
        ? String(view.year)
        : `${yearBlockStart} – ${yearBlockStart + 11}`;

  return (
    <div ref={rootRef} className="relative">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="inline-flex w-full items-center justify-between gap-2 rounded-lg border border-zinc-200/90 bg-white px-3 py-2 text-left text-xs font-semibold text-zinc-900 transition hover:border-zinc-300 hover:bg-zinc-50/80"
        aria-expanded={open}
        aria-haspopup="dialog"
      >
        <span>{value.trim() ? formatDisplayDate(value) : `Today · ${formatDisplayDate(todayIso)}`}</span>
        <svg className="h-3.5 w-3.5 shrink-0 text-zinc-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
        </svg>
      </button>
      {open && (
        <div
          role="dialog"
          aria-label="Choose as-of date"
          className="absolute right-0 z-10 mt-1.5 w-[17rem] rounded-xl border border-zinc-200/90 bg-white p-3 shadow-lg shadow-zinc-950/10 ring-1 ring-zinc-950/[0.04]"
        >
          <div className="mb-2 flex items-center justify-between">
            <button
              type="button"
              className="rounded-md px-1.5 py-0.5 text-zinc-500 hover:bg-zinc-100 hover:text-zinc-800"
              onClick={() =>
                setView((v) => {
                  if (mode === "year") return { ...v, year: v.year - 12 };
                  if (mode === "month") return { ...v, year: v.year - 1 };
                  const m = v.month - 1;
                  return m < 0 ? { year: v.year - 1, month: 11 } : { year: v.year, month: m };
                })
              }
              aria-label={mode === "day" ? "Previous month" : mode === "month" ? "Previous year" : "Previous years"}
            >
              ‹
            </button>
            <button
              type="button"
              onClick={() => setMode((m) => (m === "day" ? "month" : m === "month" ? "year" : "month"))}
              className="rounded-md px-2 py-0.5 text-xs font-semibold text-zinc-800 hover:bg-zinc-100"
              aria-label="Switch month/year"
            >
              {headerLabel}
            </button>
            <button
              type="button"
              className="rounded-md px-1.5 py-0.5 text-zinc-500 hover:bg-zinc-100 hover:text-zinc-800 disabled:cursor-not-allowed disabled:text-zinc-300"
              disabled={
                mode === "year"
                  ? yearBlockStart + 11 >= maxYear
                  : mode === "month"
                    ? view.year >= maxYear
                    : view.year > maxYear || (view.year === maxYear && view.month >= maxMonth)
              }
              onClick={() =>
                setView((v) => {
                  if (mode === "year") return { ...v, year: v.year + 12 };
                  if (mode === "month") return { ...v, year: v.year + 1 };
                  const m = v.month + 1;
                  return m > 11 ? { year: v.year + 1, month: 0 } : { year: v.year, month: m };
                })
              }
              aria-label={mode === "day" ? "Next month" : mode === "month" ? "Next year" : "Next years"}
            >
              ›
            </button>
          </div>
          {mode === "year" ? (
            <div className="grid grid-cols-3 gap-1">
              {Array.from({ length: 12 }).map((_, i) => {
                const y = yearBlockStart + i;
                const disabled = y > maxYear;
                const selected = y === parseIso(selectedIso).getFullYear();
                return (
                  <button
                    key={y}
                    type="button"
                    disabled={disabled}
                    onClick={() => {
                      setView((v) => ({ ...v, year: y }));
                      setMode("month");
                    }}
                    className={`h-9 rounded-md text-[11px] font-semibold tabular-nums transition ${
                      selected
                        ? "bg-indigo-600 text-white"
                        : disabled
                          ? "cursor-not-allowed text-zinc-300"
                          : "text-zinc-800 hover:bg-indigo-50 hover:text-indigo-900"
                    }`}
                  >
                    {y}
                  </button>
                );
              })}
            </div>
          ) : mode === "month" ? (
            <div className="grid grid-cols-3 gap-1">
              {Array.from({ length: 12 }).map((_, m) => {
                const label = new Date(view.year, m, 1).toLocaleDateString(undefined, { month: "short" });
                const disabled = view.year > maxYear || (view.year === maxYear && m > maxMonth);
                const selected = view.year === parseIso(selectedIso).getFullYear() && m === parseIso(selectedIso).getMonth();
                return (
                  <button
                    key={m}
                    type="button"
                    disabled={disabled}
                    onClick={() => {
                      setView({ year: view.year, month: m });
                      setMode("day");
                    }}
                    className={`h-9 rounded-md text-[11px] font-semibold transition ${
                      selected
                        ? "bg-indigo-600 text-white"
                        : disabled
                          ? "cursor-not-allowed text-zinc-300"
                          : "text-zinc-800 hover:bg-indigo-50 hover:text-indigo-900"
                    }`}
                  >
                    {label}
                  </button>
                );
              })}
            </div>
          ) : (
          <>
          <div className="mb-1 grid grid-cols-7 gap-0.5 text-center text-[9px] font-semibold uppercase tracking-wide text-zinc-400">
            {["Su", "Mo", "Tu", "We", "Th", "Fr", "Sa"].map((d) => (
              <span key={d}>{d}</span>
            ))}
          </div>
          <div className="grid grid-cols-7 gap-0.5">
            {cells.map((cell, idx) => {
              const selected = cell.iso === selectedIso;
              return (
                <button
                  key={`${cell.iso}-${idx}`}
                  type="button"
                  disabled={cell.disabled}
                  onClick={() => {
                    onChange(cell.iso);
                    setOpen(false);
                  }}
                  className={`h-7 rounded-md text-[11px] font-medium tabular-nums transition ${
                    selected
                      ? "bg-indigo-600 text-white"
                      : cell.disabled
                        ? "cursor-not-allowed text-zinc-300"
                        : cell.inMonth
                          ? "text-zinc-800 hover:bg-indigo-50 hover:text-indigo-900"
                          : "text-zinc-400 hover:bg-zinc-50"
                  }`}
                >
                  {cell.day}
                </button>
              );
            })}
          </div>
          </>
          )}
          <button
            type="button"
            className="mt-2 w-full rounded-md py-1 text-[11px] font-semibold text-indigo-700 hover:bg-indigo-50"
            onClick={() => {
              onChange("");
              setOpen(false);
            }}
          >
            Use today (UTC)
          </button>
        </div>
      )}
    </div>
  );
}

export type EvidencePackExportPanelProps = {
  frameworkId: string;
  frameworkLabel: string;
  periodKey: string | number;
  onPeriodChange: (key: string | number) => void;
  asOf: string;
  onAsOfChange: (value: string) => void;
  coverage?: EvidenceCoverage;
  coverageLoading?: boolean;
  controlsEvaluated: number;
  openFindings: number;
  passingCount: number;
  lastScanLabel?: string | null;
  downloading: boolean;
  onDownload: () => void;
};

export function EvidencePackExportPanel({
  frameworkId,
  frameworkLabel,
  periodKey,
  onPeriodChange,
  asOf,
  onAsOfChange,
  coverage,
  coverageLoading,
  controlsEvaluated,
  openFindings,
  passingCount,
  lastScanLabel,
  downloading,
  onDownload,
}: EvidencePackExportPanelProps) {
  const evidenceUi = frameworkEvidenceUi(frameworkId, coverage, periodKey, {
    controlsEvaluated,
    lastScanLabel,
  });
  const showPeriodControls = periodKey !== "last_scan";
  const scopeLabel = exportScopeSectionLabel(frameworkId);
  const asOfLabel = exportAsOfSectionLabel(frameworkId);
  const showType2AsOfHint = exportAsOfShowsType2Hint(frameworkId);
  const maxIso = toIsoDate(new Date());

  return (
    <div className="w-[min(100vw-2rem,34rem)]">
      <header className="pb-1">
        <h2 className="text-base font-bold tracking-tight text-zinc-950">Generate Audit Package — {frameworkLabel}</h2>
      </header>

      <section className="mt-3 rounded-xl border border-zinc-200/80 bg-zinc-50/50 p-4">
        <EvidenceCoverageSection ui={evidenceUi} loading={coverageLoading} />
      </section>

      <section className="mt-4 border-t border-zinc-100 pt-3">
        <CompactStatsRow
          items={[
            { label: "Controls", value: String(controlsEvaluated) },
            { label: "Findings", value: String(openFindings) },
            { label: "Passing", value: String(passingCount) },
          ]}
        />
      </section>

      <section className="mt-4 space-y-3">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500">{scopeLabel}</p>
          <div
            className="mt-2 grid grid-cols-5 gap-1 rounded-lg border border-zinc-200/80 bg-zinc-100/60 p-0.5"
            role="group"
            aria-label={scopeLabel}
          >
            {WINDOW_OPTIONS.map((opt) => {
              const active = periodKey === opt.value;
              return (
                <button
                  key={String(opt.value)}
                  type="button"
                  onClick={() => onPeriodChange(opt.value)}
                  className={`rounded-md px-2 py-1.5 text-center text-xs font-semibold transition ${
                    active
                      ? "bg-white text-zinc-900 shadow-sm ring-1 ring-zinc-200/80"
                      : "text-zinc-600 hover:text-zinc-900"
                  }`}
                >
                  {opt.label}
                </button>
              );
            })}
          </div>
        </div>

        {showPeriodControls && (
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
              {asOfLabel}
              {showType2AsOfHint && (
                <span className="ml-1 normal-case tracking-normal text-zinc-400">
                  · end of Type II sampling
                </span>
              )}
            </p>
            <div className="mt-2">
              <AuditAsOfPicker value={asOf} onChange={onAsOfChange} maxIso={maxIso} />
            </div>
          </div>
        )}
      </section>

      <button
        type="button"
        onClick={onDownload}
        disabled={downloading}
        className="mt-4 inline-flex h-10 w-full items-center justify-center gap-1.5 rounded-lg bg-indigo-600 px-4 text-sm font-semibold text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-50"
      >
        {downloading ? (
          <>
            <svg className="h-3.5 w-3.5 shrink-0 animate-spin" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            Generating…
          </>
        ) : (
          <>
            <svg className="h-3.5 w-3.5 shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
            </svg>
            Generate Audit Package
          </>
        )}
      </button>
    </div>
  );
}
