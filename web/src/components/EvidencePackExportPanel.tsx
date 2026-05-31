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
  { badge: string; dot: string; bar: string; headline: string; surface: string }
> = {
  ready: {
    badge: "bg-emerald-50 text-emerald-900 ring-emerald-200/80",
    dot: "bg-emerald-500",
    bar: "bg-emerald-500",
    headline: "text-emerald-900",
    surface: "from-emerald-50/80 via-white to-white",
  },
  partial: {
    badge: "bg-amber-50/90 text-amber-950 ring-amber-200/70",
    dot: "bg-amber-400",
    bar: "bg-amber-400",
    headline: "text-amber-950",
    surface: "from-amber-50/80 via-white to-white",
  },
  limited: {
    badge: "bg-zinc-100 text-zinc-800 ring-zinc-200/80",
    dot: "bg-zinc-400",
    bar: "bg-zinc-500",
    headline: "text-zinc-800",
    surface: "from-zinc-50 via-white to-white",
  },
  insufficient: {
    badge: "bg-rose-50/80 text-rose-900 ring-rose-200/60",
    dot: "bg-rose-500",
    bar: "bg-rose-400",
    headline: "text-zinc-900",
    surface: "from-rose-50/70 via-white to-white",
  },
  snapshot: {
    badge: "bg-indigo-50 text-indigo-900 ring-indigo-200/80",
    dot: "bg-indigo-500",
    bar: "bg-indigo-500",
    headline: "text-indigo-900",
    surface: "from-indigo-50/80 via-white to-white",
  },
  neutral: {
    badge: "bg-zinc-100 text-zinc-800 ring-zinc-200/80",
    dot: "bg-zinc-500",
    bar: "bg-zinc-500",
    headline: "text-zinc-900",
    surface: "from-zinc-50 via-white to-white",
  },
};

function getFrameworkExportCopy(frameworkId: string) {
  if (frameworkId === "soc2") {
    return {
      eyebrow: "SOC 2 Type II",
      subtitle: "Build a reviewer-ready package around the Type II sampling window.",
      scopeHelper: "SOC 2 Type II needs a continuous 90-day audit period. Shorter exports are useful for dry runs, but the 90-day window should be the default audit packet.",
      dateHelper: "Choose the end date for the Type II sampling window.",
      contextLabel: "90-day evidence window",
    };
  }

  if (frameworkId === "cis_aws_l1") {
    return {
      eyebrow: "CIS AWS Foundations",
      subtitle: "Package the latest benchmark posture with optional history for reviewers.",
      scopeHelper: "CIS is usually a point-in-time benchmark. Use Last scan for the cleanest packet, or add a lookback window when you want evidence history.",
      dateHelper: "Optional snapshot anchor. This is not a fixed CIS requirement.",
      contextLabel: "Benchmark snapshot",
    };
  }

  if (frameworkId === "iso27001") {
    return {
      eyebrow: "ISO 27001",
      subtitle: "Export control evidence and historical posture without forcing an audit date.",
      scopeHelper: "ISO exports can include evidence history, but there is no hard 90-day requirement here. Pick the period that matches the reviewer request.",
      dateHelper: "Optional as-of date for the evidence package.",
      contextLabel: "Evidence history",
    };
  }

  return {
    eyebrow: "Evidence export",
    subtitle: "Create an evidence package for this framework.",
    scopeHelper: "Choose the export scope that matches the review request.",
    dateHelper: "Optional as-of date for the evidence package.",
    contextLabel: "Audit package",
  };
}

function getWindowOptionMeta(frameworkId: string, value: string | number) {
  if (value === "last_scan") {
    return {
      title: "Latest posture",
      detail:
        frameworkId === "soc2"
          ? "Point-in-time dry run"
          : "Best for CIS and snapshot reviews",
      badge: frameworkId === "soc2" ? null : "Cleanest",
    };
  }

  if (frameworkId === "soc2") {
    if (value === 90) {
      return { title: "Type II window", detail: "Continuous audit period", badge: "Recommended" };
    }
    if (value === 30) return { title: "Short dry run", detail: "Not enough for Type II", badge: null };
    if (value === 180) return { title: "Extended trail", detail: "More than required", badge: null };
    return { title: "Full-year trail", detail: "Broad historical export", badge: null };
  }

  if (frameworkId === "cis_aws_l1") {
    if (value === 30) return { title: "Recent drift", detail: "Short evidence history", badge: null };
    if (value === 90) return { title: "Quarter view", detail: "Optional context", badge: null };
    if (value === 180) return { title: "Half-year view", detail: "Longer trend", badge: null };
    return { title: "Full-year view", detail: "Deep history", badge: null };
  }

  if (value === 30) return { title: "Recent evidence", detail: "Short history", badge: null };
  if (value === 90) return { title: "Quarter evidence", detail: "Common review window", badge: null };
  if (value === 180) return { title: "Half-year evidence", detail: "Expanded history", badge: null };
  return { title: "Full-year evidence", detail: "Maximum context", badge: null };
}

function EvidenceCoverageSection({
  ui,
  loading,
}: {
  ui: FrameworkEvidenceUi;
  loading?: boolean;
}) {
  const styles = readinessStyles[ui.tone];
  return (
    <section
      className={`relative overflow-hidden rounded-2xl border border-zinc-200/80 bg-gradient-to-br ${styles.surface} p-4 shadow-sm`}
      aria-label="Evidence coverage"
    >
      <div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-indigo-200/80 to-transparent" />
      <div className="flex items-start gap-3">
        <div className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-white/80 text-indigo-700 shadow-sm ring-1 ring-zinc-200/80">
          <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden>
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75 11.25 15 15 9.75M12 3.75 5.25 6v5.25c0 4.2 2.84 8.12 6.75 9.25 3.91-1.13 6.75-5.05 6.75-9.25V6L12 3.75Z" />
          </svg>
        </div>

        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span
              className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ${styles.badge}`}
            >
              <span className={`h-1.5 w-1.5 rounded-full ${styles.dot}`} aria-hidden />
              {ui.badgeLabel}
            </span>
            {loading && <span className="text-[11px] font-medium text-zinc-400">Updating…</span>}
          </div>

          {ui.headline && (
            <p className={`mt-3 text-sm font-semibold tabular-nums ${styles.headline}`}>{ui.headline}</p>
          )}

          {ui.showProgressBar && (
            <div className="mt-3 h-2 w-full overflow-hidden rounded-full bg-zinc-200/80">
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
              className="mt-3 flex items-start gap-2 rounded-xl border border-amber-200/70 bg-amber-50/90 px-3 py-2.5 text-xs font-medium leading-snug text-amber-950"
              role="note"
            >
              <span
                className="mt-px flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-amber-100 text-[10px] font-bold leading-none text-amber-800 ring-1 ring-amber-200/80"
                aria-hidden
              >
                i
              </span>
              <span>{ui.guidanceLine}</span>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

function MetricCards({
  items,
}: {
  items: { label: string; value: string }[];
}) {
  return (
    <dl className="grid grid-cols-3 gap-2">
      {items.map((item) => (
        <div
          key={item.label}
          className="rounded-xl border border-zinc-200/80 bg-white px-3 py-2.5 shadow-sm"
        >
          <dt className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400">{item.label}</dt>
          <dd className="mt-1 text-base font-bold tabular-nums text-zinc-950">{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

function PeriodWindowPicker({
  frameworkId,
  scopeLabel,
  helper,
  periodKey,
  onPeriodChange,
}: {
  frameworkId: string;
  scopeLabel: string;
  helper: string;
  periodKey: string | number;
  onPeriodChange: (key: string | number) => void;
}) {
  return (
    <div>
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500">{scopeLabel}</p>
          <p className="mt-1 text-xs leading-relaxed text-zinc-500">{helper}</p>
        </div>
      </div>

      <div
        className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-5"
        role="radiogroup"
        aria-label={scopeLabel}
      >
        {WINDOW_OPTIONS.map((opt) => {
          const active = periodKey === opt.value;
          const meta = getWindowOptionMeta(frameworkId, opt.value);
          return (
            <button
              key={String(opt.value)}
              type="button"
              onClick={() => onPeriodChange(opt.value)}
              role="radio"
              aria-checked={active}
              className={`group relative min-h-[4.75rem] rounded-xl border p-3 text-left transition ${
                active
                  ? "border-indigo-300 bg-indigo-50/80 shadow-sm ring-1 ring-indigo-200"
                  : "border-zinc-200/80 bg-white hover:border-zinc-300 hover:bg-zinc-50/80"
              }`}
            >
              <span className="flex items-start justify-between gap-2">
                <span
                  className={`text-sm font-bold tabular-nums ${
                    active ? "text-indigo-950" : "text-zinc-900"
                  }`}
                >
                  {opt.label}
                </span>
                <span
                  className={`mt-0.5 h-2 w-2 rounded-full ${
                    active ? "bg-indigo-600" : "bg-zinc-200 group-hover:bg-zinc-300"
                  }`}
                  aria-hidden
                />
              </span>
              <span
                className={`mt-1 block text-[11px] font-semibold ${
                  active ? "text-indigo-900" : "text-zinc-600"
                }`}
              >
                {meta.title}
              </span>
              <span className="mt-0.5 block text-[10px] leading-snug text-zinc-500">{meta.detail}</span>
              {meta.badge && (
                <span className="mt-2 inline-flex rounded-full bg-white/80 px-2 py-0.5 text-[9px] font-bold uppercase tracking-wide text-indigo-800 ring-1 ring-indigo-200/80">
                  {meta.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>
    </div>
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
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
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
        : `${yearBlockStart} - ${yearBlockStart + 11}`;

  return (
    <div ref={rootRef} className="relative">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="group inline-flex h-11 w-full items-center justify-between gap-3 rounded-xl border border-zinc-200/90 bg-gradient-to-b from-white to-zinc-50 px-3.5 text-left text-sm font-semibold text-zinc-900 shadow-sm transition hover:border-zinc-300 hover:shadow-md"
        aria-expanded={open}
        aria-haspopup="dialog"
      >
        <span className="flex min-w-0 items-center gap-2">
          <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-indigo-50 text-indigo-700 ring-1 ring-indigo-100">
            <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden>
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2Z" />
            </svg>
          </span>
          <span className="truncate whitespace-nowrap">
            {value.trim() ? formatDisplayDate(value) : `Today · ${formatDisplayDate(todayIso)}`}
          </span>
        </span>
        <svg
          className={`h-4 w-4 shrink-0 text-zinc-400 transition group-hover:text-zinc-600 ${open ? "rotate-180" : ""}`}
          fill="none"
          stroke="currentColor"
          strokeWidth={2}
          viewBox="0 0 24 24"
          aria-hidden
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="m6 9 6 6 6-6" />
        </svg>
      </button>
      {open && (
        <div
          role="dialog"
          aria-label="Choose as-of date"
          className="absolute right-0 z-10 mt-2 w-[18rem] rounded-2xl border border-zinc-200/90 bg-white p-3 shadow-xl shadow-zinc-950/15 ring-1 ring-zinc-950/[0.04]"
        >
          <div className="mb-3 flex items-center justify-between rounded-xl bg-zinc-50 px-1.5 py-1">
            <button
              type="button"
              className="flex h-7 w-7 items-center justify-center rounded-lg text-zinc-500 hover:bg-white hover:text-zinc-800 hover:shadow-sm"
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
              className="rounded-lg px-2.5 py-1 text-xs font-bold text-zinc-800 hover:bg-white hover:shadow-sm"
              aria-label="Switch month/year"
            >
              {headerLabel}
            </button>
            <button
              type="button"
              className="flex h-7 w-7 items-center justify-center rounded-lg text-zinc-500 hover:bg-white hover:text-zinc-800 hover:shadow-sm disabled:cursor-not-allowed disabled:text-zinc-300 disabled:hover:bg-transparent disabled:hover:shadow-none"
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
                    className={`h-9 rounded-lg text-[11px] font-semibold tabular-nums transition ${
                      selected
                        ? "bg-indigo-600 text-white shadow-sm"
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
                    className={`h-9 rounded-lg text-[11px] font-semibold transition ${
                      selected
                        ? "bg-indigo-600 text-white shadow-sm"
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
              <div className="mb-1.5 grid grid-cols-7 gap-0.5 text-center text-[9px] font-bold uppercase tracking-wide text-zinc-400">
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
                      className={`h-8 rounded-lg text-[11px] font-semibold tabular-nums transition ${
                        selected
                          ? "bg-indigo-600 text-white shadow-sm"
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
            className="mt-3 w-full rounded-xl border border-indigo-100 bg-indigo-50/80 py-2 text-[11px] font-bold text-indigo-700 transition hover:bg-indigo-100"
            onClick={() => {
              onChange("");
              setOpen(false);
            }}
          >
            Use today
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
  const copy = getFrameworkExportCopy(frameworkId);

  return (
    <div className="w-[min(100vw-2rem,38rem)]">
      <header className="rounded-2xl border border-zinc-200/80 bg-white p-4 shadow-sm">
        <div className="flex items-start gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl bg-indigo-50 text-indigo-700 ring-1 ring-indigo-100">
            <svg className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 3.75 5.25 6v5.25c0 4.2 2.84 8.12 6.75 9.25 3.91-1.13 6.75-5.05 6.75-9.25V6L12 3.75Z" />
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6M9 15h4.5M9 9h6" />
            </svg>
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-indigo-700">{copy.eyebrow}</p>
              <span className="rounded-full bg-zinc-100 px-2 py-0.5 text-[10px] font-semibold text-zinc-600 ring-1 ring-zinc-200/80">
                {copy.contextLabel}
              </span>
            </div>
            <h2 className="mt-1 text-lg font-bold tracking-tight text-zinc-950">Generate audit package</h2>
            <p className="mt-1 max-w-[30rem] text-sm leading-relaxed text-zinc-600">{copy.subtitle}</p>
          </div>
          <span className="hidden rounded-full border border-zinc-200/80 px-2.5 py-1 text-xs font-semibold text-zinc-700 sm:inline-flex">
            {frameworkLabel}
          </span>
        </div>
      </header>

      <div className="mt-3 space-y-4">
        <EvidenceCoverageSection ui={evidenceUi} loading={coverageLoading} />

        <MetricCards
          items={[
            { label: "Controls", value: String(controlsEvaluated) },
            { label: "Findings", value: String(openFindings) },
            { label: "Passing", value: String(passingCount) },
          ]}
        />

        <section className="rounded-2xl border border-zinc-200/80 bg-white p-4 shadow-sm">
          <PeriodWindowPicker
            frameworkId={frameworkId}
            scopeLabel={scopeLabel}
            helper={copy.scopeHelper}
            periodKey={periodKey}
            onPeriodChange={onPeriodChange}
          />

          {showPeriodControls && (
            <div className="mt-4 border-t border-zinc-100 pt-4">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
                {asOfLabel}
                {showType2AsOfHint && (
                  <span className="ml-1 normal-case tracking-normal text-zinc-400">
                    · end of Type II sampling
                  </span>
                )}
              </p>
              <p className="mt-1 text-xs leading-relaxed text-zinc-500">{copy.dateHelper}</p>
              <div className="mt-3">
                <AuditAsOfPicker value={asOf} onChange={onAsOfChange} maxIso={maxIso} />
              </div>
            </div>
          )}
        </section>
      </div>

      <button
        type="button"
        onClick={onDownload}
        disabled={downloading}
        className="mt-4 inline-flex h-11 w-full items-center justify-center gap-2 rounded-xl bg-indigo-600 px-4 text-sm font-bold text-white shadow-lg shadow-indigo-600/20 transition hover:bg-indigo-700 hover:shadow-indigo-600/30 disabled:cursor-not-allowed disabled:opacity-50"
      >
        {downloading ? (
          <>
            <svg className="h-3.5 w-3.5 shrink-0 animate-spin" fill="none" viewBox="0 0 24 24" aria-hidden>
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 0 1 8-8V0C5.373 0 0 5.373 0 12h4Z" />
            </svg>
            Generating…
          </>
        ) : (
          <>
            <svg className="h-3.5 w-3.5 shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden>
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 0 0 3 3h10a3 3 0 0 0 3-3v-1m-4-4-4 4m0 0-4-4m4 4V4" />
            </svg>
            Generate audit package
          </>
        )}
      </button>
    </div>
  );
}
