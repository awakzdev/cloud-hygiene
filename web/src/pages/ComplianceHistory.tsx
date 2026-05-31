import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Navigate } from "react-router-dom";

import { api } from "../api";
import { HistoryDashboard } from "../components/HistoryDashboard";
import { HistorySnapshotDrawer } from "../components/HistorySnapshotDrawer";
import { HistoryPeriodSummary } from "../components/HistoryPeriodSummary";
import {
  type ComplianceHistoryResponse,
  type HistoryEvent,
  scanShortDate,
} from "../lib/complianceHistory";
import { ImpactList } from "../components/ImpactList";
import {
  causeSentence,
  eventPresentation,
  eventTypeLabel,
  impactItems,
} from "../lib/historyPresentation";

interface Account {
  id: string;
  label: string;
  account_id: string | null;
  status: string;
}

const FRAMEWORKS = [
  { value: "soc2", label: "SOC 2" },
  { value: "cis_aws_l1", label: "CIS AWS L1" },
  { value: "iso27001", label: "ISO 27001" },
] as const;

const PERIOD_OPTIONS = [
  { value: 30, label: "30d" },
  { value: 90, label: "90d" },
  { value: 180, label: "180d" },
] as const;

function HeroDelta({ before, after }: { before: number | null; after: number | null }) {
  if (after == null) return null;
  if (before == null || before === after) {
    return <span className="text-3xl font-bold tabular-nums tracking-tight text-zinc-950">{after}%</span>;
  }
  const down = after < before;
  const pts = after - before;
  return (
    <span className="flex flex-wrap items-baseline gap-x-2.5 gap-y-1">
      <span className="flex items-baseline gap-2 text-3xl font-bold tabular-nums tracking-tight">
        <span className="text-zinc-300">{before}%</span>
        <span className="text-xl font-normal text-zinc-300">→</span>
        <span className={down ? "text-rose-700" : "text-emerald-700"}>{after}%</span>
      </span>
      <span
        className={`rounded-md px-1.5 py-0.5 text-xs font-bold tabular-nums ${
          down ? "bg-rose-50 text-rose-700" : "bg-emerald-50 text-emerald-700"
        }`}
      >
        {pts > 0 ? "+" : "−"}
        {Math.abs(pts)} pts
      </span>
    </span>
  );
}

function TimelineEventCard({
  event,
  hasPrevious,
  onViewEvidence,
  onCompare,
  onInfrastructure,
}: {
  event: HistoryEvent;
  hasPrevious: boolean;
  onViewEvidence: () => void;
  onCompare: () => void;
  onInfrastructure: () => void;
}) {
  const pres = eventPresentation(event);
  const cause = causeSentence(event);
  const impacts = impactItems(event);
  const isBaseline = event.type === "baseline_established";

  return (
    <article className="relative pl-7">
      <span
        className={`absolute left-0 top-2 h-3 w-3 rounded-full ring-4 ring-white ${pres.dotClass}`}
        aria-hidden
      />

      <div className="flex items-center gap-2 text-[13px] text-zinc-500">
        <time className="font-medium text-zinc-700">{scanShortDate(event.timestamp)}</time>
        <span className="text-zinc-300">·</span>
        <span className="font-medium">{eventTypeLabel(event.type)}</span>
      </div>

      {isBaseline ? (
        <h3 className="mt-1.5 text-xl font-semibold tracking-tight text-zinc-950">{pres.headline}</h3>
      ) : (
        <div className="mt-1.5">
          <HeroDelta before={event.posture_before} after={event.posture_after} />
        </div>
      )}

      {cause && !isBaseline && (
        <p className="mt-2 text-base text-zinc-900">
          <span className="font-semibold">{cause.control}</span>{" "}
          <span className={cause.tone === "bad" ? "text-rose-600" : cause.tone === "good" ? "text-emerald-600" : "text-zinc-500"}>
            {cause.text}
          </span>
        </p>
      )}

      {impacts.length > 0 && (
        <div className="mt-3">
          <ImpactList items={impacts} size="sm" />
        </div>
      )}

      <div className="mt-3.5 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-sm">
        <button
          type="button"
          onClick={onViewEvidence}
          className="font-medium text-indigo-700 hover:text-indigo-900"
        >
          View evidence
        </button>
        {hasPrevious && !isBaseline && (
          <button
            type="button"
            onClick={onCompare}
            className="font-medium text-zinc-500 hover:text-zinc-900"
          >
            Compare
          </button>
        )}
        {(event.infrastructure_events_count ?? 0) > 0 && (
          <button
            type="button"
            onClick={onInfrastructure}
            className="font-medium text-zinc-500 hover:text-zinc-900"
          >
            {event.infrastructure_events_count} infrastructure event
            {event.infrastructure_events_count === 1 ? "" : "s"}
          </button>
        )}
      </div>
    </article>
  );
}

export default function ComplianceHistory() {
  const [days, setDays] = useState(90);
  const [framework, setFramework] = useState("soc2");
  const [accountId, setAccountId] = useState("");
  const [showTimeline, setShowTimeline] = useState(false);
  const [drawer, setDrawer] = useState<{
    event: HistoryEvent;
    tab: "snapshot" | "compare";
    previous: HistoryEvent | null;
    expandInfrastructure: boolean;
  } | null>(null);

  const { data: accounts } = useQuery({
    queryKey: ["accounts"],
    queryFn: () => api<Account[]>("/v1/accounts"),
  });

  const connected = accounts?.filter((a) => a.status === "connected") ?? [];
  const effectiveAccountId = accountId || connected[0]?.id || "";

  const { data, isLoading, error } = useQuery<ComplianceHistoryResponse>({
    queryKey: ["history", effectiveAccountId, framework, days],
    queryFn: () =>
      api(
        `/v1/accounts/${effectiveAccountId}/compliance-timeline?framework=${framework}&days=${days}&limit=40`,
      ),
    enabled: !!effectiveAccountId,
  });

  const events = data?.events ?? [];

  const previousByScanId = useMemo(() => {
    const map = new Map<string, HistoryEvent | null>();
    for (let i = 0; i < events.length; i++) {
      map.set(events[i].scan_run_id, i + 1 < events.length ? events[i + 1] : null);
    }
    return map;
  }, [events]);

  if (accounts && connected.length === 0) {
    return <Navigate to="/accounts" replace />;
  }

  return (
    <div className={`w-full ${drawer ? "xl:pr-[26rem]" : ""}`}>
      <header className="mb-6 flex flex-wrap items-end justify-between gap-4 border-b border-zinc-200/80 pb-4">
        <div className="min-w-0">
          <h1 className="text-2xl font-bold tracking-tight text-zinc-950">History</h1>
          <p className="mt-1 text-sm text-zinc-600">
            Compliance dashboard — posture trend, control status, and audit timeline.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <select
            value={effectiveAccountId}
            onChange={(e) => setAccountId(e.target.value)}
            className="h-9 appearance-none rounded-lg border border-zinc-200/90 bg-white px-3 text-xs font-semibold text-zinc-700 shadow-sm"
            aria-label="Account"
          >
            {connected.map((a) => (
              <option key={a.id} value={a.id}>
                {a.label}
              </option>
            ))}
          </select>
          <div
            className="inline-flex rounded-lg border border-zinc-200/80 bg-zinc-100/60 p-0.5"
            role="group"
            aria-label="Framework"
          >
            {FRAMEWORKS.map((f) => (
              <button
                key={f.value}
                type="button"
                onClick={() => setFramework(f.value)}
                className={`rounded-md px-2.5 py-1.5 text-xs font-semibold transition ${
                  framework === f.value
                    ? "bg-white text-zinc-900 shadow-sm"
                    : "text-zinc-600 hover:text-zinc-900"
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>
          <div
            className="inline-flex rounded-lg border border-zinc-200/80 bg-zinc-100/60 p-0.5"
            role="group"
            aria-label="Period"
          >
            {PERIOD_OPTIONS.map((p) => (
              <button
                key={p.value}
                type="button"
                onClick={() => setDays(p.value)}
                className={`rounded-md px-2.5 py-1.5 text-xs font-semibold transition ${
                  days === p.value
                    ? "bg-white text-zinc-900 shadow-sm"
                    : "text-zinc-600 hover:text-zinc-900"
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>
        </div>
      </header>

      {isLoading && <p className="text-sm text-zinc-500">Loading compliance dashboard…</p>}
      {error && <p className="text-sm text-red-600">Could not load timeline.</p>}

      {!isLoading && !error && data && (
        <HistoryDashboard
          events={events}
          days={days}
          currentScore={data.current_posture_score}
          currentSummary={data.current_summary}
          periodSummary={data.period_summary}
          scanCount={data.scan_count}
          scanCadence={data.scan_cadence}
          onSelectSnapshot={(scanRunId) => {
            const evt = events.find((e) => e.scan_run_id === scanRunId);
            if (!evt) return;
            setDrawer({
              event: evt,
              tab: "snapshot",
              previous: previousByScanId.get(scanRunId) ?? null,
              expandInfrastructure: false,
            });
          }}
        />
      )}

      {!isLoading && !error && events.length === 0 && (data?.scan_count ?? 0) === 0 && (
        <p className="mt-6 rounded-xl border border-dashed border-zinc-300 bg-white px-4 py-12 text-sm text-zinc-500">
          No scans in this window. Run a scan after connecting your account to populate the dashboard.
        </p>
      )}

      {!isLoading && events.length > 0 && (
        <section className="mt-6 w-full rounded-lg border border-zinc-200 bg-white">
          <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3.5">
            <div className="min-w-0">
              <h2 className="text-sm font-bold text-zinc-900">Audit timeline</h2>
              <HistoryPeriodSummary summary={data?.period_summary} />
            </div>
            <button
              type="button"
              onClick={() => setShowTimeline((v) => !v)}
              className="rounded-md border border-zinc-200 bg-zinc-50 px-3 py-1.5 text-xs font-semibold text-zinc-700 hover:bg-zinc-100"
            >
              {showTimeline ? "Hide timeline" : `Show ${events.length} snapshot${events.length === 1 ? "" : "s"}`}
            </button>
          </div>
          {showTimeline ? (
            <div className="relative mx-4 min-w-0 space-y-8 border-t border-zinc-100 py-5 before:absolute before:left-[5px] before:top-7 before:bottom-8 before:w-px before:bg-zinc-200">
              {events.map((evt) => (
                <TimelineEventCard
                  key={evt.scan_run_id}
                  event={evt}
                  hasPrevious={!!previousByScanId.get(evt.scan_run_id)}
                  onViewEvidence={() =>
                    setDrawer({
                      event: evt,
                      tab: "snapshot",
                      previous: previousByScanId.get(evt.scan_run_id) ?? null,
                      expandInfrastructure: false,
                    })
                  }
                  onCompare={() =>
                    setDrawer({
                      event: evt,
                      tab: "compare",
                      previous: previousByScanId.get(evt.scan_run_id) ?? null,
                      expandInfrastructure: false,
                    })
                  }
                  onInfrastructure={() =>
                    setDrawer({
                      event: evt,
                      tab: "snapshot",
                      previous: previousByScanId.get(evt.scan_run_id) ?? null,
                      expandInfrastructure: true,
                    })
                  }
                />
              ))}
            </div>
          ) : (
            <div className="border-t border-zinc-100 px-4 py-3 text-sm text-zinc-500">
              Latest snapshot: {scanShortDate(events[0].timestamp)} · {eventTypeLabel(events[0].type)}
            </div>
          )}
        </section>
      )}

      {drawer && (
        <HistorySnapshotDrawer
          event={drawer.event}
          previousEvent={drawer.previous}
          accountId={effectiveAccountId}
          periodDays={days}
          initialTab={drawer.tab}
          expandInfrastructure={drawer.expandInfrastructure}
          onClose={() => setDrawer(null)}
        />
      )}
    </div>
  );
}
