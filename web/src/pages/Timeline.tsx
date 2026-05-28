import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Navigate, useSearchParams } from "react-router-dom";
import { api } from "../api";
import {
  dedupeResources,
  dedupeTimelineEvents,
  eventDisplayName,
  eventVerb,
  extractRegion,
  parseActor,
  primaryResourceName,
  resourceDisplayName,
  serviceCategory,
  serviceLabel,
  truncateMiddle,
  verbStyles,
} from "../lib/timelineDisplay";

interface TimelineEvent {
  type: "cloudtrail";
  event_id: string;
  event_name: string;
  event_source: string;
  event_time: string;
  actor: string | null;
  source_ip: string | null;
  resources: { type: string | null; name: string | null }[];
}

interface Account {
  id: string;
  label: string;
  account_id: string | null;
  status: string;
}

interface TimelineMeta {
  cloudtrail_logging: boolean;
  trail_count: number;
  events_in_account: number;
  last_scan_at: string | null;
}

interface TimelineResponse {
  events: TimelineEvent[];
  total: number;
  meta?: TimelineMeta;
}

type ServiceFilter = "all" | "IAM" | "S3" | "Network" | "KMS" | "Other";

const TIMELINE_WINDOWS = [
  { value: 7, label: "Last 7 days" },
  { value: 30, label: "Last 30 days" },
  { value: 90, label: "Last 90 days" },
] as const;

const SERVICE_OPTIONS: { value: ServiceFilter; label: string }[] = [
  { value: "all", label: "All services" },
  { value: "IAM", label: "IAM" },
  { value: "S3", label: "S3" },
  { value: "Network", label: "Network" },
  { value: "KMS", label: "KMS" },
  { value: "Other", label: "Other" },
];

const selectClass =
  "h-[42px] appearance-none rounded-xl border border-zinc-200 bg-white pl-3 pr-8 text-sm font-semibold text-zinc-600 shadow-sm shadow-zinc-950/[0.03] outline-none transition hover:border-zinc-300 focus:border-indigo-300 focus:ring-2 focus:ring-indigo-500/20";

function emptyTimelineCopy(meta: TimelineMeta | undefined, days: number) {
  if (!meta?.last_scan_at) {
    return {
      title: "No events yet",
      body: "Run a scan to pull infrastructure write events from CloudTrail.",
    };
  }
  if (meta.events_in_account === 0 && !meta.cloudtrail_logging) {
    return {
      title: "CloudTrail is not logging",
      body: "Enable a multi-region trail so API changes are recorded.",
      hint: "Fix the CloudTrail finding, then re-scan.",
    };
  }
  if (meta.events_in_account === 0) {
    return {
      title: "No infrastructure changes found",
      body: "No tracked write events in the last 90 days.",
    };
  }
  return {
    title: "Nothing in this window",
    body: `No events in the last ${days} days. Try a longer window or clear filters.`,
  };
}

function fmtTimeOnly(iso: string): string {
  return new Date(iso).toLocaleString(undefined, { hour: "2-digit", minute: "2-digit" });
}

function fmtDateHeader(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    weekday: "long",
    month: "long",
    day: "numeric",
    year: "numeric",
  });
}

function dateKey(iso: string): string {
  const d = new Date(iso);
  return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
}

function serviceBadgeClass(category: ServiceFilter): string {
  switch (category) {
    case "IAM":
      return "border-amber-200 bg-amber-50 text-amber-800";
    case "S3":
      return "border-sky-200 bg-sky-50 text-sky-800";
    case "Network":
      return "border-violet-200 bg-violet-50 text-violet-800";
    case "KMS":
      return "border-indigo-200 bg-indigo-50 text-indigo-800";
    default:
      return "border-zinc-200 bg-zinc-50 text-zinc-600";
  }
}

function groupByDate(events: TimelineEvent[]): [string, TimelineEvent[]][] {
  const map = new Map<string, TimelineEvent[]>();
  for (const evt of events) {
    const key = dateKey(evt.event_time);
    if (!map.has(key)) map.set(key, []);
    map.get(key)!.push(evt);
  }
  return Array.from(map.entries());
}

function VerbIcon({ verb }: { verb: ReturnType<typeof eventVerb> }) {
  const cls = "h-3.5 w-3.5";
  if (verb === "create") {
    return (
      <svg className={cls} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 4.5v15m7.5-7.5h-15" />
      </svg>
    );
  }
  if (verb === "delete") {
    return (
      <svg className={cls} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M5 12h14" />
      </svg>
    );
  }
  if (verb === "security") {
    return (
      <svg className={cls} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m0 3.75h.008M10.29 3.86 2.82 7.13c-.96.44-1.56 1.42-1.56 2.5v5.14c0 4.66 3.84 8.52 8.52 9.46 4.68-.94 8.52-4.8 8.52-9.46V9.63c0-1.08-.6-2.06-1.56-2.5l-7.47-3.27a2.25 2.25 0 0 0-1.88 0Z" />
      </svg>
    );
  }
  return (
    <svg className={cls} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="m16.862 4.487 1.687-1.688a1.875 1.875 0 1 1 2.652 2.652L10.582 16.07a4.5 4.5 0 0 1-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 0 1 1.13-1.897l8.932-8.931Z" />
    </svg>
  );
}

function Chevron({ open }: { open: boolean }) {
  return (
    <svg
      className={`h-4 w-4 flex-shrink-0 text-zinc-400 transition-transform ${open ? "rotate-180" : ""}`}
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      viewBox="0 0 24 24"
      aria-hidden
    >
      <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
    </svg>
  );
}

function fmtEventTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      title="Copy"
      onClick={(e) => {
        e.stopPropagation();
        void navigator.clipboard.writeText(value).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        });
      }}
      className="inline-flex shrink-0 items-center self-center rounded px-1 py-0.5 text-[11px] font-normal text-zinc-500 hover:bg-zinc-100/80 hover:text-zinc-700"
    >
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

const sectionLabelClass = "mb-3 text-xs font-semibold uppercase tracking-widest text-zinc-500";
const fieldLabelClass = "text-[11px] font-semibold uppercase tracking-wide text-zinc-600";
const valueRegularClass = "mt-1 text-[13px] font-normal leading-relaxed text-zinc-800";
const valueEmphasisClass = "mt-1 text-[13px] font-semibold leading-relaxed text-zinc-900";
const valueTechnicalClass =
  "mt-1 flex min-h-[18px] items-center gap-1.5 font-mono text-xs font-normal leading-relaxed text-zinc-600";
const valueSubtextClass = "mt-0.5 text-xs font-normal leading-relaxed text-zinc-500";

function MetaSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <h4 className={sectionLabelClass}>{title}</h4>
      <dl className="space-y-3.5">{children}</dl>
    </div>
  );
}

function MetaField({
  label,
  value,
  subtext,
  emphasis,
  technical,
  fullValue,
}: {
  label: string;
  value: React.ReactNode;
  subtext?: string;
  emphasis?: boolean;
  technical?: boolean;
  fullValue?: string;
}) {
  if (value === null || value === undefined || value === "") return null;
  const copySource = fullValue || (typeof value === "string" ? value : undefined);
  const valueClass = technical ? valueTechnicalClass : emphasis ? valueEmphasisClass : valueRegularClass;

  return (
    <div>
      <dt className={fieldLabelClass}>{label}</dt>
      <dd className={valueClass}>
        <span className="min-w-0" title={fullValue || (typeof value === "string" ? value : undefined)}>
          {value}
        </span>
        {copySource && technical && <CopyButton value={copySource} />}
      </dd>
      {subtext && <p className={valueSubtextClass}>{subtext}</p>}
    </div>
  );
}

function TechnicalValue({ value, max = 48 }: { value: string; max?: number }) {
  const shown = truncateMiddle(value, max);
  return (
    <span className="break-all" title={value}>
      {shown}
    </span>
  );
}

function ExpandedEvidence({ evt }: { evt: TimelineEvent }) {
  const parsed = parseActor(evt.actor);
  const region = extractRegion(evt);
  const resources = dedupeResources(evt.resources);
  const showRole = !!parsed.role;
  const sessionIsEmail = parsed.user?.includes("@");

  return (
    <div className="border-t border-zinc-100 bg-zinc-50/40 px-4 py-3.5 sm:px-5">
      <div className="grid gap-5 lg:grid-cols-3 lg:gap-7">
        <MetaSection title="Identity">
          <MetaField label="Actor" value={parsed.label} emphasis />
          {showRole && <MetaField label="Role" value={parsed.role} />}
          {parsed.user && sessionIsEmail && parsed.user !== parsed.label && (
            <MetaField label="User" value={parsed.user} />
          )}
          {parsed.user && parsed.role && !sessionIsEmail && (
            <MetaField
              label="Session"
              value={<TechnicalValue value={parsed.user} max={40} />}
              technical
              fullValue={parsed.user}
            />
          )}
          <MetaField label="Identity type" value={parsed.origin} />
          {evt.source_ip && (
            <MetaField
              label="Source IP"
              value={<TechnicalValue value={evt.source_ip} max={36} />}
              technical
              fullValue={evt.source_ip}
            />
          )}
          {parsed.fullArn && (
            <MetaField
              label="Principal ARN"
              value={<TechnicalValue value={parsed.fullArn} max={44} />}
              technical
              fullValue={parsed.fullArn}
            />
          )}
        </MetaSection>

        <MetaSection title="Infrastructure">
          <MetaField label="AWS service" value={serviceLabel(evt.event_source)} />
          <MetaField
            label="API action"
            value={<TechnicalValue value={evt.event_name} max={32} />}
            technical
            fullValue={evt.event_name}
          />
          <MetaField label="Region" value={region || "—"} />
          <MetaField label="Event time" value={fmtEventTime(evt.event_time)} />
        </MetaSection>

        <MetaSection title="Resources">
          {resources.length === 0 ? (
            <p className={valueRegularClass}>No resources recorded</p>
          ) : (
            resources.flatMap((r, i) => {
              const name = r.name || "";
              const display = resourceDisplayName(r.name);
              const isArn = name.startsWith("arn:");
              const fields = [
                <MetaField
                  key={`res-${i}`}
                  label={resources.length > 1 ? `Resource ${i + 1}` : "Affected resource"}
                  value={display}
                  emphasis
                  subtext={r.type || undefined}
                />,
              ];
              if (isArn && name !== display) {
                fields.push(
                  <MetaField
                    key={`arn-${i}`}
                    label="Resource ARN"
                    value={<TechnicalValue value={name} max={44} />}
                    technical
                    fullValue={name}
                  />,
                );
              }
              return fields;
            })
          )}
        </MetaSection>
      </div>
    </div>
  );
}

function EventRow({ evt, isLast }: { evt: TimelineEvent; isLast: boolean }) {
  const [open, setOpen] = useState(false);
  const category = serviceCategory(evt.event_source, evt.event_name) as ServiceFilter;
  const verb = eventVerb(evt.event_name);
  const styles = verbStyles(verb);
  const parsed = parseActor(evt.actor);
  const actor = parsed.label;
  const resource = primaryResourceName(evt);
  const title = eventDisplayName(evt.event_name, evt.event_source);

  return (
    <div className="flex gap-2 sm:gap-2.5">
      <div className="flex w-7 shrink-0 flex-col items-center pt-3.5">
        <span
          className={`flex h-7 w-7 items-center justify-center rounded-lg ring-1 ring-inset ${styles.iconBg} ${styles.iconColor} ring-black/5`}
        >
          <VerbIcon verb={verb} />
        </span>
        {!isLast && <div className="mt-1 w-px flex-1 bg-zinc-200" />}
      </div>

      <div className="mb-2 min-w-0 flex-1 rounded-xl border border-zinc-200 bg-white shadow-sm shadow-zinc-950/[0.03] transition hover:border-zinc-300 hover:shadow-md">
        <button
          type="button"
          className="flex w-full items-center gap-4 px-4 py-3.5 text-left sm:px-5"
          onClick={() => setOpen(!open)}
        >
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-semibold text-zinc-900">{title}</span>
              <span
                className={`inline-flex rounded-md border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide ${serviceBadgeClass(category)}`}
              >
                {category}
              </span>
            </div>
            <p className="mt-1 truncate text-xs text-zinc-500">
              {[actor, resource].filter(Boolean).join(" · ") || "—"}
            </p>
          </div>

          <p className="hidden shrink-0 text-sm font-medium tabular-nums text-zinc-700 sm:block">
            {fmtTimeOnly(evt.event_time)}
          </p>

          <Chevron open={open} />
        </button>

        <div className="px-4 pb-3 sm:hidden">
          <p className="text-xs tabular-nums text-zinc-500">{fmtTimeOnly(evt.event_time)}</p>
        </div>

        {open && <ExpandedEvidence evt={evt} />}
      </div>
    </div>
  );
}

export default function Timeline() {
  const [params] = useSearchParams();
  if (params.get("view") === "compliance") {
    return <Navigate to="/controls" replace />;
  }

  const [days, setDays] = useState(30);
  const [serviceFilter, setServiceFilter] = useState<ServiceFilter>("all");
  const [accountId, setAccountId] = useState<string>("");

  const { data: accounts } = useQuery<Account[]>({
    queryKey: ["accounts"],
    queryFn: () => api("/v1/accounts"),
  });

  const connected = (accounts || []).filter((a) => a.status === "connected");
  const effectiveAccountId = accountId || connected[0]?.id || "";

  const { data, isLoading, error } = useQuery<TimelineResponse>({
    queryKey: ["timeline", effectiveAccountId, days],
    queryFn: () => api(`/v1/accounts/${effectiveAccountId}/timeline?days=${days}&limit=200`),
    enabled: !!effectiveAccountId,
  });

  const filteredEvents = useMemo(() => {
    if (!data?.events) return [];
    const byService = data.events.filter((evt) => {
      const cat = serviceCategory(evt.event_source, evt.event_name);
      return serviceFilter === "all" || cat === serviceFilter;
    });
    return dedupeTimelineEvents(byService);
  }, [data?.events, serviceFilter]);

  const grouped = useMemo(() => groupByDate(filteredEvents), [filteredEvents]);

  return (
    <div className="w-full pl-2 pr-4 py-6 sm:pl-3 sm:pr-6">
      <div className="mb-7 flex items-start justify-between gap-6">
        <div className="min-w-0">
          <h1 className="text-2xl font-bold tracking-tight text-zinc-950">Timeline</h1>
          <p className="mt-1 text-sm text-zinc-500">CloudTrail infrastructure changes from your last scan.</p>
        </div>
      </div>

      <div className="mb-5 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex flex-wrap items-center gap-2">
          {connected.length > 1 && (
            <select
              value={effectiveAccountId}
              onChange={(e) => setAccountId(e.target.value)}
              aria-label="AWS account"
              className={selectClass}
            >
              {connected.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.label}
                </option>
              ))}
            </select>
          )}

          <select
            value={days}
            onChange={(e) => setDays(Number(e.target.value))}
            aria-label="Timeline window"
            className={selectClass}
          >
            {TIMELINE_WINDOWS.map((w) => (
              <option key={w.value} value={w.value}>
                {w.label}
              </option>
            ))}
          </select>

          <select
            value={serviceFilter}
            onChange={(e) => setServiceFilter(e.target.value as ServiceFilter)}
            aria-label="Service filter"
            className={selectClass}
          >
            {SERVICE_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </div>

        {data && (
          <span className="text-sm tabular-nums text-zinc-500">
            {filteredEvents.length} event{filteredEvents.length !== 1 ? "s" : ""}
          </span>
        )}
      </div>

      {!effectiveAccountId && (
        <div className="rounded-2xl border border-zinc-200 bg-white px-4 py-16 text-center text-sm text-zinc-500">
          Connect an AWS account to view activity.
        </div>
      )}

      {isLoading && (
        <div className="space-y-2.5 pl-6">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-[72px] animate-pulse rounded-xl bg-zinc-100" />
          ))}
        </div>
      )}

      {error && (
        <div className="rounded-xl border border-red-200 bg-red-50 px-5 py-4 text-sm text-red-700">{String(error)}</div>
      )}

      {data && filteredEvents.length === 0 && (
        (() => {
          const copy = emptyTimelineCopy(data.meta, days);
          return (
            <div className="rounded-2xl border border-zinc-200 bg-white px-6 py-12 text-center">
              <p className="text-base font-semibold text-zinc-800">{copy.title}</p>
              <p className="mt-2 text-sm text-zinc-500">{copy.body}</p>
              {copy.hint && <p className="mt-2 text-xs text-zinc-400">{copy.hint}</p>}
            </div>
          );
        })()
      )}

      {filteredEvents.length > 0 && (
        <div className="space-y-8 pb-8">
          {grouped.map(([key, events]) => (
            <section key={key}>
              <h2 className="mb-3 text-xs font-semibold uppercase tracking-wider text-zinc-400">
                {fmtDateHeader(events[0].event_time)}
              </h2>
              <div className="space-y-2">
                {events.map((evt, idx) => (
                  <EventRow key={evt.event_id} evt={evt} isLast={idx === events.length - 1} />
                ))}
              </div>
            </section>
          ))}
        </div>
      )}
    </div>
  );
}
