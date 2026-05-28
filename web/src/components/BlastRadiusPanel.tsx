import { useState, type ReactNode } from "react";
import {
  bucketServicesByUsage,
  formatServiceLastUsed,
  type BlastRadiusService,
} from "../lib/blastRadiusDisplay";
import { ServiceAccessExplorer, type ExplorerBucket } from "./ServiceAccessExplorer";

const PREVIEW_LIMIT = 5;

type AttachedPolicy = {
  policy_arn: string;
  policy_name: string;
  policy_type: "aws_managed" | "customer_managed";
  granted_services: string[];
  unused_services: string[];
  active_services: string[];
  has_wildcard_action: boolean;
  action: "detach_and_replace" | "edit";
};

function Chevron({ open }: { open: boolean }) {
  return (
    <svg
      className={`h-3.5 w-3.5 shrink-0 text-zinc-400 transition-transform ${open ? "rotate-180" : ""}`}
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      viewBox="0 0 24 24"
    >
      <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
    </svg>
  );
}

export function BlastRadiusCollapsible({
  title,
  subtitle,
  defaultOpen = true,
  badge,
  children,
}: {
  title: string;
  subtitle?: string;
  defaultOpen?: boolean;
  badge?: ReactNode;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="rounded-lg border border-zinc-200/90 bg-zinc-50/40 overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-2 px-3 py-2.5 text-left hover:bg-zinc-50/80 transition-colors"
      >
        <Chevron open={open} />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="text-[13px] font-semibold text-zinc-800">{title}</span>
            {badge}
          </div>
          {subtitle && <p className="mt-0.5 text-[11px] text-zinc-500">{subtitle}</p>}
        </div>
      </button>
      {open && <div className="border-t border-zinc-100 px-3 pb-3 pt-2">{children}</div>}
    </div>
  );
}

/** Advisory notes — visually distinct from usage decision accordions below */
export function BlastRadiusConsiderations({
  items,
  tone = "warning",
}: {
  items: string[];
  tone?: "warning" | "info";
}) {
  const [open, setOpen] = useState(items.length <= 3);
  if (items.length === 0) return null;

  const shell =
    tone === "warning"
      ? "border-amber-300/70 bg-gradient-to-br from-amber-50/90 via-amber-50/40 to-white"
      : "border-zinc-300/60 bg-gradient-to-br from-zinc-50 to-white";
  const titleClass = tone === "warning" ? "text-amber-950" : "text-zinc-800";
  const subClass = tone === "warning" ? "text-amber-900/75" : "text-zinc-500";
  const badgeClass =
    tone === "warning" ? "bg-amber-200/70 text-amber-950" : "bg-zinc-200/80 text-zinc-700";
  const listBorder = tone === "warning" ? "border-amber-200/50" : "border-zinc-200/80";

  return (
    <div className={`rounded-lg border border-dashed ${shell} overflow-hidden`}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-start gap-3 px-4 py-3 pr-5 text-left transition-colors hover:bg-white/40"
      >
        <span
          className={`mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full ${
            tone === "warning" ? "bg-amber-100 text-amber-700" : "bg-zinc-100 text-zinc-500"
          }`}
        >
          <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden>
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="m11.25 11.25.041-.02a.75.75 0 0 1 1.063.852l-.708 2.836a.75.75 0 0 0 1.063.853l.041-.021M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-9-3.75h.008v.008H12V8.25Z"
            />
          </svg>
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className={`text-[13px] font-semibold ${titleClass}`}>Before you change this</span>
            <span className={`rounded-full px-2 py-0.5 text-[10px] font-semibold tabular-nums ${badgeClass}`}>
              {items.length} note{items.length !== 1 ? "s" : ""}
            </span>
          </div>
          <p className={`mt-0.5 text-[11px] leading-snug ${subClass}`}>
            Policy and scope warnings — not the same as service usage groups below
          </p>
        </div>
        <Chevron open={open} />
      </button>
      {open && (
        <ul className={`space-y-2 border-t px-4 pb-3.5 pt-2.5 pr-5 ${listBorder}`}>
          {items.map((text, i) => (
            <li key={i} className={`flex gap-2.5 text-[12px] leading-relaxed ${tone === "warning" ? "text-amber-950/90" : "text-zinc-600"}`}>
              <span className={`mt-1.5 h-1 w-1 shrink-0 rounded-full ${tone === "warning" ? "bg-amber-400" : "bg-zinc-400"}`} />
              <span>{text}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function ServiceUsageRow({ service, emphasis }: { service: BlastRadiusService; emphasis: "high" | "low" | "muted" }) {
  const dot =
    emphasis === "high" ? "bg-amber-500" : emphasis === "low" ? "bg-zinc-400" : "bg-zinc-300";
  const nameClass =
    emphasis === "high" ? "font-medium text-zinc-800" : emphasis === "low" ? "text-zinc-700" : "text-zinc-500";

  return (
    <div className="flex items-center justify-between gap-3 border-b border-zinc-100/80 px-3 py-1.5 pr-4 last:border-0">
      <div className="flex min-w-0 items-center gap-2">
        <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${dot}`} />
        <span className={`truncate font-mono text-[12px] ${nameClass}`}>{service.name}</span>
      </div>
      <span className="shrink-0 pl-2 text-[11px] tabular-nums text-zinc-500">
        {formatServiceLastUsed(service.days_ago)}
      </span>
    </div>
  );
}

function UsageMetricsRow({
  granted,
  recent,
  historical,
  safe,
}: {
  granted: number;
  recent: number;
  historical: number;
  safe: number;
}) {
  return (
    <div className="grid grid-cols-4 gap-px overflow-hidden rounded-lg border border-zinc-200/80 bg-zinc-200/80">
      {[
        { label: "Granted", value: granted, valueClass: "text-zinc-900" },
        { label: "Recent", value: recent, valueClass: "text-amber-700" },
        { label: "Historical", value: historical, valueClass: "text-zinc-800" },
        { label: "Likely safe", value: safe, valueClass: "text-emerald-700" },
      ].map((m) => (
        <div key={m.label} className="bg-white px-2 py-2.5 text-center">
          <div className={`text-base font-semibold tabular-nums leading-none ${m.valueClass}`}>{m.value}</div>
          <div className="mt-1 text-[10px] font-medium text-zinc-500">{m.label}</div>
        </div>
      ))}
    </div>
  );
}

type DecisionTone = "danger" | "caution" | "safe";

const DECISION_TONE: Record<
  DecisionTone,
  {
    shell: string;
    header: string;
    headerHover: string;
    badge: string;
    tag: string;
    tagText: string;
    divider: string;
    list: string;
    moreText: string;
  }
> = {
  danger: {
    shell: "border-amber-200/80 shadow-sm shadow-amber-900/[0.04]",
    header: "bg-gradient-to-r from-amber-50/95 to-amber-50/40",
    headerHover: "hover:from-amber-50 hover:to-amber-50/60",
    badge: "bg-amber-200/60 text-amber-950",
    tag: "bg-amber-100 text-amber-900 ring-amber-200/80",
    tagText: "High impact",
    divider: "border-amber-100/80",
    list: "bg-white",
    moreText: "text-amber-900/60",
  },
  caution: {
    shell: "border-zinc-200/90 shadow-sm shadow-zinc-900/[0.03]",
    header: "bg-gradient-to-r from-zinc-50 to-white",
    headerHover: "hover:from-zinc-100/80 hover:to-zinc-50",
    badge: "bg-zinc-200/70 text-zinc-800",
    tag: "bg-zinc-100 text-zinc-700 ring-zinc-200/80",
    tagText: "Verify first",
    divider: "border-zinc-100",
    list: "bg-white",
    moreText: "text-zinc-500",
  },
  safe: {
    shell: "border-emerald-200/70 shadow-sm shadow-emerald-900/[0.04]",
    header: "bg-gradient-to-r from-emerald-50/90 to-emerald-50/30",
    headerHover: "hover:from-emerald-50 hover:to-emerald-50/50",
    badge: "bg-emerald-200/50 text-emerald-950",
    tag: "bg-emerald-100 text-emerald-900 ring-emerald-200/70",
    tagText: "Cleanup",
    divider: "border-emerald-100/70",
    list: "bg-white",
    moreText: "text-emerald-800/55",
  },
};

function DecisionSection({
  label,
  description,
  services,
  emphasis,
  defaultOpen,
  tone,
}: {
  label: string;
  description: string;
  services: BlastRadiusService[];
  emphasis: "high" | "low" | "muted";
  defaultOpen: boolean;
  tone: DecisionTone;
}) {
  const [open, setOpen] = useState(defaultOpen);
  if (services.length === 0) return null;

  const t = DECISION_TONE[tone];
  const preview = services.slice(0, PREVIEW_LIMIT);
  const hidden = services.length - preview.length;

  return (
    <div className={`overflow-hidden rounded-xl border bg-white ${t.shell}`}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className={`flex w-full items-start gap-3 px-4 py-3 pr-5 text-left transition-colors ${t.header} ${t.headerHover}`}
      >
        <span
          className={`mt-0.5 shrink-0 rounded-md px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ring-1 ring-inset ${t.tag}`}
        >
          {t.tagText}
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center justify-between gap-3">
            <span className="text-[13px] font-semibold text-zinc-900">{label}</span>
            <span className={`shrink-0 rounded-full px-2 py-0.5 text-[11px] font-semibold tabular-nums ${t.badge}`}>
              {services.length}
            </span>
          </div>
          <p className="mt-1 pr-1 text-[11px] leading-snug text-zinc-600">{description}</p>
        </div>
        <span className="mt-1 shrink-0">
          <Chevron open={open} />
        </span>
      </button>
      {open && (
        <div className={`border-t ${t.divider} ${t.list}`}>
          {preview.map((s) => (
            <ServiceUsageRow key={s.name} service={s} emphasis={emphasis} />
          ))}
          {hidden > 0 && (
            <p className={`px-4 py-2 pr-5 text-[11px] font-medium ${t.moreText}`}>+{hidden} more in this group</p>
          )}
        </div>
      )}
    </div>
  );
}

export function RoleServiceUsageAnalysis({
  services,
  activeCount,
  unusedCount,
}: {
  services: BlastRadiusService[];
  activeCount?: number;
  unusedCount?: number;
}) {
  const { recentlyActive, historicallyUsed, likelySafe } = bucketServicesByUsage(services);
  const [explorerOpen, setExplorerOpen] = useState(false);
  const [explorerBucket, setExplorerBucket] = useState<ExplorerBucket>("all");

  return (
    <>
      <div className="space-y-2.5">
        <UsageMetricsRow
          granted={services.length}
          recent={recentlyActive.length}
          historical={historicallyUsed.length}
          safe={likelySafe.length}
        />
        {activeCount != null && unusedCount != null && (
          <p className="text-center text-[10px] text-zinc-400">
            Scan snapshot · {activeCount} active · {unusedCount} unused
          </p>
        )}

        <div className="space-y-2">
          <p className="px-0.5 text-[10px] font-semibold uppercase tracking-wider text-zinc-400">
            Service usage
          </p>
          <DecisionSection
            label="Recently active"
            description="Dangerous to remove — used in the last 30 days"
            services={recentlyActive}
            emphasis="high"
            defaultOpen
            tone="danger"
          />
          <DecisionSection
            label="Historically used"
            description="Verify before removing — used 31–90 days ago"
            services={historicallyUsed}
            emphasis="low"
            defaultOpen={historicallyUsed.length <= 6}
            tone="caution"
          />
          <DecisionSection
            label="Likely safe to remove"
            description="No recorded use in 90+ days — best cleanup candidates"
            services={likelySafe}
            emphasis="muted"
            defaultOpen={likelySafe.length <= 8}
            tone="safe"
          />
        </div>

        <div className="flex justify-end pt-0.5">
          <button
            type="button"
            onClick={() => {
              setExplorerBucket("all");
              setExplorerOpen(true);
            }}
            className="rounded-lg border border-zinc-200/90 bg-white px-3 py-1.5 text-[11px] font-medium text-zinc-600 shadow-sm transition-colors hover:border-zinc-300 hover:bg-zinc-50 hover:text-zinc-800"
          >
            Browse all services
          </button>
        </div>
      </div>

      <ServiceAccessExplorer
        open={explorerOpen}
        onClose={() => setExplorerOpen(false)}
        services={services}
        initialBucket={explorerBucket}
        title="Service access explorer"
      />
    </>
  );
}

function CompactServiceList({ names, tone }: { names: string[]; tone: "remove" | "keep" | "neutral" }) {
  const [expanded, setExpanded] = useState(false);
  const limit = 8;
  const visible = expanded ? names : names.slice(0, limit);
  const hidden = names.length - visible.length;

  if (names.length === 0) {
    return <span className="text-[11px] text-zinc-400">—</span>;
  }

  const chipClass =
    tone === "keep"
      ? "bg-zinc-100 text-zinc-600"
      : tone === "remove"
        ? "bg-zinc-100/80 text-zinc-500"
        : "bg-white text-zinc-600 ring-1 ring-zinc-200/60";

  return (
    <div>
      <div className="flex flex-wrap gap-1">
        {visible.map((n) => (
          <span key={n} className={`rounded px-1.5 py-0.5 font-mono text-[10px] ${chipClass}`}>
            {n}
          </span>
        ))}
      </div>
      {hidden > 0 && (
        <button
          type="button"
          onClick={() => setExpanded(true)}
          className="mt-1 text-[10px] font-medium text-indigo-600 hover:text-indigo-800"
        >
          +{hidden} more
        </button>
      )}
      {expanded && names.length > limit && (
        <button
          type="button"
          onClick={() => setExpanded(false)}
          className="mt-1 text-[10px] font-medium text-zinc-500 hover:text-zinc-700"
        >
          Show less
        </button>
      )}
    </div>
  );
}

export function RolePoliciesAnalysis({
  policies,
  renderConsoleLink,
}: {
  policies: AttachedPolicy[];
  renderConsoleLink: (pol: AttachedPolicy) => ReactNode;
}) {
  const [expandedPolicies, setExpandedPolicies] = useState<Record<string, boolean>>({});

  const togglePolicy = (arn: string) => {
    setExpandedPolicies((prev) => ({ ...prev, [arn]: !prev[arn] }));
  };

  return (
    <BlastRadiusCollapsible
      title="Policy breakdown"
      subtitle={`${policies.length} attached polic${policies.length === 1 ? "y" : "ies"}`}
      defaultOpen={policies.length <= 2}
    >
      <div className="space-y-1.5">
        {policies.map((pol) => {
          const open = expandedPolicies[pol.policy_arn] ?? policies.length === 1;
          const removable = pol.unused_services.length;
          const active = pol.active_services.length;
          return (
            <div key={pol.policy_arn} className="rounded-md border border-zinc-200/80 bg-white overflow-hidden">
              <button
                type="button"
                onClick={() => togglePolicy(pol.policy_arn)}
                className="flex w-full items-center gap-2 px-2.5 py-2 text-left hover:bg-zinc-50/50"
              >
                <Chevron open={open} />
                <span className="min-w-0 flex-1 truncate font-mono text-[11px] font-medium text-zinc-800">
                  {pol.policy_name}
                </span>
                <span
                  className={`shrink-0 rounded px-1 py-0.5 text-[9px] font-semibold uppercase ${
                    pol.policy_type === "aws_managed"
                      ? "bg-blue-50 text-blue-700"
                      : "bg-violet-50 text-violet-700"
                  }`}
                >
                  {pol.policy_type === "aws_managed" ? "AWS" : "Custom"}
                </span>
                {removable > 0 && (
                  <span className="shrink-0 text-[10px] tabular-nums text-zinc-500">{removable} removable</span>
                )}
                {pol.has_wildcard_action && (
                  <span className="shrink-0 text-[9px] font-medium text-amber-700">wildcard</span>
                )}
              </button>
              {open && (
                <div className="border-t border-zinc-100 px-2.5 py-2 space-y-2">
                  <div className="flex justify-end">{renderConsoleLink(pol)}</div>
                  {active > 0 && (
                    <div>
                      <p className="mb-1 text-[10px] font-medium uppercase tracking-wide text-zinc-500">
                        Keep — recently used ({active})
                      </p>
                      <CompactServiceList names={pol.active_services} tone="keep" />
                    </div>
                  )}
                  {removable > 0 && (
                    <div>
                      <p className="mb-1 text-[10px] font-medium uppercase tracking-wide text-zinc-500">
                        Removable ({removable})
                      </p>
                      <CompactServiceList names={pol.unused_services} tone="remove" />
                    </div>
                  )}
                  {active === 0 && removable === 0 && pol.granted_services.length > 0 && (
                    <p className="text-[11px] text-zinc-400">No usage data yet — run another scan.</p>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </BlastRadiusCollapsible>
  );
}

export function RoleTrustPrincipals({ principals }: { principals: string[] }) {
  if (principals.length === 0) return null;
  return (
    <BlastRadiusCollapsible
      title="Trusted by"
      subtitle={`${principals.length} principal${principals.length !== 1 ? "s" : ""} can assume this role`}
      defaultOpen={principals.length <= 3}
    >
      <ul className="space-y-1">
        {principals.map((p, i) => (
          <li key={i} className="truncate font-mono text-[11px] text-zinc-600 py-0.5">
            {p}
          </li>
        ))}
      </ul>
    </BlastRadiusCollapsible>
  );
}
