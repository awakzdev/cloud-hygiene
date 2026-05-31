import { useState, type ReactNode } from "react";

/** Shared workflow primitives. Same rhythm as What If, reusable across drawer tabs. */

export function DrawerFlowLabel({ children }: { children: ReactNode }) {
  return (
    <p className="px-0.5 text-[10px] font-semibold uppercase tracking-wider text-zinc-400">{children}</p>
  );
}

type SemanticTone = "neutral" | "caution" | "action" | "positive";

const TONE_STYLES: Record<
  SemanticTone,
  { shell: string; header: string; tag: string }
> = {
  neutral: {
    shell: "border-zinc-200/90 shadow-sm shadow-zinc-900/[0.03]",
    header: "bg-gradient-to-r from-zinc-50/95 to-white",
    tag: "bg-zinc-100 text-zinc-700 ring-zinc-200/80",
  },
  caution: {
    shell: "border-amber-200/75 shadow-sm shadow-amber-900/[0.04]",
    header: "bg-gradient-to-r from-amber-50/90 to-white",
    tag: "bg-amber-100 text-amber-900 ring-amber-200/80",
  },
  action: {
    shell: "border-zinc-200/90 shadow-sm shadow-zinc-900/[0.03]",
    header: "bg-gradient-to-r from-indigo-50/40 to-white",
    tag: "bg-indigo-100 text-indigo-900 ring-indigo-200/70",
  },
  positive: {
    shell: "border-emerald-200/65 shadow-sm shadow-emerald-900/[0.04]",
    header: "bg-gradient-to-r from-emerald-50/50 to-white",
    tag: "bg-emerald-100 text-emerald-900 ring-emerald-200/70",
  },
};

export function SemanticNarrativeBlock({
  tag,
  title,
  tone = "neutral",
  children,
  icon,
}: {
  tag: string;
  title?: string;
  tone?: SemanticTone;
  children: ReactNode;
  icon?: ReactNode;
}) {
  const t = TONE_STYLES[tone];
  return (
    <div className={`overflow-hidden rounded-xl border bg-white ${t.shell}`}>
      <div className={`flex items-start gap-3 px-4 py-2.5 pr-5 ${t.header}`}>
        {icon ?? (
          <span
            className={`mt-0.5 shrink-0 rounded-md px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ring-1 ring-inset ${t.tag}`}
          >
            {tag}
          </span>
        )}
        {title ? (
          <span className="pt-0.5 text-[13px] font-semibold leading-snug text-zinc-900">{title}</span>
        ) : null}
      </div>
      <div className="border-t border-zinc-100/90 px-4 py-3 pr-5 text-[13px] leading-relaxed text-zinc-700">
        {children}
      </div>
    </div>
  );
}

export type PostureMetricVariant = "status" | "compact";

export function PostureMetricCell({
  label,
  value,
  sub,
  valueClassName = "text-zinc-900",
  variant = "compact",
}: {
  label?: string;
  value: ReactNode;
  sub?: string;
  valueClassName?: string;
  variant?: PostureMetricVariant;
}) {
  if (variant === "status") {
    return (
      <div className="flex flex-col items-center justify-center rounded-lg bg-white px-2.5 py-3.5 text-center ring-1 ring-zinc-100/80">
        <div className={`text-lg font-semibold tabular-nums leading-tight tracking-tight ${valueClassName}`}>
          {value}
        </div>
        {sub ? (
          <div className="mt-2 text-[11px] font-normal leading-snug tabular-nums text-zinc-400">{sub}</div>
        ) : null}
        {label ? (
          <div className={`text-[11px] font-medium text-zinc-400 ${sub ? "mt-2.5" : "mt-1.5"}`}>{label}</div>
        ) : null}
      </div>
    );
  }

  return (
    <div className="flex min-h-[4.75rem] flex-col items-center justify-center rounded-lg bg-white px-2.5 py-3.5 text-center ring-1 ring-zinc-100/80">
      <div className={`text-base font-semibold tabular-nums leading-tight ${valueClassName}`}>{value}</div>
      {sub ? <div className="mt-1.5 text-[11px] font-normal leading-snug tabular-nums text-zinc-400">{sub}</div> : null}
      {label ? (
        <div className={`text-[11px] font-medium text-zinc-400 ${sub ? "mt-2" : "mt-1.5"}`}>{label}</div>
      ) : null}
    </div>
  );
}

export function PostureMetricsRow({
  children,
  variant = "compact",
}: {
  children: ReactNode;
  variant?: PostureMetricVariant;
}) {
  if (variant === "status") {
    return <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">{children}</div>;
  }
  return <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4">{children}</div>;
}

export function FlowCallout({
  title,
  children,
  tone = "neutral",
}: {
  title: string;
  children: ReactNode;
  tone?: "neutral" | "positive";
}) {
  const shell =
    tone === "positive"
      ? "border-emerald-200/70 bg-emerald-50/40"
      : "border-zinc-200/80 bg-zinc-50/60";
  return (
    <div className={`rounded-xl border px-4 py-3 pr-5 ${shell}`}>
      <p className="text-[12px] font-semibold text-zinc-800">{title}</p>
      <p className="mt-1 text-[12px] leading-relaxed text-zinc-600">{children}</p>
    </div>
  );
}

export function FlowBadge({
  children,
  variant = "neutral",
}: {
  children: ReactNode;
  variant?: "neutral" | "caution" | "high" | "positive" | "muted";
}) {
  const cls =
    variant === "high"
      ? "bg-amber-100 text-amber-900 ring-amber-200/80"
      : variant === "caution"
        ? "bg-amber-50 text-amber-800 ring-amber-200/60"
        : variant === "positive"
          ? "bg-emerald-100 text-emerald-900 ring-emerald-200/70"
          : variant === "muted"
            ? "bg-zinc-100 text-zinc-600 ring-zinc-200/80"
            : "bg-zinc-100 text-zinc-700 ring-zinc-200/80";
  return (
    <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ring-1 ring-inset ${cls}`}>
      {children}
    </span>
  );
}

function ExceptionDetailCell({
  label,
  children,
  muted = false,
}: {
  label: string;
  children: ReactNode;
  muted?: boolean;
}) {
  return (
    <div className="min-w-0 rounded-lg border border-amber-200/45 bg-white/75 px-3 py-2.5">
      <p className="text-[10px] font-semibold uppercase tracking-wider text-amber-800/70">{label}</p>
      <div className={`mt-1 text-[13px] leading-relaxed ${muted ? "text-zinc-400" : "text-zinc-800"}`}>{children}</div>
    </div>
  );
}

export function ExceptionFlowPanel({
  reason,
  approvedBy,
  expiresAt,
}: {
  reason?: string | null;
  approvedBy?: string | null;
  expiresAt?: string | null;
}) {
  const hasApprovedBy = Boolean(approvedBy?.trim());
  const hasExpiry = Boolean(expiresAt);
  const hasReason = Boolean(reason?.trim());

  return (
    <div className="w-full overflow-hidden rounded-xl border border-amber-200/70 bg-white shadow-sm shadow-amber-900/[0.04]">
      <div className="flex items-start justify-between gap-3 border-b border-amber-100/80 bg-gradient-to-r from-amber-50/90 via-white to-white px-4 py-3 pr-5">
        <div>
          <div className="flex items-center gap-2">
            <FlowBadge variant="caution">Exception</FlowBadge>
            <span className="text-[12px] font-semibold text-zinc-900">Documented risk acceptance</span>
          </div>
          <p className="mt-1 text-[11px] leading-relaxed text-zinc-500">
            Kept in the evidence pack for auditor review.
          </p>
        </div>
      </div>

      <div className="grid gap-2 px-4 py-3 pr-5 sm:grid-cols-2">
        <div className="sm:col-span-2">
          <ExceptionDetailCell label="Reason" muted={!hasReason}>
            {hasReason ? reason : "No reason captured"}
          </ExceptionDetailCell>
        </div>
        <ExceptionDetailCell label="Approved by" muted={!hasApprovedBy}>
          {hasApprovedBy ? approvedBy : "Not captured"}
        </ExceptionDetailCell>
        <ExceptionDetailCell label="Expires" muted={!hasExpiry}>
          {hasExpiry ? new Date(expiresAt!).toLocaleDateString() : "No expiry set"}
        </ExceptionDetailCell>
      </div>
    </div>
  );
}

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

/** Semantic group. Whitespace plus divider only, no section heading. */
export function ResourceGroup({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={`border-t border-zinc-100/70 px-4 py-3.5 pr-5 ${className}`}>{children}</div>
  );
}

export function ResourceFieldRow({
  label,
  children,
  mono,
}: {
  label: string;
  children: ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="flex gap-3 py-2 first:pt-0 last:pb-0">
      <span className="w-[4.75rem] shrink-0 pt-0.5 text-[11px] font-medium text-zinc-500">{label}</span>
      <div
        className={`min-w-0 flex-1 text-[13px] leading-relaxed text-zinc-800 ${mono ? "font-mono text-[12px] break-all" : ""}`}
      >
        {children}
      </div>
    </div>
  );
}

export function ResourceGroupBlock({
  tag,
  title,
  children,
  defaultOpen = true,
}: {
  tag: string;
  title: string;
  children: ReactNode;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="border-t border-zinc-100/70 first:border-t-0">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-2 px-4 py-2.5 pr-5 text-left text-zinc-500 hover:bg-zinc-50/50"
      >
        <Chevron open={open} />
        <span className="text-[10px] font-semibold uppercase tracking-wider">{tag}</span>
        <span className="text-[11px] font-medium text-zinc-600">{title}</span>
      </button>
      {open && <div className="px-4 pb-3 pr-5 pt-0">{children}</div>}
    </div>
  );
}
