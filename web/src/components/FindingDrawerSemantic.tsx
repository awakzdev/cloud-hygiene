import { useState, type ReactNode } from "react";

/** Shared “workflow” primitives — same rhythm as What If, reusable across drawer tabs */

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
  title: string;
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
        <span className="pt-0.5 text-[13px] font-semibold leading-snug text-zinc-900">{title}</span>
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
  label: string;
  value: ReactNode;
  sub?: string;
  valueClassName?: string;
  variant?: PostureMetricVariant;
}) {
  if (variant === "status") {
    return (
      <div className="flex min-h-[8rem] flex-col items-center justify-center rounded-xl bg-zinc-50/50 px-3 py-6 text-center">
        <div className={`text-xl font-semibold tabular-nums leading-none tracking-tight ${valueClassName}`}>
          {value}
        </div>
        {sub ? (
          <div className="mt-4 text-[11px] font-normal leading-relaxed tabular-nums text-zinc-400">{sub}</div>
        ) : null}
        <div className={`text-[11px] font-medium text-zinc-400 ${sub ? "mt-4" : "mt-3.5"}`}>{label}</div>
      </div>
    );
  }

  return (
    <div className="flex min-h-[4.75rem] flex-col items-center justify-center rounded-lg bg-zinc-50/70 px-2.5 py-3.5 text-center">
      <div className={`text-base font-semibold tabular-nums leading-tight ${valueClassName}`}>{value}</div>
      {sub ? <div className="mt-1.5 text-[10px] tabular-nums text-zinc-400">{sub}</div> : null}
      <div className={`text-[10px] font-medium text-zinc-400 ${sub ? "mt-2" : "mt-1.5"}`}>{label}</div>
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
    return <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">{children}</div>;
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

export function ExceptionFlowPanel({
  reason,
  approvedBy,
  expiresAt,
}: {
  reason?: string | null;
  approvedBy?: string | null;
  expiresAt?: string | null;
}) {
  return (
    <div className="overflow-hidden rounded-xl border border-dashed border-amber-300/70 bg-gradient-to-br from-amber-50/85 to-white shadow-sm shadow-amber-900/[0.03]">
      <div className="flex items-center gap-2 border-b border-amber-200/50 px-4 py-2.5 pr-5">
        <FlowBadge variant="caution">Exception</FlowBadge>
        <span className="text-[12px] font-semibold text-amber-950">Documented risk acceptance</span>
      </div>
      <div className="space-y-2 px-4 py-3 pr-5 text-[13px] leading-relaxed text-amber-950/90">
        {reason && <p>{reason}</p>}
        {approvedBy && (
          <p>
            <span className="text-[10px] font-semibold uppercase tracking-wide text-amber-800/80">Approved by </span>
            {approvedBy}
          </p>
        )}
        {expiresAt && (
          <p>
            <span className="text-[10px] font-semibold uppercase tracking-wide text-amber-800/80">Expires </span>
            {new Date(expiresAt).toLocaleDateString()}
          </p>
        )}
        {!reason && !approvedBy && <p>Approved exception on this finding.</p>}
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

/** Semantic group — whitespace + divider only, no section heading */
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
