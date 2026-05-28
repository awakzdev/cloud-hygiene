import { useEffect, useMemo, useState } from "react";
import { formatServiceLastUsed } from "../lib/blastRadiusDisplay";
import { allCategories, isSensitiveService, serviceCategory } from "../lib/awsServiceCatalog";

export type ServiceAccessItem = {
  name: string;
  last_used: string | null;
  days_ago: number | null;
  active: boolean;
  in_policy?: boolean;
};

export type ExplorerBucket = "all" | "recent" | "historical" | "safe" | "sensitive";

function bucketFilter(bucket: ExplorerBucket, item: ServiceAccessItem): boolean {
  if (bucket === "all") return true;
  if (bucket === "sensitive") {
    return isSensitiveService(item.name) && (item.days_ago === null || item.days_ago > 30);
  }
  if (bucket === "recent") return item.days_ago !== null && item.days_ago <= 30;
  if (bucket === "historical") return item.days_ago !== null && item.days_ago > 30 && item.days_ago <= 90;
  return item.days_ago === null || item.days_ago > 90;
}

function ExplorerRow({ item }: { item: ServiceAccessItem }) {
  const sensitive = isSensitiveService(item.name);
  return (
    <div className="flex items-center justify-between gap-3 border-b border-zinc-100/80 px-4 py-2 last:border-0">
      <div className="flex min-w-0 items-center gap-2">
        <span className="truncate font-mono text-[12px] text-zinc-800">{item.name}</span>
        {sensitive && (
          <span className="shrink-0 rounded bg-amber-100/90 px-1 py-px text-[9px] font-semibold uppercase tracking-wide text-amber-800">
            Sensitive
          </span>
        )}
      </div>
      <span className="shrink-0 text-[11px] tabular-nums text-zinc-400">{formatServiceLastUsed(item.days_ago)}</span>
    </div>
  );
}

export function ServiceAccessExplorer({
  open,
  onClose,
  services,
  initialBucket = "all",
  title = "Service explorer",
}: {
  open: boolean;
  onClose: () => void;
  services: ServiceAccessItem[];
  initialBucket?: ExplorerBucket;
  title?: string;
}) {
  const [bucket, setBucket] = useState<ExplorerBucket>(initialBucket);
  const [categoryId, setCategoryId] = useState<string>("all");
  const [query, setQuery] = useState("");

  useEffect(() => {
    if (open) setBucket(initialBucket);
  }, [open, initialBucket]);

  const categories = useMemo(() => {
    const counts = new Map<string, number>();
    for (const s of services) {
      const { id } = serviceCategory(s.name);
      counts.set(id, (counts.get(id) ?? 0) + 1);
    }
    return allCategories().filter((c) => counts.has(c.id) || c.id === "other");
  }, [services]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return services
      .filter((s) => bucketFilter(bucket, s))
      .filter((s) => categoryId === "all" || serviceCategory(s.name).id === categoryId)
      .filter((s) => !q || s.name.toLowerCase().includes(q))
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [services, bucket, categoryId, query]);

  if (!open) return null;

  const bucketTabs: { id: ExplorerBucket; label: string }[] = [
    { id: "all", label: "All" },
    { id: "recent", label: "Recent" },
    { id: "historical", label: "Historical" },
    { id: "safe", label: "Likely safe" },
  ];

  return (
    <div className="fixed inset-0 z-[80] flex items-center justify-center p-4">
      <button type="button" className="absolute inset-0 bg-zinc-900/40 backdrop-blur-[2px]" onClick={onClose} aria-label="Close explorer" />
      <div className="relative flex max-h-[min(88vh,720px)] w-full max-w-lg flex-col overflow-hidden rounded-xl border border-zinc-200 bg-white shadow-2xl shadow-zinc-900/15">
        <div className="flex items-start justify-between gap-3 border-b border-zinc-100 px-4 py-3">
          <div>
            <h3 className="text-sm font-semibold text-zinc-900">{title}</h3>
            <p className="mt-0.5 text-[11px] text-zinc-500">
              {filtered.length} of {services.length} services
            </p>
          </div>
          <button type="button" onClick={onClose} className="rounded-md p-1 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-600">
            <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <div className="border-b border-zinc-100 px-4 py-2.5 space-y-2">
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search services…"
            className="w-full rounded-lg border border-zinc-200 bg-zinc-50/50 px-3 py-2 text-[13px] text-zinc-800 outline-none placeholder:text-zinc-400 focus:border-zinc-300 focus:bg-white"
          />
          <div className="flex flex-wrap gap-1">
            {bucketTabs.map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => setBucket(t.id)}
                className={`rounded-md px-2 py-0.5 text-[11px] font-medium transition-colors ${
                  bucket === t.id ? "bg-zinc-900 text-white" : "bg-zinc-100 text-zinc-600 hover:bg-zinc-200/80"
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>
        </div>
        <div className="flex min-h-0 flex-1">
          <aside className="w-36 shrink-0 overflow-y-auto border-r border-zinc-100 bg-zinc-50/40 py-2">
            <p className="px-3 pb-1 text-[10px] font-semibold uppercase tracking-wide text-zinc-400">Category</p>
            <button
              type="button"
              onClick={() => setCategoryId("all")}
              className={`block w-full px-3 py-1.5 text-left text-[11px] font-medium ${
                categoryId === "all" ? "bg-white text-zinc-900 shadow-sm" : "text-zinc-600 hover:text-zinc-900"
              }`}
            >
              All
            </button>
            {categories.map((c) => (
              <button
                key={c.id}
                type="button"
                onClick={() => setCategoryId(c.id)}
                className={`block w-full px-3 py-1.5 text-left text-[11px] font-medium ${
                  categoryId === c.id ? "bg-white text-zinc-900 shadow-sm" : "text-zinc-600 hover:text-zinc-900"
                }`}
              >
                {c.label}
              </button>
            ))}
          </aside>
          <div className="min-h-0 flex-1 overflow-y-auto">
            {filtered.length === 0 ? (
              <p className="px-4 py-8 text-center text-[13px] text-zinc-500">No services match these filters.</p>
            ) : (
              filtered.map((s) => <ExplorerRow key={s.name} item={s} />)
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
