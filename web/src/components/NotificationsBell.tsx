import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  useRecheckNotifications,
  type CloudTrailNotification,
  type NotificationItem,
} from "../context/RecheckNotificationsContext";
import { friendlyPolicyGenerationError } from "../lib/policyGenerationErrors";
import { checkLabels } from "../data/checkLabels";

function formatWhen(ts: number): string {
  const sec = Math.round((Date.now() - ts) / 1000);
  if (sec < 60) return "just now";
  const min = Math.round(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.round(min / 60);
  if (hr < 48) return `${hr}h ago`;
  return new Date(ts).toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}

function cloudTrailTitle(item: CloudTrailNotification): string {
  if (item.status === "running") return "CloudTrail Analyzes running";
  if (item.status === "succeeded") return "CloudTrail Analyzes complete";
  return "CloudTrail Analyzes failed";
}

function cloudTrailBody(item: CloudTrailNotification): string {
  if (item.message) return friendlyPolicyGenerationError(item.message);
  if (item.status === "running") return "~15 min · resource ARNs · IAM unchanged until you apply";
  if (item.status === "succeeded") return "Rebuild suggestion to apply resource ARNs.";
  return "Could not complete analysis for this role.";
}

function itemStyles(item: NotificationItem): string {
  if (item.kind === "cloudtrail") {
    if (item.status === "running") return "border-indigo-100 bg-indigo-50/80";
    if (item.status === "succeeded") return "border-emerald-100 bg-emerald-50/90";
    return "border-amber-100 bg-amber-50/90";
  }
  return item.status === "verified" ? "border-emerald-100 bg-emerald-50/90" : "border-amber-100 bg-amber-50/90";
}

function itemTitle(item: NotificationItem): string {
  if (item.kind === "cloudtrail") return cloudTrailTitle(item);
  return item.status === "verified" ? "Verified" : "Still open";
}

function itemBody(item: NotificationItem): string {
  if (item.kind === "cloudtrail") return cloudTrailBody(item);
  return item.status === "verified"
    ? "Re-check passed — finding resolved."
    : "Verify finished — issue still detected.";
}

function itemSubtitle(item: NotificationItem): string {
  if (item.kind === "cloudtrail") return item.roleLabel;
  return checkLabels[item.checkId] ?? item.checkId;
}

function titleColor(item: NotificationItem): string {
  if (item.kind === "cloudtrail") {
    if (item.status === "running") return "text-indigo-950";
    if (item.status === "succeeded") return "text-emerald-950";
    return "text-amber-950";
  }
  return item.status === "verified" ? "text-emerald-950" : "text-amber-950";
}

export default function NotificationsBell() {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const panelRef = useRef<HTMLDivElement>(null);
  const {
    pendingRecheck,
    pendingCloudTrail,
    notificationHistory,
    notificationCount,
    dismissNotification,
    clearAll,
  } = useRecheckNotifications();

  useEffect(() => {
    if (!open) return;
    function onDocClick(e: MouseEvent) {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", onDocClick);
    return () => document.removeEventListener("mousedown", onDocClick);
  }, [open]);

  function viewFinding(findingId: string) {
    setOpen(false);
    navigate(`/findings?finding=${encodeURIComponent(findingId)}`);
  }

  const historyVisible = notificationHistory.filter(
    (h) =>
      !(
        h.kind === "cloudtrail" &&
        h.status === "running" &&
        pendingCloudTrail?.notificationId === h.id
      ),
  );

  const hasItems = pendingRecheck || pendingCloudTrail || historyVisible.length > 0;

  return (
    <div className="relative" ref={panelRef}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="relative inline-flex h-10 w-10 items-center justify-center rounded-xl border border-zinc-200/80 bg-white text-zinc-600 shadow-sm transition hover:border-zinc-300 hover:bg-zinc-50 hover:text-zinc-900"
        aria-label={notificationCount ? `${notificationCount} notifications` : "Notifications"}
        aria-expanded={open}
      >
        <svg className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24" aria-hidden>
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0"
          />
        </svg>
        {notificationCount > 0 && (
          <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-[1rem] items-center justify-center rounded-full bg-indigo-600 px-1 text-[10px] font-bold text-white ring-2 ring-zinc-50">
            {notificationCount > 9 ? "9+" : notificationCount}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 z-50 mt-2 w-[min(28rem,calc(100vw-2rem))] overflow-hidden rounded-lg border border-zinc-200/90 bg-white shadow-lg shadow-zinc-900/10">
          <div className="flex items-center justify-between gap-2 border-b border-zinc-100 px-3 py-2">
            <p className="text-[13px] font-semibold text-zinc-900">Notifications</p>
            {notificationHistory.length > 0 && (
              <button
                type="button"
                onClick={() => clearAll()}
                className="text-[11px] font-medium text-zinc-500 hover:text-zinc-800"
              >
                Clear log
              </button>
            )}
          </div>
          <div className="max-h-[min(24rem,70vh)] overflow-y-auto p-2.5">
            {!hasItems && (
              <p className="px-1 py-4 text-center text-xs text-zinc-500">No notifications right now.</p>
            )}
            {pendingRecheck && (
              <div className="mb-1.5 rounded-md border border-indigo-100 bg-indigo-50/80 px-2.5 py-2">
                <div className="flex items-start gap-2">
                  <Spinner />
                  <div className="min-w-0 flex-1">
                    <p className="text-[13px] font-medium text-indigo-950">Verifying</p>
                    <p className="mt-0.5 text-[11px] leading-snug text-indigo-900/80">
                      {checkLabels[pendingRecheck.checkId] ?? pendingRecheck.checkId}
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => viewFinding(pendingRecheck.findingId)}
                  className="mt-1.5 text-[11px] font-semibold text-indigo-700 hover:text-indigo-900"
                >
                  View finding
                </button>
              </div>
            )}
            {pendingCloudTrail && (
              <div className="mb-1.5 rounded-md border border-indigo-100 bg-indigo-50/80 px-2.5 py-2">
                <div className="flex items-start gap-2">
                  <Spinner />
                  <div className="min-w-0 flex-1">
                    <p className="text-[13px] font-medium text-indigo-950">CloudTrail Analyzes</p>
                    <p className="mt-0.5 text-[11px] leading-snug text-indigo-900/80">
                      ~15 min · checking AWS job status
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => viewFinding(pendingCloudTrail.findingId)}
                  className="mt-1.5 text-[11px] font-semibold text-indigo-700 hover:text-indigo-900"
                >
                  View finding
                </button>
              </div>
            )}
            {historyVisible.map((item) => (
              <NotificationRow
                key={item.id}
                item={item}
                onView={() => viewFinding(item.findingId)}
                onDismiss={() => dismissNotification(item.id)}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function Spinner() {
  return (
    <svg className="mt-0.5 h-4 w-4 shrink-0 animate-spin text-indigo-600" fill="none" viewBox="0 0 24 24" aria-hidden>
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
    </svg>
  );
}

function NotificationRow({
  item,
  onView,
  onDismiss,
}: {
  item: NotificationItem;
  onView: () => void;
  onDismiss: () => void;
}) {
  return (
    <div className={`mb-1.5 rounded-md border px-2.5 py-2 last:mb-0 ${itemStyles(item)} ${item.readAt ? "opacity-70" : ""}`}>
      <div className="flex items-start justify-between gap-2">
        <p className={`text-[13px] font-semibold leading-snug ${titleColor(item)}`}>{itemTitle(item)}</p>
        <span className="shrink-0 text-[10px] font-medium text-zinc-500">{formatWhen(item.completedAt)}</span>
      </div>
      <p className="mt-0.5 line-clamp-3 text-xs leading-snug text-zinc-600 break-words">{itemBody(item)}</p>
      <p className="mt-1 text-xs font-medium text-zinc-800">{itemSubtitle(item)}</p>
      <div className="mt-1.5 flex items-center gap-2.5">
        <button type="button" onClick={onView} className="text-[11px] font-semibold text-zinc-800 underline hover:text-zinc-950">
          View finding
        </button>
        {!item.readAt && (
          <button type="button" onClick={onDismiss} className="text-[11px] font-medium text-zinc-500 hover:text-zinc-800">
            Dismiss
          </button>
        )}
      </div>
    </div>
  );
}
