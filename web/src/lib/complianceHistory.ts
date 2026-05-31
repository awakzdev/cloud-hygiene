import { BASE, token } from "../api";

export interface ControlDiff {
  control_id: string;
  title: string;
  open_finding_count?: number;
}

export interface ScanDiff {
  newly_failed: ControlDiff[];
  newly_passed: ControlDiff[];
}

export type HistoryEventType =
  | "baseline_established"
  | "compliance_regressed"
  | "compliance_improved"
  | "scan_with_changes";

export interface TopChange {
  control_id: string | null;
  title: string;
  direction: "baseline" | "improved" | "regressed" | "changed";
  label: string;
}

export interface SnapshotSummary {
  posture_score: number | null;
  controls_passed: number;
  controls_failed: number;
  controls_no_data: number;
  findings_opened: number;
  findings_resolved: number;
}

export interface HistoryEvent {
  type: HistoryEventType;
  timestamp: string;
  scan_run_id: string;
  framework: string;
  posture_before: number | null;
  posture_after: number | null;
  controls_failed_before: number | null;
  controls_failed_after: number;
  controls_passed_before?: number | null;
  controls_passed_after?: number;
  new_failures_count: number;
  resolved_count: number;
  findings_opened: number;
  findings_resolved: number;
  findings_discovered?: number;
  infrastructure_events_count?: number;
  snapshot: SnapshotSummary;
  top_change: TopChange;
  diff: ScanDiff;
}

export interface PeriodSummary {
  compliance_changes: number;
  controls_regressed: number;
  controls_improved: number;
  evidence_snapshots: number;
}

export interface CurrentSummary {
  controls_passed: number;
  controls_failed: number;
  controls_no_data: number;
}

export interface ScanCadenceDay {
  date: string;
  scan_count: number;
  posture_change_count: number;
}

export interface ComplianceHistoryResponse {
  framework: string;
  period_days: number;
  events: HistoryEvent[];
  period_summary?: PeriodSummary;
  current_summary?: CurrentSummary | null;
  current_posture_score: number | null;
  total_failing: number;
  scan_count?: number;
  scan_cadence?: ScanCadenceDay[];
}

export function scanDateLabel(iso: string) {
  return new Date(iso).toLocaleDateString(undefined, {
    month: "long",
    day: "numeric",
    year: "numeric",
  });
}

export function scanShortDate(iso: string) {
  return new Date(iso).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

export function scanAsOfDate(iso: string) {
  return new Date(iso).toISOString().slice(0, 10);
}

export async function downloadEvidenceForScan(
  accountId: string,
  framework: string,
  scanIso: string,
  periodDays = 90,
) {
  const tok = token();
  const params = new URLSearchParams({
    framework,
    account_id: accountId,
    period: String(periodDays),
    as_of: scanAsOfDate(scanIso),
  });
  const res = await fetch(`${BASE}/v1/exports/evidence-pack?${params}`, {
    headers: { Authorization: `Bearer ${tok}` },
  });
  if (!res.ok) throw new Error(await res.text());
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `vigil-evidence-${framework}-${scanAsOfDate(scanIso)}.zip`;
  a.click();
  URL.revokeObjectURL(url);
}
