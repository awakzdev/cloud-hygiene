import type { EvidenceCoverage } from "./evidenceCoverage";

export type EvidenceTone = "ready" | "partial" | "limited" | "insufficient" | "snapshot" | "neutral";

export type FrameworkEvidenceUi = {
  badgeLabel: string;
  tone: EvidenceTone;
  headline: string | null;
  showProgressBar: boolean;
  progressPct: number;
  progressAriaLabel: string | null;
  detailLine: string | null;
  guidanceLine: string | null;
};

function collectionStartedRecently(cov: EvidenceCoverage): boolean {
  if (!cov.coverage_start || !cov.period_start) return false;
  const startMs = new Date(cov.coverage_start).getTime();
  const periodMs = new Date(cov.period_start).getTime();
  return startMs - periodMs > 2 * 86_400_000;
}

function soc2Type2Presentation(
  cov: EvidenceCoverage | undefined,
  periodKey: string | number,
): FrameworkEvidenceUi {
  if (periodKey === "last_scan") {
    return {
      badgeLabel: "Point-in-time snapshot",
      tone: "snapshot",
      headline: "Exports posture from your latest successful scan.",
      showProgressBar: false,
      progressPct: 100,
      progressAriaLabel: null,
      detailLine: null,
      guidanceLine: null,
    };
  }
  if (!cov) {
    return {
      badgeLabel: "SOC 2 Type II readiness",
      tone: "limited",
      headline: null,
      showProgressBar: true,
      progressPct: 0,
      progressAriaLabel: "Audit days with evidence",
      detailLine: "Run a scan to assess Type II evidence coverage.",
      guidanceLine: null,
    };
  }

  const days = cov.days_with_data ?? 0;
  const total = cov.days_requested ?? 90;
  const pct = total > 0 ? Math.round((days / total) * 100) : 0;
  const ratio = total > 0 ? days / total : 0;
  const recent = collectionStartedRecently(cov);
  const recentLine = `Exports generated today may not satisfy a full ${total}-day Type II period.`;

  let tone: EvidenceTone = "insufficient";
  let badgeLabel = "SOC 2 Type II readiness";
  if (ratio >= 0.85) tone = "ready";
  else if (ratio >= 0.35) tone = "partial";
  else if (ratio >= 0.12) tone = "limited";

  let guidanceLine: string | null = null;
  if (ratio < 0.85) {
    guidanceLine = recent ? recentLine : "Additional scan history recommended for Type II sampling.";
  }

  return {
    badgeLabel,
    tone,
    headline: `${days} / ${total} audit days collected`,
    showProgressBar: true,
    progressPct: pct,
    progressAriaLabel: `${days} of ${total} audit days with evidence`,
    detailLine: null,
    guidanceLine,
  };
}

function cisPresentation(
  cov: EvidenceCoverage | undefined,
  periodKey: string | number,
  opts?: { controlsEvaluated?: number; lastScanLabel?: string | null },
): FrameworkEvidenceUi {
  if (periodKey === "last_scan") {
    return {
      badgeLabel: "Latest scan evidence",
      tone: "snapshot",
      headline: "Includes latest scan results, control mappings, findings, and remediation state.",
      showProgressBar: false,
      progressPct: 0,
      progressAriaLabel: null,
      detailLine: opts?.lastScanLabel ? `Last scan ${opts.lastScanLabel}` : null,
      guidanceLine: null,
    };
  }

  const days = cov?.days_with_data ?? 0;
  const controls = opts?.controlsEvaluated;
  const detailParts: string[] = [];
  if (opts?.lastScanLabel) detailParts.push(`Last scan ${opts.lastScanLabel}`);
  if (controls != null && controls > 0) {
    detailParts.push(`${controls} controls evaluated`);
  }
  if (days > 0) detailParts.push(`${days} day${days === 1 ? "" : "s"} of scan history in window`);

  return {
    badgeLabel: "CIS evidence package",
    tone: "neutral",
    headline: "Latest CIS scan evidence included",
    showProgressBar: false,
    progressPct: 0,
    progressAriaLabel: null,
    detailLine: detailParts.length > 0 ? detailParts.join(" · ") : null,
    guidanceLine: null,
  };
}

function isoPresentation(
  cov: EvidenceCoverage | undefined,
  periodKey: string | number,
): FrameworkEvidenceUi {
  if (periodKey === "last_scan") {
    return {
      badgeLabel: "Point-in-time evidence",
      tone: "snapshot",
      headline: "Exports posture from your latest successful scan.",
      showProgressBar: false,
      progressPct: 0,
      progressAriaLabel: null,
      detailLine: null,
      guidanceLine: null,
    };
  }

  const days = cov?.days_with_data ?? 0;
  const total = cov?.days_requested ?? 90;
  const headline =
    days === 0
      ? "No scan history in selected period"
      : days === 1
        ? "1 day collected"
        : `${days} days collected`;

  return {
    badgeLabel: "Evidence history",
    tone: days > 0 ? "neutral" : "limited",
    headline,
    showProgressBar: false,
    progressPct: 0,
    progressAriaLabel: null,
    detailLine: `Evidence included for the selected ${total}-day export period (not a fixed audit requirement).`,
    guidanceLine: null,
  };
}

export function frameworkEvidenceUi(
  frameworkId: string,
  cov: EvidenceCoverage | undefined,
  periodKey: string | number,
  opts?: { controlsEvaluated?: number; lastScanLabel?: string | null },
): FrameworkEvidenceUi {
  if (frameworkId === "soc2") return soc2Type2Presentation(cov, periodKey);
  if (frameworkId === "cis_aws_l1") return cisPresentation(cov, periodKey, opts);
  if (frameworkId === "iso27001") return isoPresentation(cov, periodKey);
  return cisPresentation(cov, periodKey, opts);
}

/** Per-control drawer: SOC 2 shows Type II days; ISO shows history count; CIS omits. */
export function showControlEvidenceSection(frameworkId: string): boolean {
  return frameworkId === "soc2" || frameworkId === "iso27001";
}

export function controlEvidenceSectionTitle(frameworkId: string): string {
  if (frameworkId === "soc2") return "Type II evidence";
  if (frameworkId === "iso27001") return "Evidence history";
  return "Evidence coverage";
}

export function controlEvidenceUsesType2Bar(frameworkId: string): boolean {
  return frameworkId === "soc2";
}

/** Generate Audit Package modal — period window selector label. */
export function exportScopeSectionLabel(frameworkId: string): string {
  if (frameworkId === "soc2") return "Audit period";
  if (frameworkId === "iso27001") return "Evidence period";
  if (frameworkId === "cis_aws_l1") return "Export scope";
  return "Export scope";
}

/** Generate Audit Package modal — as-of / snapshot date picker label. */
export function exportAsOfSectionLabel(frameworkId: string): string {
  if (frameworkId === "soc2") return "Audit end date";
  if (frameworkId === "cis_aws_l1") return "Snapshot date";
  if (frameworkId === "iso27001") return "As-of date";
  return "As-of date";
}

export function exportAsOfShowsType2Hint(frameworkId: string): boolean {
  return frameworkId === "soc2";
}
