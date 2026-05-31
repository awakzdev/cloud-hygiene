import { useState, useEffect, useMemo, useRef, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, formatApiError } from "../api";
import { IaCRemediationSection } from "./IaCRemediationSection";
import { drawerPanel } from "./drawerStyles";
import {
  credentialUnusedFrameworkImpact,
  type CredentialFrameworkImpactItem,
} from "../data/credentialFrameworkImpact";
import { frameworkLabel } from "../data/frameworks";
import { supportsBlastRadius } from "../data/blastRadiusChecks";
import { checkLabels } from "../data/checkLabels";
import { documentationForCheck } from "../data/checkDocumentation";
import { policyGenerationReasonLabel } from "../data/policyGenerationCopy";
import {
  formatCloudTrailStartFeedback,
  friendlyPolicyGenerationError,
} from "../lib/policyGenerationErrors";
import { useRecheckNotifications } from "../context/RecheckNotificationsContext";
import { remediationSummaryFor } from "../data/remediationSummaries";
import {
  daysAgo,
  awsRegionFromArn,
  regionsFromFindingEvidence,
  resourceDetailRowsFromFinding,
  resourceDisplayName,
  resourceRegionForFinding,
  resourceShortName,
  resourceTypeLabel,
} from "../lib/findingDisplay";
import {
  applyCliPlaceholders,
  buildCliPlaceholders,
  fetchClientIpForRemediation,
  formatCliStepSpacing,
  injectEc2RegionFlags,
} from "../lib/cliRemediation";
import {
  BlastRadiusConsiderations,
  RolePoliciesAnalysis,
  RoleServiceUsageAnalysis,
  RoleTrustPrincipals,
} from "./BlastRadiusPanel";
import {
  DrawerFlowLabel,
  ExceptionFlowPanel,
  FlowBadge,
  FlowCallout,
  PostureMetricCell,
  PostureMetricsRow,
  ResourceFieldRow,
  ResourceGroup,
  SemanticNarrativeBlock,
} from "./FindingDrawerSemantic";

const DRAWER_MAX_W = "max-w-[640px]";

/** Shared drawer inspection UI — aligned with Resources tab rhythm */
const drawerSectionHead = "border-b border-zinc-100 px-4 py-3";
const drawerSectionBody = "px-4 py-3.5";
const drawerSectionTitle = "text-sm font-semibold text-zinc-900";
const drawerFieldLabelBlock = "text-[11px] font-medium text-zinc-500";
const drawerBodyGap = "space-y-3";
const drawerFooterPrimary =
  "flex-[1.12] rounded-lg px-3.5 py-2 text-[13px] font-medium text-white bg-zinc-800 shadow-sm shadow-zinc-900/8 ring-1 ring-zinc-900/5 transition-all duration-200 hover:bg-zinc-700 hover:shadow-md hover:shadow-zinc-900/10 active:scale-[0.995]";
const drawerFooterSecondary =
  "flex-1 inline-flex items-center justify-center gap-2 rounded-lg border border-zinc-200/60 bg-white px-3 py-2 text-[13px] font-medium text-zinc-600 transition-all duration-200 hover:border-zinc-300 hover:bg-zinc-50 hover:text-zinc-800 active:scale-[0.995] disabled:opacity-50";
const drawerFooterException =
  "flex-[0.88] rounded-lg border border-amber-200/50 bg-amber-50/40 px-3 py-2 text-[13px] font-medium text-amber-800/75 transition-all duration-200 hover:border-amber-300/60 hover:bg-amber-50/70 hover:text-amber-900 active:scale-[0.995]";

function DrawerChevronButton({
  expanded,
  title,
  onClick,
}: {
  expanded: boolean;
  title: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="inline-flex h-7 w-7 items-center justify-center rounded-md text-zinc-400 transition-all duration-150 hover:bg-zinc-100 hover:text-zinc-700 active:scale-95"
      aria-label={expanded ? `Collapse ${title}` : `Expand ${title}`}
      aria-expanded={expanded}
    >
      <svg
        className={`h-4 w-4 transition-transform ${expanded ? "rotate-180" : ""}`}
        fill="none"
        stroke="currentColor"
        strokeWidth={2}
        viewBox="0 0 24 24"
        aria-hidden
      >
        <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
      </svg>
    </button>
  );
}

function DrawerSection({
  title,
  children,
  action,
  className = "",
  collapsible = false,
  defaultExpanded = true,
  expanded: expandedProp,
  onExpandedChange,
}: {
  title: string;
  children: ReactNode;
  action?: ReactNode;
  className?: string;
  collapsible?: boolean;
  defaultExpanded?: boolean;
  expanded?: boolean;
  onExpandedChange?: (expanded: boolean) => void;
}) {
  const [expandedInternal, setExpandedInternal] = useState(defaultExpanded);
  const expanded = expandedProp ?? expandedInternal;
  const setExpanded = onExpandedChange ?? setExpandedInternal;
  const showBody = !collapsible || expanded;

  return (
    <div className={`${drawerPanel} ${className}`}>
      <div className={`${drawerSectionHead} flex items-center justify-between gap-2`}>
        <h3 className={drawerSectionTitle}>{title}</h3>
        <div className="flex shrink-0 items-center gap-2">
          {action}
          {collapsible && (
            <DrawerChevronButton
              expanded={expanded}
              title={title}
              onClick={() => setExpanded(!expanded)}
            />
          )}
        </div>
      </div>
      {showBody && children}
    </div>
  );
}

type RemediationMode = "console" | "cli" | "terraform" | "automation";

const SG_AUTOMATION_ONLY_CHECKS = new Set([
  "ec2.security_group.unrestricted_ssh",
  "ec2.security_group.unrestricted_rdp",
]);

export function defaultFindingRemediationMode(checkId: string): FindingRemediationMode {
  return SG_AUTOMATION_ONLY_CHECKS.has(checkId) ? "automation" : "console";
}

function RemediationModeToggle({
  value,
  onChange,
  hideTerraform,
}: {
  value: RemediationMode;
  onChange: (mode: RemediationMode) => void;
  hideTerraform?: boolean;
}) {
  const modes: { id: RemediationMode; label: string }[] = [
    { id: "console", label: "Console" },
    { id: "cli", label: "CLI" },
    ...(hideTerraform ? [] : [{ id: "terraform" as const, label: "Terraform" }]),
    { id: "automation", label: "SSM Automation" },
  ];
  return (
    <div className="inline-flex max-w-full flex-wrap gap-0.5 rounded-lg bg-zinc-100/80 p-0.5">
      {modes.map((mode) => (
        <button
          key={mode.id}
          type="button"
          onClick={() => onChange(mode.id)}
          className={`rounded-md px-2.5 py-1 text-[11px] font-medium transition-all duration-150 ${
            value === mode.id
              ? "bg-white text-zinc-900 shadow-sm ring-1 ring-zinc-900/5"
              : "text-zinc-500 hover:text-zinc-700"
          }`}
        >
          {mode.label}
        </button>
      ))}
    </div>
  );
}

function awsAccountIdFromArn(arn: string): string | null {
  const m = arn.match(/^arn:aws:[^:]+::(\d{12}):/);
  return m ? m[1] : null;
}

function SelectedResourceInspector({
  finding,
  attachedToList = false,
}: {
  finding: Finding;
  attachedToList?: boolean;
}) {
  const accountId = awsAccountIdFromArn(finding.resource_arn);
  const ev = finding.evidence;
  const isUnusedRoleFinding = finding.check_id === "iam.role.unused_services_90d";
  const isIamRoleFinding =
    finding.check_id.startsWith("iam.role.") && finding.resource_arn.includes(":role/");
  const showWhatIfHint = supportsBlastRadius(finding.check_id) && isIamRoleFinding;
  const unusedCount = (ev.unused_services as string[] | undefined)?.length;
  const totalGranted = ev.total_granted_services as number | undefined;
  const thresholdDays = ev.threshold_days as number | undefined;
  const withRecordedUse =
    totalGranted != null && unusedCount != null ? Math.max(0, totalGranted - unusedCount) : null;
  const detailRows = resourceDetailRowsFromFinding(finding);
  const exposingRules = Array.isArray(ev.exposing_rules) ? (ev.exposing_rules as Record<string, unknown>[]) : [];
  const affectedRegions = regionsFromFindingEvidence(ev);
  const affectedRegionsLabel =
    finding.check_id === "aws.access_analyzer.not_enabled"
      ? "Regions without Access Analyzer"
      : finding.check_id === "guardduty.detector.not_enabled"
        ? "Regions without GuardDuty"
        : finding.check_id === "aws.securityhub.not_enabled"
          ? "Regions without Security Hub"
          : finding.check_id === "aws.config.not_enabled"
            ? "Regions without full Config recording"
            : "Affected regions";

  const statusLabel = finding.status.replace(/_/g, " ");
  const riskTone =
    finding.severity === "critical" || finding.severity === "high"
      ? "text-red-700"
      : finding.severity === "medium"
        ? "text-amber-700"
        : "text-zinc-800";

  return (
    <div
      className={`${drawerPanel} overflow-hidden ${
        attachedToList ? "border-l-2 border-l-zinc-300/45 shadow-sm shadow-zinc-900/[0.04]" : ""
      }`}
    >
      {detailRows.length === 0 && (
        <div
          className={`border-b border-zinc-100 px-4 py-3.5 pr-5 ${attachedToList ? "bg-zinc-50/70" : "bg-white"}`}
        >
          <h3 className={`${drawerSectionTitle} text-[15px] leading-snug break-words`}>
            {resourceShortName(finding)}
          </h3>
        </div>
      )}

      {detailRows.length > 0 && (
        <ResourceGroup className="border-t-0 bg-zinc-50/30">
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
            {detailRows.map((row) => (
              <div
                key={row.label}
                className="min-w-0 rounded-lg border border-zinc-200/80 bg-white px-2.5 py-2 shadow-sm shadow-zinc-900/[0.02]"
              >
                <div className="text-[10px] font-semibold uppercase tracking-wide text-zinc-400">
                  {row.label}
                </div>
                <div
                  className={`mt-0.5 truncate text-[12px] font-medium text-zinc-900 ${row.mono ? "font-mono text-[11px]" : ""}`}
                  title={row.value}
                >
                  {row.value}
                </div>
              </div>
            ))}
          </div>
        </ResourceGroup>
      )}

      {exposingRules.length > 0 && (
        <ResourceGroup>
          <p className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-zinc-500">
            Public ingress ({exposingRules.length})
          </p>
          <ul className="space-y-1.5">
            {exposingRules.map((rule, i) => {
              const proto = String(rule.protocol ?? "tcp");
              const from = rule.from_port as number | null | undefined;
              const to = rule.to_port as number | null | undefined;
              const cidr = String(rule.cidr ?? "0.0.0.0/0");
              const portLabel =
                proto === "all" || from == null || to == null
                  ? "all ports"
                  : from === to
                    ? `${from}`
                    : `${from}–${to}`;
              return (
                <li
                  key={`${cidr}-${portLabel}-${i}`}
                  className="flex items-center justify-between gap-2 rounded-md border border-red-100/80 bg-red-50/50 px-2.5 py-1.5 text-[11px]"
                >
                  <span className="font-mono text-zinc-800">
                    {proto.toUpperCase()} {portLabel}
                  </span>
                  <span className="shrink-0 font-mono text-red-800/90">{cidr}</span>
                </li>
              );
            })}
          </ul>
        </ResourceGroup>
      )}

      <ResourceGroup className={detailRows.length > 0 ? "" : "border-t-0"}>
        {accountId && <ResourceFieldRow label="Account">{accountId}</ResourceFieldRow>}
        <ResourceFieldRow label="ARN" mono>
          {finding.resource_arn}
        </ResourceFieldRow>
      </ResourceGroup>

      {affectedRegions.length > 0 && (
        <ResourceGroup>
          <div className="px-4 py-3 pr-5">
            <p className="mb-2.5 text-xs font-medium text-zinc-500">
              {affectedRegionsLabel} ({affectedRegions.length})
            </p>
            <RegionPills regions={affectedRegions} />
          </div>
        </ResourceGroup>
      )}

      {isUnusedRoleFinding && totalGranted != null && (
        <ResourceGroup>
          <PostureMetricsRow variant="compact">
            <PostureMetricCell label="Granted" value={totalGranted} variant="compact" />
            <PostureMetricCell
              label="In use"
              value={withRecordedUse ?? "—"}
              valueClassName="text-emerald-700"
              variant="compact"
            />
            <PostureMetricCell
              label="Unused 90d+"
              value={unusedCount ?? "—"}
              valueClassName="text-zinc-700"
              variant="compact"
            />
            <PostureMetricCell
              label="Window"
              value={thresholdDays != null ? `${thresholdDays}d` : "—"}
              variant="compact"
            />
          </PostureMetricsRow>
        </ResourceGroup>
      )}

      <ResourceGroup>
        <PostureMetricsRow variant="compact">
          <PostureMetricCell
            label="Risk score"
            value={finding.risk_score}
            valueClassName={riskTone}
            variant="compact"
          />
          <PostureMetricCell
            label="Status"
            value={<span className="capitalize text-[13px]">{statusLabel}</span>}
            variant="compact"
          />
          <PostureMetricCell
            label="First seen"
            value={daysAgo(finding.first_seen)}
            variant="compact"
          />
          <PostureMetricCell
            label="Last seen"
            value={daysAgo(finding.last_seen)}
            variant="compact"
          />
        </PostureMetricsRow>
      </ResourceGroup>

      {showWhatIfHint && (
        <p className="border-t border-zinc-100/80 bg-zinc-50/30 px-4 py-2.5 pr-5 text-[11px] leading-relaxed text-zinc-500">
          {isUnusedRoleFinding
            ? "Usage confidence and safe-removal analysis are on the What If tab."
            : "Open the What If tab for used services, trust principals, and whether to proceed with caution before scoping this role."}
        </p>
      )}
    </div>
  );
}

type Finding = {
  id: string;
  check_id: string;
  resource_arn: string;
  title: string;
  severity: string;
  risk_score: number;
  status: string;
  evidence: Record<string, unknown>;
  first_seen: string;
  last_seen: string;
  exception_reason?: string | null;
  exception_approved_by?: string | null;
  exception_expires_at?: string | null;
};

const sevHeaderBadge: Record<string, string> = {
  critical: "bg-red-50 text-red-700 border-red-200",
  high: "bg-red-50 text-red-600 border-red-200",
  medium: "bg-amber-50 text-amber-700 border-amber-200",
  low: "bg-zinc-100 text-zinc-500 border-zinc-200",
};

const sevWash: Record<string, string> = {
  critical: "from-red-100 to-stone-50",
  high: "from-red-50 to-stone-50",
  medium: "from-amber-50 to-stone-50",
  low: "from-slate-50 to-stone-50",
};

const sevStep: Record<string, string> = {
  critical: "bg-stone-700 text-white",
  high: "bg-stone-700 text-white",
  medium: "bg-stone-700 text-white",
  low: "bg-stone-700 text-white",
};

type Remediation = {
  why: string;
  console: string[];
  cli: string;
  risk: string;
};

function remediationImpactBadge(severity: string): { label: string; variant: "high" | "caution" | "muted" } {
  if (severity === "critical" || severity === "high") return { label: "High impact", variant: "high" };
  if (severity === "medium") return { label: "Verify impact", variant: "caution" };
  return { label: "Lower impact", variant: "muted" };
}

function frameworkCompact(framework: string): string {
  if (framework === "soc2") return "SOC2";
  if (framework === "cis_aws_l1") return "CIS AWS";
  if (framework === "iso27001") return "ISO 27001";
  return frameworkLabel(framework);
}

function OverviewSummaryRow({
  label,
  children,
  valueClassName = "text-zinc-800",
}: {
  label: string;
  children: ReactNode;
  valueClassName?: string;
}) {
  return (
    <div className="grid grid-cols-[7.5rem_1fr] gap-x-4 gap-y-0.5 px-4 py-2.5 sm:grid-cols-[8.5rem_1fr]">
      <dt className="text-[11px] font-medium text-zinc-500">{label}</dt>
      <dd className={`text-[13px] leading-snug ${valueClassName}`}>{children}</dd>
    </div>
  );
}

function FrameworkThresholdCard({ item }: { item: CredentialFrameworkImpactItem }) {
  const isCis = item.isActive;
  return (
    <div
      className={`flex flex-col rounded-xl px-3 py-2.5 ring-1 ${
        isCis
          ? "bg-gradient-to-b from-amber-50/95 to-amber-50/40 ring-amber-200/80"
          : "bg-white ring-zinc-200/80"
      }`}
    >
      <p className={`text-[13px] font-semibold leading-tight ${isCis ? "text-amber-950" : "text-zinc-900"}`}>
        {item.framework}
        {item.control ? <span className="font-medium text-zinc-500"> {item.control}</span> : null}
      </p>
      <p className="mt-1.5 text-[12px] font-medium text-zinc-700">Fails at {item.thresholdDays}+ days</p>
      <p
        className={`mt-1 text-[10px] font-medium uppercase tracking-wide ${
          isCis ? "text-amber-800/90" : "text-zinc-400"
        }`}
      >
        {item.statusLabel}
      </p>
    </div>
  );
}

function FrameworkImpactCard({ items }: { items: readonly CredentialFrameworkImpactItem[] }) {
  return (
    <div className={`${drawerPanel} overflow-hidden px-4 py-4 shadow-sm shadow-zinc-900/[0.03]`}>
      <h3 className="text-sm font-semibold text-zinc-900">Framework impact</h3>
      <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2">
        {items.map((item) => (
          <FrameworkThresholdCard key={item.id} item={item} />
        ))}
      </div>
    </div>
  );
}

function OverviewTabContent({
  impact,
  risk,
  fix,
  finding,
  hasException,
  documentation,
  accountId,
}: {
  impact: string;
  risk: string;
  fix: string;
  finding: Finding;
  hasException: boolean;
  documentation?: ReturnType<typeof documentationForCheck>;
  accountId?: string | null;
}) {
  const riskLine = documentation?.overview?.context ?? impact;
  const businessImpact = documentation?.overview?.exposure ?? risk;
  const recommendedAction = documentation?.overview?.fix ?? fix;
  const frameworkImpact = credentialUnusedFrameworkImpact(finding.check_id);
  const severityLabel = finding.severity.charAt(0).toUpperCase() + finding.severity.slice(1);
  const severityClass =
    finding.severity === "critical" || finding.severity === "high"
      ? "font-semibold text-red-800"
      : finding.severity === "medium"
        ? "font-semibold text-amber-800"
        : "font-semibold text-zinc-800";

  const { data: controlBundle, isLoading: controlsLoading } = useQuery({
    queryKey: ["controls-by-check", finding.check_id],
    queryFn: () =>
      api<CheckControlBundle>(`/v1/controls/by-check/${encodeURIComponent(finding.check_id)}`),
  });

  const mappings = controlBundle?.controls ?? [];

  return (
    <div className="space-y-3">
      <div className={`${drawerPanel} overflow-hidden shadow-sm shadow-zinc-900/[0.03]`}>
        <div className="border-b border-zinc-100 bg-white px-4 py-3">
          <h3 className="text-sm font-semibold text-zinc-900">Security summary</h3>
        </div>
        <dl className="divide-y divide-zinc-100/90 bg-white">
          <OverviewSummaryRow label="Severity" valueClassName={severityClass}>
            {severityLabel}
          </OverviewSummaryRow>
          <OverviewSummaryRow label="Risk">{riskLine}</OverviewSummaryRow>
          <OverviewSummaryRow label="Business impact">{businessImpact}</OverviewSummaryRow>
          <OverviewSummaryRow label="Compliance mappings">
            {controlsLoading ? (
              <span className="text-zinc-500">Loading…</span>
            ) : mappings.length === 0 ? (
              <span className="text-zinc-500">Not mapped</span>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {mappings.map((c) => (
                  <Link
                    key={`${c.framework}:${c.control_id}`}
                    to={compliancePageHref(c, accountId)}
                    className="inline-flex items-center rounded-md bg-zinc-100 px-2 py-0.5 text-[12px] font-medium text-zinc-800 ring-1 ring-zinc-200/80 transition hover:bg-indigo-50 hover:text-indigo-900 hover:ring-indigo-200/80"
                  >
                    {frameworkCompact(c.framework)} {c.control_id}
                  </Link>
                ))}
              </div>
            )}
          </OverviewSummaryRow>
          <OverviewSummaryRow label="Recommended action" valueClassName="font-medium text-zinc-900">
            {recommendedAction}
          </OverviewSummaryRow>
        </dl>
      </div>

      {frameworkImpact && <FrameworkImpactCard items={frameworkImpact} />}

      {hasException && (
        <ExceptionFlowPanel
          reason={finding.exception_reason}
          approvedBy={finding.exception_approved_by}
          expiresAt={finding.exception_expires_at}
        />
      )}
    </div>
  );
}

const remediations: Record<string, Remediation> = {
  "iam.user.no_mfa": {
    why: "Users without MFA can be fully compromised with only a stolen password. A second factor an attacker must physically control is the single most effective control against credential phishing.",
    console: [
      "Open IAM → Users → select the user",
      'Open the "Security credentials" tab → "Multi-factor authentication" → "Assign MFA device"',
      "Complete the MFA enrollment wizard",
    ],
    cli: `aws iam create-virtual-mfa-device --virtual-mfa-device-name <name> --outfile /tmp/qr.png --bootstrap-method QRCodePNG

aws iam enable-mfa-device --user-name <user> --serial-number <arn> --authentication-code1 <code1> --authentication-code2 <code2>`,
    risk: "Until MFA is enabled, a leaked password can be enough to sign in to the console.",
  },
  "iam.user.inactive_90d": {
    why: "Inactive accounts have no baseline of normal activity, making compromise invisible. Attackers who obtain credentials can operate undetected for months.",
    console: ["Open IAM → Users → select the user", 'Click "Security credentials" tab', 'Under "Console sign-in", click "Disable console access"', "Confirm with the team, then delete the user if no longer needed"],
    cli: `# Disable console access
aws iam delete-login-profile --user-name <user>

# Or delete the user entirely (remove keys + policies first)
aws iam delete-user --user-name <user>`,
    risk: "Stale console users should be disabled or removed after ownership is confirmed.",
  },
  "iam.user.credentials_unused_45d": {
    why: "Console credentials unused for 45+ days are often forgotten accounts. Inactive users have no baseline of normal activity, making compromise harder to spot.",
    console: ["Open IAM → Users → select the user", 'Click "Security credentials" tab', 'Under "Console sign-in", click "Disable console access"', "Confirm with the team, then delete the user if no longer needed"],
    cli: `# Disable console access
aws iam delete-login-profile --user-name <user>

# Or delete the user entirely (remove keys + policies first)
aws iam delete-user --user-name <user>`,
    risk: "Stale console users should be disabled or removed after ownership is confirmed.",
  },
  "iam.user.direct_policy_attachment": {
    why: "CIS expects permissions on IAM users to come from groups or roles — not policies attached directly to the user. Direct attachment is harder to audit, review, and revoke at scale.",
    console: [
      "Open IAM → Users → select the user",
      'Click "Permissions" tab',
      "Detach any managed policies attached directly to the user",
      "Delete any inline user policies",
      "Add the user to an IAM group or grant access via an assumable role instead",
    ],
    cli: `# List direct attachments
aws iam list-attached-user-policies --user-name <user>
aws iam list-user-policies --user-name <user>

# Detach managed policy
aws iam detach-user-policy --user-name <user> --policy-arn <policy-arn>

# Delete inline policy
aws iam delete-user-policy --user-name <user> --policy-name <policy-name>`,
    risk: "Detaching policies may break scripts or console workflows that depend on user-scoped grants — confirm usage before removing.",
  },
  "iam.access_key.unused_90d": {
    why: "Unused access keys are typically abandoned in scripts, CI config, or developer machines — often forgotten and never rotated. They're persistent credentials with no expiry.",
    console: ["Open IAM → Users → select the user", 'Click "Security credentials" tab', "Find the key under Access Keys", 'Click "Deactivate" first to verify nothing breaks, then "Delete"'],
    cli: `# Deactivate first, confirm nothing breaks, then delete
aws iam update-access-key --access-key-id <key-id> --status Inactive --user-name <user>

aws iam delete-access-key --access-key-id <key-id> --user-name <user>`,
    risk: "Forgotten keys are long-lived credentials. Deactivate first, then delete after confirming nothing still depends on them.",
  },
  "iam.access_key.unused_45d": {
    why: "Access keys unused for 45+ days are often abandoned in scripts, CI config, or developer machines and never rotated.",
    console: ["Open IAM → Users → select the user", 'Click "Security credentials" tab', "Find the key under Access Keys", 'Click "Deactivate" first to verify nothing breaks, then "Delete"'],
    cli: `# Deactivate first, confirm nothing breaks, then delete
aws iam update-access-key --access-key-id <key-id> --status Inactive --user-name <user>

aws iam delete-access-key --access-key-id <key-id> --user-name <user>`,
    risk: "Forgotten keys are long-lived credentials. Deactivate first, then delete after confirming nothing still depends on them.",
  },
  "iam.access_key.no_rotation_90d": {
    why: "This access key is older than the configured key-age threshold. Long-lived keys are harder to reason about because they may be stored in old scripts, CI secrets, or developer machines.",
    console: ["Open IAM → Users → select the user", 'Click "Security credentials" tab', "Create a replacement access key for the current workload", "Update the workload secret, then deactivate and delete the old key"],
    cli: `# Create a replacement key, update the workload, then retire the old one
aws iam create-access-key --user-name <user>

aws iam update-access-key --access-key-id <key-id> --status Inactive --user-name <user>

aws iam delete-access-key --access-key-id <key-id> --user-name <user>`,
    risk: "This is a key hygiene finding. Validate where the key is used before rotation or deletion.",
  },
  "iam.access_key.multiple_active": {
    why: "The user has more than one active access key. That can be valid during rotation, but persistent duplicate keys make ownership and cleanup harder.",
    console: ["Open IAM → Users → select the user", 'Click "Security credentials" tab', "Review both active access keys, including creation and last-used dates", "Deactivate and delete the key that is no longer needed"],
    cli: `# Review active keys for the user
aws iam list-access-keys --user-name <user>

# Deactivate the unused key first, then delete it
aws iam update-access-key --access-key-id <key-id> --status Inactive --user-name <user>
aws iam delete-access-key --access-key-id <key-id> --user-name <user>`,
    risk: "Treat this as a review item unless the extra key is clearly stale or unauthorized.",
  },
  "iam.role.unassumed_90d": {
    why: "Roles not assumed in 90+ days are often orphaned. They add attack surface and may carry policies that nobody actively owns.",
    console: ["Open IAM → Roles → select the role", "Review the trust policy and attached policies", "Confirm with the owning team whether the role is still needed", 'If not needed, click "Delete" at the top of the role page'],
    cli: `# Check last activity
aws iam get-role --role-name <role-name> --query 'Role.RoleLastUsed'

# Delete if confirmed unused
aws iam delete-role --role-name <role-name>`,
    risk: "Unused roles should be removed after ownership and service dependencies are confirmed.",
  },
  "iam.role.wildcard_action": {
    why: 'Action: "*" in an inline policy is admin-like unless constrained by resource, condition, or permissions boundary. It should be reviewed and scoped to the actions the role actually needs.',
    console: [
      'Use "Suggested policy" above (Generate) to preview a scoped policy from recorded usage',
      "Open IAM → Roles → select the role → Permissions → edit or replace the inline policy",
      "Apply the generated policy document, then verify the workload",
    ],
    cli: `# Option A — use Suggested policy (Generate) in this drawer, then:
aws iam put-role-policy --role-name <role-name> --policy-name <policy-name> --policy-document file://scoped-policy.json

# Option B — review inline policy manually
aws iam get-role-policy --role-name <role-name> --policy-name <policy-name>`,
    risk: "Broad wildcard permissions increase blast radius if the role is compromised or misused.",
  },
  "iam.perm.granted_vs_used": {
    why: "This role has write or mutating actions in its policies that have no recorded usage in the last 90 days (action-level data from IAM last-accessed). Removing unused write permissions reduces the blast radius if the role is compromised.",
    console: [
      "Open IAM → Roles → select the role → Permissions tab",
      "Review the actions listed in the finding evidence",
      "For each unused action, remove it from the role's inline or attached policies",
      'Use "Suggested policy" above (Generate) to preview a least-privilege policy from recorded usage',
      "Test the workload after each change to confirm functionality",
    ],
    cli: `# View current role policy
aws iam get-role-policy --role-name <role-name> --policy-name <policy-name>

# Update with unused write actions removed
aws iam put-role-policy --role-name <role-name> --policy-name <policy-name> --policy-document file://scoped-policy.json`,
    risk: "Roles with unused write actions can modify or delete resources they have no business touching — removing them shrinks the attack surface with no operational impact.",
  },
  "iam.policy.unattached": {
    why: "Customer-managed policies that are not attached to any user, group, or role are dead weight. They may contain overly permissive statements written for a workload that no longer exists, and they clutter the policy namespace making access reviews harder.",
    console: [
      "Open IAM → Policies → filter to Customer managed",
      "Sort by Attached entities to find policies with 0 attachments",
      "Review each policy — confirm it is no longer needed",
      'Click the policy → "Delete" (IAM will block deletion if it has any attachments)',
    ],
    cli: `# List customer-managed policies with 0 attachments
aws iam list-policies --scope Local --query 'Policies[?AttachmentCount==\`0\`].[PolicyName,Arn]' --output table

# Delete a specific unattached policy (fails if still attached)
aws iam delete-policy --policy-arn <policy-arn>`,
    risk: "Stale policies are low-risk but add noise to access reviews and may be accidentally re-attached with broad permissions later.",
  },
  "iam.policy.wildcard_resource": {
    why: "This policy grants write or sensitive actions on Resource: \"*\" — they apply to every resource of that type in the account. CIS benchmarks only require fixing full admin (Action: '*' with Resource: '*'); this is optional least-privilege hygiene, not a scored compliance fail.",
    console: [
      "Open IAM → Roles → select the role → Permissions tab",
      "Find the policy listed in the finding evidence",
      "For each flagged statement, replace Resource: '*' with the specific ARN(s) the role actually needs",
      "If specific ARNs are unknown, use IAM Access Analyzer to generate a least-privilege policy from CloudTrail history",
      "Save the updated policy and verify the workload still functions",
    ],
    cli: `# Review the flagged policy
aws iam get-role-policy --role-name <role-name> --policy-name <policy-name>

# Replace with scoped version (Resource narrowed to specific ARNs)
aws iam put-role-policy --role-name <role-name> --policy-name <policy-name> --policy-document file://scoped-policy.json

# For customer-managed attached policies
aws iam get-policy-version --policy-arn <policy-arn> --version-id v1
aws iam create-policy-version --policy-arn <policy-arn> --policy-document file://scoped-policy.json --set-as-default`,
    risk: "Wildcard resources on write actions mean the role can modify or delete any resource of that type in the account — not just the ones it should own.",
  },
  "iam.role.unused_services_90d": {
    why: "This role has permissions to services it has not recently used according to IAM service-last-accessed data. Those permissions may be removable, but should be validated against workload behavior and data freshness.",
    console: ["Open IAM → Roles → select the role", 'Click "Permissions" tab → find inline policies under "Permissions policies"', "Review each inline policy and remove statements for the unused services listed below", "Save the updated policy (or delete it entirely if all its services are unused)"],
    cli: `# List inline policies on the role
aws iam list-role-policies --role-name <role-name>

# Get a specific inline policy
aws iam get-role-policy --role-name <role-name> --policy-name <policy-name>

# Replace with scoped version (unused service statements removed)
aws iam put-role-policy --role-name <role-name> --policy-name <policy-name> --policy-document file://scoped-policy.json

# Or delete entirely if all permissions are unused
aws iam delete-role-policy --role-name <role-name> --policy-name <policy-name>`,
    risk: "Unused service permissions increase blast radius. Removing them improves least privilege after validation.",
  },
  "iam.role.trust_wildcard": {
    why: 'This role trust policy allows any AWS principal. That is high risk unless strong conditions narrow who can assume the role.',
    console: ["Open IAM → Roles → select the role", 'Click "Trust relationships"', "Review the principal and any conditions", "Replace wildcard principals with specific AWS accounts, roles, services, or federated identities"],
    cli: `# Review the role trust policy
aws iam get-role --role-name <role-name> --query 'Role.AssumeRolePolicyDocument'

# Update the trust policy after scoping Principal and Conditions
aws iam update-assume-role-policy --role-name <role-name> --policy-document file://trust-policy.json`,
    risk: "Wildcard trust can expose a role to unintended principals, especially when conditions are missing or weak.",
  },
  "iam.role.external_account_trust": {
    why: "The role's trust policy allows an AWS principal in another account to call sts:AssumeRole. That is expected for some integrations but must be documented and scoped — unknown external accounts are a common path for lateral access.",
    console: [
      "Open IAM → Roles → select the role",
      'Open the "Trust relationships" tab',
      "Review Principal.AWS entries — note each external 12-digit account ID",
      "Confirm with the owning team that each account is still required",
      "Remove stale principals, or add ExternalId / aws:PrincipalArn conditions to narrow who can assume",
      "Save an approved exception in Vigil if the trust is intentional (vendor, security tool, shared services)",
    ],
    cli: `# Read trust policy
aws iam get-role --role-name <role-name> --query 'Role.AssumeRolePolicyDocument'

# After editing trust-policy.json locally
aws iam update-assume-role-policy --role-name <role-name> --policy-document file://trust-policy.json`,
    risk: "Anyone who can assume this role from the trusted account receives all permissions attached to the role in your account.",
  },

  "iam.root.has_access_keys": {
    why: "Root account access keys bypass all IAM policies and have unrestricted access to every service and resource. There is no legitimate use case for programmatic root credentials.",
    console: ["Sign in as root", "Open IAM → Security credentials (via account menu top-right)", 'Under "Access keys", delete all active keys', "Create an IAM admin user for any automation that previously used root credentials"],
    cli: `# List root access keys (requires root credentials or AWS Support)
aws iam list-access-keys

# Delete each active root key
aws iam delete-access-key --access-key-id <key-id>`,
    risk: "Root access keys cannot be scoped with policies. Anyone with these credentials has full, unrevokable control of the account.",
  },

  "iam.root.no_mfa": {
    why: "The root account has no IAM policy restrictions. If its password is compromised without MFA, an attacker has unrestricted access to the entire account.",
    console: ["Sign in as root", "Open IAM → Security credentials (via account menu top-right)", 'Under "Multi-factor authentication", click "Assign MFA device"', "Register a hardware MFA device — virtual MFA is acceptable but hardware is preferred for root"],
    cli: `# MFA for root must be configured via the console — the AWS CLI cannot enable root MFA directly.
# Sign in as root and use the Security credentials page.`,
    risk: "Root without MFA is the highest-severity finding possible. Prioritise this above everything else.",
  },

  "iam.root.usage": {
    why: "Root is the most privileged identity in AWS — all IAM policies and SCPs are bypassed. Any API call using root credentials is a red flag. Engineers should never use root for day-to-day work.",
    console: ["Sign in as root → open CloudTrail → Event history", "Identify the event(s) that triggered this finding — review the event name, source IP, and user agent", "Determine whether the action required root or could have been done with an IAM user/role", "Create an IAM admin user or role for those operations and use root only for tasks that explicitly require it (e.g. closing the account, managing root MFA, changing account plan)"],
    cli: `# View recent root-initiated CloudTrail events
aws cloudtrail lookup-events \\
  --lookup-attributes AttributeKey=Username,AttributeValue=root \\
  --start-time $(date -u -d "90 days ago" +%Y-%m-%dT%H:%M:%SZ) \\
  --query 'Events[*].{Time:EventTime,Event:EventName,IP:CloudTrailEvent}' \\
  --output table`,
    risk: "Root activity should be extremely rare. Recurring root use indicates a process gap — automate those tasks with scoped IAM roles instead.",
  },

  "s3.bucket.public_access_not_blocked": {
    why: "S3 Block Public Access is an account and bucket-level guard against accidentally making objects public via ACLs or bucket policies. One or more of the four settings is currently off.",
    console: ["Open S3 → select the bucket", 'Click "Permissions" tab', 'Under "Block public access", click "Edit"', "Enable all four settings and save"],
    cli: `# Enable all four Block Public Access settings
aws s3api put-public-access-block \\
  --bucket <bucket-name> \\
  --public-access-block-configuration '{
    "BlockPublicAcls": true,
    "IgnorePublicAcls": true,
    "BlockPublicPolicy": true,
    "RestrictPublicBuckets": true
  }'`,
    risk: "Without this, a misconfigured ACL or bucket policy can silently expose objects to the internet.",
  },

  "s3.account.public_access_not_blocked": {
    why: "Account-level S3 Block Public Access is the broad guardrail that prevents accidental public bucket ACLs or policies across the entire account.",
    console: ["Open S3 → Block Public Access settings for this account", 'Click "Edit"', "Enable all four Block Public Access settings", "Save changes"],
    cli: `aws s3control put-public-access-block \\
  --account-id <account-id> \\
  --public-access-block-configuration \\
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`,
    risk: "Without the account-level guardrail, a single bucket policy or ACL mistake can expose data publicly.",
  },

  "s3.bucket.no_https_policy": {
    why: "A deny-HTTP bucket policy is defense in depth — it blocks the rare client that still uses http:// even though AWS SDKs, CLI, and Terraform default to HTTPS. Auditors often expect this as evidence of encryption in transit.",
    console: [
      "Remediation tab → Suggested policy → Generate (reads live bucket policy from AWS)",
      "Open S3 → select the bucket → Permissions → Bucket policy",
      "Paste the merged policy from Generate → Save",
    ],
    cli: `# After Generate: apply the merged policy document
aws s3api put-bucket-policy --bucket <bucket-name> --policy file://merged-policy.json`,
    risk: "Low practical blast radius for modern apps. Main value is compliance (CIS/SOC2) and blocking misconfigured legacy scripts that hard-code http:// URLs.",
  },

  "s3.bucket.no_kms": {
    why: "Server-side encryption with KMS (SSE-KMS) uses a customer-managed key, giving you control over key rotation, access policies, and audit logs. SSE-S3 uses an AWS-managed key you cannot audit or revoke.",
    console: ["Open S3 → select the bucket", 'Click "Properties" tab', 'Under "Default encryption", click "Edit"', 'Select "SSE-KMS", choose an existing CMK or create a new one, and save'],
    cli: `# Enable SSE-KMS with an existing CMK
aws s3api put-bucket-encryption --bucket <bucket-name> \\
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "<kms-key-arn>"
      },
      "BucketKeyEnabled": true
    }]
  }'`,
    risk: "SSE-S3 protects data at rest but the key is fully managed by AWS — you cannot restrict, rotate, or audit it independently.",
  },

  "s3.bucket.no_logging": {
    why: "Server access logging records every request made to a bucket — who accessed what, when, and from where. Without it there is no audit trail for forensics or compliance.",
    console: [
      "Create a central logging bucket (e.g. my-access-logs-<account-id>) if one does not exist",
      "On the logging bucket, set ownership to 'Bucket owner preferred' under Object Ownership",
      "Open the source bucket → Properties tab",
      'Under "Server access logging", click Edit',
      "Enable logging and set the target bucket and a prefix (e.g. the source bucket name)",
    ],
    cli: `# 1. Create a dedicated logging bucket (skip if it already exists)
aws s3api create-bucket --bucket my-access-logs-<account-id> --region us-east-1

# 2. Set object ownership so the log delivery service can write
aws s3api put-bucket-ownership-controls \\
  --bucket my-access-logs-<account-id> \\
  --ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerPreferred}]'

# 3. Enable access logging on the source bucket
aws s3api put-bucket-logging \\
  --bucket <bucket-name> \\
  --bucket-logging-status '{
    "LoggingEnabled": {
      "TargetBucket": "my-access-logs-<account-id>",
      "TargetPrefix": "<bucket-name>/"
    }
  }'`,
    risk: "Without access logs you cannot detect data exfiltration, unauthorized access, or misconfigured permissions after the fact.",
  },

  "kms.key.no_rotation": {
    why: "Automatic key rotation replaces the backing key material annually. If the key material is ever exposed, rotation limits the window of exposure.",
    console: ["Open KMS → Customer managed keys", "Select the key", 'Click "Key rotation" tab', 'Enable "Automatically rotate this KMS key every year"'],
    cli: `# Enable annual automatic rotation
aws kms enable-key-rotation --key-id <key-id>

# Confirm rotation is enabled
aws kms get-key-rotation-status --key-id <key-id>`,
    risk: "Keys that never rotate accumulate exposure over time. AWS retains old backing keys so existing ciphertexts remain decryptable after rotation.",
  },
  "cloudtrail.trail.not_enabled": {
    why: "Without CloudTrail, there is no record of API calls. Incidents cannot be investigated, compliance cannot be proven, and unauthorized access may go undetected.",
    console: ["Open CloudTrail → Trails → Create trail", "Set a name, enable logging in all regions (multi-region trail)", "Select or create an S3 bucket for log delivery", 'Enable "Log file validation" and save'],
    cli: `# Create a multi-region trail
aws cloudtrail create-trail \\
  --name vigil-audit \\
  --s3-bucket-name <your-log-bucket> \\
  --is-multi-region-trail \\
  --enable-log-file-validation

# Start logging
aws cloudtrail start-logging --name vigil-audit`,
    risk: "Without audit logs, compromise may go undetected and incident response is severely hampered.",
  },
  "cloudtrail.trail.no_log_validation": {
    why: "Without log file validation, CloudTrail logs can be silently modified or deleted. Attackers who compromise log storage can erase evidence of their activity.",
    console: ["Open CloudTrail → Trails → select the trail", 'Under "General details", click "Edit"', 'Enable "Log file validation"', "Save changes"],
    cli: `# Enable log file integrity validation on an existing trail
aws cloudtrail update-trail \\
  --name <trail-name> \\
  --enable-log-file-validation

# Verify
aws cloudtrail get-trail --name <trail-name>`,
    risk: "Tampered logs are indistinguishable from authentic ones without validation enabled.",
  },
  "cloudtrail.trail.no_kms": {
    why: "CloudTrail log files should be encrypted with a customer-managed KMS key so access to audit history can be controlled, monitored, and revoked independently from the S3 bucket.",
    console: [
      "Open CloudTrail → Trails → select the trail",
      'Under "General details", click "Edit"',
      "Enable SSE-KMS encryption",
      "Choose a customer-managed KMS key for log encryption",
      "Save changes",
    ],
    cli: `aws cloudtrail update-trail \\
  --name <trail-name> \\
  --kms-key-id <kms-key-arn>`,
    risk: "Unencrypted audit logs weaken evidence integrity and make it harder to prove tight access control over security history.",
  },
  "guardduty.detector.not_enabled": {
    why: "GuardDuty is AWS's threat detection service. Without it, there is no automated detection of port scans, credential abuse, crypto-mining, or data exfiltration.",
    console: ["Open GuardDuty in each affected region listed in Scan details", 'Click "Get Started" then "Enable GuardDuty"', "Alternatively, use AWS Organizations to enable GuardDuty in all regions centrally"],
    cli: `# Enable GuardDuty in each disabled region (repeat per region)
aws guardduty create-detector --enable --region <region>

# Or enable across all regions using a loop
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  aws guardduty create-detector --enable --region $region
done`,
    risk: "Threats such as compromised credentials, unusual API calls, and lateral movement go undetected.",
  },
  "vpc.flow_logs.not_enabled": {
    why: "VPC flow logs capture accepted and rejected network traffic. Without them, lateral movement, port scans, and data exfiltration are invisible at the network layer.",
    console: ["Open VPC → Your VPCs → select the VPC", 'Click "Flow logs" tab → "Create flow log"', 'Set filter to "All", destination to CloudWatch Logs or S3', "Select or create an IAM role for delivery and save"],
    cli: `# Create a flow log to CloudWatch Logs
aws ec2 create-flow-logs \\
  --resource-type VPC \\
  --resource-ids <vpc-id> \\
  --traffic-type ALL \\
  --log-destination-type cloud-watch-logs \\
  --log-group-name /aws/vpc/flowlogs \\
  --deliver-logs-permission-arn <delivery-role-arn>`,
    risk: "Network-level attacks and lateral movement are invisible without flow logs.",
  },
  "ec2.security_group.unrestricted_ssh": {
    why: "SSH open to 0.0.0.0/0 exposes instances to brute-force and credential-stuffing attacks from the entire internet.",
    console: ["Open EC2 → Security Groups → select the group", 'Click "Inbound rules" tab → "Edit inbound rules"', "Find the rule for port 22 with source 0.0.0.0/0 or ::/0", "Replace with a specific IP range, or remove and use Systems Manager Session Manager instead"],
    cli: `# Remove the unrestricted SSH rule
aws ec2 revoke-security-group-ingress \\
  --group-id <sg-id> \\
  --protocol tcp \\
  --port 22 \\
  --cidr 0.0.0.0/0

# Optionally restrict to a known IP
aws ec2 authorize-security-group-ingress \\
  --group-id <sg-id> \\
  --protocol tcp \\
  --port 22 \\
  --cidr <your-ip>/32`,
    risk: "Open SSH is continuously probed. A single weak credential or leaked key is sufficient for full instance compromise.",
  },
  "ec2.security_group.unrestricted_rdp": {
    why: "RDP open to 0.0.0.0/0 is a primary attack vector for Windows instances and is actively exploited by ransomware operators.",
    console: ["Open EC2 → Security Groups → select the group", 'Click "Inbound rules" tab → "Edit inbound rules"', "Find the rule for port 3389 with source 0.0.0.0/0 or ::/0", "Replace with a specific IP range, or use AWS Fleet Manager for browser-based RDP"],
    cli: `# Remove the unrestricted RDP rule
aws ec2 revoke-security-group-ingress \\
  --group-id <sg-id> \\
  --protocol tcp \\
  --port 3389 \\
  --cidr 0.0.0.0/0

# Optionally restrict to a known IP
aws ec2 authorize-security-group-ingress \\
  --group-id <sg-id> \\
  --protocol tcp \\
  --port 3389 \\
  --cidr <your-ip>/32`,
    risk: "Exposed RDP is a leading cause of ransomware incidents. The port is constantly scanned by automated attackers.",
  },
  "rds.instance.publicly_accessible": {
    why: "A publicly accessible RDS instance can be reached directly from the internet. Combined with weak credentials or an unpatched vulnerability, this is a direct path to data exfiltration.",
    console: ["Open RDS → Databases → select the instance", 'Click "Modify"', 'Under "Connectivity", set "Publicly accessible" to No', 'Click "Continue" and apply immediately or during the next maintenance window'],
    cli: `# Disable public accessibility
aws rds modify-db-instance \\
  --db-instance-identifier <instance-id> \\
  --no-publicly-accessible \\
  --apply-immediately`,
    risk: "Direct internet exposure combines with database credentials — one exposure is enough for a full data breach.",
  },
  "rds.instance.no_encryption": {
    why: "RDS encryption cannot be enabled on a running instance. An unencrypted instance stores data as plaintext on disk — a snapshot or EBS volume leak exposes raw data.",
    console: [
      "Open RDS → Databases → select the instance",
      'Click "Actions" → "Take snapshot" to create a backup',
      "Open RDS → Snapshots → select the snapshot",
      'Click "Actions" → "Copy snapshot", enable encryption, choose a KMS key',
      'Restore the encrypted snapshot via "Actions" → "Restore snapshot"',
      "Validate the new instance, update application connection strings, then delete the old instance",
    ],
    cli: `# Step 1: snapshot the current instance
aws rds create-db-snapshot \\
  --db-instance-identifier <instance-id> \\
  --db-snapshot-identifier <snapshot-id>

# Step 2: copy with encryption enabled
aws rds copy-db-snapshot \\
  --source-db-snapshot-identifier <snapshot-id> \\
  --target-db-snapshot-identifier <encrypted-snapshot-id> \\
  --kms-key-id <kms-key-arn>

# Step 3: restore to a new encrypted instance
aws rds restore-db-instance-from-db-snapshot \\
  --db-instance-identifier <new-instance-id> \\
  --db-snapshot-identifier <encrypted-snapshot-id>`,
    risk: "Unencrypted storage means any physical disk access or snapshot leak exposes plaintext database contents.",
  },
  "rds.instance.no_automated_backup": {
    why: "Automated backups provide point-in-time recovery. Without them, accidental deletion, bad migrations, or data corruption can become permanent data loss.",
    console: [
      "Open RDS → Databases → select the instance",
      'Click "Modify"',
      "Set Backup retention period to at least 7 days",
      "Choose a backup window that avoids peak traffic",
      'Click "Continue" and apply during the next maintenance window unless urgent',
    ],
    cli: `aws rds modify-db-instance \\
  --db-instance-identifier <instance-id> \\
  --backup-retention-period 7 \\
  --preferred-backup-window 03:00-04:00`,
    risk: "No automated backups means no point-in-time recovery. Operational mistakes or corruption may require manual snapshot rollback, if any snapshot exists.",
  },
  "dynamodb.table.no_encryption": {
    why: "Tables without explicit encryption at rest rely on legacy defaults. Enabling SSE-KMS or AWS-owned encryption protects item data on disk and satisfies auditor expectations for data-at-rest controls.",
    console: [
      "Open DynamoDB → Tables → select the table",
      'Open the "Additional settings" tab',
      'Under "Encryption at rest", click "Manage encryption"',
      'Choose "Owned by Amazon DynamoDB" or "AWS managed key (aws/dynamodb)" for the simplest path',
      "For a customer-managed key, select your KMS key and confirm IAM roles can use it",
      "Save — the table stays online during the update",
    ],
    cli: `# Enable encryption in place (AWS managed DynamoDB key)
aws dynamodb update-table \\
  --table-name <table-name> \\
  --region <region> \\
  --sse-specification Enabled=true,SSEType=KMS,KMSMasterKeyId=alias/aws/dynamodb

# Or use AWS-owned encryption (AES256)
aws dynamodb update-table \\
  --table-name <table-name> \\
  --region <region> \\
  --sse-specification Enabled=true,SSEType=AES256`,
    risk: "Unencrypted tables store data without explicit at-rest protection. Encryption can be enabled in place, but customer-managed KMS keys require kms:Decrypt on consuming roles.",
  },
  "dynamodb.table.no_pitr": {
    why: "Point-in-time recovery (PITR) provides continuous backups and restore to any second within the last 35 days. Without it, accidental deletes or bad writes require manual on-demand backups — if any exist.",
    console: [
      "Open DynamoDB → Tables → select the table",
      'Open the "Backups" tab',
      'Under "Point-in-time recovery (PITR)", click "Edit"',
      "Enable PITR and save",
    ],
    cli: `aws dynamodb update-continuous-backups \\
  --table-name <table-name> \\
  --region <region> \\
  --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true`,
    risk: "Without PITR, table data loss from accidental deletes or application bugs may be irreversible.",
  },
  "s3.bucket.no_default_encryption": {
    why: "Without default encryption, objects uploaded without an explicit encryption header are stored unencrypted. Default bucket encryption applies SSE to every new object automatically.",
    console: [
      "Open S3 → select the bucket",
      'Open the "Properties" tab → "Default encryption" → Edit',
      "Enable SSE-S3 (AES-256) or SSE-KMS with your preferred key",
      "Save — only affects new uploads; existing objects are unchanged",
    ],
    cli: `aws s3api put-bucket-encryption \\
  --bucket <bucket-name> \\
  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"},"BucketKeyEnabled":true}]}'`,
    risk: "Existing objects are not retroactively encrypted. Re-upload or use S3 Batch Operations if you need to encrypt historical data.",
  },
  "s3.bucket.no_mfa_delete": {
    why: "With versioning enabled but MFA Delete off, a compromised IAM principal can permanently delete all object versions without a second factor. MFA Delete requires root credentials to enable or disable.",
    console: [
      "Sign in as the root user (MFA Delete cannot be enabled by IAM users)",
      "Open S3 → select the bucket → Properties",
      'Under "Bucket Versioning", click Edit',
      "Enable MFA Delete and provide your root MFA device serial and two consecutive codes",
    ],
    cli: `# MFA Delete requires root credentials
aws s3api put-bucket-versioning \\
  --bucket <bucket-name> \\
  --versioning-configuration Status=Enabled,MFADelete=Enabled \\
  --mfa "<root-mfa-serial> <code1> <code2>"`,
    risk: "Disabling MFA Delete later also requires root MFA. Treat this as a permanent hardening step once enabled.",
  },
  "ec2.ebs.snapshot_public": {
    why: "Public EBS snapshots can be copied or mounted by any AWS account worldwide. They may contain full disk images with credentials, keys, or customer data.",
    console: [
      "Open EC2 → Snapshots → select the snapshot",
      'Click "Actions" → "Modify snapshot permissions"',
      'Remove any "Groups" entry (e.g. all) and confirm only your account ID is listed',
      "If the snapshot is no longer needed, delete it",
    ],
    cli: `# Remove public access — allow only this account
aws ec2 modify-snapshot-attribute \\
  --snapshot-id <snapshot-id> \\
  --region <region> \\
  --attribute createVolumePermission \\
  --operation-type remove \\
  --group-names all

# Verify permissions
aws ec2 describe-snapshot-attribute \\
  --snapshot-id <snapshot-id> \\
  --region <region> \\
  --attribute createVolumePermission`,
    risk: "Public snapshots may already have been copied by external accounts — removing access stops new copies but not existing ones.",
  },
  "ec2.ebs.snapshot_unencrypted": {
    why: "Unencrypted snapshots store block data in plaintext. Anyone with snapshot access (including after a cross-account share) can read the full disk contents.",
    console: [
      "Open EC2 → Snapshots → select the snapshot",
      'Click "Actions" → "Copy snapshot"',
      "Enable encryption and choose a KMS key",
      "After validating the encrypted copy, delete the original unencrypted snapshot",
    ],
    cli: `aws ec2 copy-snapshot \\
  --source-region <region> \\
  --source-snapshot-id <snapshot-id> \\
  --region <region> \\
  --description "Encrypted copy" \\
  --encrypted \\
  --kms-key-id alias/aws/ebs

# After validation, delete the original
aws ec2 delete-snapshot --snapshot-id <snapshot-id> --region <region>`,
    risk: "Copying large snapshots takes time and incurs storage cost for both copies until the original is deleted.",
  },
  "ec2.ami.public": {
    why: "A public AMI exposes your machine image to every AWS account. Images may contain hardcoded secrets, internal tooling, or proprietary code.",
    console: [
      "Open EC2 → AMIs → select the AMI",
      'Click "Actions" → "Modify image permissions"',
      'Set visibility to "Private" (remove all and add only your account if needed)',
      "Deregister the AMI if it was shared accidentally and is no longer needed",
    ],
    cli: `# Make AMI private (this account only)
aws ec2 modify-image-attribute \\
  --image-id <image-id> \\
  --region <region> \\
  --launch-permission '{"Remove":[{"Group":"all"}]}'

# Verify
aws ec2 describe-image-attribute \\
  --image-id <image-id> \\
  --region <region> \\
  --attribute launchPermission`,
    risk: "If the AMI was public, assume it may have been copied — rotate any secrets baked into the image.",
  },
  "cloudtrail.trail.s3_bucket_public": {
    why: "CloudTrail logs contain every API call in your account. A public S3 bucket receiving those logs exposes your full operational history to the internet.",
    console: [
      "Identify the S3 bucket receiving CloudTrail logs (CloudTrail → Trails → select trail → Storage location)",
      "Open S3 → select that bucket → Permissions",
      "Enable all four Block Public Access settings",
      "Review the bucket policy — remove any Principal: * grants",
      "Confirm the bucket is not listed as publicly accessible in S3 → Access Points or ACLs",
    ],
    cli: `# Block all public access on the CloudTrail log bucket
aws s3api put-public-access-block \\
  --bucket <bucket-name> \\
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`,
    risk: "Audit logs may already have been downloaded if the bucket was public. Treat this as a potential data breach and rotate sensitive credentials.",
  },
  "cloudtrail.trail.no_cloudwatch_logs": {
    why: "CloudWatch Logs integration enables real-time alerting on suspicious API activity. S3-only delivery delays detection until logs are delivered and queried.",
    console: [
      "Open CloudTrail → Trails → select the trail",
      'Click "Edit" → expand "CloudWatch Logs"',
      "Create or select a CloudWatch Logs log group",
      "Attach the CloudTrail service role (or create one with logs:CreateLogStream and logs:PutLogEvents)",
      "Save and verify events appear in the log group within a few minutes",
    ],
    cli: `# Create log group and enable CloudWatch delivery (requires CloudTrail service role)
aws logs create-log-group --log-group-name CloudTrail/<trail-name> --region <region>

aws cloudtrail update-trail \\
  --name <trail-name> \\
  --cloud-watch-logs-log-group-arn arn:aws:logs:<region>:<account-id>:log-group:CloudTrail/<trail-name>:* \\
  --cloud-watch-logs-role-arn <cloudtrail-cloudwatch-role-arn> \\
  --region <region>`,
    risk: "CloudWatch Logs ingestion adds cost (~$0.50/GB). Set a retention period on the log group to control spend.",
  },
  "cloudtrail.trail.s3_bucket_no_logging": {
    why: "The S3 bucket storing CloudTrail logs should have server access logging enabled. Without it, access to your audit trail itself is not recorded.",
    console: [
      "Identify the S3 bucket receiving CloudTrail logs",
      "Create a separate logging target bucket (do not log the log bucket into itself)",
      "Open the CloudTrail bucket → Properties → Server access logging → Edit",
      "Enable logging to the target bucket with a clear prefix (e.g. cloudtrail-access-logs/)",
    ],
    cli: `aws s3api put-bucket-logging \\
  --bucket <bucket-name> \\
  --bucket-logging-status '{"LoggingEnabled":{"TargetBucket":"<logging-bucket>","TargetPrefix":"cloudtrail-access-logs/"}}'`,
    risk: "Low operational risk — logging adds a small storage cost to the target bucket.",
  },
  "acm.certificate.expiring": {
    why: "An expiring TLS certificate will break HTTPS for any service using it — load balancers, CloudFront, API Gateway. Browsers will show certificate errors and API clients will fail TLS handshakes.",
    console: [
      "Open ACM → Certificates → select the certificate",
      "Confirm the expiry date and associated services (ELB, CloudFront, etc.)",
      "If DNS-validated and auto-renewal eligible, verify the CNAME validation record still exists in Route 53",
      "If not auto-renewing, request a new certificate and update the listener/distribution before expiry",
    ],
    cli: `# Check certificate status and expiry
aws acm describe-certificate \\
  --certificate-arn <certificate-arn> \\
  --region <region>

# Request a replacement (DNS validation recommended)
aws acm request-certificate \\
  --domain-name <domain-name> \\
  --validation-method DNS \\
  --region <region>`,
    risk: "Replacing a certificate on a live listener requires updating the attachment — plan a brief maintenance window if auto-renewal cannot be restored.",
  },
  "lambda.function.deprecated_runtime": {
    why: "Deprecated Lambda runtimes no longer receive security patches. AWS will eventually block creates/updates and then disable invocation on unsupported runtimes.",
    console: [
      "Open Lambda → Functions → select the function",
      'Click "Configuration" → "General configuration" → Edit',
      "Select a supported runtime (e.g. python3.12, nodejs20.x, java21)",
      "Test thoroughly in a staging alias before updating production",
    ],
    cli: `# Update runtime
aws lambda update-function-configuration \\
  --function-name <function-name> \\
  --region <region> \\
  --runtime python3.12

# Test with a dry-run invocation
aws lambda invoke \\
  --function-name <function-name> \\
  --region <region> \\
  --payload '{}' /tmp/out.json`,
    risk: "Runtime upgrades can break dependencies — test in non-prod. Python 3.12 and Node 20 may require dependency updates.",
  },
  "lambda.function.no_dlq": {
    why: "Without a dead-letter queue (DLQ), failed async invocations are retried until they expire silently. You lose visibility into poison messages and cannot replay failures.",
    console: [
      "Create an SQS queue or SNS topic to use as the DLQ",
      "Open Lambda → Functions → select the function",
      'Click "Configuration" → "Asynchronous invocation" → Edit',
      "Set the dead-letter queue ARN and a maximum retry attempt count (e.g. 2)",
      "Save and trigger a test failure to confirm messages arrive in the DLQ",
    ],
    cli: `# Create DLQ queue
aws sqs create-queue --queue-name <function-name>-dlq --region <region>

# Attach DLQ to function
aws lambda update-function-configuration \\
  --function-name <function-name> \\
  --region <region> \\
  --dead-letter-config TargetArn=<dlq-arn>`,
    risk: "Low risk — adding a DLQ does not change successful invocation behaviour. Monitor DLQ depth after enabling.",
  },
  "rds.instance.no_deletion_protection": {
    why: "Without deletion protection, a mistaken `delete-db-instance` call (human error, bad automation, or compromised credentials) permanently destroys the database.",
    console: [
      "Open RDS → Databases → select the instance",
      'Click "Modify"',
      "Enable Deletion protection",
      'Apply immediately or during the next maintenance window',
    ],
    cli: `aws rds modify-db-instance \\
  --db-instance-identifier <instance-id> \\
  --region <region> \\
  --deletion-protection \\
  --apply-immediately`,
    risk: "Deletion protection must be disabled before intentional deletion — this is the intended safety trade-off.",
  },
  "rds.instance.no_multi_az": {
    why: "Single-AZ RDS has no automatic failover during host failure or maintenance. Multi-AZ provides synchronous standby replication and automatic failover, typically within 60–120 seconds.",
    console: [
      "Open RDS → Databases → select the instance",
      'Click "Modify"',
      "Enable Multi-AZ deployment",
      "Review the maintenance window — conversion causes a brief failover (~60s downtime)",
      'Apply during a planned maintenance window',
    ],
    cli: `aws rds modify-db-instance \\
  --db-instance-identifier <instance-id> \\
  --region <region> \\
  --multi-az \\
  --apply-immediately`,
    risk: "Enabling Multi-AZ doubles instance cost and triggers a failover with brief downtime. Plan a maintenance window.",
  },
  "secretsmanager.secret.no_rotation": {
    why: "Secrets without automatic rotation stay static indefinitely. Long-lived database passwords and API keys are harder to revoke and more valuable if leaked.",
    console: [
      "Open Secrets Manager → select the secret",
      'Click "Edit rotation"',
      "Enable automatic rotation and choose an interval (e.g. 30 days)",
      "Select or create a Lambda rotation function for the secret type",
      "Run a test rotation to confirm the secret updates and downstream apps reconnect",
    ],
    cli: `# Enable rotation (requires a rotation Lambda — use AWS-managed templates where available)
aws secretsmanager rotate-secret \\
  --secret-id <secret-name> \\
  --region <region> \\
  --rotation-lambda-arn <rotation-lambda-arn> \\
  --rotation-rules AutomaticallyAfterDays=30`,
    risk: "First rotation updates the live secret — verify applications read the latest version from Secrets Manager, not a cached copy.",
  },
  "ssm.parameter.plaintext_secret": {
    why: "This SSM parameter is stored as plaintext String type but its name suggests it holds a secret. Plaintext parameters appear in API responses, CloudTrail logs, and console views without decryption controls.",
    console: [
      "Open Systems Manager → Parameter Store → select the parameter",
      "Create a new SecureString parameter with the same value (KMS-encrypted)",
      "Update applications to read the SecureString parameter",
      "Delete the plaintext parameter after migration",
    ],
    cli: `# Read current value, write as SecureString, then delete original
VALUE=$(aws ssm get-parameter --name <parameter-name> --region <region> --query Parameter.Value --output text)

aws ssm put-parameter \\
  --name <parameter-name> \\
  --region <region> \\
  --type SecureString \\
  --value "$VALUE" \\
  --overwrite`,
    risk: "Rotating to SecureString changes the parameter type in place with --overwrite, but verify apps handle SecureString decryption (kms:Decrypt may be required).",
  },
  "elb.load_balancer.no_access_logs": {
    why: "Load balancer access logs record every request — source IP, path, response code, and TLS cipher. Without them, investigating abuse or debugging routing issues requires guesswork.",
    console: [
      "Create an S3 bucket to receive access logs (separate from application data)",
      "Open EC2 → Load Balancers → select the load balancer",
      'Click "Attributes" → Edit → Access logs',
      "Enable logging, specify the S3 bucket and prefix",
      "Ensure the bucket policy grants ELB log delivery permission for your region",
    ],
    cli: `aws elbv2 modify-load-balancer-attributes \\
  --load-balancer-arn <load-balancer-arn> \\
  --region <region> \\
  --attributes Key=access_logs.s3.enabled,Value=true Key=access_logs.s3.bucket,Value=<bucket-name> Key=access_logs.s3.prefix,Value=elb-logs/`,
    risk: "Low risk — logging adds S3 storage cost. Set a lifecycle policy on the log bucket to expire old logs.",
  },
  "elb.load_balancer.weak_tls_policy": {
    why: "The load balancer uses a legacy SSL/TLS policy that allows outdated cipher suites (TLS 1.0/1.1, weak ciphers). Modern clients and compliance frameworks require TLS 1.2+.",
    console: [
      "Open EC2 → Load Balancers → select the load balancer",
      'Open the "Listeners" tab → select the HTTPS/TLS listener → Edit',
      "Change the security policy to ELBSecurityPolicy-TLS13-1-2-2021-06 or TLS-1-2-2017-01 minimum",
      "Save and verify client connectivity from your oldest supported browsers/API clients",
    ],
    cli: `aws elbv2 modify-listener \\
  --listener-arn <listener-arn> \\
  --region <region> \\
  --ssl-policy ELBSecurityPolicy-TLS13-1-2-2021-06`,
    risk: "Stricter TLS policies break legacy clients still on TLS 1.0/1.1 — test with your oldest production clients before applying.",
  },
  "sns.topic.no_encryption": {
    why: "SNS topics without KMS encryption deliver messages in plaintext at rest. Any principal with sns:Subscribe or CloudWatch log access can read message contents.",
    console: [
      "Open SNS → Topics → select the topic",
      'Click "Edit" → expand "Encryption"',
      "Enable encryption with the AWS managed key (alias/aws/sns) or a customer-managed KMS key",
      "Update publisher/subscriber IAM policies to include kms:Decrypt and kms:GenerateDataKey if using a CMK",
    ],
    cli: `aws sns set-topic-attributes \\
  --topic-arn <topic-arn> \\
  --region <region> \\
  --attribute-name KmsMasterKeyId \\
  --attribute-value alias/aws/sns`,
    risk: "Enabling encryption requires publishers and subscribers to have KMS permissions — test publish/subscribe after enabling.",
  },
  "sqs.queue.no_encryption": {
    why: "SQS queues without KMS encryption store messages in plaintext at rest. Queue contents may include PII, tokens, or job payloads visible to anyone with sqs:ReceiveMessage.",
    console: [
      "Open SQS → Queues → select the queue",
      'Click "Edit" → expand "Encryption"',
      "Enable server-side encryption with the AWS managed key (alias/aws/sqs) or a customer-managed KMS key",
      "Update producer/consumer IAM roles with kms:Decrypt and kms:GenerateDataKey if using a CMK",
    ],
    cli: `aws sqs set-queue-attributes \\
  --queue-url <queue-url> \\
  --region <region> \\
  --attributes KmsMasterKeyId=alias/aws/sqs`,
    risk: "Enabling encryption on a live queue requires KMS permissions on all producers and consumers — test end-to-end after enabling.",
  },
  "iam.account.no_support_role": {
    why: "CIS expects a dedicated path to open and manage AWS Support cases. Without a role that has AWSSupportAccess, teams often fall back to root or over-privileged users.",
    console: [
      "Open IAM → Roles → Create role",
      "Select AWS account as trusted entity",
      "Attach the AWS managed policy AWSSupportAccess",
      "Name the role (e.g. AWSSupportRole) and create it",
      "Grant assume-role only to break-glass users or your SSO permission set",
    ],
    cli: `aws iam create-role --role-name AWSSupportRole \\
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::ACCOUNT_ID:root"},"Action":"sts:AssumeRole"}]}'
aws iam attach-role-policy --role-name AWSSupportRole \\
  --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess`,
    risk: "Low severity — operational friction during incidents, not direct exposure.",
  },
  "iam.account.password_policy_weak": {
    why: "A weak account password policy means IAM users can set short, simple, or reused passwords. Attackers who obtain one password may rotate through accounts trivially.",
    console: [
      "Open IAM → Account settings",
      'Under "Password policy", click "Edit"',
      "Set minimum length to 14, enable uppercase, lowercase, numbers, and symbols",
      "Set password expiration to 90 days and password reuse prevention to 24",
      'Click "Save changes"',
    ],
    cli: `aws iam update-account-password-policy \\
  --minimum-password-length 14 \\
  --require-uppercase-characters \\
  --require-lowercase-characters \\
  --require-numbers \\
  --require-symbols \\
  --allow-users-to-change-password \\
  --max-password-age 90 \\
  --password-reuse-prevention 24`,
    risk: "Weak password policy increases the blast radius of credential-stuffing attacks on console users.",
  },
  "aws.access_analyzer.not_enabled": {
    why: "IAM Access Analyzer continuously monitors resource policies to identify when resources are shared with external principals. Without it, over-permissive cross-account access goes undetected.",
    console: [
      "Open IAM → Access Analyzer",
      'Click "Create analyzer"',
      'Set Zone of trust to "Current account", provide a name',
      'Click "Create analyzer"',
      "Repeat for each region where you have resources",
    ],
    cli: `# Enable in each region
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  aws accessanalyzer create-analyzer \\
    --analyzer-name vigil-analyzer \\
    --type ACCOUNT \\
    --region $region 2>/dev/null || true
done`,
    risk: "Without Access Analyzer you have no automated detection when S3 buckets, KMS keys, or IAM roles are made accessible to external accounts.",
  },
  "aws.config.not_enabled": {
    why: "AWS Config records configuration changes to AWS resources over time. Without it there is no change history — auditors cannot verify that a control was in place before an incident, and you cannot roll back to a known-good state.",
    console: [
      "Open AWS Config → Get started",
      "Select 'Record all resources supported in this region'",
      "Create or select an S3 bucket for Config history storage",
      "Create an SNS topic for delivery notifications (optional)",
      'Click "Next" → "Confirm"',
      "Repeat for each active region",
    ],
    cli: `# Create S3 bucket for Config delivery
aws s3 mb s3://config-history-$(aws sts get-caller-identity --query Account --output text)

# Create a Config recorder and delivery channel
aws configservice put-configuration-recorder \\
  --configuration-recorder name=default,roleARN=<config-role-arn>

aws configservice put-delivery-channel \\
  --delivery-channel name=default,s3BucketName=<bucket>

aws configservice start-configuration-recorder --configuration-recorder-name default`,
    risk: "No Config means no configuration change history — a gap auditors will flag and a blocker for SOC 2 CC6.1.",
  },
  "guardduty.open_findings": {
    why: "GuardDuty is enabled but has active (non-archived) findings. Enablement alone does not mean threats are resolved — auditors expect triage and remediation evidence.",
    console: [
      "Open GuardDuty → Findings",
      "Review active findings by severity",
      "Archive false positives with justification; remediate confirmed threats",
      "Document owner and resolution in your incident tracker",
    ],
    cli: `aws guardduty list-findings --detector-id <detector-id> --finding-criteria '{"Criterion":{"archived":{"Eq":["false"]}}}'`,
    risk: "Unaddressed GuardDuty findings may indicate active compromise or misconfiguration.",
  },
  "aws.config.rules_non_compliant": {
    why: "AWS Config is recording but one or more managed rules report NON_COMPLIANT. Enablement without passing rules is insufficient for change-management evidence.",
    console: [
      "Open AWS Config → Rules",
      "Filter by Non-compliant",
      "Remediate each resource or document approved exception",
      "Re-evaluate until compliant or excepted",
    ],
    cli: `aws configservice describe-compliance-by-config-rule --config-rule-names <rule-name>`,
    risk: "Drift from your security baseline may go unnoticed until audit sampling.",
  },
  "ec2.ami.aged": {
    why: "The AMI backing an instance exceeds the age threshold (patch baseline proxy). Stale AMIs often lack current OS patches.",
    console: [
      "Identify instances launched from aged AMIs",
      "Build or adopt a newer hardened AMI",
      "Replace instances via rolling deploy or ASG refresh",
    ],
    cli: `aws ec2 describe-images --owners self --image-ids <ami-id>`,
    risk: "Known CVEs in the base image may affect every instance launched from this AMI.",
  },
  "iam.access_inventory_gap": {
    why: "Vigil could not reconcile IAM users, roles, and access keys against a complete inventory (missing collectors or partial scan).",
    console: [
      "Confirm the scan role can list IAM (users, roles, keys)",
      "Re-run a full account scan from Vigil",
      "Compare IAM console user count to Vigil collected count",
    ],
    cli: `aws iam get-account-summary`,
    risk: "Access reviews and evidence packs may omit principals until inventory is complete.",
  },
  "iam.role.full_admin_policy": {
    why: "A customer-managed policy attached to this role grants Action:* on Resource:* (full administrative access). CIS 1.22 targets this pattern specifically.",
    console: [
      "Open IAM → Roles → select the role",
      "Review inline and customer-managed attached policies",
      "Replace full-admin policies with least-privilege statements",
      "Use IAM Access Analyzer or Vigil usage data to scope actions",
    ],
    cli: `aws iam list-attached-role-policies --role-name <role-name>
aws iam get-policy-version --policy-arn <arn> --version-id <v>`,
    risk: "Any principal that can assume this role has unrestricted account control.",
  },
  "github.repo.no_codeowners": {
    why: "Optional security check: no CODEOWNERS file in standard Git repo paths. SOC 2 change management typically relies on branch protection and required reviews, not CODEOWNERS.",
    console: [
      "Add CODEOWNERS under `/`, `.github/`, or `docs/` if your policy requires code-owner reviews",
      "Or disable under Detection coverage → Optional security checks (git.repo.no_codeowners)",
    ],
    cli: `# Create .github/CODEOWNERS with team ownership lines`,
    risk: "Without CODEOWNERS, code-owner review rules cannot be enforced for this repository.",
  },
  "gitlab.repo.no_codeowners": {
    why: "Optional security check: no CODEOWNERS file in standard Git project paths. SOC 2 change management typically relies on branch protection and required merge request approvals, not CODEOWNERS.",
    console: [
      "Add CODEOWNERS at repo root, `.gitlab/CODEOWNERS`, or `docs/CODEOWNERS` if your policy requires code-owner approvals",
      "Or disable under Detection coverage → Optional security checks (git.repo.no_codeowners)",
    ],
    cli: `# Create CODEOWNERS or .gitlab/CODEOWNERS with team ownership lines`,
    risk: "Without CODEOWNERS, code-owner approval rules cannot be enforced for this project.",
  },
  "aws.securityhub.not_enabled": {
    why: "Security Hub centralizes AWS security findings and posture checks across regions. Without it, security signals stay fragmented across services and are harder to evidence consistently.",
    console: [
      "Open Security Hub in each affected region listed in Scan details",
      'Click "Go to Security Hub" or "Enable Security Hub"',
      "Enable the AWS Foundational Security Best Practices standard",
      "Repeat for each active region, or enable centrally with AWS Organizations",
    ],
    cli: `# Enable Security Hub in each region
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  aws securityhub enable-security-hub --region $region 2>/dev/null || true
done`,
    risk: "Without Security Hub, posture checks and service findings are not centralized, making investigation and audit evidence weaker.",
  },
  "ec2.security_group.default_allows_traffic": {
    why: "The default security group is automatically assigned to new instances and network interfaces if no explicit group is specified. If it has rules, any accidentally unconfigured resource inherits inbound or outbound access — often unintentionally.",
    console: [
      "Open EC2 → Security Groups, filter for 'default'",
      "Select the default security group for each VPC",
      'Under "Inbound rules", select all rules → "Delete"',
      'Under "Outbound rules", select all rules → "Delete"',
      "Assign traffic to named security groups on your existing instances",
    ],
    cli: `# List rules on the default SG
SG_ID=$(aws ec2 describe-security-groups \\
  --filters Name=group-name,Values=default Name=vpc-id,Values=<vpc-id> \\
  --query 'SecurityGroups[0].GroupId' --output text)

# Remove all inbound rules
aws ec2 revoke-security-group-ingress --group-id $SG_ID \\
  --ip-permissions "$(aws ec2 describe-security-groups --group-ids $SG_ID \\
    --query 'SecurityGroups[0].IpPermissions' --output json)"

# Remove all outbound rules
aws ec2 revoke-security-group-egress --group-id $SG_ID \\
  --ip-permissions "$(aws ec2 describe-security-groups --group-ids $SG_ID \\
    --query 'SecurityGroups[0].IpPermissionsEgress' --output json)"`,
    risk: "Removing rules from the default SG affects instances that rely on it — verify instance SG assignments before making changes.",
  },
  "ec2.instance.imdsv2_not_required": {
    why: "IMDSv1 is vulnerable to Server-Side Request Forgery (SSRF): an attacker who exploits a web app can request http://169.254.169.254/ and retrieve temporary IAM credentials. IMDSv2 requires a session token obtained via PUT, breaking this attack.",
    console: [
      "Open EC2 → Instances → select the instance",
      'Click "Actions" → "Instance settings" → "Modify instance metadata options"',
      'Set "IMDSv2" to "Required"',
      'Set "Metadata response hop limit" to 1',
      'Click "Save"',
    ],
    cli: `aws ec2 modify-instance-metadata-options \\
  --instance-id <instance-id> \\
  --http-tokens required \\
  --http-put-response-hop-limit 1 \\
  --http-endpoint enabled`,
    risk: "Requiring IMDSv2 only breaks applications that use the old IMDSv1 path without a session token — test in non-prod first.",
  },
  "ec2.ebs.encryption_not_default": {
    why: "Without the default encryption setting, any EBS volume created without an explicit KMS key is unencrypted. Developers and launch templates that omit the encryption flag silently create unencrypted volumes.",
    console: [
      "Open EC2 → Settings (under Account attributes)",
      'Under "EBS encryption", click "Manage"',
      'Check "Enable" and select a default KMS key',
      'Click "Update EBS encryption"',
      "Repeat for each region where you launch EC2 instances",
    ],
    cli: `# Enable default encryption in each region
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  aws ec2 enable-ebs-encryption-by-default --region $region
  echo "Enabled in $region"
done`,
    risk: "This only affects new volumes — existing unencrypted volumes require a snapshot copy with encryption enabled to remediate.",
  },
  "ec2.ebs.volume_unencrypted": {
    why: "Existing unencrypted EBS volumes keep data at rest outside your encryption baseline. Enabling encryption by default does not retrofit current volumes.",
    console: [
      "Open EC2 → Volumes and select the affected volume",
      'Click "Actions" → "Create snapshot"',
      "Open Snapshots, select the new snapshot, then copy it with encryption enabled",
      "Create a new volume from the encrypted snapshot",
      "Detach the old volume and attach the encrypted replacement during a maintenance window",
    ],
    cli: `# Step 1: Snapshot the unencrypted volume
aws ec2 create-snapshot --volume-id <volume-id> --description "Encrypt <volume-id>"

# Step 2: Copy snapshot with encryption (use snapshot ID from step 1)
aws ec2 copy-snapshot \\
  --source-region <region> \\
  --source-snapshot-id <snapshot-id> \\
  --encrypted

# Step 3: Create encrypted volume (same AZ as the original)
aws ec2 create-volume \\
  --snapshot-id <encrypted-snapshot-id> \\
  --availability-zone <az>`,
    risk: "Replacing an attached volume can require downtime. Confirm the attachment, mount point, filesystem, and backup plan before cutover.",
  },
};

const identityRemediations: Record<string, Remediation> = {
  "github.org.mfa_not_enforced": {
    why: "Without MFA enforcement, any compromised GitHub account password gives an attacker full write access to your repositories. A single phished developer can push malicious code or delete branches with no second factor stopping them.",
    console: [
      "Go to your GitHub organization page",
      'Click "Settings" → "Authentication security"',
      'Enable "Require two-factor authentication for everyone in your organization"',
      "Members without MFA will be removed and must re-enroll to rejoin",
    ],
    cli: "",
    risk: "Without org-level MFA enforcement, individual members can disable their own MFA and retain full access.",
  },
  "github.org.dormant_members": {
    why: "Dormant members hold valid tokens and SSH keys even when they've left the project or company. Attackers who obtain stale credentials can act as a legitimate insider with no unusual login pattern to detect.",
    console: [
      "Go to your GitHub organization → People",
      'Filter by "Dormant members" or sort by last activity',
      "Review each member and confirm whether they still need access",
      'Remove members who are no longer active via "Remove from organization"',
    ],
    cli: "",
    risk: "Stale memberships are a common vector in insider-threat and ex-employee compromise scenarios.",
  },
  "github.org.outside_collaborators": {
    why: "Outside collaborators are non-organization members who have been granted direct repository access. Unlike org members, their activity is less visible to administrators — they don't appear in org-level member lists and may retain access after a project ends or after they change employers.",
    console: [
      "Go to your GitHub organization → People → Outside collaborators",
      "Review each collaborator — confirm they still need access and which repos they can access",
      "To remove a collaborator: click the three-dot menu → Remove from all repositories",
      "If they still need access, consider inviting them as an org member for better visibility",
    ],
    cli: "",
    risk: "Outside collaborators with stale access can push code, read sensitive repositories, and exfiltrate data without appearing in standard member audit reports.",
  },
  "github.repo.no_branch_protection": {
    why: "Without branch protection, any contributor can push directly to the default branch — bypassing code review, CI checks, and deployment gates. This makes it trivial to introduce unauthorized changes or backdoors.",
    console: [
      "Go to the repository → Settings → Branches",
      'Click "Add rule" under "Branch protection rules"',
      'Enter the default branch name (e.g. "main")',
      'Enable "Require a pull request before merging" and "Require approvals"',
      'Optionally enable "Require status checks" and "Restrict who can push"',
    ],
    cli: "",
    risk: "Unprotected branches allow unauthorized commits to reach production without review or audit trail.",
  },
  "github.repo.no_env_protection": {
    why: "GitHub deployment environments without required reviewers allow workflows to deploy to production without any human approval gate. This bypasses the change management control that ensures at least one person signs off before code reaches production.",
    console: [
      "Go to the repository → Settings → Environments",
      "Click on the environment (e.g. 'production', 'staging')",
      'Enable "Required reviewers" and add the team or individuals who must approve deployments',
      "Set a wait timer if appropriate to prevent immediate re-runs",
      "Save the protection rules",
    ],
    cli: "",
    risk: "Without required reviewers on deployment environments, any GitHub Actions workflow can ship to production without human sign-off — violating SOC2 CC8.1 change management controls.",
  },
  "github.repo.self_merge_allowed": {
    why: "Allowing authors to merge their own pull requests removes the peer review step that catches bugs, backdoors, and security regressions. It is the single most common change-management gap flagged in SOC2 CC8.1 audits.",
    console: [
      "Go to the repository → Settings → Branches",
      "Edit the branch protection rule for your default branch",
      'Enable "Require approvals" and set minimum reviewers to at least 1',
      'Enable "Dismiss stale pull request approvals when new commits are pushed"',
      "Confirm the PR author cannot satisfy the approval requirement",
    ],
    cli: "",
    risk: "Self-merged code bypasses the peer review control required by SOC2 CC8.1 and most change management policies.",
  },
  "github.repo.insufficient_reviews": {
    why: "Merging with fewer approvals than required means the review policy is either misconfigured or being bypassed. Each approval gap is a break in the change-management evidence chain auditors will sample.",
    console: [
      "Go to the repository → Settings → Branches",
      "Edit the branch protection rule for your default branch",
      'Increase "Required approving reviews" to at least 1 (ideally 2)',
      'Enable "Dismiss stale pull request approvals when new commits are pushed"',
      "Review recent merges that bypassed the policy and document exceptions",
    ],
    cli: "",
    risk: "Each under-reviewed merge is a gap in change-management evidence and an opportunity for unauthorized code to reach production.",
  },
  "gitlab.org.mfa_not_enforced": {
    why: "Without group-level MFA enforcement, any compromised GitLab account password gives full write access to your projects. A single phished developer can push malicious code or bypass protected branch rules.",
    console: [
      "Go to your GitLab group → Settings → General",
      'Expand "Permissions and group features"',
      'Enable "Require all users in this group to set up two-factor authentication"',
      "Set a grace period, then enforce — non-compliant members will be locked out until they enroll",
    ],
    cli: "",
    risk: "Without group-level MFA, individual members can remove their own 2FA and retain full repository access.",
  },
  "gitlab.org.dormant_members": {
    why: "Dormant group members retain valid tokens and SSH keys even after leaving the project. Stale access tokens have no expiry by default in GitLab and can be used by an attacker indefinitely.",
    console: [
      "Go to your GitLab group → Members",
      "Sort by 'Last activity' to identify inactive members",
      "Review each dormant member and confirm whether they still need access",
      'Remove inactive members via "Remove member"',
      "Consider enabling token expiration policies for personal access tokens",
    ],
    cli: "",
    risk: "Dormant accounts with persistent tokens are a high-value target for credential-stuffing and ex-employee access.",
  },
  "gitlab.repo.no_branch_protection": {
    why: "Without protected branches, any developer with Maintainer or Owner access can push directly to the default branch, bypassing code review and CI pipelines. This breaks the change-management control chain.",
    console: [
      "Go to the project → Settings → Repository → Protected branches",
      'Click "Protect a branch"',
      'Enter the default branch name (e.g. "main")',
      'Set "Allowed to merge" to "Maintainers" and "Allowed to push" to "No one"',
      'Enable "Code owner approval" if CODEOWNERS is configured',
    ],
    cli: "",
    risk: "Unprotected branches allow direct pushes to production branches without review or audit evidence.",
  },
  "gitlab.repo.self_merge_allowed": {
    why: "When MR authors can merge their own requests, the peer review step that catches bugs and unauthorized changes is eliminated. GitLab's approval rules must explicitly prevent author self-approval to satisfy SOC2 CC8.1.",
    console: [
      "Go to the project → Settings → Merge requests",
      'Enable "Merge request approvals" and set "Required approvals" to at least 1',
      'Enable "Prevent approval by the author" under approval settings',
      'Enable "Prevent approvals by users who add commits"',
      "Save the settings and re-review any pending MRs",
    ],
    cli: "",
    risk: "Author self-approval bypasses the segregation-of-duties control and will fail a SOC2 CC8.1 evidence review.",
  },
  "gitlab.repo.insufficient_reviews": {
    why: "MRs merged below the required approval threshold mean the policy is being bypassed or is misconfigured. Each under-approved merge is a gap in the change-management evidence chain.",
    console: [
      "Go to the project → Settings → Merge requests",
      'Set "Required approvals" to at least 1 (ideally 2 for critical branches)',
      'Enable "Reset approvals on push" to prevent stale approvals',
      "Review the approval rules to ensure they cannot be overridden by project members",
      "Audit recent MRs and document any approved exceptions",
    ],
    cli: "",
    risk: "Under-reviewed merges are evidence gaps that auditors will flag during SOC2 CC8.1 sampling.",
  },
};

function fallbackRemediationFor(checkId: string): Remediation {
  if (checkId.startsWith("iam.role.")) {
    return {
      why: "Review this IAM role's trust and permission policies against your access standards.",
      console: [
        "Open IAM → Roles → select the role",
        'Review "Trust relationships" and "Permissions"',
        "Confirm the configuration matches an approved integration or workload",
      ],
      cli: `aws iam get-role --role-name <role-name>
aws iam list-attached-role-policies --role-name <role-name>
aws iam list-role-policies --role-name <role-name>`,
      risk: "Over-permissive or broadly trusted roles expand blast radius if assumed by the wrong principal.",
    };
  }
  if (checkId.startsWith("iam.user.")) {
    return {
      why: "Review this IAM user's access (console, MFA, keys, and policies).",
      console: ["Open IAM → Users → select the user", 'Review "Security credentials" and "Permissions"'],
      cli: "aws iam get-user --user-name <user>\naws iam list-mfa-devices --user-name <user>\naws iam list-access-keys --user-name <user>",
      risk: "Unresolved identity findings increase risk of unauthorized console or API access.",
    };
  }
  if (checkId.startsWith("ec2.security_group.")) {
    return {
      why: "Review this security group's rules and which ENIs/instances reference it.",
      console: ["Open EC2 → Security Groups → select the group", "Review inbound and outbound rules and the Resources tab"],
      cli: "aws ec2 describe-security-groups --group-ids <sg-id>",
      risk: "Security group changes can immediately affect network reachability for attached resources.",
    };
  }
  return {
    why: "Review this finding and take corrective action based on your security policy.",
    console: ["Open the AWS Console", "Locate the affected resource", "Compare configuration to your baseline"],
    cli: "# Use the service CLI for this resource type — see AWS docs for the matching describe-* API",
    risk: "Unresolved findings increase your attack surface.",
  };
}

const SERVICE_PILL_COLLAPSED_LIMIT = 24;

function ServiceListExpandToggle({
  expanded,
  total,
  hiddenCount,
  onToggle,
}: {
  expanded: boolean;
  total: number;
  hiddenCount: number;
  onToggle: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onToggle}
      className="mb-2 text-xs font-medium text-zinc-500 transition-colors hover:text-zinc-800"
    >
      {expanded ? "Show less" : `Show all ${total} services (${hiddenCount} more)`}
    </button>
  );
}

type GrantedServicePill = {
  name: string;
  last_used: string | null;
  days_ago: number | null;
  active: boolean;
};

function GrantedServicePills({ services }: { services: GrantedServicePill[] }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {services.map((s) => (
        <span
          key={s.name}
          title={s.last_used ? `Last used ${s.days_ago}d ago` : "Never used"}
          className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium ${
            s.active ? "border-red-200 bg-red-50 text-red-700" : "border-zinc-200 bg-zinc-50 text-zinc-500"
          }`}
        >
          <span className={`h-1.5 w-1.5 rounded-full ${s.active ? "bg-red-400" : "bg-zinc-300"}`} />
          {s.name}
          {s.days_ago !== null && <span className="opacity-60">{s.days_ago}d</span>}
        </span>
      ))}
    </div>
  );
}

function CollapsibleGrantedServices({ services }: { services: GrantedServicePill[] }) {
  const [expanded, setExpanded] = useState(false);
  const collapsible = services.length > SERVICE_PILL_COLLAPSED_LIMIT;
  const visible = collapsible && !expanded ? services.slice(0, SERVICE_PILL_COLLAPSED_LIMIT) : services;
  const hiddenCount = services.length - SERVICE_PILL_COLLAPSED_LIMIT;

  return (
    <div>
      {collapsible && (
        <ServiceListExpandToggle
          expanded={expanded}
          total={services.length}
          hiddenCount={hiddenCount}
          onToggle={() => setExpanded((v) => !v)}
        />
      )}
      <GrantedServicePills services={visible} />
    </div>
  );
}

function generatePolicyIntro(cloudTrailLogging: boolean) {
  const build =
    "Build suggestion uses IAM last-accessed data and, when available, the latest completed AWS CloudTrail policy-generation job for this role. It does not start a new AWS analysis.";
  const resource = cloudTrailLogging
    ? "Use “Start CloudTrail analysis” below when you need a fresher job; resource ARNs are only applied when AWS returns concrete (non-template) ARNs."
    : "Without CloudTrail logging, action scope comes from IAM last-accessed only; resources stay *.";
  return `${build} ${resource}`;
}

function KeyActivityCard({ keyData }: { keyData: { key_id: string; last_used: string | null; days_ago: number | null; last_used_service: string | null; last_used_region: string | null; active: boolean } }) {
  const service = keyData.last_used_service ?? "unknown service";
  const region = keyData.last_used_region ?? "unknown region";
  const age = keyData.days_ago != null ? `${keyData.days_ago}d ago` : "recently";

  return (
    <div className={`rounded-lg border px-3 py-2.5 text-xs ${keyData.active ? "border-red-100 bg-red-50" : "border-zinc-200 bg-zinc-50"}`}>
      <div className="font-mono font-semibold text-zinc-700">{keyData.key_id}</div>
      {keyData.last_used ? (
        <>
          <div className="mt-1 text-[11px] font-semibold uppercase tracking-wide text-zinc-400">Last API activity</div>
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            <span className="rounded-md border border-zinc-200 bg-white px-1.5 py-0.5 text-zinc-600">{service}</span>
            <span className="rounded-md border border-zinc-200 bg-white px-1.5 py-0.5 text-zinc-600">{region}</span>
            <span className="rounded-md border border-zinc-200 bg-white px-1.5 py-0.5 text-zinc-600">{age}</span>
          </div>
        </>
      ) : (
        <div className="mt-1 text-zinc-500">No recorded API activity</div>
      )}
    </div>
  );
}

const AWS_REGION_LABELS: Record<string, string> = {
  "af-south-1": "Cape Town",
  "ap-east-1": "Hong Kong",
  "ap-northeast-1": "Tokyo",
  "ap-northeast-2": "Seoul",
  "ap-northeast-3": "Osaka",
  "ap-south-1": "Mumbai",
  "ap-south-2": "Hyderabad",
  "ap-southeast-1": "Singapore",
  "ap-southeast-2": "Sydney",
  "ap-southeast-3": "Jakarta",
  "ap-southeast-4": "Melbourne",
  "ca-central-1": "Canada",
  "ca-west-1": "Calgary",
  "eu-central-1": "Frankfurt",
  "eu-central-2": "Zurich",
  "eu-north-1": "Stockholm",
  "eu-south-1": "Milan",
  "eu-south-2": "Spain",
  "eu-west-1": "Ireland",
  "eu-west-2": "London",
  "eu-west-3": "Paris",
  "il-central-1": "Tel Aviv",
  "me-central-1": "UAE",
  "me-south-1": "Bahrain",
  "mx-central-1": "Mexico",
  "sa-east-1": "São Paulo",
  "us-east-1": "N. Virginia",
  "us-east-2": "Ohio",
  "us-west-1": "N. California",
  "us-west-2": "Oregon",
};

function RegionPills({ regions }: { regions: string[] }) {
  const [expanded, setExpanded] = useState(false);
  const previewLimit = 8;
  const sorted = [...regions].sort((a, b) => (AWS_REGION_LABELS[a] ?? a).localeCompare(AWS_REGION_LABELS[b] ?? b));
  const hidden = sorted.length - previewLimit;
  const visible = expanded || hidden <= 0 ? sorted : sorted.slice(0, previewLimit);

  return (
    <div className="space-y-2">
      <div className="grid grid-cols-2 gap-2">
        {visible.map((code) => {
          const name = AWS_REGION_LABELS[code];
          return (
            <div
              key={code}
              title={code}
              className="flex min-w-0 items-center justify-between gap-2 rounded-lg border border-zinc-200 bg-zinc-50/80 px-2.5 py-2"
            >
              <span className="truncate text-xs font-medium text-zinc-800">{name ?? code}</span>
              {name && <span className="shrink-0 font-mono text-[10px] tabular-nums text-zinc-400">{code}</span>}
            </div>
          );
        })}
      </div>
      {hidden > 0 && (
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          className="text-xs font-medium text-indigo-600 hover:text-indigo-700"
        >
          {expanded ? "Show fewer regions" : `Show all ${sorted.length} regions`}
        </button>
      )}
    </div>
  );
}

function resolvedCli(finding: Finding, clientIp?: string | null): string {
  const arn = finding.resource_arn;
  const roleMatch = arn.match(/:role\/(.+)$/);
  const roleName = roleMatch ? (roleMatch[1].split("/").pop() ?? "") : "";
  const removable = finding.evidence.removable_statements as unknown[] | undefined;
  const hasInline = Array.isArray(removable) && removable.length > 0;
  if (finding.check_id === "iam.role.unused_services_90d" && !hasInline && roleName) {
    return `# Permissions come from managed/attached policies — inline policies have no matching statements.

# 1. See what's attached
aws iam list-attached-role-policies --role-name ${roleName}

# 2. For each attached policy, review its document
aws iam get-policy-version --policy-arn <policy-arn> --version-id v1

# 3. Start CloudTrail policy generation for this role (IAM console: Permissions tab, or API)
aws accessanalyzer start-policy-generation \\
  --policy-generation-details '{"principalArn":"${arn}"}' \\
  --cloud-trail-details '{"trails":["<trail-arn>"]}'

# 4. Poll for the generated policy (takes ~30s)
aws accessanalyzer get-generated-policy --job-id <job-id>`;
  }
  const rem = remediations[finding.check_id] ?? fallbackRemediationFor(finding.check_id);
  const placeholders = buildCliPlaceholders(finding, clientIp);
  let cli = applyCliPlaceholders(rem.cli, placeholders);
  cli = injectEc2RegionFlags(cli, placeholders["<region>"]);
  return formatCliStepSpacing(cli);
}

function RemediationCliBlock({ finding }: { finding: Finding }) {
  const { data: clientIp } = useQuery({
    queryKey: ["remediation-client-ip"],
    queryFn: fetchClientIpForRemediation,
    staleTime: 300_000,
  });
  const code = useMemo(
    () => resolvedCli(finding, clientIp ?? null),
    [finding.id, finding.check_id, finding.resource_arn, finding.evidence, clientIp],
  );
  return <CliBlock code={code} />;
}

type AttachedPolicyAnalysis = {
  policy_arn: string;
  policy_name: string;
  policy_type: "aws_managed" | "customer_managed";
  granted_services: string[];
  unused_services: string[];
  active_services: string[];
  has_wildcard_action: boolean;
  action: "detach_and_replace" | "edit";
};

function iamPolicyConsoleUrl(policyArn: string): string {
  return `https://console.aws.amazon.com/iam/home#/policies/details/${encodeURIComponent(policyArn)}`;
}

function iamRolePermissionsConsoleUrl(roleArn: string): string {
  const match = roleArn.match(/:role\/(.+)$/);
  const roleName = match ? match[1] : "";
  return `https://console.aws.amazon.com/iam/home#/roles/details/${encodeURIComponent(roleName)}?section=permissions`;
}

function ConsoleLink({ href, children, title }: { href: string; children: React.ReactNode; title: string }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      title={title}
      className="inline-flex flex-shrink-0 items-center gap-1 text-xs font-medium text-sky-600 hover:text-sky-800 hover:underline"
    >
      {children}
      <svg className="h-3 w-3 opacity-70" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
        <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25" />
      </svg>
    </a>
  );
}

type BlastRadiusData = {
  resource_type: string;
  confidence: "high" | "medium" | "low";
  // role fields
  days_since_last_assumed?: number | null;
  trust_principals?: string[];
  services?: { name: string; last_used: string | null; days_ago: number | null; active: boolean; in_policy: boolean }[];
  active_service_count?: number;
  unused_service_count?: number;
  has_inline_policies?: boolean;
  attached_policies?: AttachedPolicyAnalysis[];
  // access key fields
  keys?: { key_id: string; last_used: string | null; days_ago: number | null; last_used_service: string | null; last_used_region: string | null; active: boolean }[];
  // user fields
  has_console_password?: boolean;
  days_inactive?: number | null;
  active_key_count?: number;
  attached_policies?: { policy_arn: string; policy_name: string; policy_type?: string }[];
  inline_policy_names?: string[];
  // security group fields
  group_id?: string;
  group_name?: string;
  vpc_id?: string;
  region?: string;
  is_default?: boolean;
  affected_instances?: { instance_id: string; instance_type: string | null; state: string; vpc_id: string | null; name: string }[];
  running_count?: number;
  total_count?: number;
  // kms key fields
  key_id?: string;
  alias?: string | null;
  key_state?: string | null;
  rotation_enabled?: boolean;
  dependent_trails?: { name: string; arn: string; region: string; is_multi_region: boolean }[];
  dependent_trail_count?: number;
  // s3 bucket fields
  bucket_name?: string;
  encrypted?: boolean;
  kms_encrypted?: boolean;
  versioning_enabled?: boolean;
  public_access_blocked?: boolean;
  https_only?: boolean;
  logging_enabled?: boolean;
  // rds instance fields
  db_instance_id?: string;
  engine?: string | null;
  storage_encrypted?: boolean;
  publicly_accessible?: boolean;
  backup_retention_period?: number;
  // dynamodb table fields
  table_name?: string;
  pitr_enabled?: boolean;
  // ec2 instance fields
  instance_id?: string;
  instance_type?: string | null;
  state?: string;
  imdsv2_required?: boolean;
  // ebs volume fields
  volume_id?: string;
  size_gib?: number | null;
  volume_type?: string | null;
  attached_instances?: { instance_id: string; state: string; name: string; instance_type: string | null }[];
  // ebs encryption default fields
  existing_unencrypted_count?: number;
  // cloudtrail trail fields
  trail_name?: string;
  home_region?: string;
  is_multi_region?: boolean;
  is_logging?: boolean;
  log_validation_enabled?: boolean;
  kms_key_id?: string | null;
  trail_count?: number;
  existing_trails?: { name: string; home_region: string; is_multi_region: boolean; is_logging: boolean }[];
  // vpc fields (vpc_id and region reused from security_group fields above)
  instance_count?: number;
  // iam root / password policy fields
  min_length?: number | null;
  max_age?: number | null;
  password_reuse_prevention?: number | null;
  // s3 account block fields
  public_bucket_count?: number;
  public_bucket_names?: string[];
  // guardduty fields
  disabled_regions?: string[];
  // identity (GitHub/GitLab)
  provider_type?: string;
  org?: string;
  username?: string;
  source?: string;
  email?: string | null;
  mfa_enabled?: boolean | null;
  repo?: string;
  default_branch?: string;
  has_branch_protection?: boolean;
  required_reviews?: number;
  recent_merge_count?: number;
  active_member_count?: number;
  outside_collaborator_count?: number;
  // session-18 resource detail
  snapshot_id?: string;
  is_public?: boolean;
  image_id?: string;
  domain_name?: string;
  expires_at?: string | null;
  days_until_expiry?: number | null;
  function_name?: string;
  runtime?: string | null;
  has_dlq?: boolean;
  access_logs_enabled?: boolean;
  ssl_policy?: string | null;
  lb_type?: string | null;
  name?: string;
  warnings: string[];
};

const confidenceConfig = {
  high: { label: "Safe to remediate", color: "bg-emerald-50 text-emerald-700 border-emerald-200", dot: "bg-emerald-500", desc: "No active usage detected in the past 90 days." },
  medium: { label: "Review first", color: "bg-amber-50 text-amber-700 border-amber-200", dot: "bg-amber-400", desc: "Some recent activity detected — verify before making changes." },
  low: { label: "Active — proceed with caution", color: "bg-red-50 text-red-700 border-red-200", dot: "bg-red-500", desc: "Resource was actively used in the last 30 days." },
};

function buildVerdict(data: BlastRadiusData, checkId?: string): { text: string; type: "safe" | "caution" | "warning" } {
  const { resource_type, confidence } = data;

  if (resource_type === "iam_role") {
    const active = data.active_service_count ?? 0;
    const scopePolicy =
      checkId === "iam.role.full_admin_policy" ||
      checkId === "iam.role.wildcard_action" ||
      checkId === "iam.perm.granted_vs_used";
    if (scopePolicy) {
      if (confidence === "high") {
        return {
          text: "Low recent usage — scoping admin or wildcard grants is unlikely to break active workloads. Validate in non-prod before applying.",
          type: "safe",
        };
      }
      if (confidence === "medium") {
        return {
          text: `Proceed with caution — ${active} service${active !== 1 ? "s" : ""} show recent API use. Review the service list before narrowing permissions.`,
          type: "caution",
        };
      }
      return {
        text: `Do not scope blindly — ${active} service${active !== 1 ? "s" : ""} were actively used in the last 30 days. Check used actions and trust principals first.`,
        type: "warning",
      };
    }
    if (confidence === "high") {
      const never = data.days_since_last_assumed == null;
      return never
        ? { text: "Safe to remove — role has never been assumed and no active service usage detected.", type: "safe" }
        : { text: `Safe to remove — unassumed for ${data.days_since_last_assumed} days with no active service usage.`, type: "safe" };
    }
    if (confidence === "medium") {
      return { text: `Review before removing — ${active} service${active !== 1 ? "s" : ""} show recent activity. Verify the workload before making changes.`, type: "caution" };
    }
    return { text: `Do not remove without verification — ${active} service${active !== 1 ? "s" : ""} were actively used in the last 30 days.`, type: "warning" };
  }

  if (resource_type === "iam_access_key") {
    const key = data.keys?.[0];
    if (confidence === "high") {
      return key?.days_ago != null
        ? { text: `Safe to delete — key unused for ${key.days_ago} days.`, type: "safe" }
        : { text: "Safe to delete — key has never been used.", type: "safe" };
    }
    if (key?.last_used_service && key?.days_ago != null) {
      return { text: `Active key — last used ${key.days_ago} days ago via ${key.last_used_service}. Rotate carefully.`, type: "warning" };
    }
    return { text: "Active key — verify usage before rotating or deleting.", type: "warning" };
  }

  if (resource_type === "iam_user") {
    if (checkId === "iam.user.direct_policy_attachment") {
      return {
        text: "Move permissions to a group or role before detaching — confirm nothing still depends on these user-scoped grants.",
        type: "caution",
      };
    }
    if (checkId === "iam.user.no_mfa") {
      return {
        text: "Safe to require — MFA applies to console sign-in only; IAM access keys and programmatic access are unchanged until keys are rotated separately.",
        type: "safe",
      };
    }
    if (confidence === "high") {
      return data.days_inactive != null
        ? { text: `Safe to disable — user inactive for ${data.days_inactive} days.`, type: "safe" }
        : { text: "Safe to disable — no recorded activity for this user.", type: "safe" };
    }
    if (confidence === "low") return { text: "Active user — verify ownership and dependencies before disabling.", type: "warning" };
    return { text: "Review before disabling — some recent activity detected.", type: "caution" };
  }

  if (resource_type === "security_group") {
    const running = data.running_count ?? 0;
    const total = data.total_count ?? 0;
    if (running > 0) {
      return {
        text: `Restrict with care — ${running} running instance${running !== 1 ? "s" : ""} use this group (${total} total).`,
        type: "warning",
      };
    }
    if (total > 0) {
      if (data.is_default) {
        return {
          text: `${total} instance${total !== 1 ? "s" : ""} attached to this default SG (none running) — confirm explicit SG assignments before clearing rules.`,
          type: "caution",
        };
      }
      return {
        text: `${total} instance${total !== 1 ? "s" : ""} attached, none running — safe to modify.`,
        type: "caution",
      };
    }
    if (data.is_default) {
      return {
        text: "Safe to clear rules — no instances use this VPC's default security group. An empty default SG is recommended so future launches without an explicit group stay locked down.",
        type: "safe",
      };
    }
    return { text: "No instances attached to this security group — safe to update.", type: "safe" };
  }

  if (resource_type === "kms_key") {
    const state = (data.key_state ?? "").toLowerCase();
    if (state === "pendingdeletion") return { text: "Key is pending deletion — cancel deletion before enabling rotation.", type: "caution" };
    if (state === "disabled") return { text: "Key is disabled — re-enable the key before enabling rotation.", type: "caution" };
    return { text: "Safe to enable — KMS key rotation is transparent to applications. AWS retains old key material; no application changes required.", type: "safe" };
  }

  if (resource_type === "s3_bucket") {
    if (checkId === "s3.bucket.no_https_policy") {
      return {
        text: "Safe to enable — AWS SDKs, CLI, and Terraform already use HTTPS. Only clients with explicit http:// URLs would be denied.",
        type: "safe",
      };
    }
    if (confidence === "high") return { text: "Safe to enable — enabling S3 access logging has no impact on bucket access or application behaviour.", type: "safe" };
    if (confidence === "low") return { text: "Review before applying — bucket may have public access patterns that depend on current settings.", type: "warning" };
    return { text: "Verify before applying — this change may affect applications accessing the bucket. See warnings below.", type: "caution" };
  }

  if (resource_type === "rds_instance") {
    if (checkId === "rds.instance.no_multi_az") {
      return { text: "Enabling Multi-AZ causes a brief failover (~60s) and doubles cost — plan a maintenance window.", type: "caution" };
    }
    if (checkId === "rds.instance.no_deletion_protection") {
      return { text: "Safe to enable — deletion protection only blocks accidental deletes; intentional deletion requires disabling it first.", type: "safe" };
    }
    if (confidence === "low") return { text: "High blast radius — encrypting an RDS instance requires creating a new instance from an encrypted snapshot. Plan a maintenance window.", type: "warning" };
    if (confidence === "high") return { text: "Safe to enable — automated backups have no impact on application availability and can be enabled at any time.", type: "safe" };
    return { text: "Verify connectivity before applying — disabling public access removes the external endpoint. Ensure your app connects via VPC.", type: "caution" };
  }

  if (resource_type === "dynamodb_table") {
    if (checkId === "dynamodb.table.no_pitr") {
      return { text: "Safe to enable — point-in-time recovery is turned on in place with no downtime or application changes.", type: "safe" };
    }
    return { text: "Safe to enable — DynamoDB encryption at rest updates in place with no downtime. Reads and writes continue during the update.", type: "safe" };
  }

  if (resource_type === "ebs_snapshot") {
    if (checkId === "ec2.ebs.snapshot_public") {
      return { text: "Remove public access immediately — assume the snapshot may already have been copied externally.", type: "warning" };
    }
    return { text: "Safe to encrypt via snapshot copy — no running instances affected.", type: "safe" };
  }

  if (resource_type === "ec2_ami") {
    return { text: "Make private immediately — assume the image may have been copied. Rotate any secrets baked into the AMI.", type: "warning" };
  }

  if (resource_type === "acm_certificate") {
    if (confidence === "low") return { text: "Urgent — certificate expires within a week. Renew now to avoid HTTPS outages.", type: "warning" };
    return { text: "Plan renewal before expiry — update listeners/distributions after issuing a replacement certificate.", type: "caution" };
  }

  if (resource_type === "lambda_function") {
    if (checkId === "lambda.function.deprecated_runtime") {
      return { text: "Test runtime upgrade in a staging alias first — dependency incompatibilities are common.", type: "caution" };
    }
    return { text: "Safe to add — DLQ only captures failed async invocations; successful calls are unaffected.", type: "safe" };
  }

  if (resource_type === "secrets_manager_secret") {
    return { text: "First rotation updates the live secret — verify applications fetch the latest version from Secrets Manager.", type: "caution" };
  }

  if (resource_type === "ssm_parameter") {
    return { text: "Converting to SecureString is low-risk if apps already use the SSM API — confirm kms:Decrypt on consuming roles.", type: "caution" };
  }

  if (resource_type === "elb_load_balancer") {
    if (checkId === "elb.load_balancer.weak_tls_policy") {
      return { text: "Test with your oldest TLS clients before tightening the listener policy.", type: "caution" };
    }
    return { text: "Safe to enable — access logs add S3 storage cost only; no impact on traffic.", type: "safe" };
  }

  if (resource_type === "sns_topic" || resource_type === "sqs_queue") {
    return { text: "Enable encryption, then verify producers and consumers can still publish and receive messages.", type: "safe" };
  }

  if (resource_type === "ec2_instance") {
    return { text: "Verify application compatibility first — apps using IMDSv1 without a session token will fail. Test in non-prod before applying.", type: "caution" };
  }

  if (resource_type === "ebs_volume") {
    const running = data.running_count ?? 0;
    if (running > 0) return { text: `High blast radius — ${running} running instance(s) attached. Replacing the volume requires downtime unless it is a non-root, remountable volume.`, type: "warning" };
    if (confidence === "high") return { text: "No instances attached — safe to encrypt via snapshot copy with no downtime risk.", type: "safe" };
    return { text: "Instances attached but not running — plan volume replacement during maintenance.", type: "caution" };
  }

  if (resource_type === "ebs_encryption_default") {
    return { text: "Safe to enable — only affects volumes created after this change.", type: "safe" };
  }

  if (resource_type === "cloudtrail_trail") {
    if (checkId === "cloudtrail.trail.s3_bucket_public") {
      return { text: "Remove public access immediately — assume audit logs may have been exposed while the bucket was public.", type: "warning" };
    }
    if (checkId === "cloudtrail.trail.s3_bucket_no_logging") {
      return { text: "Safe to enable — S3 access logging on the log bucket adds visibility with no impact on CloudTrail delivery.", type: "safe" };
    }
    if (checkId === "cloudtrail.trail.no_cloudwatch_logs") {
      return { text: "Safe to enable — real-time alerting only; does not change existing S3 log delivery.", type: "safe" };
    }
    if (confidence === "high") return { text: "Safe to enable — no application impact. Note: CloudTrail storage in S3 incurs a small ongoing cost.", type: "safe" };
    return { text: "Verify CloudTrail's delivery role has the required KMS permissions before applying.", type: "caution" };
  }

  if (resource_type === "cloudtrail_account") {
    if ((data.trail_count ?? 0) === 0) {
      return { text: "No CloudTrail trails found — safe to create a new multi-region trail. No existing logging to disrupt.", type: "safe" };
    }
    return { text: "Existing trails don't meet the multi-region + logging requirement — enable a compliant trail or fix the ones below.", type: "caution" };
  }

  if (resource_type === "vpc") {
    const count = data.instance_count ?? 0;
    return count > 0
      ? { text: "Safe to enable — flow logs add visibility without affecting network traffic.", type: "safe" }
      : { text: "Safe to enable — no instances in this VPC yet.", type: "safe" };
  }

  if (resource_type === "iam_root") {
    if (confidence === "low") return { text: "Check all automation for root credentials before deleting — any process using these keys will immediately break.", type: "warning" };
    return { text: "Safe to apply — no application impact. This change only affects the root identity itself.", type: "safe" };
  }

  if (resource_type === "iam_password_policy") {
    if (confidence === "medium") return { text: "Users with passwords older than the new maximum age will be forced to reset at next login.", type: "caution" };
    return { text: "Safe to update — no current max age policy set, so no forced password resets will occur.", type: "safe" };
  }

  if (resource_type === "s3_account_block") {
    const count = data.public_bucket_count ?? 0;
    if (count > 0) return { text: `${count} bucket(s) are not yet blocking public access at the bucket level — enabling the account block will override them and may break public-read buckets or static websites.`, type: "warning" };
    return { text: "Safe to enable — all buckets already block public access at the bucket level. Account-level block adds a belt-and-suspenders guard.", type: "safe" };
  }

  if (resource_type === "guardduty" || resource_type === "aws_config" || resource_type === "securityhub" || resource_type === "access_analyzer") {
    return { text: "Safe to enable — adds security visibility without impacting existing resources or applications.", type: "safe" };
  }

  if (resource_type === "iam_policy_wildcard_resource") {
    return { text: "Scoping down Resource: * requires knowing which specific ARNs each action needs — test in non-prod before applying to production roles.", type: "caution" };
  }

  if (resource_type === "iam_policy_unattached") {
    return { text: "Safe to delete — policy is not attached to any principal and grants no access.", type: "safe" };
  }

  if (resource_type === "iam_perm_granted_vs_used") {
    if (confidence === "high") return { text: "No service usage recorded in 90 days — high confidence unused permissions can be removed safely.", type: "safe" };
    return { text: "Some services were recently used — verify application behaviour before removing unused permission grants.", type: "caution" };
  }

  if (resource_type === "identity_org") {
    if (checkId?.endsWith("outside_collaborators")) {
      return { text: "Review each outside collaborator — revoking access may break contractors, auditors, or CI bots using personal accounts.", type: "caution" };
    }
    if (checkId?.endsWith("mfa_not_enforced")) {
      return { text: "Org-wide MFA enforcement blocks password-only logins — members must enroll before next sign-in.", type: "caution" };
    }
    return { text: "Removing dormant members revokes access to all org repositories — confirm with owners first.", type: "caution" };
  }

  if (resource_type === "identity_user") {
    if (checkId?.endsWith("mfa_not_enforced")) {
      return { text: "Safe to require MFA — affects console login only; personal access tokens and SSH keys keep working until rotated.", type: "safe" };
    }
    return { text: "Suspending this member immediately revokes repository access — verify they are not on-call or release owner.", type: "caution" };
  }

  if (resource_type === "identity_repo") {
    if (checkId?.endsWith("no_branch_protection")) {
      return { text: "Branch protection blocks direct pushes to the default branch — coordinate with teams using hotfix workflows.", type: "caution" };
    }
    if (checkId?.endsWith("no_env_protection")) {
      return { text: "Environment protection pauses production deploys until approved — align with release managers before enabling.", type: "caution" };
    }
    if (checkId?.endsWith("self_merge_allowed") || checkId?.endsWith("insufficient_reviews")) {
      return { text: "Tighter review rules slow merges but reduce unreviewed code reaching default branch.", type: "caution" };
    }
    return { text: "Low risk — adding CODEOWNERS or review rules does not rewrite history or block existing open PRs.", type: "safe" };
  }

  if (confidence === "high") return { text: "No active usage detected — safe to remediate.", type: "safe" };
  if (confidence === "medium") return { text: "Some recent activity detected — review before making changes.", type: "caution" };
  return { text: "Active resource — proceed with caution.", type: "warning" };
}

const verdictStyle = {
  safe: { card: "border-emerald-200/80 bg-emerald-50/60", text: "text-emerald-900", icon: "text-emerald-500" },
  caution: { card: "border-zinc-200 bg-zinc-50", text: "text-zinc-800", icon: "text-amber-500" },
  warning: { card: "border-red-200/80 bg-red-50/70", text: "text-red-900", icon: "text-red-500" },
};

function VerdictIcon({ type }: { type: "safe" | "caution" | "warning" }) {
  if (type === "safe") return (
    <svg className="h-4 w-4 flex-shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
    </svg>
  );
  if (type === "caution") return (
    <svg className="h-4 w-4 flex-shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
    </svg>
  );
  return (
    <svg className="h-4 w-4 flex-shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
    </svg>
  );
}

function InfoNote({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-2 rounded-lg border border-zinc-200 bg-zinc-50 px-3 py-2.5 text-xs leading-relaxed text-zinc-600">
      <svg className="mt-0.5 h-3.5 w-3.5 flex-shrink-0 text-zinc-400" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
        <path strokeLinecap="round" strokeLinejoin="round" d="m11.25 11.25.041-.02a.75.75 0 0 1 1.063.852l-.708 2.836a.75.75 0 0 0 1.063.853l.041-.021M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-9-3.75h.008v.008H12V8.25Z" />
      </svg>
      <span>{children}</span>
    </div>
  );
}

function BlastRadiusSection({
  accountId,
  finding,
}: {
  accountId: string;
  finding: Finding;
}) {
  const [enabled, setEnabled] = useState(false);

  useEffect(() => {
    setEnabled(false);
  }, [finding.id, finding.check_id, finding.resource_arn]);

  const { data, isLoading, error } = useQuery<BlastRadiusData>({
    queryKey: ["blast-radius", accountId, finding.resource_arn, finding.check_id, finding.last_seen],
    queryFn: () => api(`/v1/accounts/${accountId}/blast-radius?resource_arn=${encodeURIComponent(finding.resource_arn)}&check_id=${encodeURIComponent(finding.check_id)}`),
    enabled,
    staleTime: 0,
  });

  if (!enabled) {
    return (
      <div className="rounded-xl border border-zinc-200 bg-white p-4 space-y-2">
        <div className="flex items-center justify-between gap-3">
          <div>
            <div className="text-sm font-semibold text-zinc-900">What If I fix this?</div>
            <div className="text-xs text-zinc-400 mt-0.5">
              Analyse what currently depends on this resource before remediating.
            </div>
          </div>
          <button
            type="button"
            onClick={() => setEnabled(true)}
            className="shrink-0 rounded-lg border border-zinc-200 bg-zinc-50 px-5 py-2.5 text-xs font-semibold text-zinc-700 transition-colors hover:bg-zinc-100"
          >
            Analyse
          </button>
        </div>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div
        className="flex flex-col items-center justify-center gap-3 py-12"
        role="status"
        aria-busy="true"
        aria-live="polite"
      >
        <svg
          className="h-5 w-5 animate-spin text-zinc-400"
          fill="none"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
        <p className="text-xs text-zinc-500">Analysing blast radius…</p>
      </div>
    );
  }
  if (error) {
    const message = formatApiError(error);
    const isNetwork =
      error instanceof TypeError ||
      (error instanceof Error && /failed to fetch|networkerror|load failed/i.test(error.message));
    return (
      <div className="rounded-xl border border-red-100 bg-red-50 p-4 text-xs text-red-500 space-y-1">
        <p>{message}</p>
        {isNetwork && (
          <p className="text-red-400">
            Check that the API is running and <code className="font-mono">VITE_API_URL</code> matches your setup
            (e.g. <code className="font-mono">http://localhost:8000</code> locally, or{" "}
            <code className="font-mono">https://api.vigil.cclab.cloud-castles.com</code> on the remote host).
          </p>
        )}
      </div>
    );
  }
  if (!data) return null;

  const verdict = buildVerdict(data, finding.check_id);
  const conf = confidenceConfig[
    finding.check_id === "s3.bucket.no_https_policy" || verdict.type === "safe"
      ? "high"
      : data.confidence
  ];
  const vs = verdictStyle[verdict.type];
  const normalizedVerdict = verdict.text.toLowerCase().replace(/\s+/g, " ").trim();
  function warningKey(text: string) {
    const n = text.toLowerCase().replace(/\s+/g, " ").trim();
    if ((n.includes("scoping down resource: *") || n.includes("scoping resource: *")) && (n.includes("specific arn") || n.includes("specific resource"))) {
      return "scope-resource-star";
    }
    if (n.includes("running instance") && (n.includes("downtime") || n.includes("replacing") || n.includes("detaching"))) {
      return "ebs-running-downtime";
    }
    if (n.includes("bucket") && n.includes("public access") && n.includes("account") && n.includes("block")) {
      return "s3-public-bucket-block";
    }
    return n;
  }
  const verdictKey = warningKey(normalizedVerdict);
  const seen = new Set<string>();
  const baseWarnings = (data.resource_type === "iam_access_key" ? [] : data.warnings).filter((warning) => {
    if (data.resource_type !== "iam_user") return true;
    const normalized = warning.toLowerCase();
    return !(normalized.startsWith("access key ") && normalized.includes(" used ") && normalized.includes(" deactivate keys before disabling user"));
  });
  const mfaOnlyUserCheck = finding.check_id === "iam.user.no_mfa";
  const keyUsageWarnings =
    !mfaOnlyUserCheck && data.resource_type === "iam_user" && data.keys
      ? data.keys
          .filter((k) => k.last_used && k.days_ago != null)
          .map(
            (k) =>
              `Access key ${k.key_id} shows API activity ${k.days_ago} days ago via ${k.last_used_service ?? "unknown service"}${k.last_used_region ? ` (${k.last_used_region})` : ""} — deactivate keys before disabling user`,
          )
      : [];
  const allNotices = mfaOnlyUserCheck ? [] : [...baseWarnings, ...keyUsageWarnings];
  const rootSafeMinimal = data.resource_type === "iam_root" && verdict.type === "safe";
  const infoRows = rootSafeMinimal ? [] : verdict.type === "safe" ? allNotices : [];
  const warningRows = rootSafeMinimal
    ? []
    : verdict.type === "safe"
      ? []
      : allNotices.filter((warning) => {
    const key = warningKey(warning);
    if (key === verdictKey) return false;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return (
    <div className="rounded-xl border border-zinc-200 bg-white overflow-hidden">
      <div className="flex items-center justify-between gap-2 border-b border-zinc-100 px-4 py-3.5">
        <span className="text-[15px] font-semibold text-zinc-900">Blast radius</span>
        <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold ${conf.color}`}>
          <span className={`h-1.5 w-1.5 rounded-full ${conf.dot}`} />
          {conf.label}
        </span>
      </div>

      <div className="space-y-3 p-4 pr-5">
        <div className={`flex items-start gap-2.5 rounded-lg border px-4 py-3 pr-5 ${vs.card}`}>
          <span className={vs.icon}><VerdictIcon type={verdict.type} /></span>
          <div className="min-w-0">
            <p className={`text-sm font-medium leading-snug ${vs.text}`}>{verdict.text}</p>
            {data.resource_type === "iam_role" && data.services && data.services.length > 0 && (
              <p className="mt-1.5 text-[11px] text-zinc-500">
                {data.active_service_count ?? 0} services with recent API use · {data.unused_service_count ?? 0} likely
                removable
              </p>
            )}
          </div>
        </div>

        {data.resource_type === "vpc" && (
          <InfoNote>
            {(data.instance_count ?? 0) === 0
              ? "Log volume and cost are negligible until workloads are added."
              : `${data.instance_count} instance${data.instance_count !== 1 ? "s" : ""} in this VPC will be covered. Flow logs deliver to CloudWatch Logs or S3 — budget ~$0.50/GB for CloudWatch ingestion.`}
          </InfoNote>
        )}

        {infoRows.length > 0 && <BlastRadiusConsiderations items={infoRows} tone="info" />}

        {warningRows.length > 0 && <BlastRadiusConsiderations items={warningRows} tone="warning" />}

        {data.resource_type === "iam_role" && data.services && data.services.length > 0 && (
          <RoleServiceUsageAnalysis
            services={data.services}
            activeCount={data.active_service_count}
            unusedCount={data.unused_service_count}
          />
        )}

        {data.resource_type === "iam_role" && data.trust_principals && data.trust_principals.length > 0 && (
          <RoleTrustPrincipals principals={data.trust_principals} />
        )}

        {data.resource_type === "iam_role" && data.attached_policies && data.attached_policies.length > 0 && (
          <RolePoliciesAnalysis
            policies={data.attached_policies}
            renderConsoleLink={(pol) => (
              <ConsoleLink
                href={
                  pol.action === "detach_and_replace"
                    ? iamRolePermissionsConsoleUrl(finding.resource_arn)
                    : iamPolicyConsoleUrl(pol.policy_arn)
                }
                title={
                  pol.action === "detach_and_replace"
                    ? "Open role permissions in AWS Console to detach this managed policy"
                    : "Open policy in AWS Console to edit"
                }
              >
                {pol.action === "detach_and_replace" ? "Detach + replace" : "Edit policy"}
              </ConsoleLink>
            )}
          />
        )}

        {data.resource_type === "iam_role" && (
          <p className="text-[11px] text-zinc-500 px-0.5">
            {data.days_since_last_assumed !== null && data.days_since_last_assumed !== undefined
              ? `Role last assumed ${data.days_since_last_assumed} days ago`
              : "Role has never been assumed"}
          </p>
        )}

        {/* Access key: key list */}
        {data.resource_type === "iam_access_key" && data.keys && data.keys.length > 0 && (
          <div className="space-y-2">
            {data.keys.map((k) => (
              <KeyActivityCard key={k.key_id} keyData={k} />
            ))}
          </div>
        )}

        {/* User: summary (hidden for MFA-only — keys/password are not part of remediation) */}
        {data.resource_type === "iam_user" && !mfaOnlyUserCheck && (
          <div className="space-y-2">
            <div className="overflow-hidden rounded-lg border border-zinc-200 bg-zinc-50">
              <div className="px-3 py-2 text-xs text-zinc-600">
                {data.active_key_count} active access key{data.active_key_count !== 1 ? "s" : ""}
              </div>
              {data.has_console_password && (
                <div className="border-t border-zinc-200 px-3 py-2 text-xs text-zinc-600">
                  Has console password
                </div>
              )}
            </div>
            {((data.attached_policies?.length ?? 0) > 0 || (data.inline_policy_names?.length ?? 0) > 0) && (
              <div>
                <div className="mb-2 text-sm font-semibold text-zinc-700">Direct policy attachments</div>
                <div className="space-y-1.5">
                  {(data.attached_policies ?? []).map((pol) => (
                    <div key={pol.policy_arn} className="rounded-md border border-zinc-200 bg-zinc-50 px-3 py-2 text-xs font-mono text-zinc-700">
                      {pol.policy_name}
                    </div>
                  ))}
                  {(data.inline_policy_names ?? []).map((name) => (
                    <div key={name} className="rounded-md border border-violet-200 bg-violet-50 px-3 py-2 text-xs font-mono text-violet-800">
                      {name} <span className="text-violet-600">(inline)</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* RDS instance: metadata grid */}
        {data.resource_type === "rds_instance" && (
          <div className="grid grid-cols-3 gap-2 text-xs">
            {([
              ["Instance", data.db_instance_id ?? "—", null],
              ["Engine", data.engine ?? "—", null],
              ["Region", data.region ?? "—", null],
              ["Encrypted", data.storage_encrypted ? "Yes" : "No", data.storage_encrypted],
              ["Public access", data.publicly_accessible ? "Enabled" : "Disabled", !data.publicly_accessible],
              ["Backup retention", data.backup_retention_period != null ? `${data.backup_retention_period}d` : "—", (data.backup_retention_period ?? 0) > 0],
            ] as [string, string, boolean | null][]).map(([label, val, ok]) => (
              <div key={label} className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
                <div className="font-medium text-zinc-400 mb-0.5">{label}</div>
                <div className={`font-mono font-medium truncate ${ok === true ? "text-emerald-700" : ok === false ? "text-red-600" : "text-zinc-700"}`}>{val}</div>
              </div>
            ))}
          </div>
        )}

        {/* DynamoDB table: metadata grid */}
        {data.resource_type === "dynamodb_table" && (
          <div className="grid grid-cols-2 gap-2 text-xs">
            {([
              ["Table", data.table_name ?? "—", null],
              ["Region", data.region ?? "—", null],
              ["Encrypted", data.kms_encrypted ? "Yes" : "No", data.kms_encrypted],
              ["PITR", data.pitr_enabled ? "Enabled" : "Disabled", data.pitr_enabled],
            ] as [string, string, boolean | null][]).map(([label, val, ok]) => (
              <div key={label} className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
                <div className="font-medium text-zinc-400 mb-0.5">{label}</div>
                <div className={`font-mono font-medium truncate ${ok === true ? "text-emerald-700" : ok === false ? "text-red-600" : "text-zinc-700"}`}>{val}</div>
              </div>
            ))}
          </div>
        )}

        {/* EC2 instance: metadata grid */}
        {data.resource_type === "ec2_instance" && (
          <div className="grid grid-cols-2 gap-2 text-xs">
            {([
              ["Instance", data.instance_id ?? "—", null],
              ["Type", data.instance_type ?? "—", null],
              ["State", data.state ?? "—", data.state === "running"],
              ["Region", data.region ?? "—", null],
            ] as [string, string, boolean | null][]).map(([label, val, ok]) => (
              <div key={label} className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
                <div className="font-medium text-zinc-400 mb-0.5">{label}</div>
                <div className={`font-mono font-medium ${ok === true ? "text-emerald-700" : ok === false ? "text-zinc-500" : "text-zinc-700"}`}>{val}</div>
              </div>
            ))}
          </div>
        )}

        {/* EBS volume: metadata + attached instances */}
        {data.resource_type === "ebs_volume" && (
          <div className="space-y-3">
            <div className="grid grid-cols-3 gap-2 text-xs">
              {([
                ["Volume", data.volume_id ?? "—", null],
                ["Size", data.size_gib != null ? `${data.size_gib} GiB` : "—", null],
                ["Type", data.volume_type ?? "—", null],
                ["State", data.state ?? "—", null],
                ["Region", data.region ?? "—", null],
                ["Attached", `${(data.attached_instances ?? []).length}`, null],
              ] as [string, string, null][]).map(([label, val]) => (
                <div key={label} className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
                  <div className="font-medium text-zinc-400 mb-0.5">{label}</div>
                  <div className="font-mono font-medium text-zinc-700 truncate">{val}</div>
                </div>
              ))}
            </div>
            {data.attached_instances && data.attached_instances.length > 0 && (
              <div>
                <div className="text-sm font-semibold text-zinc-700 mb-2">
                  Attached instances
                  {(data.running_count ?? 0) > 0 && <span className="ml-2 text-xs font-medium text-red-500">{data.running_count} running</span>}
                </div>
                <div className="space-y-1.5">
                  {data.attached_instances.map((inst) => (
                    <div key={inst.instance_id} className={`flex items-center justify-between rounded-md border px-3 py-2 text-xs ${inst.state === "running" ? "border-red-100 bg-red-50" : "border-zinc-200 bg-zinc-50"}`}>
                      <div className="flex items-center gap-2 min-w-0">
                        <span className={`h-1.5 w-1.5 flex-shrink-0 rounded-full ${inst.state === "running" ? "bg-red-400" : "bg-zinc-300"}`} />
                        <span className="font-mono text-zinc-700 truncate">{inst.name !== inst.instance_id ? inst.name : inst.instance_id}</span>
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0 pl-2">
                        {inst.instance_type && <span className="text-zinc-400">{inst.instance_type}</span>}
                        <span className={`font-medium ${inst.state === "running" ? "text-red-600" : "text-zinc-400"}`}>{inst.state}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* EBS encryption default: unencrypted volume count */}
        {data.resource_type === "ebs_encryption_default" && (
          <div className="rounded-lg border border-zinc-200 bg-zinc-50/80 px-3 py-3 text-xs">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="font-medium text-zinc-500">Existing unencrypted volumes</div>
                <p className="mt-1.5 leading-relaxed text-zinc-600">
                  Default encryption applies to <span className="font-medium text-zinc-800">new</span> volumes only.
                  Migrate each existing volume with snapshot copy when ready.
                </p>
              </div>
              <div
                className={`shrink-0 rounded-lg border border-zinc-200 bg-white px-3 py-2 text-center tabular-nums ${
                  (data.existing_unencrypted_count ?? 0) > 0 ? "text-amber-700" : "text-emerald-700"
                }`}
              >
                <div className="text-[10px] font-medium uppercase tracking-wide text-zinc-400">Count</div>
                <div className="text-xl font-semibold leading-tight">{data.existing_unencrypted_count ?? 0}</div>
              </div>
            </div>
          </div>
        )}

        {/* CloudTrail account: existing non-compliant trails */}
        {data.resource_type === "cloudtrail_account" && (data.trail_count ?? 0) > 0 && (
          <div className="space-y-2">
            <div className="space-y-1.5">
              {(data.existing_trails ?? []).map((trail) => (
                <div key={trail.name} className="flex items-center justify-between gap-3 rounded-lg border border-zinc-200 bg-zinc-50 px-3 py-2.5 text-xs">
                  <div className="min-w-0">
                    <div className="truncate font-mono font-medium text-zinc-800">{trail.name}</div>
                    <div className="mt-0.5 text-zinc-400">{trail.home_region}</div>
                  </div>
                  <div className="flex shrink-0 flex-wrap justify-end gap-1">
                    <span className={`rounded border px-1.5 py-0.5 font-medium ${trail.is_logging ? "border-emerald-200 bg-emerald-50 text-emerald-700" : "border-zinc-200 bg-white text-zinc-500"}`}>
                      {trail.is_logging ? "Logging" : "Stopped"}
                    </span>
                    <span className={`rounded border px-1.5 py-0.5 font-medium ${trail.is_multi_region ? "border-blue-200 bg-blue-50 text-blue-700" : "border-amber-200 bg-amber-50 text-amber-800"}`}>
                      {trail.is_multi_region ? "Multi-region" : "Single-region"}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* CloudTrail trail: metadata grid */}
        {data.resource_type === "cloudtrail_trail" && (
          <div className="grid grid-cols-2 gap-2 text-xs">
            {([
              ["Trail", data.trail_name ?? "—", null],
              ["Region", data.home_region ?? "—", null],
              ["Logging", data.is_logging ? "Active" : "Stopped", data.is_logging],
              ["Multi-region", data.is_multi_region ? "Yes" : "No", data.is_multi_region],
              ["Log validation", data.log_validation_enabled ? "Enabled" : "Off", data.log_validation_enabled],
              ["KMS encrypted", data.kms_key_id ? "Yes" : "No", !!data.kms_key_id],
            ] as [string, string, boolean | null][]).map(([label, val, ok]) => (
              <div key={label} className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
                <div className="font-medium text-zinc-400 mb-0.5">{label}</div>
                <div className={`font-mono font-medium ${ok === true ? "text-emerald-700" : ok === false ? "text-zinc-500" : "text-zinc-700"}`}>{val}</div>
              </div>
            ))}
          </div>
        )}

        {/* VPC: metadata */}
        {data.resource_type === "vpc" && (
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
              <div className="font-medium text-zinc-400 mb-0.5">VPC</div>
              <div className="font-mono font-medium text-zinc-700">{data.vpc_id ?? "—"}</div>
            </div>
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
              <div className="font-medium text-zinc-400 mb-0.5">Region</div>
              <div className="font-mono font-medium text-zinc-700">{data.region ?? "—"}</div>
            </div>
            <div className="col-span-2 rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
              <div className="font-medium text-zinc-400 mb-0.5">Instances in VPC</div>
              <div className="text-2xl font-bold tabular-nums text-zinc-700">{data.instance_count ?? 0}</div>
            </div>
          </div>
        )}

        {/* IAM password policy: current settings */}
        {data.resource_type === "iam_password_policy" && (
          <div className="grid grid-cols-3 gap-2 text-xs">
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
              <div className="font-medium text-zinc-400 mb-0.5">Min length</div>
              <div className="font-mono font-medium text-zinc-700">{data.min_length ?? "none"}</div>
            </div>
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
              <div className="font-medium text-zinc-400 mb-0.5">Max age</div>
              <div className={`font-mono font-medium ${data.max_age ? "text-amber-700" : "text-zinc-400"}`}>{data.max_age ? `${data.max_age}d` : "none"}</div>
            </div>
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
              <div className="font-medium text-zinc-400 mb-0.5">Reuse prevention</div>
              <div className="font-mono font-medium text-zinc-700">{data.password_reuse_prevention ?? "none"}</div>
            </div>
          </div>
        )}

        {/* S3 account-level block: affected buckets */}
        {data.resource_type === "s3_account_block" && (data.public_bucket_count ?? 0) > 0 && (
          <div>
            <div className="mb-2.5 text-xs font-medium text-zinc-500">
              Affected buckets ({data.public_bucket_count})
            </div>
            <div className="flex flex-wrap gap-2">
              {(data.public_bucket_names ?? []).map((name) => (
                <span key={name} className="inline-flex max-w-full items-center rounded-lg border border-zinc-200 bg-zinc-50 px-2.5 py-1.5 font-mono text-xs text-zinc-700">
                  <span className="truncate">{name}</span>
                </span>
              ))}
            </div>
          </div>
        )}

        {/* S3 bucket: posture grid */}
        {data.resource_type === "s3_bucket" && (
          <div className="space-y-3">
            <div className="grid grid-cols-3 gap-2 text-xs">
              {([
                ["Encryption", data.encrypted ? "Enabled" : "None", data.encrypted],
                ["KMS", data.kms_encrypted ? "Enabled" : "SSE-S3 / None", data.kms_encrypted],
                ["Public access", data.public_access_blocked ? "Blocked" : "Open", data.public_access_blocked],
                ["HTTPS-only", data.https_only ? "Enforced" : "Not enforced", data.https_only],
                ["Versioning", data.versioning_enabled ? "Enabled" : "Off", data.versioning_enabled],
                ["Logging", data.logging_enabled ? "Enabled" : "Off", data.logging_enabled],
              ] as [string, string, boolean | undefined][]).map(([label, val, ok]) => (
                <div key={label} className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
                  <div className="font-medium text-zinc-400 mb-0.5">{label}</div>
                  <div className={`font-mono font-medium ${ok ? "text-emerald-700" : "text-zinc-500"}`}>{val}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* KMS key: metadata + dependent trails */}
        {data.resource_type === "kms_key" && (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
                <div className="font-medium text-zinc-400 mb-0.5">Alias</div>
                <div className="font-mono text-zinc-700 truncate">{data.alias ?? "no alias"}</div>
              </div>
              <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
                <div className="font-medium text-zinc-400 mb-0.5">Key state</div>
                <div className={`font-mono font-medium ${data.key_state === "Enabled" ? "text-emerald-700" : "text-amber-700"}`}>
                  {data.key_state ?? "unknown"}
                </div>
              </div>
            </div>

            {data.dependent_trails && data.dependent_trails.length > 0 ? (
              <div>
                <div className="text-sm font-semibold text-zinc-700 mb-2">
                  Used by CloudTrail ({data.dependent_trail_count})
                </div>
                <div className="space-y-1.5">
                  {data.dependent_trails.map((trail) => (
                    <div key={trail.arn} className="flex items-center justify-between rounded-md border border-zinc-200 bg-zinc-50 px-3 py-2 text-xs">
                      <span className="font-mono text-zinc-700 truncate">{trail.name}</span>
                      <div className="flex items-center gap-2 flex-shrink-0 pl-2">
                        <span className="text-zinc-400">{trail.region}</span>
                        {trail.is_multi_region && <span className="rounded border border-blue-200 bg-blue-50 px-1.5 py-0.5 text-[10px] font-semibold text-blue-700">multi-region</span>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <p className="text-xs text-zinc-400">No CloudTrail trails reference this key. Note: S3, RDS, and EBS key associations are not yet tracked per-key in Vigil.</p>
            )}
          </div>
        )}

        {/* Security group: metadata + affected instances */}
        {data.resource_type === "security_group" && (
          <div className="space-y-3">
            <div className="grid grid-cols-3 gap-2 text-xs">
              <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2 min-w-0">
                <div className="font-medium text-zinc-400 mb-0.5">Security group</div>
                <div className="font-mono text-zinc-700 truncate" title={data.group_id}>{data.group_id}</div>
                {data.is_default && (
                  <div className="mt-1">
                    <span className="rounded border border-violet-200 bg-violet-50 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-violet-700">
                      Default
                    </span>
                  </div>
                )}
              </div>
              <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2 min-w-0">
                <div className="font-medium text-zinc-400 mb-0.5">VPC</div>
                <div className="font-mono text-zinc-700 truncate" title={data.vpc_id ?? undefined}>{data.vpc_id ?? "—"}</div>
              </div>
              <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2 min-w-0">
                <div className="font-medium text-zinc-400 mb-0.5">Region</div>
                <div className="text-zinc-700 truncate" title={data.region}>{AWS_REGION_LABELS[data.region ?? ""] ?? data.region}</div>
                {data.region && AWS_REGION_LABELS[data.region] && (
                  <div className="mt-0.5 font-mono text-[10px] text-zinc-400 truncate">{data.region}</div>
                )}
              </div>
            </div>

            {data.affected_instances && data.affected_instances.length > 0 ? (
              <div>
                <div className="text-sm font-semibold text-zinc-700 mb-2">
                  Exposed instances ({data.total_count})
                  {data.running_count !== undefined && data.running_count > 0 && (
                    <span className="ml-2 text-xs font-medium text-red-500">{data.running_count} running</span>
                  )}
                </div>
                <div className="space-y-1.5">
                  {data.affected_instances.map((inst) => (
                    <div
                      key={inst.instance_id}
                      className={`flex items-center justify-between rounded-md border px-3 py-2 text-xs ${
                        inst.state === "running"
                          ? "border-red-100 bg-red-50"
                          : "border-zinc-200 bg-zinc-50"
                      }`}
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <span className={`h-1.5 w-1.5 flex-shrink-0 rounded-full ${inst.state === "running" ? "bg-red-400" : "bg-zinc-300"}`} />
                        <span className="font-mono text-zinc-700 truncate">{inst.name !== inst.instance_id ? inst.name : inst.instance_id}</span>
                        {inst.name !== inst.instance_id && <span className="font-mono text-zinc-400 truncate">{inst.instance_id}</span>}
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0 pl-2">
                        {inst.instance_type && <span className="text-zinc-400">{inst.instance_type}</span>}
                        <span className={`font-medium ${inst.state === "running" ? "text-red-600" : "text-zinc-400"}`}>{inst.state}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="text-xs text-zinc-400">
                {data.is_default
                  ? "No instances in this region are attached to this VPC's default security group."
                  : "No instances currently attached to this security group."}
              </div>
            )}
          </div>
        )}

        {data.resource_type === "ebs_snapshot" && (
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
              <div className="font-medium text-zinc-400 mb-0.5">Snapshot</div>
              <div className="font-mono font-medium text-zinc-700 truncate">{data.snapshot_id ?? "—"}</div>
            </div>
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
              <div className="font-medium text-zinc-400 mb-0.5">Encrypted</div>
              <div className={`font-mono font-medium ${data.encrypted ? "text-emerald-700" : "text-red-600"}`}>{data.encrypted ? "Yes" : "No"}</div>
            </div>
          </div>
        )}

        {data.resource_type === "ec2_ami" && (
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2 col-span-2">
              <div className="font-medium text-zinc-400 mb-0.5">AMI</div>
              <div className="font-mono font-medium text-zinc-700 truncate">{data.image_id ?? data.name ?? "—"}</div>
            </div>
          </div>
        )}

        {data.resource_type === "acm_certificate" && (
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2 col-span-2">
              <div className="font-medium text-zinc-400 mb-0.5">Domain</div>
              <div className="font-mono font-medium text-zinc-700 truncate">{data.domain_name ?? "—"}</div>
            </div>
            {data.days_until_expiry != null && (
              <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
                <div className="font-medium text-zinc-400 mb-0.5">Expires in</div>
                <div className={`font-mono font-medium ${data.days_until_expiry <= 7 ? "text-red-600" : "text-amber-700"}`}>{data.days_until_expiry}d</div>
              </div>
            )}
          </div>
        )}

        {data.resource_type === "lambda_function" && (
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2 col-span-2">
              <div className="font-medium text-zinc-400 mb-0.5">Function</div>
              <div className="font-mono font-medium text-zinc-700 truncate">{data.function_name ?? "—"}</div>
            </div>
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
              <div className="font-medium text-zinc-400 mb-0.5">Runtime</div>
              <div className="font-mono font-medium text-zinc-700">{data.runtime ?? "—"}</div>
            </div>
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
              <div className="font-medium text-zinc-400 mb-0.5">DLQ</div>
              <div className={`font-mono font-medium ${data.has_dlq ? "text-emerald-700" : "text-zinc-500"}`}>{data.has_dlq ? "Yes" : "No"}</div>
            </div>
          </div>
        )}

        {data.resource_type === "elb_load_balancer" && (
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2 col-span-2">
              <div className="font-medium text-zinc-400 mb-0.5">Load balancer</div>
              <div className="font-mono font-medium text-zinc-700 truncate">{data.name ?? "—"}</div>
            </div>
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
              <div className="font-medium text-zinc-400 mb-0.5">Access logs</div>
              <div className={`font-mono font-medium ${data.access_logs_enabled ? "text-emerald-700" : "text-zinc-500"}`}>{data.access_logs_enabled ? "On" : "Off"}</div>
            </div>
            {data.ssl_policy && (
              <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
                <div className="font-medium text-zinc-400 mb-0.5">TLS policy</div>
                <div className="font-mono text-[10px] text-zinc-700 truncate">{data.ssl_policy}</div>
              </div>
            )}
          </div>
        )}

        {(data.resource_type === "sns_topic" || data.resource_type === "sqs_queue") && (
          <div className="rounded-md border border-zinc-200 bg-zinc-50 px-3 py-2.5 text-xs text-zinc-600">
            Region <span className="font-mono font-medium text-zinc-800">{data.region ?? "—"}</span>
            {" · "}
            KMS <span className={`font-mono font-medium ${data.kms_encrypted ? "text-emerald-700" : "text-zinc-500"}`}>{data.kms_encrypted ? "enabled" : "not enabled"}</span>
          </div>
        )}

        {data.resource_type === "identity_repo" && (
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2 col-span-2">
              <div className="font-medium text-zinc-400 mb-0.5">Repository</div>
              <div className="font-mono font-medium text-zinc-700 truncate">{data.repo ?? "—"}</div>
            </div>
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
              <div className="font-medium text-zinc-400 mb-0.5">Default branch</div>
              <div className="font-mono font-medium text-zinc-700">{data.default_branch ?? "main"}</div>
            </div>
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
              <div className="font-medium text-zinc-400 mb-0.5">Protection</div>
              <div className={`font-mono font-medium ${data.has_branch_protection ? "text-emerald-700" : "text-zinc-500"}`}>
                {data.has_branch_protection ? `${data.required_reviews ?? 0} reviews` : "None"}
              </div>
            </div>
          </div>
        )}

        {data.resource_type === "identity_user" && (
          <div className="rounded-md border border-zinc-200 bg-zinc-50 px-3 py-2.5 text-xs text-zinc-600">
            <span className="font-mono font-medium text-zinc-800">{data.username}</span>
            {data.source && <> @ {data.source}</>}
            {data.days_inactive != null && <> · inactive {data.days_inactive}d</>}
          </div>
        )}

        {data.resource_type === "identity_org" && (
          <div className="rounded-md border border-zinc-200 bg-zinc-50 px-3 py-2.5 text-xs text-zinc-600">
            {data.provider_type === "github" ? "GitHub" : "GitLab"} org{" "}
            <span className="font-mono font-medium text-zinc-800">{data.org}</span>
            {(data.outside_collaborator_count ?? 0) > 0 && (
              <> · {data.outside_collaborator_count} outside collaborator(s)</>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export type FindingDrawerTab = "overview" | "resources" | "compliance" | "remediation" | "whatif";
export type FindingRemediationMode = "console" | "cli" | "terraform" | "automation";

type Tab = FindingDrawerTab;

type MappedControl = {
  framework: string;
  control_id: string;
  title: string;
  description: string;
  guidance: string | null;
  narrative: string | null;
  reference_url: string;
  reference_label: string;
  reference_note?: string | null;
};

type CheckControlBundle = {
  check_id: string;
  primary: MappedControl | null;
  controls: MappedControl[];
};

function compliancePageHref(ctrl: MappedControl, accountId?: string | null) {
  const params = new URLSearchParams({
    framework: ctrl.framework,
    control: ctrl.control_id,
  });
  if (accountId) params.set("account_id", accountId);
  return `/controls?${params}`;
}

function ExternalReferenceLink({
  href,
  children,
  className = "text-[12px] font-medium text-zinc-600 hover:text-zinc-900",
  title,
}: {
  href: string;
  children: React.ReactNode;
  className?: string;
  title?: string;
}) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      title={title}
      className={`inline-flex items-center gap-1 ${className}`}
    >
      {children}
      <svg
        className="h-3 w-3 shrink-0 opacity-70"
        fill="none"
        stroke="currentColor"
        strokeWidth={2}
        viewBox="0 0 24 24"
        aria-hidden
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          d="M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25"
        />
      </svg>
    </a>
  );
}

function ComplianceTabContent({
  checkId,
  accountId,
}: {
  checkId: string;
  accountId?: string | null;
}) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["controls-by-check", checkId],
    queryFn: () => api<CheckControlBundle>(`/v1/controls/by-check/${encodeURIComponent(checkId)}`),
  });

  const primary = data?.primary;
  const alternates = (data?.controls ?? []).filter(
    (c) => !primary || c.framework !== primary.framework || c.control_id !== primary.control_id,
  );

  if (isLoading) {
    return (
      <div className={`${drawerPanel} px-4 py-3 text-[13px] text-zinc-500`}>Loading compliance mapping…</div>
    );
  }

  if (isError || !primary) {
    return (
      <FlowCallout tone="neutral" title="Framework mapping">
        This check is not yet mapped to SOC 2 / CIS / ISO control rows in Vigil.
      </FlowCallout>
    );
  }

  const checkDoc = documentationForCheck(checkId);
  const evidenceGuidance = checkDoc?.compliance?.evidenceGuidance ?? null;
  const auditNarrative = checkDoc?.compliance?.auditNarrative ?? null;

  return (
    <div className="space-y-2.5">
      <div className={`${drawerPanel} px-4 py-3`}>
        <div className="flex flex-wrap items-center gap-2">
          <span className="rounded-md border border-indigo-200 bg-indigo-50 px-2 py-0.5 text-[11px] font-semibold text-indigo-800">
            {frameworkLabel(primary.framework)}
          </span>
          <span className="font-mono text-[12px] font-semibold text-zinc-800">{primary.control_id}</span>
        </div>
        <h3 className="mt-2 text-[13px] font-semibold text-zinc-900">{primary.title}</h3>
        <p className="mt-2 text-[12px] leading-relaxed text-zinc-600">{primary.description}</p>
        {evidenceGuidance && (
          <p className="mt-2 text-[11px] leading-relaxed text-zinc-500">
            <span className="font-medium text-zinc-600">Guidance: </span>
            {evidenceGuidance}
          </p>
        )}
        <div className="mt-3 flex flex-col gap-2 border-t border-zinc-100 pt-3">
          <Link
            to={compliancePageHref(primary, accountId)}
            className="text-[12px] font-medium text-indigo-600 hover:text-indigo-800"
          >
            View on Compliance page →
          </Link>
          <ExternalReferenceLink href={primary.reference_url} title={primary.reference_label}>
            {primary.reference_label}
          </ExternalReferenceLink>
        </div>
      </div>
      {auditNarrative && (
        <SemanticNarrativeBlock tag="Detection Logic" tone="neutral">
          {auditNarrative}
        </SemanticNarrativeBlock>
      )}
      {alternates.length > 0 && (
        <div className={`${drawerPanel} px-4 py-3`}>
          <p className="text-[11px] font-medium text-zinc-500">Also mapped to</p>
          <ul className="mt-2 space-y-1.5">
            {alternates.map((c) => (
              <li
                key={`${c.framework}:${c.control_id}`}
                className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[12px]"
              >
                <Link
                  to={compliancePageHref(c, accountId)}
                  className="font-medium text-indigo-600 hover:text-indigo-800"
                >
                  {frameworkLabel(c.framework)} {c.control_id}
                </Link>
                <ExternalReferenceLink
                  href={c.reference_url}
                  className="text-zinc-500 hover:text-zinc-800"
                  title={
                    c.framework === "iso27001"
                      ? `${c.control_id} maps to ISO/IEC 27002:2022 on iso.org; full text may require purchase`
                      : c.reference_label
                  }
                >
                  Official doc
                </ExternalReferenceLink>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
type GeneratedPolicy = {
  has_inline_policies: boolean;
  unused_services: string[];
  used_services: string[];
  used_actions?: string[];
  granularity?: "action" | "service";
  statements_removed?: number;
  statements_modified?: number;
  original_policies?: Record<string, unknown>;
  cleaned_policies?: Record<string, unknown>;
  note?: string;
  coverage?: { actions: boolean; resources: boolean };
  source_label?: string;
  access_analyzer_enabled?: boolean;
  advanced_available?: boolean;
  advanced_requested?: boolean;
  advanced_effective?: boolean;
  advanced_note?: string | null;
  improve_via_cloudtrail?: boolean;
  policy_warnings?: string[];
  used_services_service_only?: string[];
  preserved_service_wildcards?: string[];
  observed_action_count?: number;
  confidence?: "high" | "medium" | "low";
  confidence_note?: string;
  access_analyzer?: {
    available: boolean;
    reason?: string | null;
    region?: string | null;
    job_id?: string | null;
    generation_status?: string | null;
    completed_on?: string | null;
    has_concrete_resources?: boolean;
    placeholder_resources_ignored?: number;
    resource_statements?: { actions: string[]; resources: string[]; placeholder_resources?: string[] }[];
    placeholder_resources?: string[];
  };
};

const POLICY_CONFIDENCE_STYLE: Record<string, string> = {
  high: "border-emerald-200 bg-emerald-50 text-emerald-900",
  medium: "border-amber-200 bg-amber-50 text-amber-900",
  low: "border-zinc-300 bg-zinc-100 text-zinc-700",
};

function PolicyCoverageMeta({ data }: { data: GeneratedPolicy }) {
  const cov = data.coverage ?? { actions: (data.used_actions?.length ?? 0) > 0, resources: false };
  const preserved = data.preserved_service_wildcards ?? [];
  const observed =
    data.observed_action_count ??
    (data.used_actions?.filter((a) => !a.endsWith(":*") && a !== "*").length ?? 0);
  const aaStatements = (data.access_analyzer?.resource_statements ?? []).filter(
    (st) => st.resources.length > 0,
  );
  const hasConcreteResources = data.access_analyzer?.has_concrete_resources ?? cov.resources;
  const [techOpen, setTechOpen] = useState(false);
  const jobCompleted = Boolean(data.access_analyzer?.job_id);
  const showNoJobHint =
    data.access_analyzer && !data.access_analyzer.available && data.access_analyzer.reason;

  return (
    <div className="rounded-lg border border-zinc-200 bg-zinc-50/90 px-3 py-2.5 text-[11px] leading-relaxed text-zinc-700">
      <div className="flex flex-wrap items-center justify-between gap-2">
        {data.confidence && (
          <span
            className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold capitalize tracking-wide ${
              POLICY_CONFIDENCE_STYLE[data.confidence] ?? POLICY_CONFIDENCE_STYLE.low
            }`}
          >
            {data.confidence} confidence
          </span>
        )}
        <p className="text-zinc-800">
          <span className={cov.actions ? "text-emerald-800" : "text-amber-800"}>
            {cov.actions ? "✓ Actions scoped" : "✗ Actions not scoped"}
          </span>
          <span className="mx-2 text-zinc-300">·</span>
          <span className={cov.resources ? "text-emerald-800" : "text-zinc-600"}>
            {cov.resources ? "✓ Resource scope applied" : "✕ Resources unchanged"}
          </span>
        </p>
      </div>
      {data.confidence_note && <p className="mt-1 text-zinc-600">{data.confidence_note}</p>}
      <p className="mt-1 text-zinc-500">
        <span className="font-medium text-zinc-600">Source</span>
        <br />
        {data.source_label ?? "IAM last accessed"}
      </p>
      <p className="mt-2 text-zinc-700">
        {preserved.length > 0
          ? "Vigil narrowed the full-admin policy to observed actions. Some services only returned service-level usage, so their wildcard permissions were preserved to avoid breaking the workload."
          : observed > 0 && jobCompleted
            ? `Vigil narrowed Action:* to ${observed} observed actions using IAM last-accessed and CloudTrail policy generation.`
            : observed > 0
              ? `Vigil narrowed the policy to ${observed} observed actions from IAM last-accessed data.`
              : "Review the suggested policy against your workload before applying."}
      </p>
      {observed > 0 && !cov.resources && (
        <p className="mt-2 text-zinc-600">
          {preserved.length > 0
            ? "AWS did not return apply-ready resource ARNs for some services; Resource remains * where needed."
            : "AWS did not return apply-ready resource ARNs for this role, so Resource remains *."}
        </p>
      )}
      {data.access_analyzer?.reason === "in_progress" && (
        <p className="mt-2 rounded-md border border-indigo-200/80 bg-indigo-50/80 px-2 py-1.5 text-indigo-950">
          {policyGenerationReasonLabel("in_progress")}
        </p>
      )}
      {preserved.length > 0 && (
        <p className="mt-2">
          <span className="font-medium text-zinc-800">Preserved service wildcards</span>
          <br />
          <span className="font-mono text-[10px] text-zinc-700">{preserved.join(" · ")}</span>
        </p>
      )}
      {preserved.length > 0 && (
        <p className="mt-2 text-zinc-600">
          <span className="font-medium text-zinc-700">Why</span> — AWS reported recent usage for these services but
          did not return action or resource-level detail for this role.
        </p>
      )}
      {observed > 0 && (
        <p className="mt-2 text-zinc-600">
          <span className="font-medium text-zinc-700">Result</span> —{" "}
          {preserved.length > 0
            ? `Action:* was replaced with ${observed} observed actions. Resource remains *.`
            : cov.resources
              ? `${observed} observed actions with resource ARNs where available.`
              : `${observed} observed actions scoped. Resource remains *.`}
        </p>
      )}
      {showNoJobHint && (
        <p className="mt-2 text-amber-900">
          {policyGenerationReasonLabel(data.access_analyzer!.reason) ?? data.access_analyzer!.reason}
        </p>
      )}
      {data.advanced_note && hasConcreteResources && (
        <p className="mt-2 rounded-md border border-emerald-100 bg-emerald-50/70 px-2 py-1.5 text-emerald-950">
          {data.advanced_note}
        </p>
      )}
      {hasConcreteResources && aaStatements.length > 0 && (
        <div className="mt-2 rounded-md border border-emerald-100 bg-emerald-50/70 px-2 py-1.5 text-emerald-950">
          <p className="font-semibold">Apply-ready resource ARNs ({aaStatements.length})</p>
          <ul className="mt-1 space-y-1">
            {aaStatements.slice(0, 4).map((st, i) => (
              <li key={i} className="font-mono text-[10px] leading-snug">
                {st.actions.slice(0, 2).join(", ")}
                {st.actions.length > 2 ? ` +${st.actions.length - 2}` : ""}
                {` → ${st.resources[0]}`}
                {st.resources.length > 1 ? ` +${st.resources.length - 1}` : ""}
              </li>
            ))}
          </ul>
        </div>
      )}
      {(data.policy_warnings?.length ?? 0) > 0 && (
        <p className="mt-2 rounded-md border border-amber-200/80 bg-amber-50/80 px-2 py-1.5 text-amber-950">
          {data.policy_warnings![0]}
        </p>
      )}
      {(jobCompleted || (data.access_analyzer?.placeholder_resources?.length ?? 0) > 0) && (
        <div className="mt-2 border-t border-zinc-200/80 pt-2">
          <button
            type="button"
            onClick={() => setTechOpen((o) => !o)}
            className="text-[10px] font-medium text-zinc-500 hover:text-zinc-800"
          >
            {techOpen ? "Hide" : "Show"} technical details
          </button>
          {techOpen && (
            <div className="mt-1.5 space-y-1 text-[10px] text-zinc-500">
              <p>
                CloudTrail policy generation:{" "}
                {jobCompleted
                  ? "completed"
                  : data.access_analyzer?.reason === "in_progress"
                    ? "in progress"
                    : "none"}
              </p>
              <p>IAM last-accessed: available</p>
              {(data.access_analyzer?.placeholder_resources_ignored ?? 0) > 0 && (
                <p>
                  Resource templates ignored: {data.access_analyzer!.placeholder_resources_ignored} (
                  <span className="font-mono">${"{"}…{"}"}</span> placeholders are not apply-ready)
                </p>
              )}
              {jobCompleted && data.access_analyzer?.job_id && (
                <p className="font-mono">
                  job {data.access_analyzer.job_id}
                  {data.access_analyzer.completed_on ? ` · ${data.access_analyzer.completed_on}` : ""}
                </p>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

type GeneratedS3HttpsPolicy = {
  bucket_name: string;
  had_policy: boolean;
  already_has_https_deny: boolean;
  original_policy: Record<string, unknown> | null;
  merged_policy: Record<string, unknown>;
  statement_added: boolean;
};

const ROLE_POLICY_GEN_CHECKS = new Set([
  "iam.role.unused_services_90d",
  "iam.role.wildcard_action",
  "iam.role.full_admin_policy",
  "iam.perm.granted_vs_used",
]);

const MISLEADING_INLINE_POLICY_NAMES = new Set([
  "AdministratorAccess",
  "PowerUserAccess",
  "ReadOnlyAccess",
  "IAMFullAccess",
  "IAMUserChangePassword",
  "SecurityAudit",
  "ViewOnlyAccess",
]);

function roleShortName(roleArn: string): string {
  const match = roleArn.match(/:role\/(.+)$/);
  return match ? (match[1].split("/").pop() ?? "role") : "role";
}

function suggestedInlinePolicyName(roleArn: string): string {
  const base = roleShortName(roleArn).replace(/[^a-zA-Z0-9+=,.@-]/g, "-");
  return `${base}-scoped`;
}

function policyRenameHint(policyName: string, roleArn: string, narrowed: boolean): string | null {
  if (!narrowed && !MISLEADING_INLINE_POLICY_NAMES.has(policyName)) return null;
  if (MISLEADING_INLINE_POLICY_NAMES.has(policyName)) {
    return `Inline policy name "${policyName}" no longer matches its scope. Consider renaming to ${suggestedInlinePolicyName(roleArn)} when you apply.`;
  }
  if (narrowed && /admin/i.test(policyName)) {
    return `Policy "${policyName}" was narrowed — rename on apply so the name reflects least privilege.`;
  }
  return null;
}

function policyChangeSummary(data: GeneratedPolicy) {
  const removed = data.statements_removed ?? 0;
  const modified = data.statements_modified ?? 0;
  const preserved = data.preserved_service_wildcards ?? [];
  const observed =
    data.observed_action_count ??
    (data.used_actions?.filter((a) => !a.endsWith(":*") && a !== "*").length ?? 0);
  const parts: string[] = [];
  if (removed) parts.push(`${removed} unused statement${removed !== 1 ? "s" : ""} removed`);
  if (modified && observed) {
    if (preserved.length) {
      parts.push(
        `Full admin narrowed to ${observed} observed action${observed !== 1 ? "s" : ""}, with ${preserved.length} service wildcard${preserved.length !== 1 ? "s" : ""} preserved`,
      );
    } else if (data.granularity === "action") {
      parts.push(`Action:* replaced with ${observed} observed action${observed !== 1 ? "s" : ""}`);
    } else {
      const usedServices = data.used_services?.length ?? 0;
      parts.push(`Scoped to ${usedServices} used service${usedServices !== 1 ? "s" : ""}`);
    }
  }
  return parts.length ? parts.join(" · ") : "No changes";
}

type PolicyStatement = { Sid?: string; Effect?: string; Action?: string | string[]; Resource?: string | string[]; [k: string]: unknown };

type PolicyDiffLine = { kind: "context" | "remove" | "add" | "header"; text: string };

function actionService(action: string): string | null {
  const i = action.indexOf(":");
  return i > 0 ? action.slice(0, i).toLowerCase() : null;
}

function isSubsumedByPreservedWildcard(action: string, preserved: Set<string>): boolean {
  if (preserved.has(action.toLowerCase())) return true;
  const svc = actionService(action);
  return svc != null && preserved.has(`${svc}:*`);
}

const POLICY_DIFF_PREVIEW = 14;

function asPolicyList(value: string | string[] | undefined): string[] {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

function diffPolicyField(
  label: string,
  orig: string[],
  clean: string[],
  mode: "removed" | "modified",
  opts?: { preservedServiceWildcards?: string[] },
): PolicyDiffLine[] {
  const lines: PolicyDiffLine[] = [];
  const origSet = new Set(orig);
  const cleanSet = new Set(clean);
  const wildcardNarrowed =
    mode === "modified" && orig.length === 1 && orig[0] === "*" && clean.length > 0 && !clean.includes("*");

  if (wildcardNarrowed && label === "Action") {
    const preservedSet = new Set((opts?.preservedServiceWildcards ?? []).map((a) => a.toLowerCase()));
    const preserved = [...clean].filter((a) => a.endsWith(":*") && preservedSet.has(a.toLowerCase())).sort();
    const observed = [...clean]
      .filter((a) => !isSubsumedByPreservedWildcard(a, preservedSet))
      .sort();
    lines.push({ kind: "header", text: "Removed" });
    lines.push({ kind: "remove", text: `${label}: *` });
    if (observed.length) {
      lines.push({ kind: "header", text: "Added observed actions" });
      for (const item of observed) {
        lines.push({ kind: "add", text: `  ${item}` });
      }
    }
    if (preserved.length) {
      lines.push({ kind: "header", text: "Preserved service wildcards" });
      for (const item of preserved) {
        lines.push({ kind: "add", text: `  ${item}` });
      }
    }
    return lines;
  }

  if (wildcardNarrowed) {
    lines.push({ kind: "remove", text: `${label}: "*"` });
    lines.push({ kind: "add", text: `${label}:` });
    for (const item of [...clean].sort()) {
      lines.push({ kind: "add", text: `  ${item}` });
    }
    return lines;
  }

  if (mode === "removed") {
    if (orig.length === 0) return lines;
    if (orig.length === 1) {
      lines.push({ kind: "remove", text: `${label}: ${orig[0]}` });
      return lines;
    }
    lines.push({ kind: "remove", text: `${label}:` });
    for (const item of orig) lines.push({ kind: "remove", text: `  ${item}` });
    return lines;
  }

  const removed = orig.filter((x) => !cleanSet.has(x));
  const added = clean.filter((x) => !origSet.has(x));
  if (removed.length === 0 && added.length === 0) {
    if (orig.length > 0) lines.push({ kind: "context", text: `${label}: ${orig.join(", ")}` });
    return lines;
  }
  if (removed.length === 1 && added.length === 0) {
    lines.push({ kind: "remove", text: `${label}: ${removed[0]}` });
  } else if (removed.length > 0) {
    lines.push({ kind: "remove", text: `${label}:` });
    for (const item of removed) lines.push({ kind: "remove", text: `  ${item}` });
  }
  if (added.length === 1 && removed.length === 0) {
    lines.push({ kind: "add", text: `${label}: ${added[0]}` });
  } else if (added.length > 0) {
    lines.push({ kind: "add", text: `${label}:` });
    for (const item of added) lines.push({ kind: "add", text: `  ${item}` });
  }
  return lines;
}

function buildNewStatementDiffLines(stmt: PolicyStatement): PolicyDiffLine[] {
  const lines: PolicyDiffLine[] = [];
  if (stmt.Sid) lines.push({ kind: "add", text: `Sid: ${stmt.Sid}` });
  if (stmt.Effect) lines.push({ kind: "add", text: `Effect: ${stmt.Effect}` });
  if (stmt.Principal) {
    const p = typeof stmt.Principal === "string" ? stmt.Principal : "*";
    lines.push({ kind: "add", text: `Principal: ${p}` });
  }
  lines.push(...diffPolicyField("Action", [], asPolicyList(stmt.Action), "modified"));
  lines.push(...diffPolicyField("Resource", [], asPolicyList(stmt.Resource), "modified"));
  return lines;
}

function buildStatementDiffLines(
  orig: PolicyStatement,
  clean: PolicyStatement | null,
  opts: { hideUnchangedResources?: boolean; preservedServiceWildcards?: string[] },
): PolicyDiffLine[] {
  if (!clean) {
    const lines: PolicyDiffLine[] = [];
    if (orig.Sid) lines.push({ kind: "remove", text: `Sid: ${orig.Sid}` });
    if (orig.Effect) lines.push({ kind: "remove", text: `Effect: ${orig.Effect}` });
    lines.push(...diffPolicyField("Action", asPolicyList(orig.Action), [], "removed"));
    lines.push(...diffPolicyField("Resource", asPolicyList(orig.Resource), [], "removed"));
    return lines;
  }

  const lines: PolicyDiffLine[] = [];
  if (orig.Sid) lines.push({ kind: "context", text: `Sid: ${orig.Sid}` });
  if (orig.Effect) lines.push({ kind: "context", text: `Effect: ${orig.Effect}` });
  lines.push(
    ...diffPolicyField("Action", asPolicyList(orig.Action), asPolicyList(clean.Action), "modified", {
      preservedServiceWildcards: opts.preservedServiceWildcards,
    }),
  );

  const origRes = asPolicyList(orig.Resource);
  const cleanRes = asPolicyList(clean.Resource);
  const hideResources =
    opts.hideUnchangedResources &&
    origRes.length === 1 &&
    origRes[0] === "*" &&
    cleanRes.length === 1 &&
    cleanRes[0] === "*";
  if (!hideResources) {
    lines.push(...diffPolicyField("Resource", origRes, cleanRes, "modified"));
  }
  return lines;
}

function PolicyDiffLineRow({ line }: { line: PolicyDiffLine }) {
  if (line.kind === "header") {
    return (
      <div className="border-t border-zinc-200/80 bg-zinc-100/90 px-3 py-1 font-mono text-[10px] font-semibold uppercase tracking-wide text-zinc-500 first:border-t-0">
        {line.text}
      </div>
    );
  }
  const prefix = line.kind === "remove" ? "-" : line.kind === "add" ? "+" : " ";
  const rowClass =
    line.kind === "remove"
      ? "bg-red-50/90 text-red-900"
      : line.kind === "add"
        ? "bg-emerald-50/90 text-emerald-900"
        : "bg-zinc-50/80 text-zinc-600";
  const prefixClass =
    line.kind === "remove" ? "text-red-500" : line.kind === "add" ? "text-emerald-600" : "text-zinc-400";

  return (
    <div className={`flex min-w-0 gap-0 font-mono text-[11px] leading-[1.45] ${rowClass}`}>
      <span className={`w-7 shrink-0 select-none pl-2 text-center font-semibold tabular-nums ${prefixClass}`}>{prefix}</span>
      <span className="min-w-0 flex-1 whitespace-pre-wrap break-all py-px pr-2">{line.text}</span>
    </div>
  );
}

function PolicyStatementDiffBlock({
  title,
  lines,
}: {
  title?: string;
  lines: PolicyDiffLine[];
}) {
  const [expanded, setExpanded] = useState(false);
  const addDetailLines = lines.filter((l) => l.kind === "add" && l.text.startsWith("  "));
  const hiddenAddCount = Math.max(0, addDetailLines.length - POLICY_DIFF_PREVIEW);
  const showCollapse = hiddenAddCount > 0 && !expanded;

  let visible = lines;
  if (showCollapse) {
    let addSeen = 0;
    visible = [];
    for (const line of lines) {
      if (line.kind === "add" && line.text.startsWith("  ")) {
        if (addSeen >= POLICY_DIFF_PREVIEW) continue;
        addSeen += 1;
      }
      visible.push(line);
    }
  }

  return (
    <div className="overflow-hidden rounded-lg border border-zinc-200/90">
      {title ? (
        <div className="border-b border-zinc-200/80 bg-zinc-100/80 px-3 py-1.5">
          <span className="font-mono text-[10px] font-medium uppercase tracking-wide text-zinc-500">{title}</span>
        </div>
      ) : null}
      <div className="divide-y divide-zinc-100/60">
        {visible.map((line, i) => (
          <PolicyDiffLineRow key={i} line={line} />
        ))}
      </div>
      {showCollapse && (
        <button
          type="button"
          onClick={() => setExpanded(true)}
          className="w-full border-t border-zinc-200/80 bg-zinc-50 px-3 py-2 text-left font-mono text-[11px] text-zinc-600 hover:bg-zinc-100"
        >
          + {hiddenAddCount} more…
        </button>
      )}
    </div>
  );
}

function PolicyDiffView({
  original,
  cleaned,
  hideUnchangedResources,
  preservedServiceWildcards,
}: {
  original: Record<string, unknown>;
  cleaned: Record<string, unknown>;
  granularity?: "action" | "service";
  hideUnchangedResources?: boolean;
  preservedServiceWildcards?: string[];
}) {
  const sections = Object.entries(original).map(([name, origDoc]) => {
    const origStmts: PolicyStatement[] = (origDoc as { Statement?: PolicyStatement[] })?.Statement ?? [];
    const cleanStmts: PolicyStatement[] = (cleaned as Record<string, { Statement?: PolicyStatement[] }>)?.[name]?.Statement ?? [];
    const changes = origStmts
      .map((stmt, i) => {
        const clean = cleanStmts[i];
        const origJson = JSON.stringify(stmt);
        const cleanJson = clean ? JSON.stringify(clean) : null;
        if (cleanJson && origJson === cleanJson) return null;
        const kind = !clean ? ("removed" as const) : ("modified" as const);
        const lines = buildStatementDiffLines(stmt, clean ?? null, {
          hideUnchangedResources,
          preservedServiceWildcards,
        });
        const title = kind === "removed" ? "Removed — no usage in 90 days" : undefined;
        return { index: i, lines, title };
      })
      .filter((x): x is NonNullable<typeof x> => x !== null && x.lines.length > 0);
    return { name, changes };
  });

  const hasChanges = sections.some((s) => s.changes.length > 0);
  if (!hasChanges) {
    return <p className="text-[12px] text-zinc-500">No inline policy changes.</p>;
  }

  return (
    <div className="space-y-3">
      {sections.map(({ name, changes }) =>
        changes.length === 0 ? null : (
          <div key={name}>
            {sections.length > 1 && (
              <div className="mb-1.5 font-mono text-[11px] font-medium text-zinc-500">{name}</div>
            )}
            <div className="space-y-2">
              {changes.map((change) => (
                <PolicyStatementDiffBlock key={change.index} title={change.title} lines={change.lines} />
              ))}
            </div>
          </div>
        ),
      )}
    </div>
  );
}

function PolicyCloudTrailStartAction({
  findingId,
  accountId,
  roleArn,
  data,
  onRefresh,
}: {
  findingId: string;
  accountId: string;
  roleArn: string;
  data: GeneratedPolicy;
  onRefresh: () => void;
}) {
  const { startCloudTrailAnalysis, failCloudTrailAnalysis } = useRecheckNotifications();
  const [busy, setBusy] = useState(false);
  const [feedback, setFeedback] = useState<string | null>(null);
  const inProgress = data.access_analyzer?.reason === "in_progress";
  const canStart = data.improve_via_cloudtrail && data.confidence !== "high";

  if (!canStart && !inProgress) return null;

  const feedbackDisplay = feedback ? formatCloudTrailStartFeedback(feedback) : null;

  const start = async () => {
    setBusy(true);
    setFeedback(null);
    try {
      const res = await api<{ message: string }>(
        `/v1/accounts/${accountId}/roles/policy-generation/start?role_arn=${encodeURIComponent(roleArn)}`,
        { method: "POST" },
      );
      setFeedback(res.message);
      startCloudTrailAnalysis({ findingId, accountId, roleArn, message: res.message });
      onRefresh();
    } catch (e) {
      const raw = e instanceof Error ? e.message : String(e);
      const msg = friendlyPolicyGenerationError(raw);
      setFeedback(msg);
      failCloudTrailAnalysis({ findingId, accountId, roleArn, message: msg });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mt-3 overflow-hidden rounded-xl border border-zinc-200/90 bg-white shadow-sm shadow-zinc-900/[0.04]">
      <div className="flex flex-col gap-3 border-b border-zinc-100 px-4 py-3.5 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0">
          <p className="text-[12px] font-semibold text-zinc-900">CloudTrail Analyzes</p>
          <p className="mt-0.5 text-[11px] text-zinc-500">~15 min · resource ARNs · IAM unchanged until you apply</p>
        </div>
        {!inProgress && (
          <button
            type="button"
            disabled={busy}
            onClick={start}
            className="inline-flex shrink-0 items-center justify-center rounded-lg bg-zinc-900 px-3.5 py-2 text-[11px] font-semibold text-white shadow-sm transition hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busy ? "Starting…" : "Start analysis"}
          </button>
        )}
      </div>
      {inProgress && (
        <div className="flex items-start gap-2.5 border-b border-indigo-100 bg-indigo-50/60 px-4 py-3">
          <svg
            className="mt-0.5 h-4 w-4 shrink-0 animate-spin text-indigo-600"
            fill="none"
            viewBox="0 0 24 24"
            aria-hidden
          >
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          <p className="text-[11px] leading-relaxed text-indigo-950">
            {policyGenerationReasonLabel("in_progress")}
          </p>
        </div>
      )}
      {feedbackDisplay && (
        <div
          className={`px-4 py-3 text-[11px] leading-relaxed ${
            feedbackDisplay.tone === "error"
              ? "border-t border-red-100 bg-red-50 text-red-900"
              : feedbackDisplay.tone === "success"
                ? "border-t border-emerald-100 bg-emerald-50 text-emerald-950"
                : "border-t border-zinc-100 bg-zinc-50 text-zinc-700"
          }`}
        >
          {feedbackDisplay.message}
        </div>
      )}
    </div>
  );
}

function GeneratePolicySection({
  accountId,
  finding,
  cloudTrailLogging,
}: {
  accountId: string;
  finding: Finding;
  cloudTrailLogging: boolean;
}) {
  const [enabled, setEnabled] = useState(false);
  const [policyOpen, setPolicyOpen] = useState(true);
  const [view, setView] = useState<"diff" | "cleaned" | "original">("diff");
  const { data, isLoading, error, refetch, isFetching } = useQuery<GeneratedPolicy>({
    queryKey: ["generated-policy", accountId, finding.resource_arn, finding.last_seen],
    queryFn: () =>
      api(
        `/v1/accounts/${accountId}/roles/generated-policy?role_arn=${encodeURIComponent(finding.resource_arn)}&advanced=true`,
      ),
    enabled,
    staleTime: 0,
  });

  return (
    <DrawerSection
      title="Suggested policy"
      collapsible={enabled}
      expanded={policyOpen}
      onExpandedChange={setPolicyOpen}
      action={
        !enabled ? (
          <button
            onClick={() => {
              setEnabled(true);
              setPolicyOpen(true);
            }}
            className="rounded-md border border-zinc-300 bg-white px-2.5 py-0.5 text-[11px] font-medium text-zinc-700 transition-colors hover:bg-zinc-50"
          >
            Build suggestion
          </button>
        ) : (
          <button
            type="button"
            onClick={() => void refetch()}
            disabled={isFetching}
            className="rounded-md border border-zinc-300 bg-white px-2.5 py-0.5 text-[11px] font-medium text-zinc-700 transition-colors hover:bg-zinc-50 disabled:opacity-60"
          >
            {isFetching ? "Refreshing…" : "Rebuild"}
          </button>
        )
      }
    >
      <div className={drawerSectionBody}>
      {!enabled && (
        <p className="text-[13px] leading-snug text-zinc-600">{generatePolicyIntro(cloudTrailLogging)}</p>
      )}
      {enabled && isLoading && <div className="py-2 text-[13px] text-zinc-500">Building suggestion…</div>}
      {enabled && error && <div className="py-1 text-[13px] text-red-600">{String(error)}</div>}
      {enabled && data && !data.has_inline_policies && (
        <div className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-[13px] leading-snug text-amber-900">{data.note ?? "No inline policies found. Permissions come from attached managed policies."}</div>
      )}
      {enabled && data && (
        <>
          <PolicyCoverageMeta data={data} />
          <PolicyCloudTrailStartAction
            findingId={finding.id}
            accountId={accountId}
            roleArn={finding.resource_arn}
            data={data}
            onRefresh={() => void refetch()}
          />
        </>
      )}
      {enabled && data && data.has_inline_policies && data.original_policies && data.cleaned_policies && (
        <div className="mt-2.5 space-y-2.5">
          <div className="flex items-center justify-between gap-2">
            <span className="text-[11px] text-zinc-600">
              {policyChangeSummary(data)}
            </span>
            <div className="flex gap-0.5 rounded-md bg-zinc-100 p-0.5">
              {(["diff", "cleaned", "original"] as const).map((v) => (
                <button key={v} onClick={() => setView(v)} className={`rounded px-2 py-0.5 text-[11px] font-medium capitalize transition-colors ${view === v ? "bg-white text-zinc-900 shadow-sm" : "text-zinc-600 hover:text-zinc-800"}`}>
                  {v}
                </button>
              ))}
            </div>
          </div>
          {Object.keys(data.cleaned_policies).map((policyName) => {
            const hint = policyRenameHint(policyName, finding.resource_arn, (data.statements_modified ?? 0) > 0);
            if (!hint) return null;
            return (
              <div key={policyName} className="rounded-md border border-indigo-200 bg-indigo-50 px-3 py-2 text-[13px] leading-snug text-indigo-900">
                {hint}
              </div>
            );
          })}
          {view === "diff" && (
            <PolicyDiffView
              original={data.original_policies}
              cleaned={data.cleaned_policies}
              granularity={data.granularity}
              hideUnchangedResources={finding.check_id === "iam.role.unused_services_90d"}
              preservedServiceWildcards={data.preserved_service_wildcards}
            />
          )}
          {view !== "diff" && <CliBlock code={JSON.stringify(view === "cleaned" ? data.cleaned_policies : data.original_policies, null, 2)} />}
          {data.granularity === "service" && !data.access_analyzer?.job_id && (
            <p className="text-[11px] leading-snug text-zinc-500">
              Per-action usage not available yet — scoped to services with recorded activity. Run another scan to refresh.
            </p>
          )}
        </div>
      )}
      </div>
    </DrawerSection>
  );
}

function GenerateS3HttpsPolicySection({
  accountId,
  finding,
}: {
  accountId: string;
  finding: Finding;
}) {
  const [enabled, setEnabled] = useState(false);
  const [policyOpen, setPolicyOpen] = useState(true);
  const [view, setView] = useState<"diff" | "merged" | "original">("diff");
  const { data, isLoading, error } = useQuery<GeneratedS3HttpsPolicy>({
    queryKey: ["generated-s3-https-policy", accountId, finding.resource_arn, finding.last_seen],
    queryFn: () =>
      api(
        `/v1/accounts/${accountId}/s3/generated-https-policy?bucket_arn=${encodeURIComponent(finding.resource_arn)}`,
      ),
    enabled,
    staleTime: 0,
  });

  const originalPolicies = data
    ? {
        "Bucket policy": data.original_policy ?? { Version: "2012-10-17", Statement: [] },
      }
    : undefined;
  const mergedPolicies = data ? { "Bucket policy": data.merged_policy } : undefined;

  return (
    <DrawerSection
      title="Suggested policy"
      collapsible={enabled}
      expanded={policyOpen}
      onExpandedChange={setPolicyOpen}
      action={
        !enabled ? (
          <button
            onClick={() => {
              setEnabled(true);
              setPolicyOpen(true);
            }}
            className="rounded-md border border-zinc-300 bg-white px-2.5 py-0.5 text-[11px] font-medium text-zinc-700 transition-colors hover:bg-zinc-50"
          >
            Generate
          </button>
        ) : undefined
      }
    >
      <div className={drawerSectionBody}>
        {enabled && isLoading && <div className="py-2 text-[13px] text-zinc-500">Generating…</div>}
        {enabled && error && <div className="py-1 text-[13px] text-red-600">{String(error)}</div>}
        {enabled && data?.already_has_https_deny && (
          <div className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-[13px] leading-snug text-amber-900">
            Live bucket policy already denies requests where{" "}
            <span className="font-mono text-[12px]">aws:SecureTransport</span> is false. Re-scan after any change if this
            finding still appears.
          </div>
        )}
        {enabled && data && !data.already_has_https_deny && originalPolicies && mergedPolicies && (
          <div className="space-y-2.5">
            <div className="flex justify-end">
              <div className="flex gap-0.5 rounded-md bg-zinc-100 p-0.5">
                {(["diff", "merged", "original"] as const).map((v) => (
                  <button
                    key={v}
                    onClick={() => setView(v)}
                    className={`rounded px-2 py-0.5 text-[11px] font-medium capitalize transition-colors ${view === v ? "bg-white text-zinc-900 shadow-sm" : "text-zinc-600 hover:text-zinc-800"}`}
                  >
                    {v === "merged" ? "merged" : v}
                  </button>
                ))}
              </div>
            </div>
            {view === "diff" &&
              (!data.had_policy ? (
                <div className="space-y-2">
                  <p className="text-[12px] text-zinc-500">This bucket never had a policy.</p>
                  <PolicyStatementDiffBlock
                    lines={buildNewStatementDiffLines(
                      ((data.merged_policy.Statement as PolicyStatement[]) ?? [])[0] ?? {},
                    )}
                  />
                </div>
              ) : (
                <PolicyDiffView original={originalPolicies} cleaned={mergedPolicies} />
              ))}
            {view === "merged" && <CliBlock code={JSON.stringify(data.merged_policy, null, 2)} label="Policy" />}
            {view === "original" && (
              <CliBlock code={JSON.stringify(originalPolicies["Bucket policy"], null, 2)} label="Policy" />
            )}
          </div>
        )}
      </div>
    </DrawerSection>
  );
}

function CliBlock({ code, label = "Command" }: { code: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  function copy() {
    const executable = code
      .split("\n")
      .filter((l) => !l.trimStart().startsWith("#"))
      .join("\n")
      .replace(/\n{3,}/g, "\n\n")
      .trim();
    navigator.clipboard.writeText(executable).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    });
  }
  return (
    <div className="rounded-lg bg-zinc-100/60 overflow-hidden">
      <div className="flex items-center justify-between px-3.5 py-2">
        <span className="text-[10px] font-medium uppercase tracking-wide text-zinc-400">{label}</span>
        <button
          onClick={copy}
          className={`rounded-md px-2 py-0.5 text-[11px] font-medium transition-all duration-150 ${
            copied
              ? "text-emerald-600"
              : "text-zinc-500 hover:bg-white/60 hover:text-zinc-800"
          }`}
        >
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="overflow-x-auto whitespace-pre-wrap px-4 pb-4 pt-0 font-mono text-[12px] leading-[1.7] text-zinc-700">{code}</pre>
    </div>
  );
}

function ExceptionButton({ findingId, onDone }: { findingId: string; onDone: () => void }) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [approvedBy, setApprovedBy] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [done, setDone] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!reason.trim() || !approvedBy.trim()) return;
    setSubmitting(true);
    try {
      await api(`/v1/findings/${findingId}/exception`, {
        method: "POST",
        body: JSON.stringify({
          reason: reason.trim(),
          approved_by: approvedBy.trim(),
          expires_at: expiresAt || null,
        }),
      });
      setDone(true);
      setTimeout(() => { setOpen(false); onDone(); }, 800);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        className={`${drawerFooterException} ${done ? "!border-emerald-200/80 !bg-emerald-50/80 !text-emerald-800 hover:!bg-emerald-50" : ""}`}
      >
        {done ? "Approved" : "Exception"}
      </button>
      {open && (
        <div className="fixed inset-0 z-[70] flex items-center justify-center p-4 sm:p-6">
          <div
            className="absolute inset-0 bg-zinc-950/25 backdrop-blur-[2px]"
            onClick={() => setOpen(false)}
            aria-hidden
          />
          <div
            role="dialog"
            aria-labelledby="exception-dialog-title"
            className="relative w-full max-w-[520px] overflow-hidden rounded-2xl border border-zinc-200 bg-zinc-50 shadow-2xl shadow-zinc-900/15"
          >
            <div className="border-b border-amber-200/80 bg-amber-50/90 px-4 py-2.5 text-[12px] leading-snug text-amber-950">
              <span className="font-semibold">Audit evidence.</span> This exception, approver, and expiry will appear in your evidence pack.
            </div>
            <div className="p-6">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <h3 id="exception-dialog-title" className="text-base font-semibold text-zinc-900">
                    Document exception
                  </h3>
                  <p className="mt-1 text-sm leading-relaxed text-zinc-500">
                    Exceptions are retained in the evidence pack. Auditors can review the reason, approver, and expiry.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setOpen(false)}
                  className="shrink-0 rounded-lg p-1 text-zinc-400 transition hover:bg-zinc-100 hover:text-zinc-600"
                  aria-label="Close"
                >
                  <svg className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
              <form onSubmit={submit} className="mt-5 space-y-4">
                <div>
                  <label className="mb-1 block text-xs font-medium text-zinc-700">
                    Reason <span className="text-red-500">*</span>
                  </label>
                  <textarea
                    value={reason}
                    onChange={(e) => setReason(e.target.value)}
                    rows={3}
                    placeholder="e.g. Internal sandbox repo — no production code. Risk accepted by CTO."
                    className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-800 shadow-sm placeholder:text-zinc-400 focus:border-zinc-300 focus:outline-none focus:ring-2 focus:ring-zinc-900/10"
                    required
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium text-zinc-700">
                    Approved by <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    value={approvedBy}
                    onChange={(e) => setApprovedBy(e.target.value)}
                    placeholder="e.g. Alice Smith (CTO)"
                    className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-800 shadow-sm placeholder:text-zinc-400 focus:border-zinc-300 focus:outline-none focus:ring-2 focus:ring-zinc-900/10"
                    required
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium text-zinc-700">Expires (optional)</label>
                  <input
                    type="date"
                    value={expiresAt}
                    onChange={(e) => setExpiresAt(e.target.value)}
                    className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-800 shadow-sm focus:border-zinc-300 focus:outline-none focus:ring-2 focus:ring-zinc-900/10"
                  />
                </div>
                <div className="flex flex-col-reverse gap-2 pt-2 sm:flex-row sm:justify-end">
                  <button
                    type="button"
                    onClick={() => setOpen(false)}
                    className="rounded-lg border border-zinc-200 bg-white px-4 py-2.5 text-sm font-semibold text-zinc-700 shadow-sm transition hover:border-zinc-300 hover:bg-zinc-50 sm:min-w-[7rem]"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={submitting || !reason.trim() || !approvedBy.trim()}
                    className="rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-50 sm:min-w-[9rem]"
                  >
                    {submitting ? "Saving…" : "Save exception"}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}
    </>
  );
}


function AffectedResourcesPanel({
  findings,
  activeId,
  onSelect,
  checkId,
}: {
  findings: Finding[];
  activeId: string;
  onSelect: (f: Finding) => void;
  checkId: string;
}) {
  const [search, setSearch] = useState("");

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return findings;
    return findings.filter((f) => {
      const name = resourceDisplayName(f).toLowerCase();
      return name.includes(q) || f.resource_arn.toLowerCase().includes(q);
    });
  }, [findings, search]);

  const typeLabel = resourceTypeLabel(checkId);

  return (
    <DrawerSection
      title={typeLabel}
      action={
        <div className="flex items-center gap-2">
          <span className="text-[11px] tabular-nums text-zinc-500">{findings.length}</span>
          {findings.length > 6 && (
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search…"
              className="w-24 rounded-md border-0 bg-zinc-100 px-2 py-0.5 text-[11px] text-zinc-800 outline-none ring-1 ring-zinc-200/60 placeholder:text-zinc-400 focus:ring-indigo-500/30"
            />
          )}
        </div>
      }
    >
      <ul className="max-h-44 space-y-px overflow-y-auto px-2 py-1.5">
        {filtered.map((f) => {
          const active = f.id === activeId;
          return (
            <li key={f.id}>
              <button
                type="button"
                onClick={() => onSelect(f)}
                className={`flex w-full items-center justify-between gap-3 rounded-lg border-l-2 py-2 pr-4 text-left text-[12px] transition ${
                  active
                    ? "border-l-zinc-400 bg-zinc-50/90 pl-2.5 font-medium text-zinc-900"
                    : "border-l-transparent pl-3 text-zinc-600 hover:bg-zinc-50 hover:text-zinc-800"
                }`}
              >
                <span className="min-w-0">
                  <span className="block truncate">{resourceDisplayName(f)}</span>
                  {f.check_id.startsWith("ec2.security_group.") && (
                    <span className="mt-0.5 block truncate font-mono text-[10px] text-zinc-400">
                      {(f.evidence.group_id as string) || f.resource_arn.split("/").pop()}
                    </span>
                  )}
                </span>
                <span className="shrink-0 pl-2 text-[10px] tabular-nums text-zinc-400">{daysAgo(f.first_seen)}</span>
              </button>
            </li>
          );
        })}
      </ul>
    </DrawerSection>
  );
}

export function FindingDrawer({
  finding,
  relatedFindings,
  onSelectRelated,
  accountId,
  onClose,
  onAction,
  tab,
  onTabChange,
  remTab,
  onRemTabChange,
  verified,
  verifyUnchanged,
  verifying,
  onDismissVerifyOutcome,
}: {
  finding: Finding | null;
  relatedFindings?: Finding[];
  onSelectRelated?: (f: Finding) => void;
  accountId: string | null;
  onClose: () => void;
  onAction: (id: string, action: "recheck" | "reopen") => void;
  tab: FindingDrawerTab;
  onTabChange: (tab: FindingDrawerTab) => void;
  remTab: FindingRemediationMode;
  onRemTabChange: (mode: FindingRemediationMode) => void;
  verified?: boolean;
  verifyUnchanged?: boolean;
  verifying?: boolean;
  onDismissVerifyOutcome?: () => void;
}) {
  const prevCheckId = useRef<string | null>(null);

  const { data: accountMeta } = useQuery({
    queryKey: ["account-cloudtrail", accountId],
    queryFn: () =>
      api<{ meta: { cloudtrail_logging: boolean } }>(`/v1/accounts/${accountId}/timeline?days=1&limit=1`),
    enabled: !!accountId && !!finding,
    staleTime: 300_000,
  });
  const cloudTrailLogging = accountMeta?.meta?.cloudtrail_logging ?? false;

  useEffect(() => {
    if (!finding) {
      prevCheckId.current = null;
      return;
    }
    const differentCheck =
      prevCheckId.current !== null && prevCheckId.current !== finding.check_id;
    if (differentCheck) {
      onTabChange("overview");
      onRemTabChange(defaultFindingRemediationMode(finding.check_id));
    }
    prevCheckId.current = finding.check_id;
  }, [finding?.id, finding?.check_id, onTabChange, onRemTabChange]);

  useEffect(() => {
    if (finding && SG_AUTOMATION_ONLY_CHECKS.has(finding.check_id) && remTab === "terraform") {
      onRemTabChange("automation");
    }
  }, [finding?.check_id, finding?.id, remTab, onRemTabChange]);

  const multiResource = (relatedFindings?.length ?? 0) > 1;
  const showBlastRadius = !!finding && supportsBlastRadius(finding.check_id) && !!accountId;

  useEffect(() => {
    if (!finding) return;
    const available = new Set<Tab>([
      "overview",
      "compliance",
      "remediation",
      "resources",
      ...(showBlastRadius ? (["whatif"] as Tab[]) : []),
    ]);
    if (!available.has(tab)) onTabChange("overview");
  }, [finding?.id, showBlastRadius, tab, onTabChange]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!verified || !finding) return;
    const t = window.setTimeout(() => {
      onDismissVerifyOutcome?.();
      onClose();
    }, 3000);
    return () => window.clearTimeout(t);
  }, [verified, finding?.id, onClose, onDismissVerifyOutcome]);

  if (!finding) return null;

  const showReopenFooter =
    (finding.status === "resolved" || finding.status === "ignored") && !verified && !verifying;

  const rem =
    identityRemediations[finding.check_id] ??
    remediations[finding.check_id] ??
    fallbackRemediationFor(finding.check_id);
  const ops = remediationSummaryFor(finding.check_id);
  const checkDoc = documentationForCheck(finding.check_id);
  const isIdentityCheck = finding.check_id.startsWith("github.") || finding.check_id.startsWith("gitlab.");
  const headerBadge = sevHeaderBadge[finding.severity] ?? sevHeaderBadge.low;
  const wash = sevWash[finding.severity] ?? sevWash.low;
  const step = sevStep[finding.severity] ?? sevStep.low;
  const categoryLabel: Record<string, string> = {
    "iam.root": "Root Account",
    "iam.user": "IAM User",
    "iam.access_key": "Access Key",
    "iam.role": "IAM Role",
    "s3.bucket": "S3 Bucket",
    "kms.key": "KMS Key",
    "dynamodb.table": "DynamoDB Table",
    "lambda.function": "Lambda Function",
    "acm.certificate": "ACM Certificate",
    "secretsmanager.secret": "Secrets Manager",
    "ssm.parameter": "SSM Parameter",
    "elb.load_balancer": "Load Balancer",
    "sns.topic": "SNS Topic",
    "sqs.queue": "SQS Queue",
    "ec2.ami": "EC2 AMI",
    "ec2.ebs.snapshot": "EBS Snapshot",
    "github.org": "GitHub Organization",
    "github.repo": "GitHub Repository",
    "gitlab.org": "GitLab Group",
    "gitlab.repo": "GitLab Project",
  };
  const category = Object.entries(categoryLabel).find(([prefix]) => finding.check_id.startsWith(prefix))?.[1] ?? "Finding";
  const showPolicyGen = ROLE_POLICY_GEN_CHECKS.has(finding.check_id) && !!accountId;

  const tabs: { id: Tab; label: string }[] = [
    { id: "overview", label: "Overview" },
    { id: "resources", label: "Resources" },
    { id: "compliance", label: "Compliance" },
    { id: "remediation", label: "Remediation" },
    ...(showBlastRadius ? [{ id: "whatif" as Tab, label: "What If" }] : []),
  ];
  const hasException =
    finding.status === "excepted" ||
    !!finding.exception_reason ||
    !!finding.exception_approved_by;

  return <><div className="fixed inset-0 z-40 bg-black/25 backdrop-blur-[2px]" onClick={onClose} /><div className={`fixed right-0 top-0 z-50 flex h-full w-full ${DRAWER_MAX_W} flex-col overflow-hidden bg-white shadow-2xl`}>
    {verified && (
      <div
        className="absolute inset-0 z-[60] flex flex-col items-center justify-center bg-gradient-to-b from-emerald-50 via-emerald-50/95 to-white px-8 text-center"
        role="status"
        aria-live="polite"
      >
        <div className="relative mb-6 flex h-24 w-24 items-center justify-center">
          <span
            className="absolute inset-0 rounded-full bg-emerald-400/30 animate-ping"
            style={{ animationDuration: "1.4s" }}
            aria-hidden
          />
          <span className="relative flex h-24 w-24 items-center justify-center rounded-full bg-emerald-500 text-white shadow-lg shadow-emerald-500/35 ring-4 ring-emerald-100">
            <svg className="h-11 w-11" fill="none" stroke="currentColor" strokeWidth={2.5} viewBox="0 0 24 24" aria-hidden>
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
            </svg>
          </span>
        </div>
        <p className="text-2xl font-bold tracking-tight text-emerald-950">Verified</p>
        <p className="mt-2 max-w-xs text-sm leading-relaxed text-emerald-900/75">
          Re-check passed — this finding is resolved.
        </p>
      </div>
    )}
    <div className={`relative overflow-hidden bg-gradient-to-b ${wash} px-6 pt-5 pb-3`}>
      <button onClick={onClose} className="absolute right-4 top-4 rounded-md p-1 text-zinc-400 transition hover:bg-white/70 hover:text-zinc-600"><svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg></button>
      <div className="flex items-center gap-2 pr-10"><span className="text-[11px] font-medium text-zinc-600">{category}</span><span className="text-zinc-300">·</span><span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide ${headerBadge}`}>{finding.severity}</span></div>
      <h2 className="mt-1.5 pr-8 text-base font-semibold leading-snug text-zinc-900">{checkLabels[finding.check_id] ?? finding.title}</h2>
      <div className="mt-2.5 rounded-lg border border-black/[0.07] bg-white/70 px-3 py-2">
        <div className="mb-0.5 flex items-baseline justify-between gap-2">
          <div className={drawerFieldLabelBlock}>Resource</div>
          {multiResource && relatedFindings && (
            <span className="shrink-0 text-[10px] tabular-nums text-zinc-500">
              {(relatedFindings.findIndex((f) => f.id === finding.id) + 1) || 1} of {relatedFindings.length}
            </span>
          )}
        </div>
        <div className="group relative">
          <p className="truncate font-mono text-xs text-zinc-700">{resourceDisplayName(finding)}</p>
          <div className="pointer-events-none absolute bottom-full left-0 z-50 mb-2 hidden max-w-xs rounded-lg border border-zinc-200 bg-white px-3 py-2 shadow-lg group-hover:block">
            <p className="break-all font-mono text-xs leading-relaxed text-zinc-700">{finding.resource_arn}</p>
          </div>
        </div>
      </div>
      {/* Segmented tab control — w-fit keeps track background from stretching full width */}
      <div className="mt-3">
        <div className="inline-flex max-w-full gap-0.5 overflow-x-auto rounded-lg bg-zinc-900/[0.06] p-0.5">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => onTabChange(t.id)}
            className={`flex shrink-0 items-center justify-center gap-1.5 whitespace-nowrap rounded-md px-3 py-1.5 text-[13px] font-medium transition-all ${
              tab === t.id ? "bg-white text-zinc-900 shadow-sm ring-1 ring-zinc-900/5" : "text-zinc-600 hover:text-zinc-800"
            }`}
          >
            {t.id === "whatif" && (
              <svg className="h-3.5 w-3.5 text-amber-400" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M9.879 7.519c1.171-1.025 3.071-1.025 4.242 0 1.172 1.025 1.172 2.687 0 3.712-.203.179-.43.326-.67.442-.745.361-1.45.999-1.45 1.827v.75M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9 5.25h.008v.008H12v-.008z" />
              </svg>
            )}
            {t.label}
          </button>
        ))}
        </div>
      </div>
    </div>
    <div className={`flex-1 ${drawerBodyGap} overflow-y-auto bg-zinc-50/80 px-6 pb-5 pt-4`}>
      {verifyUnchanged && !verified && (
        <div
          className="flex items-start gap-3 rounded-xl border border-amber-200/80 bg-amber-50/90 px-4 py-3.5 text-[12px] leading-relaxed text-amber-950"
          role="status"
        >
          <p className="min-w-0 flex-1">
            <span className="font-semibold">Still open</span> — verify finished but this finding did not resolve. Fix
            the issue in AWS, then try again.
          </p>
          {onDismissVerifyOutcome && (
            <button
              type="button"
              onClick={onDismissVerifyOutcome}
              className="shrink-0 text-[11px] font-medium text-amber-900/80 hover:text-amber-950"
            >
              Dismiss
            </button>
          )}
        </div>
      )}
      {tab === "overview" && (
        <OverviewTabContent
          impact={ops.impact}
          risk={ops.risk}
          fix={ops.fix}
          finding={finding}
          hasException={hasException}
          documentation={checkDoc}
          accountId={accountId}
        />
      )}
      {tab === "resources" && (
        <div className="space-y-2.5">
          {multiResource && relatedFindings && onSelectRelated && (
            <AffectedResourcesPanel
              findings={relatedFindings}
              activeId={finding.id}
              onSelect={onSelectRelated}
              checkId={finding.check_id}
            />
          )}
          <SelectedResourceInspector finding={finding} attachedToList={!!multiResource} />
        </div>
      )}
      {tab === "compliance" && (
        <ComplianceTabContent checkId={finding.check_id} accountId={accountId} />
      )}
      {tab === "remediation" && (
        <div className="space-y-2.5">
          {showPolicyGen && (
            <GeneratePolicySection
              accountId={accountId!}
              finding={finding}
              cloudTrailLogging={cloudTrailLogging}
            />
          )}
          {finding.check_id === "s3.bucket.no_https_policy" && accountId && (
            <GenerateS3HttpsPolicySection accountId={accountId} finding={finding} />
          )}
          <div className={`${drawerPanel} overflow-hidden shadow-sm shadow-zinc-900/[0.03]`}>
            <div className="flex flex-wrap items-center gap-2 border-b border-zinc-100 bg-zinc-50/80 px-4 py-2.5">
              {!isIdentityCheck && (
                <RemediationModeToggle
                  value={remTab}
                  onChange={onRemTabChange}
                  hideTerraform={SG_AUTOMATION_ONLY_CHECKS.has(finding.check_id)}
                />
              )}
              <FlowBadge variant={remediationImpactBadge(finding.severity).variant}>
                {remediationImpactBadge(finding.severity).label}
              </FlowBadge>
            </div>
            <div className="px-4 py-3.5 pr-5">
              {(isIdentityCheck || remTab === "console") && (
                <ol className="space-y-2.5">
                  {rem.console.map((item, i) => (
                    <li key={i} className="flex gap-2.5 text-[13px] leading-relaxed text-zinc-800">
                      <span className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded text-[10px] font-bold ${step}`}>{i + 1}</span>
                      <span className="min-w-0 pt-px">{item}</span>
                    </li>
                  ))}
                </ol>
              )}
              {!isIdentityCheck && remTab === "cli" && <RemediationCliBlock finding={finding} />}
              {!isIdentityCheck && remTab === "terraform" && (
                <IaCRemediationSection
                  embedMode="terraform"
                  findingId={finding.id}
                  checkId={finding.check_id}
                />
              )}
              {!isIdentityCheck && remTab === "automation" && (
                <IaCRemediationSection
                  embedMode="automation"
                  findingId={finding.id}
                  checkId={finding.check_id}
                  accountId={accountId}
                  resourceRegion={resourceRegionForFinding(finding)}
                />
              )}
            </div>
          </div>
          <FlowCallout tone="positive" title="Validate after remediation">
            Click Verify to confirm the fix in AWS. Supported checks resolve in seconds; others queue a full re-scan.
          </FlowCallout>
        </div>
      )}
      {tab === "whatif" && showBlastRadius && (
        <BlastRadiusSection accountId={accountId!} finding={finding} />
      )}
    </div>
    <div className="flex gap-2 border-t border-zinc-200/50 bg-white/90 px-6 py-3 shadow-[0_-1px_0_rgba(0,0,0,0.03),0_-6px_16px_-6px_rgba(0,0,0,0.04)] backdrop-blur-sm">
      {showReopenFooter ? (
        <button
          type="button"
          onClick={() => onAction(finding.id, "reopen")}
          className={drawerFooterPrimary}
        >
          Reopen finding
        </button>
      ) : (
        <button
          type="button"
          disabled={verifying || verified}
          onClick={() => onAction(finding.id, "recheck")}
          className={`${drawerFooterPrimary} relative inline-flex min-h-[38px] min-w-[7.5rem] shrink-0 items-center justify-center gap-2 ${
            verified ? "!bg-emerald-600 shadow-emerald-900/15 ring-emerald-700/20 hover:!bg-emerald-600" : ""
          }`}
        >
          <span className={verifying ? "invisible" : ""} aria-hidden={verifying}>
            {verified ? "Verified" : "Verify"}
          </span>
          {verifying && (
            <span className="absolute inset-0 flex items-center justify-center gap-2">
              <svg className="h-3.5 w-3.5 shrink-0 animate-spin" fill="none" viewBox="0 0 24 24" aria-hidden>
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              <span>Verifying…</span>
            </span>
          )}
          {verified && !verifying && (
            <span className="absolute inset-0 flex items-center justify-center gap-1.5 text-emerald-100">
              <svg className="h-3.5 w-3.5 shrink-0" fill="none" stroke="currentColor" strokeWidth={2.5} viewBox="0 0 24 24" aria-hidden>
                <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
              </svg>
              <span>Verified</span>
            </span>
          )}
        </button>
      )}
      <ExceptionButton findingId={finding.id} onDone={onClose} />
    </div>
  </div></>;
}
