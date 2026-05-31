import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { api, formatApiError } from "../api";
import { DeploymentParametersCard } from "../components/accountOnboardingUI";
import {
  ADVANCED_POLICY_RAW_ACTIONS,
} from "../data/capabilityCopy";
import { resolveDeployArtifacts, type CfnConnectionOptions } from "../lib/cfnDeployCommands";
import { isValidIamRoleArn } from "../lib/awsArn";
import {
  DEFAULT_REMEDIATION_MODULES,
  REMEDIATION_MODULE_SPECS,
  anyRemediationEnabled,
  countRemediationEnabled,
  type RemediationModules,
} from "../data/remediationModules";
import ScanProgressBar from "../components/ScanProgressBar";
import ConfirmDialog from "../components/ConfirmDialog";
import { useDebouncedCallback } from "../hooks/useDebouncedCallback";
import { useTriggeredScan } from "../hooks/useTriggeredScan";
import { isAccountConnected } from "../lib/accountConnection";
import { CONNECTOR_STACK_NAME, SCANNER_ROLE_NAME } from "../lib/connectionPosture";

type ConnectionOptions = {
  enable_advanced_policy_generation: boolean;
  remediation_modules: RemediationModules;
};

type Account = {
  id: string;
  label: string;
  account_id: string | null;
  status: string;
  external_id: string;
  role_arn: string | null;
  enable_advanced_policy_generation: boolean;
  remediation_modules: RemediationModules;
  remediation_modules_deployed: RemediationModules;
  advanced_policy_generation_deployed: boolean;
  cfn_stack_name: string;
  cfn_launch_url: string;
  cfn_update_launch_url: string;
  cfn_template_url: string;
  cfn_cli_command: string;
  cfn_update_cli_command: string;
  remediation_cfn_launch_url: string | null;
  remediation_cfn_template_url: string | null;
  remediation_cfn_cli_command: string | null;
  last_scan_at: string | null;
  last_error: string | null;
};

const DEFAULT_CONNECTION_OPTIONS: ConnectionOptions = {
  enable_advanced_policy_generation: false,
  remediation_modules: { ...DEFAULT_REMEDIATION_MODULES },
};

function roleArnFieldValidation(
  roleArn: string,
  verify: { isPending: boolean; isError: boolean; isSuccess: boolean },
): "idle" | "pending" | "success" | "error" | "invalid-format" {
  if (verify.isPending) return "pending";
  if (verify.isSuccess) return "success";
  if (verify.isError) return "error";
  const trimmed = roleArn.trim();
  if (trimmed && !isValidIamRoleArn(trimmed)) return "invalid-format";
  return "idle";
}

function accountConnectionOptions(acc: Account): ConnectionOptions {
  return {
    enable_advanced_policy_generation: acc.enable_advanced_policy_generation,
    remediation_modules: { ...acc.remediation_modules },
  };
}

function hasOptionalCapabilities(acc: Account): boolean {
  return (
    acc.enable_advanced_policy_generation || anyRemediationEnabled(acc.remediation_modules)
  );
}

type PermissionVerifyRow = { action: string; granted: boolean };

type ModuleVerifyStatus = "not_requested" | "ready" | "missing_permissions" | "not_assumable";

type ModuleVerifyResult = {
  deployed: boolean;
  error: string | null;
  requested: boolean;
  status?: ModuleVerifyStatus;
  assumable?: boolean | null;
  role_arn?: string | null;
  permissions?: PermissionVerifyRow[];
  granted_count?: number;
  required_count?: number;
  policy_found?: boolean;
  runner_ready?: boolean | null;
};

type CapabilityVerifyResults = {
  advanced_policy_generation?: ModuleVerifyResult;
  remediation_modules?: Record<string, ModuleVerifyResult>;
};

type VerificationMeta = {
  method: string;
  description: string;
  safe: string;
  scanner_role_arn?: string | null;
};

type VerifyCapabilitiesResponse = {
  account: Account;
  capabilities: CapabilityVerifyResults;
  verification?: VerificationMeta;
};

const PERMISSION_VERIFY_DESCRIPTION = "Verified from deployed IAM role policy.";

const workflowInlineBtn =
  "inline-flex shrink-0 items-center justify-center rounded-lg bg-zinc-900 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-50";

const workflowInlineActionBtn =
  "inline-flex shrink-0 items-center justify-center rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-50";

function WorkflowCheckIcon() {
  return (
    <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-emerald-100 text-emerald-700">
      <svg className="h-3 w-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden>
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
      </svg>
    </span>
  );
}

function WorkflowStepCard({
  variant,
  statusLabel,
  description,
  children,
}: {
  variant: "success" | "action";
  statusLabel: string;
  description?: string;
  children?: ReactNode;
}) {
  const success = variant === "success";
  return (
    <div
      className={
        success
          ? "rounded-lg border border-emerald-200/70 bg-emerald-50/50 px-4 py-3.5"
          : "rounded-lg border border-zinc-200/80 bg-zinc-50/60 px-4 py-3.5"
      }
    >
      <p
        className={`flex items-center gap-2 text-sm font-medium ${
          success ? "text-emerald-800" : "text-zinc-900"
        }`}
      >
        {success && <WorkflowCheckIcon />}
        {statusLabel}
      </p>
      {description && (
        <p
          className={`mt-1 text-xs leading-relaxed ${
            success ? "text-emerald-900/75" : "text-zinc-600"
          }`}
        >
          {description}
        </p>
      )}
      {children && <div className="mt-4 w-full">{children}</div>}
    </div>
  );
}

type ModuleStatusDisplay = {
  icon: string;
  label: string;
  tone: "success" | "warning" | "danger";
};

function moduleStatusDisplay(
  result: ModuleVerifyResult | undefined,
  deployedFallback: boolean,
): ModuleStatusDisplay | null {
  if (result?.requested) {
    if (result.status === "ready" || result.deployed) {
      const granted = result.granted_count ?? 0;
      const required = result.required_count ?? 0;
      const suffix = required > 0 ? ` · ${granted}/${required} permissions` : "";
      return { icon: "✓", label: `Ready${suffix}`, tone: "success" };
    }
    return null;
  }
  if (deployedFallback) {
    return { icon: "✓", label: "Ready", tone: "success" };
  }
  return null;
}

function ModuleStatusBadge({
  result,
  deployedFallback,
}: {
  result?: ModuleVerifyResult;
  deployedFallback: boolean;
}) {
  const status = moduleStatusDisplay(result, deployedFallback);
  if (!status) return null;
  const toneClass =
    status.tone === "success"
      ? "text-emerald-700"
      : status.tone === "danger"
        ? "text-red-700"
        : "text-amber-800";
  return (
    <span className={`mt-1.5 inline-flex items-center gap-1 text-xs font-medium ${toneClass}`}>
      <span aria-hidden>{status.icon}</span>
      <span>{status.label}</span>
    </span>
  );
}

function PermissionVerificationPanel({
  onVerify,
  verifying,
  feedback,
  verificationMeta,
  showButton,
}: {
  onVerify: () => void;
  verifying: boolean;
  feedback: CapabilityVerifyFeedback | null;
  verificationMeta: VerificationMeta | null;
  showButton: boolean;
}) {
  if (!showButton && !verificationMeta && !feedback) return null;

  const verified =
    feedback?.tone === "success" || Boolean(verificationMeta && feedback?.tone !== "error");

  if (verified) {
    return (
      <WorkflowStepCard
        variant="success"
        statusLabel="Permissions verified"
        description={verificationMeta?.description ?? PERMISSION_VERIFY_DESCRIPTION}
      />
    );
  }

  return (
    <WorkflowStepCard
      variant="action"
      statusLabel="Verify your stack"
      description="After updating CloudFormation, confirm IAM permissions match your selection."
    >
      {showButton && (
        <button
          type="button"
          onClick={onVerify}
          disabled={verifying}
          className={workflowInlineActionBtn}
        >
          {verifying ? "Verifying…" : "Verify permissions in AWS"}
        </button>
      )}
      {feedback?.tone === "error" && (
        <p className="mt-2 text-xs leading-relaxed text-red-600">{feedback.message}</p>
      )}
    </WorkflowStepCard>
  );
}

function remediationModuleVerified(
  verify: ModuleVerifyResult | undefined,
  deployedFallback: boolean,
): boolean {
  if (verify?.requested && (verify.status === "ready" || verify.deployed)) return true;
  return Boolean(deployedFallback && !verify?.requested);
}

/** IAM still has this capability — cannot turn off in Vigil until stack is updated in AWS. */
function capabilityLockedInAws(
  verify: ModuleVerifyResult | undefined,
  deployedFallback: boolean,
): boolean {
  return remediationModuleVerified(verify, deployedFallback);
}

function enforceDeployedCapabilityLocks(
  acc: Account,
  capabilityVerify: CapabilityVerifyResults | null,
  options: ConnectionOptions,
): ConnectionOptions {
  let enableAdvanced = options.enable_advanced_policy_generation;
  if (
    !enableAdvanced &&
    capabilityLockedInAws(
      capabilityVerify?.advanced_policy_generation,
      acc.advanced_policy_generation_deployed,
    )
  ) {
    enableAdvanced = true;
  }

  const remediation_modules = { ...options.remediation_modules };
  for (const spec of REMEDIATION_MODULE_SPECS) {
    if (
      !remediation_modules[spec.id] &&
      capabilityLockedInAws(
        capabilityVerify?.remediation_modules?.[spec.id],
        Boolean(acc.remediation_modules_deployed[spec.id]),
      )
    ) {
      remediation_modules[spec.id] = true;
    }
  }

  return {
    enable_advanced_policy_generation: enableAdvanced,
    remediation_modules,
  };
}

function RemediationPermissionsBlock({
  permissions,
  verifyRows,
  variant = "code",
}: {
  permissions: readonly string[];
  verifyRows?: PermissionVerifyRow[];
  variant?: "code" | "bullets";
}) {
  const items = verifyRows?.length
    ? verifyRows
    : permissions.map((action) => ({ action, granted: undefined as boolean | undefined }));

  if (variant === "bullets") {
    return (
      <div className="rounded-md border border-zinc-200/90 bg-zinc-50/90 px-3 py-2.5">
        <ul className="space-y-1">
          {items.map((row) => (
            <li key={row.action} className="flex items-start gap-2 font-mono text-[11px] leading-snug text-zinc-700">
              {row.granted === true && (
                <span className="text-emerald-600" aria-hidden>
                  ✓
                </span>
              )}
              {row.granted === false && (
                <span className="text-amber-600" aria-hidden>
                  ○
                </span>
              )}
              {row.granted === undefined && (
                <span className="mt-0.5 text-zinc-400" aria-hidden>
                  •
                </span>
              )}
              <span>{row.action}</span>
            </li>
          ))}
        </ul>
      </div>
    );
  }

  const lines = items.map((row) => {
    const mark = row.granted === true ? "✓" : row.granted === false ? "○" : "·";
    return `${mark} ${row.action}`;
  });

  return (
    <pre className="overflow-x-auto rounded-md border border-zinc-200/90 bg-zinc-50/90 px-3 py-2.5 font-mono text-[11px] leading-relaxed text-zinc-700">
      {lines.join("\n")}
    </pre>
  );
}

function CapabilityAccessBadge({
  kind,
}: {
  kind: "included" | "read-only" | "read-analysis" | "scoped-write" | "automation";
}) {
  const styles =
    kind === "included"
      ? "bg-emerald-50 text-emerald-800 ring-emerald-200/60"
      : kind === "scoped-write" || kind === "automation"
        ? "bg-amber-50 text-amber-900 ring-amber-200/60"
        : kind === "read-analysis"
          ? "bg-violet-50 text-violet-900 ring-violet-200/60"
          : "bg-sky-50 text-sky-800 ring-sky-200/60";
  const label =
    kind === "included"
      ? "Included"
      : kind === "automation"
        ? "Automation"
        : kind === "scoped-write"
          ? "Write"
          : kind === "read-analysis"
            ? "Analysis"
            : "Read-only";
  return (
    <span
      className={`inline-flex shrink-0 rounded px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider ring-1 ring-inset ${styles}`}
    >
      {label}
    </span>
  );
}

/** Green check — same visual as Core Scanner when a capability is verified and locked. */
function CapabilityVerifiedMark({ className = "" }: { className?: string }) {
  return (
    <span
      className={`mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center text-emerald-600 ${className}`}
      aria-hidden
    >
      <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
      </svg>
    </span>
  );
}

function RemediationModuleChevron({ open }: { open: boolean }) {
  return (
    <svg
      className={`h-4 w-4 shrink-0 text-zinc-400 transition-transform ${open ? "rotate-180" : ""}`}
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

function PermissionCheckList({
  rows,
  fallback,
}: {
  rows?: PermissionVerifyRow[];
  fallback: readonly string[];
}) {
  const items = rows?.length
    ? rows
    : fallback.map((action) => ({ action, granted: false as boolean | undefined }));

  const verified = Boolean(rows?.length);

  return (
    <ul className="mt-1.5 space-y-1">
      {items.map((row) => (
        <li key={row.action} className="flex items-start gap-1.5 font-mono text-[11px] leading-relaxed">
          {verified && row.granted === true && (
            <span className="text-emerald-600" aria-hidden>
              ✓
            </span>
          )}
          {verified && row.granted === false && (
            <span className="text-amber-600" aria-hidden>
              ⚠
            </span>
          )}
          {!verified && (
            <span className="text-zinc-400" aria-hidden>
              •
            </span>
          )}
          <span className={row.granted === false ? "text-amber-900" : "text-zinc-600"}>{row.action}</span>
        </li>
      ))}
    </ul>
  );
}

type CapabilityVerifyFeedback = { tone: "success" | "error"; message: string };

function capabilityVerifyFeedback(
  data: VerifyCapabilitiesResponse,
): CapabilityVerifyFeedback | null {
  const errors: string[] = [];
  const adv = data.capabilities.advanced_policy_generation;
  if (adv?.requested && adv.status !== "ready" && adv.error) {
    errors.push(`Policy generation: ${adv.error}`);
  } else if (adv?.requested && adv.status === "not_assumable") {
    errors.push("Policy generation: Not assumable");
  }
  const mods = data.capabilities.remediation_modules ?? {};
  for (const spec of REMEDIATION_MODULE_SPECS) {
    const row = mods[spec.id];
    if (!row?.requested) continue;
    if (row.status === "not_assumable") {
      errors.push(`${spec.label}: Not assumable${row.error ? ` — ${row.error}` : ""}`);
    } else if (row.status !== "ready" && row.error) {
      errors.push(`${spec.label}: ${row.error}`);
    }
  }
  if (errors.length) {
    return { tone: "error", message: errors.join(" · ") };
  }

  const anyRequested =
    Boolean(adv?.requested) ||
    REMEDIATION_MODULE_SPECS.some((m) => mods[m.id]?.requested);
  if (anyRequested) {
    return {
      tone: "success",
      message: "All selected capabilities match deployed IAM role policies.",
    };
  }
  return null;
}

type Finding = { id: string; account_id: string; severity: string; status: string };

type FindingStats = { critHigh: number; medium: number; open: number };

type ScanFreshness = "scanning" | "fresh" | "recent" | "aging" | "stale" | "none";

function AwsIcon({ className = "h-full w-full max-h-16 object-contain" }: { className?: string }) {
  return <img src="/aws.png" alt="AWS" className={className} />;
}

function scanAgeMs(iso: string | null): number | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return Date.now() - d.getTime();
}

function formatLastScan(iso: string | null) {
  const ms = scanAgeMs(iso);
  if (ms == null) return null;
  if (ms < 60_000) return "just now";
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ago`;
  if (ms < 86_400_000) return `${Math.floor(ms / 3_600_000)}h ago`;
  return new Date(iso!).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function scanFreshness(iso: string | null, isScanActive: boolean): ScanFreshness {
  if (isScanActive) return "scanning";
  const ms = scanAgeMs(iso);
  if (ms == null) return "none";
  if (ms < 3_600_000) return "fresh";
  if (ms < 86_400_000) return "recent";
  if (ms < 7 * 86_400_000) return "aging";
  return "stale";
}

const FRESHNESS_META: Record<
  ScanFreshness,
  { dot: string; text: string; hint?: string }
> = {
  scanning: { dot: "bg-indigo-500 animate-pulse", text: "text-indigo-600" },
  fresh: { dot: "bg-emerald-500", text: "text-zinc-600" },
  recent: { dot: "bg-emerald-400", text: "text-zinc-600" },
  aging: { dot: "bg-amber-400", text: "text-zinc-600", hint: "consider rescanning" },
  stale: { dot: "bg-red-400", text: "text-zinc-600", hint: "outdated" },
  none: { dot: "bg-zinc-300", text: "text-zinc-500" },
};

function CopyInputField({
  label,
  value,
  readOnly = true,
  placeholder,
  onChange,
  validation,
}: {
  label: string;
  value: string;
  readOnly?: boolean;
  placeholder?: string;
  onChange?: (v: string) => void;
  validation?: "idle" | "pending" | "success" | "error" | "invalid-format";
}) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 2000);
  }

  const ring =
    validation === "success"
      ? "ring-emerald-500/30 focus-within:ring-emerald-500/40"
      : validation === "error" || validation === "invalid-format"
        ? "ring-red-500/30 focus-within:ring-red-500/40"
        : validation === "pending"
          ? "ring-indigo-500/30 focus-within:ring-indigo-500/40"
          : "ring-zinc-200/80 focus-within:ring-indigo-500/30";

  return (
    <div>
      <label className="mb-1.5 block text-xs font-medium text-zinc-600">{label}</label>
      <div
        className={`flex items-center gap-2 rounded-lg bg-zinc-50/80 px-3 py-2.5 ring-1 ring-inset transition ${ring}`}
      >
        <input
          type="text"
          readOnly={readOnly}
          value={value}
          placeholder={placeholder}
          onChange={readOnly ? undefined : (e) => onChange?.(e.target.value)}
          className={`min-w-0 flex-1 bg-transparent font-mono text-sm text-zinc-900 outline-none placeholder:text-zinc-400 ${
            readOnly ? "cursor-default" : ""
          }`}
        />
        {readOnly && (
          <button
            type="button"
            onClick={copy}
            className={`shrink-0 rounded-md px-2 py-1 text-xs font-semibold transition ${
              copied
                ? "bg-emerald-50 text-emerald-700"
                : "bg-white text-zinc-600 shadow-sm ring-1 ring-zinc-200/80 hover:text-zinc-900"
            }`}
          >
            {copied ? "Copied" : "Copy"}
          </button>
        )}
      </div>
      {validation === "success" && (
        <p className="mt-1.5 flex items-center gap-1 text-xs text-emerald-600">
          <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
          Verified
        </p>
      )}
      {validation === "invalid-format" && (
        <p className="mt-1.5 text-xs text-red-600">
          Enter a valid IAM role ARN (e.g. arn:aws:iam::123456789012:role/VigilScannerRole)
        </p>
      )}
      {validation === "error" && (
        <p className="mt-1.5 text-xs text-red-600">Could not assume role — check stack Outputs and try again</p>
      )}
      {validation === "pending" && (
        <p className="mt-1.5 text-xs text-indigo-600">Verifying connection…</p>
      )}
    </div>
  );
}

const metadataFieldShell =
  "inline-flex w-full items-center gap-1.5 rounded-md bg-white px-2 py-1.5 ring-1 ring-zinc-200/80";

function CompactTokenField({ value, maxWidth = "max-w-xs" }: { value: string; maxWidth?: string }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className={`${metadataFieldShell} ${maxWidth}`}>
      <code className="min-w-0 flex-1 truncate font-mono text-[11px] text-zinc-800">{value}</code>
      <button
        type="button"
        onClick={copy}
        title={copied ? "Copied" : "Copy"}
        className={`shrink-0 rounded p-1 transition ${
          copied ? "text-emerald-600" : "text-zinc-400 hover:bg-zinc-50 hover:text-zinc-700"
        }`}
      >
        {copied ? (
          <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
        ) : (
          <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={1.75}
              d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"
            />
          </svg>
        )}
      </button>
    </div>
  );
}

function postureScoreTone(score: number): { bar: string; text: string } {
  if (score >= 80) return { bar: "bg-emerald-500", text: "text-emerald-700" };
  if (score >= 40) return { bar: "bg-amber-500", text: "text-amber-700" };
  return { bar: "bg-orange-500", text: "text-orange-600" };
}

function frameworkScoreTextClass(score: number | null | undefined): string {
  if (score == null) return "text-zinc-400";
  if (score >= 80) return "text-emerald-700";
  if (score >= 40) return "text-amber-700";
  return "text-orange-600";
}

function SecurityPostureModule({
  score,
  soc2,
  cis,
  iso,
  loading,
}: {
  score: number | null;
  soc2: number | null | undefined;
  cis: number | null | undefined;
  iso: number | null | undefined;
  loading?: boolean;
}) {
  if (loading) {
    return (
      <div className="w-full min-w-[200px] max-w-sm" aria-hidden>
        <div className="h-3.5 w-28 animate-pulse rounded bg-zinc-200/70" />
        <div className="mt-2.5 flex items-center gap-3">
          <div className="h-2 flex-1 animate-pulse rounded-full bg-zinc-100" />
          <div className="h-6 w-10 animate-pulse rounded bg-zinc-100" />
        </div>
        <div className="mt-2 h-3 w-48 animate-pulse rounded bg-zinc-100" />
      </div>
    );
  }

  if (score == null) {
    return (
      <div className="w-full min-w-[200px] max-w-sm">
        <p className="text-xs font-medium text-zinc-600">Security posture</p>
        <p className="mt-2 text-sm text-zinc-400">Awaiting control mapping data</p>
      </div>
    );
  }

  const tone = postureScoreTone(score);
  const benchmarks = [
    { label: "SOC2", score: soc2 },
    { label: "CIS", score: cis },
    { label: "ISO", score: iso },
  ];

  return (
    <div className="w-full min-w-[200px] max-w-sm">
      <p className="text-xs font-medium text-zinc-600">Security posture</p>
      <div className="mt-2 flex items-center gap-3">
        <div
          className="h-2 min-w-[5rem] flex-1 overflow-hidden rounded-full bg-zinc-100"
          role="progressbar"
          aria-valuenow={score}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label={`${score}% controls passing`}
        >
          <div
            className={`h-full rounded-full transition-[width] duration-500 ${tone.bar}`}
            style={{ width: `${score}%` }}
          />
        </div>
        <span className={`shrink-0 text-xl font-semibold tabular-nums leading-none ${tone.text}`}>
          {score}%
        </span>
      </div>
      <p className="mt-2 text-xs tabular-nums text-zinc-500">
        {benchmarks.map((b, i) => (
          <span key={b.label}>
            {i > 0 && <span className="text-zinc-300"> · </span>}
            <span className="text-zinc-500">{b.label} </span>
            <span className={`font-medium ${frameworkScoreTextClass(b.score)}`}>
              {b.score != null ? `${b.score}%` : "—"}
            </span>
          </span>
        ))}
      </p>
    </div>
  );
}

function DetailCell({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="w-fit max-w-full min-w-0">
      <p className="text-[10px] font-semibold uppercase tracking-wider leading-none text-zinc-400">{label}</p>
      <div className="mt-1.5 flex min-h-[34px] items-center">{children}</div>
    </div>
  );
}

const ghostBtn =
  "inline-flex items-center gap-1.5 rounded-lg border border-transparent px-3 py-1.5 text-xs font-medium text-zinc-600 transition hover:border-zinc-200 hover:bg-white hover:text-zinc-900 hover:shadow-sm disabled:cursor-not-allowed disabled:opacity-50";

const deployBtnRow = "flex w-full gap-2";
const deployPrimaryBtn =
  "flex flex-1 items-center justify-center gap-2 rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-zinc-800";
const deploySecondaryBtn =
  "flex flex-1 items-center justify-center gap-2 rounded-lg border border-zinc-300 bg-white px-4 py-2.5 text-sm font-semibold text-zinc-800 shadow-sm transition hover:bg-zinc-50";
const dangerGhostBtn =
  "inline-flex items-center gap-1.5 rounded-lg border border-transparent px-3 py-1.5 text-xs font-medium text-red-600 transition hover:border-red-200 hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-50";

function CapabilityBadges({
  acc,
  connectionOptions,
}: {
  acc: Account;
  /** During pending setup, derive posture from local selection (avoids badge flicker on save). */
  connectionOptions?: ConnectionOptions;
}) {
  const connected = isAccountConnected(acc);
  const opts = connectionOptions ?? accountConnectionOptions(acc);
  const policyGenDeployed = acc.advanced_policy_generation_deployed ?? false;

  return (
    <div className="mt-1.5 flex flex-wrap gap-1">
      <span className="rounded-full bg-emerald-50 px-2 py-0.5 text-[10px] font-medium text-emerald-800 ring-1 ring-emerald-200/60">
        Core Scanner
      </span>
      {(policyGenDeployed ||
        (connected && acc.enable_advanced_policy_generation) ||
        (!connected && opts.enable_advanced_policy_generation)) && (
        <span className="rounded-full bg-indigo-50 px-2 py-0.5 text-[10px] font-medium text-indigo-800 ring-1 ring-indigo-200/60">
          Policy Generation
        </span>
      )}
      {REMEDIATION_MODULE_SPECS.filter((m) =>
        connected ? acc.remediation_modules_deployed[m.id] : opts.remediation_modules[m.id],
      ).map((m) => (
        <span
          key={m.id}
          className="rounded-full bg-amber-50 px-2 py-0.5 text-[10px] font-medium text-amber-900 ring-1 ring-amber-200/60"
        >
          {m.badgeLabel}
        </span>
      ))}
    </div>
  );
}

function ManageCapabilitiesPanel({
  acc,
  draft,
  onDraftChange,
  onClose,
  saveError,
  onVerifyCapabilities,
  verifyingCapabilities,
  verifyFeedback,
  capabilityVerify,
  verificationMeta,
}: {
  acc: Account;
  draft: ConnectionOptions;
  onDraftChange: (next: ConnectionOptions) => void;
  onClose: () => void;
  saveError: string | null;
  onVerifyCapabilities: () => void;
  verifyingCapabilities: boolean;
  verifyFeedback: CapabilityVerifyFeedback | null;
  capabilityVerify: CapabilityVerifyResults | null;
  verificationMeta: VerificationMeta | null;
}) {
  const optionalCapabilities = hasOptionalCapabilities(acc);
  const [deployTab, setDeployTab] = useState<DeployTab>("console");
  const [cliExpanded, setCliExpanded] = useState(false);
  return (
    <div className="border-t border-zinc-200/60 bg-zinc-50/40 px-4 py-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-sm font-semibold text-zinc-900">Manage capabilities</p>
          <p className="mt-0.5 text-xs leading-relaxed text-zinc-500">
            Choose optional features, then update your{" "}
            <span className="font-mono text-zinc-600">{acc.cfn_stack_name || CONNECTOR_STACK_NAME}</span>{" "}
            stack in AWS. Core is read only; policy generation reads CloudTrail and starts
            IAM policy-generation jobs (no resource changes); remediation adds scoped write.
          </p>
          <div className="mt-1.5 flex flex-wrap items-center gap-2">
            <span className="text-[11px] text-zinc-500">After deploy:</span>
            <span className="rounded-full bg-emerald-50 px-2 py-0.5 text-[10px] font-medium text-emerald-800 ring-1 ring-emerald-200/60">
              Core Scanner
            </span>
            {draft.enable_advanced_policy_generation && (
              <span className="rounded-full bg-indigo-50 px-2 py-0.5 text-[10px] font-medium text-indigo-800 ring-1 ring-indigo-200/60">
                Policy Generation
              </span>
            )}
            {REMEDIATION_MODULE_SPECS.filter((m) => draft.remediation_modules[m.id]).map((m) => (
              <span
                key={m.id}
                className="rounded-full bg-amber-50 px-2 py-0.5 text-[10px] font-medium text-amber-900 ring-1 ring-amber-200/60"
              >
                {m.badgeLabel}
              </span>
            ))}
          </div>
        </div>
        <button type="button" onClick={onClose} className="text-xs font-medium text-zinc-500 hover:text-zinc-800">
          Close
        </button>
      </div>

      <div className="mt-4 space-y-3">
        <div className="rounded-lg border border-l-4 border-l-emerald-500 border-emerald-200/60 bg-emerald-50/30 px-3 py-2.5">
          <div className="flex flex-wrap items-center gap-2">
            <CapabilityVerifiedMark className="mt-0" />
            <p className="text-sm font-medium text-zinc-900">Core Scanner</p>
            <CapabilityAccessBadge kind="read-only" />
          </div>
          <p className="mt-1 text-xs leading-relaxed text-zinc-600">
            Continuous CIS / SOC 2 / ISO checks. Always enabled.
          </p>
        </div>

        <AdvancedPolicyGenerationCard
          enabled={draft.enable_advanced_policy_generation}
          onChange={(v) => onDraftChange({ ...draft, enable_advanced_policy_generation: v })}
          verify={capabilityVerify?.advanced_policy_generation}
          deployedFallback={acc.advanced_policy_generation_deployed}
        />

        <RemediationAutomationSection
          modules={draft.remediation_modules}
          onChange={(remediation_modules) => onDraftChange({ ...draft, remediation_modules })}
          modulesDeployed={acc.remediation_modules_deployed}
          moduleVerify={capabilityVerify?.remediation_modules}
        />
      </div>

      {saveError && (
        <p className="mt-3 text-xs text-red-600">{saveError}</p>
      )}

      <div className="mt-4 space-y-3 border-t border-zinc-200/60 pt-4">
        <DeployMethodTabs
          key="deploy-method-tabs"
          acc={acc}
          variant="update"
          activeTab={deployTab}
          onActiveTabChange={setDeployTab}
          cliExpanded={cliExpanded}
          onCliExpandedChange={setCliExpanded}
          deployOptions={draft}
        />
        {acc.status === "connected" && optionalCapabilities && (
          <PermissionVerificationPanel
            onVerify={onVerifyCapabilities}
            verifying={verifyingCapabilities}
            feedback={verifyFeedback}
            verificationMeta={verificationMeta}
            showButton
          />
        )}
      </div>
    </div>
  );
}

function ConnectionCapabilitiesPicker({
  value,
  onChange,
  disabled,
  acc,
  capabilityVerify,
}: {
  value: ConnectionOptions;
  onChange: (next: ConnectionOptions) => void;
  disabled?: boolean;
  acc?: Account;
  capabilityVerify?: CapabilityVerifyResults | null;
}) {
  const modulesDeployed = acc?.remediation_modules_deployed ?? DEFAULT_REMEDIATION_MODULES;
  const advancedDeployed = acc?.advanced_policy_generation_deployed ?? false;

  return (
    <div className="space-y-3">
      <div>
        <p className="text-sm font-semibold text-zinc-900">Connection mode</p>
        <p className="mt-0.5 text-xs leading-relaxed text-zinc-500">
          Start read-only. Enable optional capabilities only when you need them.
        </p>
      </div>

      <div className="rounded-lg border border-l-4 border-l-emerald-500 border-emerald-200/60 bg-emerald-50/30 px-3 py-2.5">
        <div className="flex flex-wrap items-center gap-2">
          <CapabilityVerifiedMark className="mt-0" />
          <p className="text-sm font-medium text-zinc-900">Core compliance scanner</p>
          <CapabilityAccessBadge kind="read-only" />
        </div>
        <p className="mt-1 text-xs leading-relaxed text-zinc-600">
          Read-only · CIS / SOC 2 / ISO checks
        </p>
      </div>

      <AdvancedPolicyGenerationCard
        enabled={value.enable_advanced_policy_generation}
        onChange={(v) => onChange({ ...value, enable_advanced_policy_generation: v })}
        disabled={disabled}
        verify={capabilityVerify?.advanced_policy_generation}
        deployedFallback={advancedDeployed}
      />

      <RemediationAutomationSection
        modules={value.remediation_modules}
        onChange={(remediation_modules) => onChange({ ...value, remediation_modules })}
        disabled={disabled}
        modulesDeployed={modulesDeployed}
        moduleVerify={capabilityVerify?.remediation_modules}
      />
    </div>
  );
}

function AdvancedPolicyGenerationCard({
  enabled,
  onChange,
  disabled,
  verify,
  deployedFallback,
  compact = false,
}: {
  enabled: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  verify?: ModuleVerifyResult;
  deployedFallback?: boolean;
  compact?: boolean;
}) {
  const locked = capabilityLockedInAws(verify, Boolean(deployedFallback));
  const checked = locked ? true : enabled;
  const inputDisabled = disabled || locked;

  const body = (
    <>
      {locked ? (
        <CapabilityVerifiedMark />
      ) : (
        <input
          type="checkbox"
          className="mt-0.5 shrink-0 rounded border-zinc-300 text-indigo-600 focus:ring-indigo-500/30"
          checked={checked}
          disabled={inputDisabled}
          aria-label="Enable Advanced IAM policy generation"
          onChange={(e) => onChange(e.target.checked)}
        />
      )}
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <p className="text-sm font-medium leading-snug text-zinc-900">Advanced IAM policy generation</p>
          <CapabilityAccessBadge kind="read-analysis" />
        </div>
        <p className="mt-0.5 text-xs leading-relaxed text-zinc-500">
          Uses CloudTrail policy generation and IAM last-accessed data for least-privilege recommendations.
        </p>
        {!compact && (
          <>
            {checked && (
              <div className="mt-2">
                <p className="text-[11px] font-semibold uppercase tracking-wide text-zinc-500">
                  Required permissions
                </p>
                <div className="mt-2">
                  <RemediationPermissionsBlock
                    permissions={ADVANCED_POLICY_RAW_ACTIONS}
                    verifyRows={verify?.permissions}
                  />
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </>
  );

  if (compact) {
    return (
      <label
        className={`flex items-start gap-2.5 py-4 ${
          inputDisabled && !locked ? "cursor-not-allowed opacity-60" : locked ? "cursor-default" : "cursor-pointer"
        }`}
      >
        {body}
      </label>
    );
  }

  return (
    <div
      className={`overflow-hidden rounded-lg border border-l-4 transition-colors ${
        locked
          ? "border-l-emerald-500 border-emerald-200/60 bg-emerald-50/30 shadow-sm shadow-zinc-950/[0.02]"
          : checked
            ? "border-l-indigo-500 border-indigo-200/60 bg-indigo-50/40 shadow-sm shadow-zinc-950/[0.03]"
            : "border-l-transparent border-zinc-200/60 bg-zinc-50/30"
      } ${inputDisabled && !locked ? "opacity-60" : ""}`}
    >
      <div className="px-2.5 py-2.5">
        <div className="flex items-start gap-2.5">{body}</div>
      </div>
    </div>
  );
}

function RemediationAutomationSection({
  modules,
  onChange,
  disabled,
  modulesDeployed,
  moduleVerify,
  compact = false,
}: {
  modules: RemediationModules;
  onChange: (next: RemediationModules) => void;
  disabled?: boolean;
  modulesDeployed: RemediationModules;
  moduleVerify?: Record<string, ModuleVerifyResult>;
  compact?: boolean;
}) {
  const anyEnabled = anyRemediationEnabled(modules);
  const [sectionOpen, setSectionOpen] = useState(anyEnabled);
  const [openModuleId, setOpenModuleId] = useState<string | null>(null);

  useEffect(() => {
    if (anyEnabled) setSectionOpen(true);
  }, [anyEnabled]);

  const handleMasterToggle = (checked: boolean) => {
    if (!checked) {
      const next = { ...DEFAULT_REMEDIATION_MODULES };
      for (const spec of REMEDIATION_MODULE_SPECS) {
        const modVerify = moduleVerify?.[spec.id];
        const deployed = Boolean(modulesDeployed[spec.id]);
        if (capabilityLockedInAws(modVerify, deployed)) {
          next[spec.id] = true;
        }
      }
      onChange(next);
      if (!anyRemediationEnabled(next)) {
        setSectionOpen(false);
        setOpenModuleId(null);
      }
      return;
    }
    setSectionOpen(true);
  };

  const toggleModuleDetails = (moduleId: string) => {
    setOpenModuleId((current) => (current === moduleId ? null : moduleId));
  };

  if (compact) {
    return (
      <div className={`py-4 ${disabled ? "opacity-60" : ""}`}>
        <label className={`flex items-start gap-3 ${disabled ? "cursor-not-allowed" : "cursor-pointer"}`}>
          <input
            type="checkbox"
            className="mt-0.5 rounded border-zinc-300 text-indigo-600 focus:ring-indigo-500/30"
            checked={sectionOpen}
            disabled={disabled}
            onChange={(e) => handleMasterToggle(e.target.checked)}
          />
          <span className="min-w-0 flex-1">
            <span className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-medium text-zinc-900">Automated remediation</span>
              {anyEnabled && <CapabilityAccessBadge kind="scoped-write" />}
            </span>
            <p className="mt-0.5 text-xs leading-relaxed text-zinc-500">
              Optional scoped write modules — enable only what you plan to automate.
            </p>
          </span>
        </label>
        {sectionOpen && (
          <ul className="mt-3 ml-7 space-y-2">
            {REMEDIATION_MODULE_SPECS.map((spec) => (
              <li key={spec.id}>
                <label
                  className={`flex items-center gap-2 text-sm ${
                    disabled ? "cursor-not-allowed" : "cursor-pointer"
                  }`}
                >
                  <input
                    type="checkbox"
                    className="rounded border-zinc-300 text-indigo-600 focus:ring-indigo-500/30"
                    checked={modules[spec.id]}
                    disabled={disabled}
                    onChange={(e) => onChange({ ...modules, [spec.id]: e.target.checked })}
                  />
                  <span className="text-zinc-800">{spec.label}</span>
                </label>
              </li>
            ))}
          </ul>
        )}
      </div>
    );
  }

  return (
    <div
      className={`rounded-lg border px-3 py-2.5 transition-colors ${
        sectionOpen ? "border-zinc-200/80 bg-zinc-50/40" : "border-zinc-200/60 bg-white"
      } ${disabled ? "opacity-60" : ""}`}
    >
      <label className={`flex items-start gap-3 ${disabled ? "cursor-not-allowed" : "cursor-pointer"}`}>
        <input
          type="checkbox"
          className="mt-0.5 rounded border-zinc-300 text-indigo-600 focus:ring-indigo-500/30"
          checked={sectionOpen}
          disabled={disabled}
          onChange={(e) => handleMasterToggle(e.target.checked)}
        />
        <span className="min-w-0 flex-1">
          <span className="text-sm font-medium text-zinc-900">Automated remediation</span>
          <p className="mt-1 text-xs leading-relaxed text-zinc-500">
            Deploy approved remediation modules. Each module grants narrowly scoped write permissions.
          </p>
        </span>
      </label>

      {sectionOpen && (
        <div className="mt-3 ml-7 space-y-2">
          {REMEDIATION_MODULE_SPECS.map((spec) => {
            const selected = modules[spec.id];
            const detailsOpen = openModuleId === spec.id;
            const verify = moduleVerify?.[spec.id];
            const deployed = Boolean(modulesDeployed[spec.id]);
            const locked = capabilityLockedInAws(verify, deployed);
            const moduleChecked = locked ? true : selected;
            const moduleDisabled = disabled || locked;

            return (
              <div
                key={spec.id}
                className={`overflow-hidden rounded-lg border border-l-4 transition-colors ${
                  locked
                    ? "border-l-emerald-500 border-emerald-200/60 bg-emerald-50/30 shadow-sm shadow-zinc-950/[0.02]"
                    : moduleChecked
                      ? "border-l-indigo-500 border-indigo-200/60 bg-indigo-50/45 shadow-sm shadow-zinc-950/[0.04]"
                      : "border-l-transparent border-zinc-200/50 bg-zinc-50/25 opacity-80"
                }`}
              >
                <div className="flex items-start gap-2.5 px-2.5 py-2.5">
                  {locked ? (
                    <CapabilityVerifiedMark />
                  ) : (
                    <input
                      type="checkbox"
                      className="mt-0.5 shrink-0 rounded border-zinc-300 text-indigo-600 focus:ring-indigo-500/30"
                      checked={moduleChecked}
                      disabled={moduleDisabled}
                      aria-label={`Enable ${spec.label}`}
                      onChange={(e) =>
                        onChange({ ...modules, [spec.id]: e.target.checked })
                      }
                    />
                  )}
                  <div className="min-w-0 flex-1">
                    <div className="flex items-start gap-2">
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <p className="text-sm font-medium leading-snug text-zinc-900">{spec.label}</p>
                          <CapabilityAccessBadge kind="scoped-write" />
                        </div>
                        <p className="mt-0.5 text-xs leading-relaxed text-zinc-500">{spec.summary}</p>
                      </div>
                      <button
                        type="button"
                        disabled={disabled}
                        onClick={() => toggleModuleDetails(spec.id)}
                        className="-mr-0.5 shrink-0 rounded-md p-1 text-zinc-400 transition hover:bg-zinc-100 hover:text-zinc-600 disabled:opacity-50"
                        aria-expanded={detailsOpen}
                        aria-label={detailsOpen ? `Hide ${spec.label} details` : `Show ${spec.label} details`}
                      >
                        <RemediationModuleChevron open={detailsOpen} />
                      </button>
                    </div>
                  </div>
                </div>

                {detailsOpen && (
                  <div className="space-y-4 border-t border-zinc-100 bg-zinc-50/50 px-3 py-3">
                    <div>
                      <p className="text-[11px] font-semibold uppercase tracking-wide text-zinc-500">
                        What Vigil can do
                      </p>
                      <ul className="mt-1 space-y-0.5">
                        {spec.bullets.map((b) => (
                          <li key={b} className="flex gap-1.5 text-xs leading-snug text-zinc-600">
                            <span className="text-zinc-400" aria-hidden>
                              •
                            </span>
                            {b}
                          </li>
                        ))}
                      </ul>
                      {spec.runnerSupported && verify?.runner_ready === false && (
                        <p className="mt-2 text-[11px] font-medium text-amber-800">
                          SSM remediation automation is not ready.
                        </p>
                      )}
                    </div>

                    <div>
                      <p className="text-[11px] font-semibold uppercase tracking-wide text-zinc-500">
                        Required permissions
                      </p>
                      <div className="mt-2">
                        <RemediationPermissionsBlock
                          permissions={spec.permissions}
                          verifyRows={verify?.permissions}
                        />
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function AccountDetailsPanel({
  acc,
  isScanActive,
  scanError,
  showManageCapabilities,
  onManageCapabilities,
  showUpdateArn,
  roleArn,
  setRoleArn,
  verify,
  onUpdateRole,
  onCancelUpdate,
  onRemove,
  removePending,
  manageCapabilitiesPanel,
}: {
  acc: Account;
  isScanActive: boolean;
  scanError: string | null;
  showManageCapabilities: boolean;
  onManageCapabilities: () => void;
  showUpdateArn: boolean;
  roleArn: string;
  setRoleArn: (v: string) => void;
  verify: {
    mutate: () => void;
    isPending: boolean;
    isError: boolean;
    isSuccess: boolean;
    reset: () => void;
  };
  onUpdateRole: () => void;
  onCancelUpdate: () => void;
  onRemove: () => void;
  removePending: boolean;
  manageCapabilitiesPanel: ReactNode;
}) {
  const roleDisplay =
    acc.role_arn ?? (acc.account_id ? `arn:aws:iam::${acc.account_id}:role/${SCANNER_ROLE_NAME}` : null);
  const roleArnValid = isValidIamRoleArn(roleArn);
  const roleArnValidation = roleArnFieldValidation(roleArn, verify);

  if (showUpdateArn) {
    return (
      <div className="space-y-3 px-4 py-3">
        <p className="text-sm font-medium text-zinc-900">Update IAM role</p>
        <p className="text-xs text-zinc-500">Paste the new Role ARN from your CloudFormation stack Outputs.</p>
        <CopyInputField label="External ID" value={acc.external_id} />
        <CopyInputField
          label="Role ARN"
          value={roleArn}
          readOnly={false}
          placeholder={`arn:aws:iam::123456789012:role/${SCANNER_ROLE_NAME}`}
          onChange={setRoleArn}
          validation={roleArnValidation}
        />
        <div className="flex flex-wrap gap-2 pt-1">
          <button
            onClick={() => verify.mutate()}
            disabled={verify.isPending || !roleArnValid}
            className="rounded-lg bg-indigo-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {verify.isPending ? "Verifying…" : "Save & verify"}
          </button>
          <button onClick={onCancelUpdate} className={ghostBtn}>
            Cancel
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="divide-y divide-zinc-200/60">
      {scanError && (
        <div className="bg-red-50/80 px-4 py-2.5 text-xs text-red-700">
          <span className="font-medium">Last scan failed</span>
          <div className="mt-0.5 break-words">{scanError}</div>
        </div>
      )}

      <div className="flex flex-col gap-3 px-4 py-3 sm:flex-row sm:flex-wrap sm:items-start sm:gap-x-6 sm:gap-y-3">
        <DetailCell label="External ID">
          <CompactTokenField value={acc.external_id} maxWidth="max-w-[18rem]" />
        </DetailCell>
        <DetailCell label="Role ARN">
          {roleDisplay ? (
            <CompactTokenField value={roleDisplay} maxWidth="max-w-[28rem]" />
          ) : (
            <div className={metadataFieldShell}>
              <span className="text-[11px] text-zinc-400">—</span>
            </div>
          )}
        </DetailCell>
      </div>

      {showManageCapabilities && manageCapabilitiesPanel}

      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-zinc-200/60 px-4 py-3">
        <div className="flex flex-wrap gap-1">
          <button
            type="button"
            onClick={onManageCapabilities}
            disabled={isScanActive}
            className={ghostBtn}
          >
            {showManageCapabilities ? "Hide capabilities" : "Manage capabilities"}
          </button>
          <button type="button" onClick={onUpdateRole} disabled={isScanActive} className={ghostBtn}>
            Update role ARN
          </button>
        </div>
        <button type="button" onClick={onRemove} disabled={removePending} className={dangerGhostBtn}>
          Disconnect account
        </button>
      </div>
    </div>
  );
}

function CliCodeBlock({
  command,
  expanded: expandedProp,
  onExpandedChange,
  defaultExpanded = false,
}: {
  command: string;
  expanded?: boolean;
  onExpandedChange?: (open: boolean) => void;
  defaultExpanded?: boolean;
}) {
  const [expandedInternal, setExpandedInternal] = useState(defaultExpanded);
  const expanded = expandedProp ?? expandedInternal;
  const setExpanded = onExpandedChange ?? setExpandedInternal;
  const [copied, setCopied] = useState(false);

  async function copy() {
    await navigator.clipboard.writeText(command);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 2000);
  }

  if (!expanded) {
    return (
      <button
        type="button"
        onClick={() => setExpanded(true)}
        className="inline-flex items-center gap-1.5 text-sm font-medium text-zinc-600 transition hover:text-zinc-900"
      >
        <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.75} d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
        </svg>
        Show CLI command
      </button>
    );
  }

  return (
    <div className="overflow-hidden rounded-lg bg-zinc-950 shadow-inner">
      <div className="flex items-center justify-between border-b border-zinc-800 px-3 py-2">
        <span className="text-[11px] font-medium uppercase tracking-wider text-zinc-500">bash</span>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setExpanded(false)}
            className="text-[11px] font-medium text-zinc-500 transition hover:text-zinc-300"
          >
            Collapse
          </button>
          <button
            type="button"
            onClick={copy}
            className={`rounded px-2 py-0.5 text-[11px] font-semibold transition ${
              copied ? "bg-emerald-500/20 text-emerald-400" : "bg-zinc-800 text-zinc-300 hover:bg-zinc-700"
            }`}
          >
            {copied ? "Copied" : "Copy"}
          </button>
        </div>
      </div>
      <pre className="overflow-x-auto whitespace-pre px-4 py-3 font-mono text-[12px] leading-relaxed text-zinc-300">
        <code>{command}</code>
      </pre>
    </div>
  );
}

type DeployTab = "console" | "cli" | "terraform";

const ONBOARDING_FLOW_STEPS = [
  { n: 1, label: "Choose capabilities" },
  { n: 2, label: "Deploy connector" },
  { n: 3, label: "Verify connection" },
] as const;

/** Map in-card wizard step → top stepper (Choose capabilities / Deploy / Verify). */
function wizardStepToFlowProgress(
  wizardStep: number,
  capabilitiesChosenExternally: boolean,
): 1 | 2 | 3 {
  if (capabilitiesChosenExternally) {
    // Capabilities picked on the empty-state page; wizard starts at deploy.
    if (wizardStep <= 1) return 2;
    return 3;
  }
  // Add-account flow: capabilities → deploy → verify inside the card.
  if (wizardStep <= 1) return 1;
  if (wizardStep === 2) return 2;
  return 3;
}

function DisclosureLink({
  open,
  onToggle,
  openLabel,
  closeLabel,
  disabled,
  className = "ml-7 mt-1.5",
  children,
}: {
  open: boolean;
  onToggle: () => void;
  openLabel: string;
  closeLabel: string;
  disabled?: boolean;
  className?: string;
  children: ReactNode;
}) {
  return (
    <div className={className}>
      <button
        type="button"
        disabled={disabled}
        onClick={onToggle}
        className="text-xs font-semibold text-indigo-600 hover:text-indigo-800 disabled:opacity-50"
        aria-expanded={open}
      >
        {open ? closeLabel : openLabel}
      </button>
      {open && <div className="mt-2">{children}</div>}
    </div>
  );
}

function OnboardingFlowProgress({ activeStep }: { activeStep: 1 | 2 | 3 }) {
  return (
    <ol className="flex flex-wrap items-center gap-2 sm:gap-0">
      {ONBOARDING_FLOW_STEPS.map((step, i) => (
        <li key={step.n} className="flex items-center">
          <span
            className={`flex items-center gap-2 rounded-lg px-2 py-1 sm:px-2.5 ${
              activeStep === step.n
                ? "bg-zinc-900 text-white"
                : activeStep > step.n
                  ? "text-emerald-700"
                  : "text-zinc-400"
            }`}
          >
            <span
              className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-xs font-bold ${
                activeStep === step.n
                  ? "bg-white/15 text-white"
                  : activeStep > step.n
                    ? "bg-emerald-100 text-emerald-700"
                    : "bg-zinc-100 text-zinc-500"
              }`}
            >
              {activeStep > step.n ? (
                <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden>
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
                </svg>
              ) : (
                step.n
              )}
            </span>
            <span className="hidden text-xs font-semibold sm:inline">{step.label}</span>
          </span>
          {i < ONBOARDING_FLOW_STEPS.length - 1 && (
            <svg
              className="mx-1 hidden h-4 w-4 shrink-0 text-zinc-300 sm:block"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
              aria-hidden
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
            </svg>
          )}
        </li>
      ))}
    </ol>
  );
}

function FirstAccountOnboarding({
  value,
  onChange,
  disabled,
  onContinue,
  continuing,
}: {
  value: ConnectionOptions;
  onChange: (next: ConnectionOptions) => void;
  disabled?: boolean;
  onContinue: () => void;
  continuing: boolean;
}) {
  return (
    <div className={`${cardClass} w-full overflow-hidden`}>
      <div className="px-6 py-6 sm:px-8 sm:py-7">
        <OnboardingFlowProgress activeStep={1} />

        <div className="mt-6 flex items-start gap-4">
          <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-zinc-200/80 bg-[#FF9900]/10">
            <AwsIcon className="h-6 w-6 object-contain" />
          </div>
          <div className="min-w-0">
            <h2 className="text-xl font-semibold tracking-tight text-zinc-900 sm:text-2xl">
              Connect your AWS account
            </h2>
            <p className="mt-1 text-sm leading-relaxed text-zinc-600">
              Choose what Vigil can do, then deploy one CloudFormation stack in your account.
            </p>
          </div>
        </div>

        <div className="mt-6">
          <ConnectionCapabilitiesPicker value={value} onChange={onChange} disabled={disabled} />
        </div>

        <button
          type="button"
          onClick={onContinue}
          disabled={disabled || continuing}
          className="mt-8 w-full rounded-lg bg-indigo-600 px-6 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-50 sm:w-auto sm:min-w-[12rem]"
        >
          {continuing ? "Setting up…" : "Continue to deploy"}
        </button>
      </div>
    </div>
  );
}

function DeployMethodTabs({
  acc,
  variant = "create",
  deployOptions,
  activeTab,
  onActiveTabChange,
  cliExpanded,
  onCliExpandedChange,
}: {
  acc: Account;
  variant?: "create" | "update";
  deployOptions?: CfnConnectionOptions;
  activeTab?: DeployTab;
  onActiveTabChange?: (tab: DeployTab) => void;
  cliExpanded?: boolean;
  onCliExpandedChange?: (open: boolean) => void;
}) {
  const [internalTab, setInternalTab] = useState<DeployTab>("console");
  const tab = activeTab ?? internalTab;
  const setTab = onActiveTabChange ?? setInternalTab;
  const isUpdate = variant === "update";
  const { consoleUrl, cliCommand } = resolveDeployArtifacts(
    acc,
    deployOptions,
    isUpdate ? "update" : "create",
  );
  const consoleLabel = isUpdate ? "Update CloudFormation" : "Launch CloudFormation";

  const tabs: { id: DeployTab; label: string }[] = [
    { id: "console", label: "Console" },
    { id: "cli", label: "CLI" },
    { id: "terraform", label: "Terraform" },
  ];

  return (
    <div>
      <div className="flex gap-1 rounded-lg bg-zinc-100/80 p-1">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className={`flex-1 rounded-md px-3 py-1.5 text-xs font-semibold transition ${
              tab === t.id
                ? "bg-white text-zinc-900 shadow-sm"
                : "text-zinc-500 hover:text-zinc-700"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div className="mt-3">
        {tab === "console" && (
          <div className="space-y-2.5">
            <div className={deployBtnRow}>
              <a href={consoleUrl} target="_blank" rel="noreferrer" className={deployPrimaryBtn}>
                {consoleLabel}
                <svg className="h-4 w-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"
                  />
                </svg>
              </a>
              <a
                href={acc.cfn_template_url}
                target="_blank"
                rel="noreferrer"
                className={deploySecondaryBtn}
              >
                Review Template
              </a>
            </div>
          </div>
        )}
        {tab === "cli" && (
          <CliCodeBlock
            command={cliCommand}
            expanded={cliExpanded}
            onExpandedChange={onCliExpandedChange}
          />
        )}
        {tab === "terraform" && (
          <div className="rounded-lg bg-zinc-50 px-4 py-6 text-center">
            <p className="text-sm font-medium text-zinc-700">Terraform module</p>
            <p className="mt-1 text-sm text-zinc-500">Coming soon — use Console or CLI for now.</p>
          </div>
        )}
      </div>
    </div>
  );
}


const ONBOARDING_STEPS = [
  { n: 1, title: "Deploy AWS connector", short: "Launch CloudFormation in your AWS account" },
  { n: 2, title: "Copy Role ARN", short: "From the stack Outputs tab after deploy completes" },
  { n: 3, title: "Verify Connection", short: "Paste the Role ARN to connect Vigil" },
] as const;

function OnboardingProgress({
  activeStep,
  onStepChange,
}: {
  activeStep: number;
  onStepChange: (n: number) => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2 sm:gap-0">
      {ONBOARDING_STEPS.map((step, i) => {
        const isActive = activeStep === step.n;
        const isPast = activeStep > step.n;
        return (
          <div key={step.n} className="flex items-center">
            <button
              type="button"
              onClick={() => onStepChange(step.n)}
              className={`flex items-center gap-2 rounded-lg px-2 py-1.5 transition sm:px-3 ${
                isActive
                  ? "bg-white shadow-sm ring-1 ring-zinc-200/80"
                  : isPast
                    ? "opacity-70 hover:opacity-100"
                    : "opacity-45 hover:opacity-70"
              }`}
            >
              <span
                className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-xs font-bold ${
                  isActive
                    ? "bg-zinc-900 text-white"
                    : isPast
                      ? "bg-emerald-100 text-emerald-700"
                      : "bg-zinc-200 text-zinc-500"
                }`}
              >
                {isPast ? (
                  <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
                  </svg>
                ) : (
                  step.n
                )}
              </span>
              <span
                className={`hidden text-sm font-semibold sm:inline ${
                  isActive ? "text-zinc-900" : "text-zinc-500"
                }`}
              >
                {step.title}
              </span>
            </button>
            {i < ONBOARDING_STEPS.length - 1 && (
              <svg
                className="mx-1 hidden h-4 w-4 shrink-0 text-zinc-300 sm:block"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
              </svg>
            )}
          </div>
        );
      })}
    </div>
  );
}

/** Stop step buttons from stealing focus (and scrolling the page) on click. */
function onboardingStepPointerDown(e: React.PointerEvent) {
  e.preventDefault();
}

function InCardAccountSetupWizard({
  acc,
  connectionOptions,
  onConnectionOptionsChange,
  connectionOptionsSaving,
  roleArn,
  setRoleArn,
  verify,
  onVerifyConnection,
  initialStep = 1,
}: {
  acc: Account;
  connectionOptions: ConnectionOptions;
  onConnectionOptionsChange: (next: ConnectionOptions) => void;
  connectionOptionsSaving?: boolean;
  roleArn: string;
  setRoleArn: (v: string) => void;
  verify: { mutate: () => void; isPending: boolean; isError: boolean; isSuccess: boolean; error: unknown };
  onVerifyConnection: () => void;
  initialStep?: number;
}) {
  const [activeStep, setActiveStep] = useState(initialStep);
  const roleArnValid = isValidIamRoleArn(roleArn);
  const roleArnValidation = roleArnFieldValidation(roleArn, verify);

  return (
    <div className="bg-zinc-50/60 px-5 py-5 sm:px-6">
      <div className="mb-5">
        <h3 className="text-base font-semibold tracking-tight text-zinc-900">AWS Account Setup</h3>
        <p className="mt-0.5 text-sm text-zinc-500">
          Choose capabilities, deploy the connector, then verify the scanner role.
        </p>
      </div>

      <OnboardingProgress activeStep={activeStep} onStepChange={setActiveStep} />

      <div className="mt-5 min-w-0">
        {activeStep === 1 && (
          <div className="space-y-5">
            <div>
              <p className="text-sm font-medium text-zinc-900">Deploy the scanner role</p>
              <p className="mt-0.5 text-sm text-zinc-500">{ONBOARDING_STEPS[0].short}</p>
            </div>
            <ConnectionCapabilitiesPicker
              value={connectionOptions}
              onChange={onConnectionOptionsChange}
              disabled={connectionOptionsSaving}
              acc={acc}
            />
            <DeployMethodTabs acc={acc} deployOptions={connectionOptions} />
            <DeploymentParametersCard externalId={acc.external_id} />
            <button
              type="button"
              onClick={() => setActiveStep(2)}
              className="text-sm font-semibold text-indigo-600 hover:text-indigo-800"
            >
              I&apos;ve deployed the stack →
            </button>
          </div>
        )}

        {activeStep === 2 && (
          <div className="space-y-4">
            <div>
              <p className="text-sm font-medium text-zinc-900">Role ARN</p>
              <p className="mt-0.5 text-sm text-zinc-500">
                CloudFormation stack → Outputs → RoleArn
              </p>
            </div>
            <CopyInputField
              label="Role ARN"
              value={roleArn}
              readOnly={false}
              placeholder={`arn:aws:iam::123456789012:role/${SCANNER_ROLE_NAME}`}
              onChange={setRoleArn}
              validation={roleArnValidation}
            />
            <button
              type="button"
              onClick={() => setActiveStep(3)}
              disabled={!roleArnValid}
              className="text-sm font-semibold text-indigo-600 hover:text-indigo-800 disabled:cursor-not-allowed disabled:opacity-40"
            >
              Continue to verify →
            </button>
          </div>
        )}

        {activeStep === 3 && (
          <div className="space-y-4">
            <div>
              <p className="text-sm font-medium text-zinc-900">Verify connection</p>
              <p className="mt-0.5 text-sm text-zinc-500">{ONBOARDING_STEPS[2].short}</p>
            </div>
            <CopyInputField label="External ID" value={acc.external_id} />
            <CopyInputField
              label="Role ARN"
              value={roleArn}
              readOnly={false}
              placeholder={`arn:aws:iam::123456789012:role/${SCANNER_ROLE_NAME}`}
              onChange={setRoleArn}
              validation={roleArnValidation}
            />
            <button
              type="button"
              onClick={onVerifyConnection}
              disabled={verify.isPending || !roleArnValid}
              className={workflowInlineActionBtn}
            >
              {verify.isPending ? "Verifying…" : "Verify connection"}
            </button>
            {verify.error && (
              <div className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700">
                {formatApiError(verify.error)}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function FindingsSeverityStrip({ stats }: { stats: FindingStats }) {
  const items = [
    { value: stats.critHigh, label: "Crit + high", warn: stats.critHigh > 0 },
    { value: stats.medium, label: "Medium", warn: false },
    { value: stats.open, label: "Open", warn: false },
  ];

  return (
    <div className="inline-flex overflow-hidden rounded-lg border border-zinc-200/90 bg-zinc-50/40 shadow-sm">
      {items.map((item, i) => (
        <div
          key={item.label}
          className={`flex min-w-[3.25rem] flex-col items-center px-3 py-1.5 ${
            i > 0 ? "border-l border-zinc-200/80" : ""
          }`}
        >
          <span
            className={`text-base font-semibold tabular-nums leading-none ${
              item.warn ? "text-orange-600" : "text-zinc-900"
            }`}
          >
            {item.value}
          </span>
          <span className="mt-0.5 text-[10px] font-medium uppercase tracking-wide text-zinc-400">
            {item.label}
          </span>
        </div>
      ))}
    </div>
  );
}


function MetricPills({ stats }: { stats: FindingStats }) {
  const pills = [
    { value: stats.critHigh, label: "Critical", accent: stats.critHigh > 0 },
    { value: stats.medium, label: "Medium", accent: false },
    { value: stats.open, label: "Open", accent: false },
  ];

  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {pills.map((p) => (
        <span
          key={p.label}
          className="inline-flex items-baseline gap-1 rounded-full bg-zinc-100/90 px-2.5 py-1 text-xs"
        >
          <span className={`font-semibold tabular-nums ${p.accent ? "text-orange-600" : "text-zinc-800"}`}>
            {p.value}
          </span>
          <span className="text-zinc-500">{p.label}</span>
        </span>
      ))}
    </div>
  );
}

const cardClass =
  "overflow-hidden rounded-xl border border-zinc-200 bg-white shadow-[0_1px_3px_rgba(0,0,0,0.06),0_4px_12px_rgba(0,0,0,0.04)] transition-[box-shadow,border-color] duration-200 hover:border-zinc-300 hover:shadow-[0_2px_8px_rgba(0,0,0,0.07),0_8px_20px_rgba(0,0,0,0.05)]";

function buildStatsMap(items: Finding[] | undefined): Map<string, FindingStats> {
  const map = new Map<string, FindingStats>();
  for (const f of items ?? []) {
    const cur = map.get(f.account_id) ?? { critHigh: 0, medium: 0, open: 0 };
    cur.open += 1;
    if (f.severity === "critical" || f.severity === "high") cur.critHigh += 1;
    if (f.severity === "medium") cur.medium += 1;
    map.set(f.account_id, cur);
  }
  return map;
}

function ScanFreshnessBadge({
  iso,
  isScanActive,
}: {
  iso: string | null;
  isScanActive: boolean;
}) {
  const freshness = scanFreshness(iso, isScanActive);
  const meta = FRESHNESS_META[freshness];
  const ago = formatLastScan(iso);

  if (freshness === "scanning") {
    return (
      <div className="flex items-center gap-1.5 text-xs text-indigo-600">
        <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${meta.dot}`} />
        <span className="font-medium">Scan in progress</span>
      </div>
    );
  }

  if (freshness === "none") {
    return (
      <div className={`flex items-center gap-1.5 text-xs ${meta.text}`}>
        <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${meta.dot}`} />
        <span>No scan yet</span>
      </div>
    );
  }

  if (freshness === "fresh" || freshness === "recent") {
    return (
      <div className={`flex items-center gap-1.5 text-xs ${meta.text}`}>
        <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${meta.dot}`} />
        <span className="font-medium text-emerald-700">Fresh scan</span>
        {ago && <span className="text-zinc-400">· {ago}</span>}
      </div>
    );
  }

  return (
    <div className={`flex items-center gap-1.5 text-xs ${meta.text}`}>
      <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${meta.dot}`} />
      <span className="font-medium text-amber-700">Scan outdated</span>
      {ago && <span className="text-zinc-400">· {ago}</span>}
      {meta.hint && <span className="text-zinc-400">· {meta.hint}</span>}
    </div>
  );
}

function AccountCard({
  acc,
  stats,
  expanded,
  onToggle,
  setupInitialStep = 1,
}: {
  acc: Account;
  stats: FindingStats | undefined;
  expanded: boolean;
  onToggle: () => void;
  setupInitialStep?: number;
}) {
  const qc = useQueryClient();
  const [roleArn, setRoleArn] = useState("");
  const [showUpdateArn, setShowUpdateArn] = useState(false);
  const [showRemoveConfirm, setShowRemoveConfirm] = useState(false);
  const [showManageCapabilities, setShowManageCapabilities] = useState(false);
  const [setupConnectionOptions, setSetupConnectionOptions] = useState(() =>
    accountConnectionOptions(acc),
  );
  const [draftCapabilities, setDraftCapabilities] = useState(() => accountConnectionOptions(acc));
  const [capabilityVerify, setCapabilityVerify] = useState<CapabilityVerifyResults | null>(null);
  const [verifyFeedback, setVerifyFeedback] = useState<CapabilityVerifyFeedback | null>(null);
  const [verificationMeta, setVerificationMeta] = useState<VerificationMeta | null>(null);
  const [patchError, setPatchError] = useState<string | null>(null);

  useEffect(() => {
    setSetupConnectionOptions(accountConnectionOptions(acc));
    setDraftCapabilities(accountConnectionOptions(acc));
  }, [
    acc.id,
    acc.enable_advanced_policy_generation,
    acc.remediation_modules,
    acc.status,
  ]);

  const connected = isAccountConnected(acc);
  const hasScanned = connected && !!acc.last_scan_at;
  const showSetup = !connected && expanded;

  const {
    scanRun,
    scanStatus,
    isRunning,
    isScanActive,
    scanProgress,
    triggerScan,
  } = useTriggeredScan(connected ? acc.id : undefined, {
    backgroundPollMs: 5000,
    onScanComplete: () => {
      qc.invalidateQueries({ queryKey: ["findings-snapshot-all"] });
      qc.invalidateQueries({ queryKey: ["controls"] });
      qc.invalidateQueries({ queryKey: ["accounts"] });
    },
  });

  const patchConnection = useMutation({
    mutationFn: (opts: ConnectionOptions) =>
      api<Account>(`/v1/accounts/${acc.id}/connection-options`, {
        method: "PATCH",
        body: JSON.stringify(opts),
      }),
    onSuccess: (updated) => {
      setPatchError(null);
      qc.setQueryData<Account[]>(["accounts"], (rows) =>
        rows ? rows.map((row) => (row.id === updated.id ? updated : row)) : [updated],
      );
    },
    onError: (e) => setPatchError(formatApiError(e)),
  });

  const debouncedPatchConnection = useDebouncedCallback((opts: ConnectionOptions) => {
    patchConnection.mutate(opts);
  }, 450);

  const applyConnectionOptions = (next: ConnectionOptions) => {
    const locked = enforceDeployedCapabilityLocks(acc, capabilityVerify, next);
    setSetupConnectionOptions(locked);
    setDraftCapabilities(locked);
    debouncedPatchConnection(locked);
  };

  const verifyCapabilities = useMutation({
    mutationFn: () =>
      api<VerifyCapabilitiesResponse>(`/v1/accounts/${acc.id}/verify-capabilities`, {
        method: "POST",
      }),
    onSuccess: (data) => {
      setCapabilityVerify(data.capabilities);
      setVerificationMeta(data.verification ?? null);
      setVerifyFeedback(capabilityVerifyFeedback(data));
      qc.setQueryData<Account[]>(["accounts"], (rows) =>
        rows ? rows.map((row) => (row.id === data.account.id ? data.account : row)) : [data.account],
      );
      const opts = accountConnectionOptions(data.account);
      setDraftCapabilities(opts);
      setSetupConnectionOptions(opts);
    },
    onError: (e) => setVerifyFeedback({ tone: "error", message: formatApiError(e) }),
  });

  const verify = useMutation({
    mutationFn: () =>
      api<Account>(`/v1/accounts/${acc.id}/verify`, {
        method: "POST",
        body: JSON.stringify({ role_arn: roleArn }),
      }),
    onSuccess: (updated) => {
      qc.setQueryData<Account[]>(["accounts"], (rows) =>
        rows ? rows.map((row) => (row.id === updated.id ? updated : row)) : [updated],
      );
      const opts = accountConnectionOptions(updated);
      setSetupConnectionOptions(opts);
      setDraftCapabilities(opts);
      setShowUpdateArn(false);
      setRoleArn("");
    },
    onError: () => {
      qc.invalidateQueries({ queryKey: ["accounts"] });
    },
  });

  const connectionOptionsDirty = () => {
    const saved = accountConnectionOptions(acc);
    return (
      setupConnectionOptions.enable_advanced_policy_generation !==
        saved.enable_advanced_policy_generation ||
      REMEDIATION_MODULE_SPECS.some(
        (m) =>
          setupConnectionOptions.remediation_modules[m.id] !== saved.remediation_modules[m.id],
      )
    );
  };

  const handleVerifyConnection = () => {
    const runVerify = () => verify.mutate();
    if (connectionOptionsDirty()) {
      patchConnection.mutate(setupConnectionOptions, { onSuccess: runVerify });
      return;
    }
    runVerify();
  };

  const remove = useMutation({
    mutationFn: () => api(`/v1/accounts/${acc.id}`, { method: "DELETE" }),
    onSuccess: () => {
      setShowRemoveConfirm(false);
      qc.invalidateQueries({ queryKey: ["accounts"] });
    },
  });

  const requestRemove = () => {
    if (!connected) {
      remove.mutate();
      return;
    }
    setShowRemoveConfirm(true);
  };

  const hasStats = connected && hasScanned && !!stats;

  return (
    <div className={`group ${cardClass} ${!connected ? "border-l-[3px] border-l-amber-400" : ""}`}>
      <div className="flex items-center gap-4 px-4 py-3">
        <div className="flex min-w-0 flex-1 items-center gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-[#FF9900]/10">
            <AwsIcon className="h-6 w-6 object-contain" />
          </div>
          <div className="min-w-0">
            <h2 className="truncate text-sm font-semibold text-zinc-900">{acc.label}</h2>
            {connected && acc.account_id ? (
              <p className="font-mono text-xs tabular-nums text-zinc-500">{acc.account_id}</p>
            ) : (
              <p className="text-xs text-zinc-500">Setup required</p>
            )}
            <CapabilityBadges acc={acc} connectionOptions={connected ? undefined : setupConnectionOptions} />
            {connected && (
              <div className="mt-0.5">
                <ScanFreshnessBadge iso={acc.last_scan_at} isScanActive={isScanActive} />
              </div>
            )}
          </div>
        </div>

        <div className="flex shrink-0 items-center gap-2">
          {hasStats && stats && (
            <div className="hidden md:block">
              <MetricPills stats={stats} />
            </div>
          )}

          {connected && (
            <button
              onClick={() => triggerScan(acc.id)}
              disabled={isScanActive}
              className="inline-flex h-8 items-center gap-1.5 rounded-lg bg-indigo-600 px-3 text-xs font-semibold text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <svg
                className={`h-3.5 w-3.5 ${isScanActive ? "animate-spin" : ""}`}
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
                />
              </svg>
              {isScanActive ? (isRunning ? "Scanning…" : "Starting…") : "Scan"}
            </button>
          )}

          {!connected && (
            <>
              <button type="button" onClick={onToggle} className={ghostBtn}>
                {expanded ? "Hide setup" : "Continue setup"}
              </button>
              <button
                type="button"
                onClick={requestRemove}
                disabled={remove.isPending}
                className={dangerGhostBtn}
              >
                Remove account
              </button>
            </>
          )}
        </div>
      </div>

      {hasStats && stats && (
        <div className="border-t border-zinc-100/80 px-4 py-2 md:hidden">
          <MetricPills stats={stats} />
        </div>
      )}

      {connected && isScanActive && (
        <div className="border-t border-zinc-100/80 px-4 pb-3 pt-2">
          <ScanProgressBar
            phase={isRunning ? "running" : "starting"}
            progress={scanProgress.progress}
            elapsedMs={scanProgress.elapsedMs}
            remainingMs={scanProgress.remainingMs}
            finishing={scanProgress.finishing}
            indeterminate={scanProgress.indeterminate}
            progressStep={scanProgress.progressStep}
            progressTotal={scanProgress.progressTotal}
            className="mb-0"
          />
        </div>
      )}

      {connected && !isScanActive && scanStatus === "error" && scanRun.data?.error && (
        <div className="border-t border-red-100/80 bg-red-50/60 px-4 py-2.5 text-xs text-red-700">
          <span className="font-semibold">Last scan failed</span>
          {scanRun.data.failed_at && (
            <>
              {" "}
              at <code className="rounded bg-red-100 px-1 font-mono">{scanRun.data.failed_at}</code>
            </>
          )}
          <div className="mt-1 line-clamp-2 break-words text-red-700/90">{scanRun.data.error}</div>
        </div>
      )}

      {connected && !hasScanned && !isScanActive && (
        <div className="border-t border-zinc-100/80 bg-zinc-50/40 px-4 py-2.5 text-center text-xs text-zinc-500">
          Run a scan to populate findings.
        </div>
      )}

      {connected && (
        <button
          type="button"
          onClick={onToggle}
          aria-expanded={expanded}
          className={`flex w-full items-center justify-between border-t px-4 py-2 text-left transition ${
            expanded
              ? "border-zinc-200/80 bg-zinc-100/50"
              : "border-zinc-100/80 bg-zinc-50/30 hover:bg-zinc-50/60"
          }`}
        >
          <span className="text-xs font-medium text-zinc-600">Details</span>
          <svg
            className={`h-4 w-4 text-zinc-400 transition-transform duration-300 ease-out ${expanded ? "rotate-180" : ""}`}
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </button>
      )}

      <div
        className={`grid transition-[grid-template-rows] duration-300 ease-in-out ${
          connected && expanded ? "grid-rows-[1fr]" : "grid-rows-[0fr]"
        }`}
      >
        <div className="overflow-hidden">
          {connected && expanded && (
            <div className="border-t border-zinc-200/60 bg-zinc-50/50">
              <AccountDetailsPanel
                acc={acc}
                isScanActive={isScanActive}
                scanError={
                  scanStatus === "error" && scanRun.data?.error
                    ? `${scanRun.data.error_type ? `(${scanRun.data.error_type}) ` : ""}${scanRun.data.error}`
                    : null
                }
                showManageCapabilities={showManageCapabilities}
                onManageCapabilities={() => setShowManageCapabilities((v) => !v)}
                showUpdateArn={showUpdateArn}
                roleArn={roleArn}
                setRoleArn={setRoleArn}
                verify={verify}
                onUpdateRole={() => setShowUpdateArn(true)}
                onCancelUpdate={() => {
                  setShowUpdateArn(false);
                  setRoleArn("");
                  verify.reset();
                }}
                onRemove={() => setShowRemoveConfirm(true)}
                removePending={remove.isPending}
                manageCapabilitiesPanel={
                  showManageCapabilities ? (
                    <ManageCapabilitiesPanel
                      acc={acc}
                      draft={draftCapabilities}
                      onDraftChange={(next) => {
                        const locked = enforceDeployedCapabilityLocks(acc, capabilityVerify, next);
                        setDraftCapabilities(locked);
                        debouncedPatchConnection(locked);
                      }}
                      onClose={() => setShowManageCapabilities(false)}
                      saveError={patchError}
                      onVerifyCapabilities={() => verifyCapabilities.mutate()}
                      verifyingCapabilities={verifyCapabilities.isPending}
                      verifyFeedback={verifyFeedback}
                      capabilityVerify={capabilityVerify}
                      verificationMeta={verificationMeta}
                    />
                  ) : null
                }
              />
            </div>
          )}
        </div>
      </div>

      {showSetup && (
        <InCardAccountSetupWizard
          acc={acc}
          connectionOptions={setupConnectionOptions}
          onConnectionOptionsChange={applyConnectionOptions}
          connectionOptionsSaving={patchConnection.isPending}
          roleArn={roleArn}
          setRoleArn={setRoleArn}
          verify={verify}
          onVerifyConnection={handleVerifyConnection}
          initialStep={setupInitialStep}
        />
      )}

      <ConfirmDialog
        open={showRemoveConfirm}
        title="Remove this account?"
        description={
          connected
            ? hasScanned
              ? `${acc.label} and all associated findings, scan history, and evidence will be permanently deleted. This cannot be undone.`
              : `${acc.label} will be disconnected and removed. No findings or evidence have been collected yet. This cannot be undone.`
            : `${acc.label} setup will be discarded. This account was never connected — no findings, scans, or evidence exist. This cannot be undone.`
        }
        confirmLabel="Disconnect account"
        variant="danger"
        loading={remove.isPending}
        onCancel={() => !remove.isPending && setShowRemoveConfirm(false)}
        onConfirm={() => remove.mutate()}
      />
    </div>
  );
}

function PostureSummary({
  accounts,
  statsMap,
}: {
  accounts: Account[];
  statsMap: Map<string, FindingStats>;
}) {
  const connected = accounts.filter((a) => isAccountConnected(a));

  let totalOpen = 0;
  let totalCrit = 0;
  let needsAttention = 0;
  for (const a of connected) {
    const s = statsMap.get(a.id);
    if (!s) continue;
    totalOpen += s.open;
    totalCrit += s.critHigh;
    if (s.critHigh > 0) needsAttention += 1;
  }

  const metricTiles: { label: string; value: number; gradient: string }[] = [
    {
      label: "Connected",
      value: connected.length,
      gradient: "from-white to-sky-50/40",
    },
    {
      label: "Open findings",
      value: totalOpen,
      gradient: "from-white to-zinc-50/90",
    },
    {
      label: "Critical + high",
      value: totalCrit,
      gradient: "from-white to-zinc-50/90",
    },
    {
      label: "Accounts at risk",
      value: needsAttention,
      gradient: "from-white to-zinc-50/90",
    },
  ];

  return (
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      {metricTiles.map((t) => (
        <div
          key={t.label}
          className={`rounded-xl border border-zinc-200 bg-gradient-to-br px-4 py-3 shadow-[0_1px_2px_rgba(0,0,0,0.04)] transition-[box-shadow,border-color] duration-200 hover:border-zinc-300 hover:shadow-[0_2px_8px_rgba(0,0,0,0.06)] ${t.gradient}`}
        >
          <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400">
            {t.label}
          </p>
          <p className="mt-1 text-2xl font-semibold tabular-nums text-zinc-900">
            {t.value}
          </p>
        </div>
      ))}
    </div>
  );
}

export default function Accounts() {
  const qc = useQueryClient();
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [setupInitialStep, setSetupInitialStep] = useState(1);
  const [pendingConnectionOptions, setPendingConnectionOptions] = useState<ConnectionOptions>(
    DEFAULT_CONNECTION_OPTIONS,
  );

  const accounts = useQuery({
    queryKey: ["accounts"],
    queryFn: () => api<Account[]>("/v1/accounts"),
    refetchOnMount: "always",
  });

  const create = useMutation({
    mutationFn: (opts: ConnectionOptions) =>
      api<Account>("/v1/accounts", {
        method: "POST",
        body: JSON.stringify({
          enable_advanced_policy_generation: opts.enable_advanced_policy_generation,
          remediation_modules: opts.remediation_modules,
        }),
      }),
    onSuccess: (acc) => {
      qc.invalidateQueries({ queryKey: ["accounts"] });
      setSetupInitialStep(1);
      setExpandedId(acc.id);
      setPendingConnectionOptions(accountConnectionOptions(acc));
    },
  });

  const patchConnection = useMutation({
    mutationFn: ({ accountId, opts }: { accountId: string; opts: ConnectionOptions }) =>
      api<Account>(`/v1/accounts/${accountId}/connection-options`, {
        method: "PATCH",
        body: JSON.stringify(opts),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["accounts"] });
    },
  });

  const allFindings = useQuery({
    queryKey: ["findings-snapshot-all"],
    queryFn: () =>
      api<{ items: Finding[]; total: number; next_cursor: string | null }>(
        `/v1/findings?status=open&limit=500`
      ),
    enabled: (accounts.data?.length ?? 0) > 0,
  });

  const statsMap = useMemo(() => buildStatsMap(allFindings.data?.items), [allFindings.data?.items]);

  const accs = useMemo(() => {
    const rows = accounts.data ?? [];
    const pending: Account[] = [];
    const connected: Account[] = [];
    for (const row of rows) {
      if (isAccountConnected(row)) connected.push(row);
      else pending.push(row);
    }
    return [...pending, ...connected];
  }, [accounts.data]);
  const hasPending = accs.some((a) => !isAccountConnected(a));
  const hasConnectedAccount = accs.some((a) => isAccountConnected(a));

  const showFirstAccountOnboarding =
    accs.length === 0 && !accounts.isLoading && !accounts.isError;

  return (
    <div className="mx-auto w-full max-w-7xl space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-zinc-950">AWS Accounts</h1>
          <p className="mt-1 text-sm text-zinc-500">
            {showFirstAccountOnboarding
              ? "Connect your AWS account to continuously monitor compliance, detect security findings, and generate auditor-ready evidence."
              : "Connected accounts and scan freshness at a glance."}
          </p>
        </div>
        {accs.length > 0 && (
          <button
            onClick={() => create.mutate(pendingConnectionOptions)}
            disabled={create.isPending || hasPending}
            title={hasPending ? "Finish setting up the pending account first" : undefined}
            className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-200 bg-white px-4 py-2 text-sm font-semibold text-zinc-700 shadow-sm transition hover:border-zinc-300 hover:bg-zinc-50 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            {create.isPending ? "Adding…" : "Add account"}
          </button>
        )}
      </div>

      {hasConnectedAccount && <PostureSummary accounts={accs} statsMap={statsMap} />}

      {accounts.isError && (
        <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
          <p className="font-medium">Could not load AWS accounts</p>
          <p className="mt-1 text-red-700">{formatApiError(accounts.error)}</p>
          <button
            type="button"
            onClick={() => accounts.refetch()}
            className="mt-3 text-sm font-semibold text-red-900 underline hover:no-underline"
          >
            Retry
          </button>
        </div>
      )}

      {accounts.isLoading && accs.length === 0 && (
        <p className="text-sm text-zinc-500">Loading accounts…</p>
      )}

      {showFirstAccountOnboarding && (
        <FirstAccountOnboarding
          value={pendingConnectionOptions}
          onChange={setPendingConnectionOptions}
          disabled={create.isPending}
          continuing={create.isPending}
          onContinue={() => create.mutate(pendingConnectionOptions)}
        />
      )}

      {accs.length > 0 && !showFirstAccountOnboarding && (
        <div className="space-y-4">
          {accs.map((acc) => (
            <AccountCard
              key={acc.id}
              acc={acc}
              stats={statsMap.get(acc.id)}
              expanded={expandedId === acc.id}
              setupInitialStep={expandedId === acc.id ? setupInitialStep : 1}
              onToggle={() => setExpandedId((id) => (id === acc.id ? null : acc.id))}
            />
          ))}
        </div>
      )}

      {hasPending && accs.length > 0 && (
        <p className="text-center text-xs text-zinc-500">Finish pending setup before adding another account.</p>
      )}

      {create.error && (
        <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
          {formatApiError(create.error)}
        </div>
      )}
    </div>
  );
}
