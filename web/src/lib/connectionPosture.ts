import {
  anyRemediationEnabled,
  type RemediationModules,
} from "../data/remediationModules";

/** How the connector behaves after deploy (core is always read-only scan). */
export type ConnectionPosture = "read-only" | "read-only-analysis" | "scoped-write";

export const SCANNER_ROLE_NAME = "VigilScannerRole";
/** Legacy split-stack policy-gen role; new deploys use one connector role only. */
export const POLICY_GENERATION_ROLE_NAME = "VigilPolicyGenerationRole";
export const SCANNER_ROLE_NAME_LEGACY = "VigilReadOnlyScannerRole";
export const REMEDIATION_AUTOMATION_ROLE_NAME = "VigilRemediationAutomationRole";
export const CONNECTOR_STACK_NAME = "VigilAccountConnector";
export const CONNECTOR_STACK_LEGACY = "VigilReadOnly";

/** UI label: pending legacy rows show current name; connected legacy keeps VigilReadOnly. */
export function displayConnectorStackName(acc: {
  cfn_stack_name: string;
  status: string;
}): string {
  if (acc.status !== "connected" && acc.cfn_stack_name === CONNECTOR_STACK_LEGACY) {
    return CONNECTOR_STACK_NAME;
  }
  return acc.cfn_stack_name || CONNECTOR_STACK_NAME;
}

export function connectionPosture(opts: {
  enable_advanced_policy_generation: boolean;
  remediation_modules: RemediationModules;
}): ConnectionPosture {
  if (anyRemediationEnabled(opts.remediation_modules)) return "scoped-write";
  if (opts.enable_advanced_policy_generation) return "read-only-analysis";
  return "read-only";
}

export function connectionPostureLabel(posture: ConnectionPosture): string {
  switch (posture) {
    case "read-only":
      return "Read-only";
    case "read-only-analysis":
      return "Read + analysis";
    case "scoped-write":
      return "Read + write";
  }
}

export function connectionPostureBadgeClass(posture: ConnectionPosture): string {
  switch (posture) {
    case "read-only":
      return "rounded-full bg-zinc-100 px-2 py-0.5 text-[10px] font-medium text-zinc-700 ring-1 ring-zinc-200/80";
    case "read-only-analysis":
      return "rounded-full bg-violet-50 px-2 py-0.5 text-[10px] font-medium text-violet-900 ring-1 ring-violet-200/60";
    case "scoped-write":
      return "rounded-full bg-amber-50 px-2 py-0.5 text-[10px] font-medium text-amber-900 ring-1 ring-amber-200/60";
  }
}
