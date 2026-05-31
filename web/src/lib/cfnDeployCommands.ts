/**
 * Client-side CFN deploy URLs/CLI — mirrors api/app/routes/accounts.py (_launch_url, _cli_command).
 * Used for instant UI updates while connection options save in the background.
 */
import {
  REMEDIATION_MODULE_SPECS,
  type RemediationModules,
} from "../data/remediationModules";
import { CONNECTOR_STACK_NAME, SCANNER_ROLE_NAME, displayConnectorStackName } from "./connectionPosture";

export type CfnConnectionOptions = {
  enable_advanced_policy_generation: boolean;
  remediation_modules: RemediationModules;
};

type CfnDeployVariant = "create" | "update";

type CfnAccountSlice = {
  external_id: string;
  cfn_template_url: string;
  cfn_launch_url: string;
  cfn_update_launch_url: string;
  cfn_cli_command: string;
  cfn_update_cli_command: string;
  cfn_stack_name: string;
  status: string;
};

function yesNo(flag: boolean): string {
  return flag ? "Yes" : "No";
}

/** Infer console region from S3 template host (e.g. .s3.us-east-1.amazonaws.com). */
export function cfnConsoleRegion(templateUrl: string): string {
  const m = templateUrl.match(/\.s3\.([a-z0-9-]+)\.amazonaws\.com/i);
  return m?.[1] ?? "us-east-1";
}

/** Global console host + region query — IAM Identity Center SSO lands here reliably. */
export function cfnConsoleBase(templateUrl: string): string {
  const region = cfnConsoleRegion(templateUrl);
  return `https://console.aws.amazon.com/cloudformation/home?region=${region}`;
}

/** Read trust principal + role name from the create-stack console URL (always has params). */
export function parseCfnLaunchMeta(launchUrl: string): {
  trustPrincipalArn: string;
  scannerRoleName: string;
} {
  const qs = launchUrl.includes("?") ? (launchUrl.split("?").pop() ?? "") : "";
  const params = new URLSearchParams(qs);
  return {
    trustPrincipalArn: params.get("param_VigilAccountPrincipal") ?? "",
    scannerRoleName: params.get("param_RoleName") ?? SCANNER_ROLE_NAME,
  };
}

function stackNameForVariant(acc: CfnAccountSlice, variant: CfnDeployVariant): string {
  const name = (acc.cfn_stack_name ?? "").trim();
  if (variant === "update") {
    return name || CONNECTOR_STACK_NAME;
  }
  return displayConnectorStackName(acc);
}

/** Filtered stack list — AWS has no supported update-wizard deep link (stackName in hash is dropped). */
export function buildCfnStackListUrl(acc: CfnAccountSlice, variant: CfnDeployVariant): string {
  const stackName = stackNameForVariant(acc, variant);
  const base = cfnConsoleBase(acc.cfn_template_url);
  return `${base}#/stacks?filteringText=${encodeURIComponent(stackName)}&filteringStatus=active`;
}

function buildCreateLaunchUrl(
  acc: CfnAccountSlice,
  opts: CfnConnectionOptions,
): string {
  const stackName = stackNameForVariant(acc, "create");
  const meta = parseCfnLaunchMeta(acc.cfn_launch_url);
  const params = new URLSearchParams();
  params.set("stackName", stackName);
  params.set("templateURL", acc.cfn_template_url);
  params.set("param_ExternalId", acc.external_id);
  params.set("param_VigilAccountPrincipal", meta.trustPrincipalArn);
  params.set("param_RoleName", meta.scannerRoleName);
  params.set(
    "param_EnableAdvancedPolicyGeneration",
    yesNo(opts.enable_advanced_policy_generation),
  );
  for (const spec of REMEDIATION_MODULE_SPECS) {
    params.set(`param_${spec.cfnParameter}`, yesNo(opts.remediation_modules[spec.id]));
  }
  const base = cfnConsoleBase(acc.cfn_template_url);
  return `${base}#/stacks/create/review?${params.toString()}`;
}

export function buildCfnCliCommand(
  acc: CfnAccountSlice,
  opts: CfnConnectionOptions,
  variant: CfnDeployVariant,
): string {
  const stackName = stackNameForVariant(acc, variant);
  const meta = parseCfnLaunchMeta(acc.cfn_launch_url);
  const region = cfnConsoleRegion(acc.cfn_template_url);
  const verb = variant === "create" ? "create-stack" : "update-stack";
  const lines = [
    `aws cloudformation ${verb} --region ${region} \\`,
    `  --stack-name ${stackName} \\`,
    `  --template-url ${acc.cfn_template_url} \\`,
    "  --parameters \\",
    `    ParameterKey=ExternalId,ParameterValue=${acc.external_id} \\`,
    `    ParameterKey=VigilAccountPrincipal,ParameterValue=${meta.trustPrincipalArn} \\`,
    `    ParameterKey=RoleName,ParameterValue=${meta.scannerRoleName} \\`,
    `    ParameterKey=EnableAdvancedPolicyGeneration,ParameterValue=${yesNo(opts.enable_advanced_policy_generation)} \\`,
  ];
  for (const spec of REMEDIATION_MODULE_SPECS) {
    lines.push(
      `    ParameterKey=${spec.cfnParameter},ParameterValue=${yesNo(opts.remediation_modules[spec.id])} \\`,
    );
  }
  lines.push("  --capabilities CAPABILITY_NAMED_IAM");
  return lines.join("\n");
}

export function resolveDeployArtifacts(
  acc: CfnAccountSlice,
  connectionOptions: CfnConnectionOptions | undefined,
  variant: CfnDeployVariant,
): { consoleUrl: string; cliCommand: string; stackListUrl: string; stackName: string } {
  const stackName = stackNameForVariant(acc, variant);
  const stackListUrl = buildCfnStackListUrl(acc, variant);
  if (!connectionOptions) {
    return {
      consoleUrl: variant === "update" ? acc.cfn_update_launch_url : acc.cfn_launch_url,
      cliCommand: variant === "update" ? acc.cfn_update_cli_command : acc.cfn_cli_command,
      stackListUrl,
      stackName,
    };
  }
  return {
    consoleUrl:
      variant === "update" ? stackListUrl : buildCreateLaunchUrl(acc, connectionOptions),
    cliCommand: buildCfnCliCommand(acc, connectionOptions, variant),
    stackListUrl,
    stackName,
  };
}
