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

/** Read trust principal + role name from a server-built console launch URL. */
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
  if (variant === "update") {
    return acc.cfn_stack_name || CONNECTOR_STACK_NAME;
  }
  return displayConnectorStackName(acc);
}

function buildLaunchUrl(
  acc: CfnAccountSlice,
  opts: CfnConnectionOptions,
  variant: CfnDeployVariant,
): string {
  const stackName = stackNameForVariant(acc, variant);
  const meta = parseCfnLaunchMeta(
    variant === "update" ? acc.cfn_update_launch_url : acc.cfn_launch_url,
  );
  const params = new URLSearchParams();
  params.set("templateURL", acc.cfn_template_url);
  params.set("stackName", stackName);
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
  const path =
    variant === "update"
      ? "https://console.aws.amazon.com/cloudformation/home#/stacks/update/review"
      : "https://console.aws.amazon.com/cloudformation/home#/stacks/create/review";
  return `${path}?${params.toString()}`;
}

export function buildCfnCliCommand(
  acc: CfnAccountSlice,
  opts: CfnConnectionOptions,
  variant: CfnDeployVariant,
): string {
  const stackName = stackNameForVariant(acc, variant);
  const meta = parseCfnLaunchMeta(
    variant === "update" ? acc.cfn_update_launch_url : acc.cfn_launch_url,
  );
  const verb = variant === "create" ? "create-stack" : "update-stack";
  const lines = [
    `aws cloudformation ${verb} \\`,
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
): { consoleUrl: string; cliCommand: string } {
  if (!connectionOptions) {
    return {
      consoleUrl: variant === "update" ? acc.cfn_update_launch_url : acc.cfn_launch_url,
      cliCommand: variant === "update" ? acc.cfn_update_cli_command : acc.cfn_cli_command,
    };
  }
  return {
    consoleUrl: buildLaunchUrl(acc, connectionOptions, variant),
    cliCommand: buildCfnCliCommand(acc, connectionOptions, variant),
  };
}
