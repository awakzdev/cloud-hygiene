# Remediation (customer-hosted)

Vigil stays **read-only** for scanning. Remediation execution runs in the customer AWS account through AWS Systems Manager Automation.

## Flow

1. Open a finding -> **Remediation plan** (`GET /v1/findings/{id}/remediation-plan`).
2. Review Console/CLI/IaC/Automation steps in the UI.
3. Prepare approved automation (`POST /v1/findings/{id}/remediation/dispatch`).
4. Vigil starts `ssm:StartAutomationExecution` through the scoped connector permissions, or the UI shows a CLI fallback.
5. SSM Automation assumes the customer-owned remediation role and applies only supported actions from the plan.

## Customer Infrastructure

Launch `infra/cfn/vigil-remediation-ssm.yaml` in the automation home region. It creates:

- `VigilRemediationAutomationRole`
- `Vigil-RemediationPlanExecutor` SSM Automation document

The document currently supports exact-match security-group ingress revocation and plaintext SSM parameter migration to `SecureString`.

## IaC / PRs

Generated Terraform snippets and repo-aware PRs remain declarative only. Live resource mutation should go through SSM Automation, Console, or CLI.
