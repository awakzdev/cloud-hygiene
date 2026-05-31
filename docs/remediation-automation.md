# Customer-account remediation (SSM Automation)

Vigil's scanner stays read-only unless the customer explicitly enables remediation modules.
Approved fixes run through AWS Systems Manager Automation in the customer account. Vigil
prefers AWS-owned runbooks where they fit the finding exactly, and uses a small custom SSM
document only when extra guardrails are needed.

## Architecture

```
Vigil UI -> approval -> ssm:StartAutomationExecution
-> AWS-owned runbook or Vigil guardrail document
-> SSM Automation assumes customer remediation role
-> document applies the approved action in resource_region
```

- **No dynamic IAM attach**: write permissions are static on the customer-owned automation role.
- **AWS-native execution**: execution history and output live in Systems Manager.
- **Automation region != resource region**: deploy `vigil-remediation-ssm.yaml` in the configured automation region; the document calls AWS APIs in `resource_region` from the plan.
- **Exact-match revoke**: security-group fixes only remove tuples from `exact_match_rules`; returns `stale_plan` if live rules drifted.
- **No custom Lambda runner**: SSM owns execution, audit trail, and output.

## Deploy

```bash
aws cloudformation deploy \
  --region us-east-1 \
  --stack-name Vigil-Remediation-SSM \
  --template-file infra/cfn/vigil-remediation-ssm.yaml \
  --capabilities CAPABILITY_NAMED_IAM
```

Set Vigil `REMEDIATION_AUTOMATION_REGION=us-east-1` to the same region.

## Supported Actions

| Check | SSM action |
|-------|------------|
| `ec2.security_group.unrestricted_ssh` | Revoke exact public SSH ingress from the finding plan |
| `ec2.security_group.unrestricted_rdp` | Revoke exact public RDP ingress from the finding plan |
| `ssm.parameter.plaintext_secret` | Rewrite plaintext `String` parameter as `SecureString` |

AWS-owned runbook mappings are tracked in `api/app/services/ssm_remediation_catalog.py`.
They should be wired only when Vigil can provide the document's required parameters safely.

Lambda service findings are detected and documented, but not auto-executed yet:

- `lambda.function.deprecated_runtime` needs an approved target runtime.
- `lambda.function.no_dlq` needs an approved DLQ ARN.

Those should become plan inputs before being automated.

## Plan Fields

| Field | Purpose |
|-------|---------|
| `resource_region` | AWS API region for the affected resource |
| `execution.runner_type` | `ssm` |
| `execution.document_name` | SSM document to execute |
| `exact_match_rules` | Security-group CIDR/protocol/port tuples to revoke |
| `expires_at` | Reject expired plans |
| `content_sha256` | Tamper detection |
| `approval` | Added only by `POST .../remediation/dispatch` |

## Execute

`POST /v1/findings/{id}/remediation/dispatch` starts SSM Automation when the connected
role has the optional remediation permissions. The UI also shows a CLI fallback:

```bash
aws ssm start-automation-execution \
  --region us-east-1 \
  --document-name Vigil-RemediationPlanExecutor \
  --parameters '{"PlanJson":["{...approved plan json...}"]}'
```

Always re-scan before preparing a plan, then re-scan after successful remediation.

## Troubleshooting

| Symptom | Cause |
|--------|-------|
| `InvalidDocument` | SSM template not deployed in the automation region |
| `plan_expired` / `content_sha256_mismatch` | Old or edited payload; prepare a fresh plan |
| `stale_plan` | Resource changed since scan; re-scan and prepare a new plan |
| `InvalidGroup.NotFound` | Wrong `resource_region` or stale security-group id |
| `AccessDenied` | Automation role lacks the module permission or resource policy blocks it |
