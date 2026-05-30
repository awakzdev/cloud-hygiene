# Customer-account remediation (Lambda v1)

Vigil stays **read-only**. Customers deploy a small CFN pack; Vigil emits a **signed, expiring** plan (`vigil_remediation_plan/v2`) that they publish with `aws events put-events`.

## Architecture

```
Vigil UI → remediation plan v2 → customer runs aws events put-events (bus home region)
→ EventBridge rule (content filter on check_id + schema) → Lambda (fixed EC2 role)
→ RevokeSecurityGroupIngress on exact_match_rules only (resource_region in plan)
```

- **No dynamic IAM attach** — role permissions are static in CFN.
- **Bus region ≠ resource region** — deploy the stack and run `put-events` in `REMEDIATION_EVENT_BUS_REGION` (Vigil `.env`). Lambda calls EC2 in `resource_region` from the plan.
- **Exact-match revoke** — only tuples in `exact_match_rules` from the finding evidence; `stale_plan` if live SG drifted.
- **Optional Ed25519** — same key material as evidence packs; pass `RemediationSigningPublicKeyBase64` to the stack.

## Deploy (security groups)

**IAM role names are unique per AWS account.** You cannot create `VigilRemediationRole` twice.

### Option A — Update the stack you already have (recommended)

```bash
aws cloudformation deploy \
  --region us-east-1 \
  --stack-name Vigil-Runner \
  --template-file infra/cfn/vigil-remediation-runner-ec2.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides EventBusName=default
```

Set Vigil `REMEDIATION_EVENT_BUS_REGION=us-east-1` to match this deploy region.

### Option B — New stack, reuse existing role

```bash
aws cloudformation deploy \
  --region us-east-1 \
  --stack-name Vigil-EC2 \
  --template-file infra/cfn/vigil-remediation-runner-ec2.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides ExistingRemediationRoleArn=arn:aws:iam::ACCOUNT:role/VigilRemediationRole
```

### Plan fields (v2)

| Field | Purpose |
|-------|---------|
| `event_bus_region` / `event_bus_name` | Where to `put-events` |
| `resource_region` | EC2 API region for the SG |
| `exact_match_rules` | CIDR + protocol + ports to revoke |
| `expires_at` | Reject expired plans |
| `content_sha256` | Tamper detection |
| `signature` | Optional Ed25519 (Vigil signing key) |

## IAM (EC2 only)

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "ec2:RevokeSecurityGroupIngress",
      "ec2:AuthorizeSecurityGroupIngress"
    ],
    "Resource": "*"
  }]
}
```

## Terraform boundary

- **S3 / KMS** — declarative Terraform snippets in UI.
- **Security groups** — Console, CLI, EventBridge only (no `null_resource` / local-exec Terraform).
- **GitHub PR** — paused (`503`) until repo-aware HCL + `terraform validate`.

## Handler behavior

For `ec2.security_group.unrestricted_ssh` / `unrestricted_rdp`:

- Revokes only rules matching `exact_match_rules` (including all-traffic `-1` when in the plan).
- Returns **`ok: false`** with `stale_plan` if nothing matched.
- CloudWatch log group retention 30 days; reserved concurrency 2.

Canonical source: `infra/lambda/remediation_runner.py`. Package and upload before deploy:

```bash
./infra/lambda/build.sh
# Single artifact location (public CFN bucket — not vigil-worm-storage evidence vault)
aws s3 cp infra/lambda/remediation_runner.zip s3://amzn-s3-vigil/lambda/remediation_runner.zip
```

Set CFN parameter `VigilExecutionWebhookUrl` to your Vigil API, e.g. `https://your-api/v1/public/remediation-execution` (shown in Prepare EventBridge UI).

CFN loads `LambdaArtifactBucket` / `LambdaArtifactKey` (defaults: `amzn-s3-vigil`, `lambda/remediation_runner.zip`).

## Troubleshooting

| Symptom | Cause |
|--------|--------|
| `put-events` succeeds, Lambda never runs | Wrong **bus region** (not resource region) |
| `plan_expired` / `content_sha256_mismatch` | Old payload — Prepare again after re-scan |
| `stale_plan` | SG changed since scan; re-scan and publish fresh plan |
| `InvalidGroup.NotFound` | Wrong `resource_region` in plan |

Always **re-scan** in Vigil, open **EventBridge** tab, **Prepare**, then run the CLI.

## SSM (v1.5)

Same plan JSON; executor becomes `StartAutomationExecution` with a document per remediation family. Prefer for enterprise auditors; Lambda remains valid for MVP.
