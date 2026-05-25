# Vigil

**AWS security evidence for SOC2 Type 2.**

Connect your AWS account read-only. Vigil scans daily, produces continuous evidence for CC6 (Logical & Physical Access) and CC7 (System Operations), maps every finding to CIS AWS Benchmark controls, and gives you an auditor-ready PDF on demand.

Aimed at engineering teams of 5–30 who are heading into their first SOC2 audit and don't have $1,500/mo for Vanta or $50k/yr for Wiz.

---

## Positioning

Vigil is **not** a CSPM. It does not try to match Wiz, Prisma, or Orca on coverage breadth.

Vigil is **not** a compliance platform. It does not replace Vanta or Drata — those are evidence aggregators that integrate HR, MDM, GitHub, Slack, and shallow AWS.

Vigil is the **AWS depth layer**. The part where Vanta is shallow and where auditors actually look — IAM, encryption at rest, CloudTrail, network exposure, access reviews. Vigil produces continuous, date-stamped evidence and a PDF the auditor will accept.

You can run Vigil alongside Vanta (recommended for full SOC2 coverage), or standalone if you're pre-Vanta and only need the AWS controls evidenced.

---

## How it works

```
Your browser
     │
     ▼
  Caddy (reverse proxy, prod only)
     ├──▶ API   (FastAPI :8000)  ──▶ Postgres
     └──▶ Web   (React :5173)
                                       ▲
                                  Worker (Celery + beat)
                                       │
                                  sts:AssumeRole
                                       │
                                       ▼
                              Customer AWS account
                          (read-only role, ExternalId,
                           deployed via CloudFormation)
```

Single VPS · Docker Compose · No Kubernetes · No microservices.

The worker runs in Vigil's control-plane account (Account A) and assumes a customer-provided role in their account (Account B). Nothing runs inside the customer's VPC. IAM and STS are AWS control-plane APIs reachable over public HTTPS.

---

## Quickstart (dev)

```bash
cp .env.example .env
# Required: set TRUST_PRINCIPAL_ARN to the ARN allowed to assume customer roles
# Required: set JWT_SECRET to a long random string
# Optional: AWS_PROFILE if running against a real AWS account locally

docker compose up -d db redis
docker compose run --rm api alembic upgrade head
docker compose up api worker web
```

Open **http://localhost:5173**.

AWS credentials in dev: mount `~/.aws` (already wired in `compose.yml`) and set `AWS_PROFILE` in `.env`. The SDK re-reads the file on every call, so `aws sso login` on the host refreshes the container immediately — no restart needed.

---

## Onboarding a customer account

1. Sign up — email + password, or GitHub / Google SSO.
2. **AWS Accounts** → name it (e.g. `prod`) → **Create**.
3. Click **Launch CloudFormation stack**. The template URL, `ExternalId`, and your control-plane principal are pre-filled.
4. In the customer's AWS Console: deploy the stack → copy the `RoleArn` output.
5. Paste the ARN → **Verify**. Vigil calls `sts:AssumeRole` to confirm the trust + ExternalId are correct.
6. **Run scan** → ~1–3 min → findings appear, grouped by check, ranked by risk score.

---

## Checks today

| Check ID | Severity | What it finds |
|---|---|---|
| `iam.user.no_mfa` | high | Console user with no MFA device |
| `iam.user.inactive_90d` | medium | Console user with no console or API activity in 90+ days |
| `iam.access_key.unused_90d` | high | Active access key unused for 90+ days |
| `iam.role.unassumed_90d` | medium | Role not assumed in 90+ days |
| `iam.role.wildcard_action` | high | Inline policy grants `Action: "*"` |
| `iam.role.unused_services_90d` | medium | Role has permissions to services it never calls (Access Analyzer + service-last-accessed) |

Service-linked roles (`/aws-service-role/`) are excluded from all checks.

Risk score = severity base + age multiplier + admin flag. See [`api/app/checks/base.py`](api/app/checks/base.py). The score is documented and hand-verifiable — no ML, no opaque ranking.

Findings are **diff-aware**: existing open findings are refreshed; findings that disappear are auto-resolved; previously-resolved findings that reappear are auto-reopened with full history.

---

## IAM permissions requested

Deployed via [`infra/cfn/hygiene-readonly-role.yaml`](infra/cfn/hygiene-readonly-role.yaml).

**Managed (will be tightened before public beta):**
- `SecurityAudit`
- `ViewOnlyAccess`

**Custom additions:**
- `iam:GenerateServiceLastAccessedDetails` / `iam:GetServiceLastAccessedDetails`
- `iam:GenerateCredentialReport` / `iam:GetCredentialReport`
- `iam:GetAccountAuthorizationDetails`
- `access-analyzer:List*` / `access-analyzer:Get*`
- `sts:GetCallerIdentity`
- `organizations:Describe*` / `organizations:List*` (for account alias resolution)

**No write permissions. Ever.** The role uses an `ExternalId` condition (confused-deputy protection) and only `TRUST_PRINCIPAL_ARN` can assume it.

---

## Project layout

```
api/
  app/
    core/         config, db, security, aws (sts), passwords
    models/       SQLAlchemy 2.0 tables (org, user, aws_account,
                  iam, finding, scan_run)
    routes/       auth, auth_oauth, accounts, findings
    collectors/   boto3 → DB upserts (iam.py, last_accessed.py)
    checks/       pure functions → FindingDraft (base, registry, persist)
    worker/       celery_app + tasks (run_scan, scan_all_accounts)
  migrations/     Alembic
web/              React + Vite + Tailwind + TanStack Query
infra/cfn/        hygiene-readonly-role.yaml
caddy/            Caddyfile (prod profile only)
compose.yml
```

---

## Auth

- Email + password (bcrypt with sha256 prehash — passlib removed due to bcrypt 4.x compat bug)
- GitHub OAuth — sign-in or connect from Account settings
- Google OAuth
- JWT (24h). Refresh tokens planned.

---

## Pricing (planned)

| Tier | Price | What's included |
|---|---|---|
| Diagnostic | $299 one-time | Single scan, full PDF report, no continuous monitoring |
| Pro | $129 / mo | Continuous scanning, 1 AWS account, weekly digest, on-demand PDF, 90 days of evidence history |
| Pro annual | $999 / yr | Same as Pro, ~35% off |
| Team | $299 / mo | Multi-account (up to 10), SOC2 evidence pack, audit-window historic export, priority support |

Free 14-day trial on all tiers. No sales call. Stripe checkout, customer portal for management.

Why monthly / annual rather than one-shot: SOC2 Type 2 requires **continuous evidence** across the audit window (typically 3–12 months). Auditors sample random dates from the window and ask for proof the control was in effect on that date. A one-time scan produces one date of evidence and fails Type 2. The scanner running daily produces 365 date-stamped evidence points per year.

---

## Roadmap

### P0 — make it sellable

1. **CIS AWS Benchmark Level 1 mapping** — every check + finding tagged with control IDs (`CIS 1.4`, `CIS 1.10`, …). Many-to-many table, seeded from JSON.
2. **TSC CC6 / CC7 mapping** — same finding rows, additional control framework tags for SOC2.
3. **PDF compliance report** — one button, "AWS Security Posture & SOC2 CC6/CC7 Evidence." Account ID, scan date, posture score, control coverage matrix, open findings grouped by control, remediation steps. Auditor-acceptable formatting.
4. **Weekly digest email** (Resend) — Monday 9am org TZ, top findings, delta vs last week, link to dashboard.
5. **Posture score over time** — single number 0–100, trend graph. Lets customers see improvement and justifies renewal.
6. **EC2 security group checks** — open to `0.0.0.0/0` on 22/3389/all. Highest insurance-questionnaire frequency.
7. **RDS public access check** — instances with `PubliclyAccessible: true`. Direct insurance question.
8. **CloudTrail enabled + multi-region + log validation** — required by SOC2 CC7.
9. **Encryption at rest checks** — EBS volumes, RDS instances, S3 default encryption.
10. **Stripe billing** — Checkout + customer portal + webhook → org plan transitions.

### P1 — operational maturity

- pytest skeleton with botocore Stubber + unit tests for checks
- Encrypt `aws_accounts.role_arn` and `external_id` at rest (pgcrypto)
- Pagination + filtering on `/v1/findings`
- CSV export
- Scan progress + error surface in UI
- TOTP MFA on user accounts
- Refresh tokens
- Audit log of all assume-role operations
- Tighten CFN policy — drop `SecurityAudit` + `ViewOnlyAccess`, list exact actions
- Hetzner deploy + Caddy auto-TLS + nightly `pg_dump` to B2

### P1.5 — coverage that closes more deals

- S3 lifecycle, versioning, block-public-access account-level setting
- KMS key rotation, key policy review
- Secrets Manager / SSM Parameter Store rotation status
- Lambda function URL exposure
- Access key age cap (e.g. 90 days regardless of usage)
- Root account usage detection (CloudTrail)

### Phase 2 — beyond AWS-only

- Multi-account via AWS Organizations StackSet (one click → role in every member account)
- Quarterly access review export (auditor-ready CSV: who-had-what-when)
- Custom controls (customer-defined checks)
- Vanta / Drata / Secureframe webhook integration (push findings as evidence)
- Slack delivery for digest + critical findings

### Explicitly out of scope

- Multi-cloud (Azure / GCP). Different scanner, different buyer journey.
- Kubernetes RBAC. Different product.
- Repository scanning (Gitleaks / Semgrep / Snyk territory). Different buyer.
- Write actions / auto-remediation. Different trust model — read-only is the entire safety story.
- LLM-generated findings or summaries unless they pass auditor review.

---

## What this is not

- Not a CSPM. We do not chase coverage parity with Wiz or Prisma. ~25 checks at depth beats 1,500 shallow ones for the target buyer.
- Not a compliance suite. We map only to controls AWS data can actually evidence (CC6, CC7, partial CC4 / CC8). Vanta covers the people / process / policy controls Vigil cannot.
- Not a SIEM. We do not store CloudTrail events or do log analytics. We read summarized AWS state.
- Not an agent. Nothing installs inside the customer environment. STS + IAM control-plane only.

---

## License

TBD. Source closed for now.
