# Vigil

**Continuous SOC2 CC6/CC7 and CIS evidence automation for engineering teams.**

Connect AWS, GitHub, or GitLab. Vigil scans daily, maps findings to SOC2 CC6/CC7, a curated subset of CIS AWS Foundations controls, and ISO 27001 Annex A, and produces auditor-ready evidence packs — JSON, CSV, and PDF — on demand.

Built for engineering-led startups heading into their first SOC2 Type 2 audit who don't want to pay $10k–80k/yr for Vanta or spend weeks doing it manually with Prowler screenshots.

**One-line:** Connect your AWS account → first downloadable SOC2 evidence pack in under 10 minutes.

---

## What it is

Vigil is a **continuous compliance evidence platform** — not a CSPM, not a compliance suite.

| What Vigil does | What Vigil does not do |
|---|---|
| Automates SOC2 CC6/CC7, selected CIS AWS controls, ISO 27001 evidence | Replace Vanta/Drata (no HR/MDM/vendor/policy) |
| Produces timestamped, auditor-ready evidence packs | Compete with Wiz/Prisma on scan breadth |
| CloudTrail change timeline + GitHub/GitLab evidence in packs | Write to your AWS account during scanning |
| Shows blast radius before you remediate a finding | Generate AI summaries in evidence outputs |
| Console / CLI / Terraform / optional customer SSM Automation | Auto-remediate without customer approval |
| Documents exceptions with approver + reason + expiry | Run agents inside customer VPCs |

---

## How it works

```
Your browser
     │
     ▼
  Reverse proxy (prod)
     ├──▶ API   (FastAPI :8000)  ──▶ Postgres
     └──▶ Web   (React :5173)
                                       ▲
                                  Worker (Celery + beat)
                                       │
                                  sts:AssumeRole (ExternalId)
                                       │
                                       ▼
                              Customer AWS account
                          (read-only role, exact actions,
                           deployed via CloudFormation)
```

Single VPS · Docker Compose · No Kubernetes · No microservices.

The worker runs in Vigil's control-plane account and assumes a customer-provided read-only role. Nothing runs inside the customer's VPC. IAM and STS are AWS control-plane APIs reachable over public HTTPS.

---

## Quickstart (dev)

```bash
cp .env.example .env
# Required: TRUST_PRINCIPAL_ARN — ARN allowed to assume customer roles
# Required: JWT_SECRET — long random string
# Optional: GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET
# Optional: GITLAB_CLIENT_ID / GITLAB_CLIENT_SECRET
# Optional: RESEND_API_KEY (weekly digest email)

docker compose up -d db redis
docker compose run --rm api alembic upgrade head
docker compose up api worker web
```

Open **http://localhost:5173**.

AWS in dev: mount `~/.aws` (already in `compose.yml`) and set `AWS_PROFILE` in `.env`.

---

## Onboarding a customer account (AWS)

1. Sign up — email/password or GitHub/Google SSO.
2. **AWS Accounts** → choose connection mode:
   - **Core Scanner** (required, read-only) — CIS / SOC 2 / ISO checks and evidence packs.
   - **Advanced IAM policy generation** (optional) — adds `iam:GenerateServiceLastAccessedDetails` and Access Analyzer policy-generation actions to a separate CFN role. Starts AWS analysis jobs only; does not modify resources.
   - **Remediation automation** (optional, second stack) — customer-owned SSM Automation for approved fixes (e.g. security groups). Not required for compliance scanning.
3. **Continue to deploy** → **Launch CloudFormation stack** — template URL, ExternalId, trust principal, and optional parameters are pre-filled from your selections.
4. Deploy the stack in the customer's AWS console → copy `RoleArn` output (and `AdvancedPolicyGenRoleArn` if enabled).
5. Paste ARN → **Verify**. Vigil calls `sts:AssumeRole` to confirm trust + ExternalId.
6. First scan triggers automatically. Findings appear in ~1–3 min.

**IaC scanning** (Terraform on GitHub/GitLab pull requests) is separate: connect GitHub under Integrations. It does not use the remediation SSM document.

---

## Evidence pack

`GET /v1/exports/evidence-pack?framework=soc2&account_id=<id>&period=90`

Returns a ZIP bundle:

```
vigil-evidence-soc2-2026-05-26.zip
  README.txt
  INDEX.csv
  checksum_manifest.json
  pack_signature.json          ← when EVIDENCE_PACK_SIGNING_KEY is set
  vault_upload_plan.json       ← when EVIDENCE_VAULT_S3_URI is set
  vault_upload_result.json     ← when EVIDENCE_VAULT_ENABLED (immutable S3 copy)
  access_roster.json           ← IAM + Identity Center users as of period end
  iam_history.json             ← point-in-time IAM snapshot entities
  controls/
    CC6.1/
      summary.json       ← status, finding count, exception count
      findings.json      ← open findings with evidence
      exceptions.json    ← approved exceptions (reason, approver, expiry)
    CC6.2/ …
    CC7.1/ …
```

**Sample pack** (no auth, no account needed):

`GET /v1/exports/sample-evidence-pack?framework=soc2`

---

## Checks (53 total)

### AWS (36 checks)

| Category | Checks |
|---|---|
| IAM root | no MFA, has access keys, root activity |
| IAM users | no MFA, inactive 90d |
| IAM access keys | unused 90d, no rotation 90d, multiple active |
| IAM roles | unassumed 90d, wildcard action, unused services 90d, trust wildcard, granted vs used |
| IAM policies | wildcard resource, unattached managed policies |
| S3 | public access (bucket + account), no HTTPS policy, no KMS, no logging |
| KMS | no rotation |
| CloudTrail | not enabled, no log validation, no KMS |
| GuardDuty | not enabled |
| EC2 / VPC | unrestricted SSH/RDP, default SG allows traffic, no flow logs, IMDSv2, EBS unencrypted, EBS default encryption |
| RDS | publicly accessible, no encryption, no automated backup |
| AWS services | Config not enabled, Security Hub not enabled, Access Analyzer not enabled, weak password policy |

### GitHub (8 checks)

`github.org.mfa_not_enforced` · `github.org.dormant_members` · `github.org.outside_collaborators` ·
`github.repo.no_branch_protection` · `github.repo.self_merge_allowed` · `github.repo.insufficient_reviews` ·
`github.repo.no_env_protection`

### GitLab (5 checks)

`gitlab.org.mfa_not_enforced` · `gitlab.org.dormant_members` ·
`gitlab.repo.no_branch_protection` · `gitlab.repo.self_merge_allowed` · `gitlab.repo.insufficient_reviews`

---

## Frameworks covered

| Framework | Controls |
|---|---|
| SOC2 TSC (CC6, CC7, CC8) | CC6.1 – CC6.8, CC7.1 – CC7.2, CC8.1 |
| CIS AWS Foundations (selected) | ~22 mapped controls (e.g. 1.4–3.8); not full CIS v5 benchmark parity |
| ISO 27001 Annex A | A.9, A.10, A.12, A.13 |

---

## Key features

**"What If?" / Control Impact tab**
Before remediating, see what depends on a resource: service usage, last-accessed data, blast radius, policy diff (before/after). Confidence score based on 90-day activity window. Available for all automated checks in the registry (~80+).

**Exception workflow**
Flag a finding as a formal documented exception: reason, approver, expiry date. Exceptions appear in evidence packs — auditors see them alongside open findings. Separate from snooze (which is operational deferral, not formal approval).

**History** (`/history`) — compliance timeline with per-snapshot infrastructure event drill-down; `/timeline` redirects here
- **Activity Log** — CloudTrail infrastructure writes from scans; filtered by default to compliance-relevant sources (IAM, S3, EC2, KMS, …). Toggle **Include operational noise** for SSM/Lambda churn.
- **History** — posture improvements/regressions and collapsed no-change scan periods per framework (SOC2 / CIS / ISO), from `GET /v1/accounts/{id}/compliance-timeline`.
- GitHub/GitLab change evidence stays in compliance packs and integration sync — not on the activity log page.

**Findings drawer**
- Tabs: Overview, Resources, Compliance, Remediation, What If (when supported).
- Opening a finding lands on **Overview**; switching resources in a group keeps your current tab.
- **Remediation**: Console | CLI | Terraform | Automation in one panel.
- **Verify** re-runs the check; if the issue is gone, the finding moves to **Resolved** automatically (no manual “mark resolved”).
- **Reopen** on resolved/ignored findings.

**Scan progress**
Accounts page shows real worker step progress (`progress_step` / `progress_total`) from the API — no misleading time-remaining estimate.

**Evidence freshness**
Every evidence item is timestamped with collection time and source API. Evidence packs include raw JSON from AWS/GitHub/GitLab APIs.

---

## Remediation (read-only scanning + optional customer automation)

Vigil scanning is read-only. If you explicitly enable remediation modules, approved fixes run through customer-owned SSM Automation with scoped permissions. Remediation paths:

| Path | What it does |
|------|----------------|
| **Console / CLI** | Step-by-step copy in the finding drawer (resource names interpolated). |
| **Terraform** | Declarative snippets for **S3 / KMS** only — not security groups (no `null_resource` / local-exec). |
| **Version-control PR** | `POST …/iac/repo-scan` scans repo `.tf`/`.hcl`; `POST …/iac/terraform-pr` opens PR for **S3 PAB** and **KMS rotation** when hclpatch finds an exact resource block. SG: scan shows file/line — fix via SSM Automation. |
| **SSM Automation** | Customer deploys [`infra/cfn/vigil-remediation-ssm.yaml`](infra/cfn/vigil-remediation-ssm.yaml); Vigil plan v2; `POST .../remediation/dispatch` starts SSM Automation when scoped permissions are enabled, with a CLI fallback. |

**Security group checks** (`ec2.security_group.unrestricted_ssh` / `unrestricted_rdp`):
- Collector flags port-specific public ingress (22 / 3389) and **all-traffic** `0.0.0.0/0`; findings include `exposing_rules` in evidence.
- Remediation: **Console, CLI, SSM Automation** — the document revokes `exact_match_rules` only; fixed customer IAM role.
- Plan v2: `resource_region`, `execution.runner_type=ssm`, `expires_at`, `content_sha256`, optional Ed25519 signature via `POST /v1/findings/{id}/remediation/dispatch`.

**APIs**

| Endpoint | Purpose |
|----------|---------|
| `GET /v1/findings/{id}/iac-snippets` | Terraform + apply paths |
| `GET /v1/findings/{id}/remediation-plan` | Signed plan for customer executor |
| `POST /v1/findings/{id}/remediation/dispatch` | SSM Automation payload + `start-automation-execution` CLI |
| `POST /v1/findings/{id}/iac/terraform-pr` | Repo-aware GitHub PR (S3 checks; requires connected GitHub) |
| `GET /v1/accounts/{id}/remediation-runner/status` | Read-only: SSM Automation document check before execution |
| `POST /v1/findings/{id}/iac/repo-scan` | Scan GitHub repo for matching Terraform resources |
| `GET /v1/findings/{id}/remediation-execution` | Dispatch / optional completion status by `plan_id` |
| `POST /v1/findings/{id}/recheck` | Verify — targeted re-collect + re-run one check |
| `POST /v1/findings/{id}/reopen` | Move resolved/ignored finding back to open |

Full runbook: [docs/remediation-automation.md](docs/remediation-automation.md).

**Roadmap:** GitLab MR; SG repo-aware Terraform PR; optional SSM execution callback keyed by `plan_id`.

---

## AWS permissions

Deployed via [`infra/cfn/vigil-readonly-role.yaml`](infra/cfn/vigil-readonly-role.yaml).

**Read-only. No write permissions. Ever.**

Base role is strictly **Read / List / Describe** access-level. Key actions: `iam:Get*` / `iam:List*` · `iam:GenerateServiceLastAccessedDetails` / `iam:GetServiceLastAccessedDetails` (read access reports; no mutation) · `s3:GetBucket*` · `s3:ListAllMyBuckets` · `kms:Describe*` / `kms:List*` · `cloudtrail:Describe*` / `cloudtrail:LookupEvents` · `guardduty:List*` / `guardduty:Get*` · `ec2:Describe*` · `rds:Describe*` · `access-analyzer:ListAnalyzers` · `config:Describe*` · `securityhub:Describe*` · `sts:GetCallerIdentity`.

The Write access-level IAM Access Analyzer **policy-generation** actions (`StartPolicyGeneration` / `GetGeneratedPolicy` / `ListPolicyGenerations` / `CancelPolicyGeneration`) are **not** in the base role. They live in an optional separate role `*AdvancedPolicyGen`, created only when `EnableAdvancedPolicyGeneration=Yes` — enable it only if you want Vigil's Advanced least-privilege policy generation. A second optional role `*AccessAnalyzerMonitor` (Access Analyzer service principal) grants CloudTrail S3 read during policy generation.

The role uses `ExternalId` (confused-deputy protection). Only `TRUST_PRINCIPAL_ARN` can assume it.

---

## Pricing

| Tier | Price | Includes |
|---|---|---|
| Free | $0 | 1 account, weekly scan, no exports, 30d retention |
| Starter | $99/mo | All AWS checks, evidence exports (JSON+CSV+PDF), 90d snapshots |
| Team | $249/mo | + GitHub + GitLab, 365d snapshots, ZIP bundle, up to 5 accounts |
| Growth | $499/mo | + multi-account orgs, Slack, custom controls |

7-day trial. No credit card required to start. SOC2 Type 2 requires continuous evidence across the audit period — one scan is one day of evidence. Daily scanning = 365 date-stamped evidence points per year.

---

## Architecture

```
api/
  app/
    core/         config, db, security, aws (sts), passwords, encryption
    models/       SQLAlchemy 2.0 tables
    routes/       auth, auth_oauth, accounts, findings, controls, exports, settings, integrations
    collectors/   boto3 → DB upserts (iam, s3, kms, ec2, rds, vpc, cloudtrail, cloudtrail_events, sg_ingress, ...)
    checks/       pure functions → FindingDraft (registry, persist — auto-resolve on recheck)
    services/     evidence_pack, pdf_report, github_sync, gitlab_sync,
                    iac_snippets, remediation_plan, remediation_dispatch, remediation_iam
    worker/       celery_app + tasks (run_scan, scan_all_accounts, recheck_finding, send_weekly_digests)
  migrations/     Alembic (0001 → 0031)
web/              React + Vite + Tailwind + TanStack Query
                  pages: Findings, Activity log, Compliance timeline, Controls, Accounts, …
tools/
  hclpatch/       Go HCL patcher for repo-aware Terraform PRs (S3 checks)
infra/
  cfn/            vigil-readonly-role.yaml
                  vigil-remediation-ssm.yaml          ← SG/SSM remediation (SSM Automation)
docs/             remediation-automation.md, evidence-vault.md
compose.yml
```

---

## Auth

- Email + password (bcrypt + sha256 prehash)
- GitHub OAuth (login + connect for evidence)
- Google OAuth (login)
- JWT access tokens (24h) + refresh tokens (30d, auto-retry on 401)

---

## Release readiness

Shipped in-repo (narrow technical / design-partner launch):

| Item | Status |
|------|--------|
| **Evidence classification** | `benchmark` / `supporting` / `hygiene` on checks; `check_evidence_classes.json` in ZIP; Detection coverage legend |
| **Root pass-state snapshots** | `account_summary` entity per scan (`GetAccountSummary` for `iam.root.*`) |
| **CIS honesty** | `cis_benchmark_coverage.json` in CIS packs; PDF meta shows mapped vs CIS v5 L1 total (40) |
| **Pack integrity** | `checksum_manifest.json` — SHA-256 per artifact (manifest not self-hashed) |
| **CI** | `.github/workflows/ci.yml` — API tests, frontend build, gitleaks, no tracked `.env` |
| **Historical packs** | Control status at `as_of` from finding events; benchmark-only fail; roster from snapshots |
| **Coverage honesty** | `days_with_data` = union of successful scan days + snapshot days (not elapsed since first scan) |
| **Activity Log** | Multi-region CloudTrail; compliance filter + operational-noise toggle; `/timeline` |
| **History** | `/history` + `GET /v1/accounts/{id}/compliance-timeline` |
| **Scan progress** | Worker `progress_step` / `progress_total` on latest scan run; UI shows steps (no ETA) |
| **Finding lifecycle** | Verify → auto-resolve via `recheck_finding`; reopen endpoint; no manual resolve in UI |
| **IaC three-tier model** | S3/KMS snippets; SG = Console/CLI/SSM Automation only; GitHub PR for S3 (hclpatch + validate) |
| **Remediation v2** | Plan signing, automation vs resource region, exact-match SSM Automation, status API |
| **Evidence vault upload** | Object Lock `PutObject` on export when `EVIDENCE_VAULT_ENABLED` + `EVIDENCE_VAULT_S3_URI` |
| **SG ingress evidence** | `public_exposure` on security groups; `exposing_rules` on findings |

### Deepsearch v3 alignment (architecture review)

Most of [deepsearch/v3.txt](deepsearch/v3.txt) **phase 1–2 and navigation (phase 5)** are in the repo. Not everything is “exact” — gaps are intentional deferrals:

| v3 recommendation | Status |
|-------------------|--------|
| Remediation plan v2 (expiry, bus/resource region, `exact_match_rules`, signature) | **Done** |
| Customer-owned automation in home region, EC2 in `resource_region` | **Done** |
| SSM document validates schema + supported `check_id`s + `execution.runner_type` | **Done** |
| No fake SG Terraform; SG = automation-only | **Done** |
| Go **hclpatch** — scan `.tf`/`.hcl`, match resource by name/attrs, patch file | **Partial** — PR patch: **S3 PAB + KMS rotation**; **scan** also finds **security groups** (manual/SSM Automation to fix) |
| Repo-aware PR | **Partial** — `POST …/iac/repo-scan` then `…/iac/terraform-pr` when `can_patch` |
| Evidence vault: WORM upload per `report_id` | **Partial** — export upload + presigned; auditor approval UI still open |
| Activity log + compliance timeline + noise toggle | **Done** |
| Activity log → related open findings | **Done** (token overlap on resource names/ARNs) |
| Customer-owned SSM Automation document | **Done** — [`infra/cfn/vigil-remediation-ssm.yaml`](infra/cfn/vigil-remediation-ssm.yaml) |
| Execution per `plan_id` | **Partial** — dispatch is recorded; SSM output remains in customer account unless a callback is added |
| `noindex` on app shell | **Done** |
| Move long-form reference to external docs site | **Not done** |

Still manual / planned (not blockers for first design partners):

| Item | Notes |
|------|--------|
| **Auditor share workflow** | Vault presign works; no “approve auditor → link for `report_id`” product flow yet |
| **Cryptographic pack signing** | Set `EVIDENCE_PACK_SIGNING_KEY` — `pack_signature.json`; public key at `GET /v1/meta/evidence-pack-signing-key` |
| **Full CIS v5 parity** | `cis_v5_level1_matrix.json`; ~24 core-mapped in Compliance |
| **IAM history UI** | `GET /v1/accounts/:id/iam-history?as_of=` + pack JSON only |
| **SSM Automation** | `runner_type: ssm` — same plan schema |
| **GitLab MR + broader Terraform PR** | GitHub S3 PR only; SG/KMS repo patches later |
| **Control copy template** | Standardize Controls UI blocks |
| **Narrative audit automation** | Script: narrative ↔ `check_id` registry |
| **Production deploy** | Your hosting + backups + secrets rotation |

### Deepsearch v4 alignment (architecture review)

See [`docs/deepsearch-v4-map.md`](docs/deepsearch-v4-map.md) for the full feature matrix. IAM policy generator / last-accessed behavior: [`docs/policy-generator-iam-last-accessed.md`](docs/policy-generator-iam-last-accessed.md). Summary:

| v4 recommendation | Status |
|-------------------|--------|
| SSM Automation remediation (not Terraform local-exec) | **Done** |
| Signed plan v2 + exact-match SG rules | **Done** |
| `approval` on dispatched plan (`token`, `approved_by`, `approved_at`) | **Done** (dispatch only; preview plan unchanged) |
| Evidence vault Object Lock upload | **Done** when `EVIDENCE_VAULT_ENABLED` |
| Export row vault metadata (`report_id`, S3 URI, version, lock mode) | **Done** (migration 0034) |
| AWS-owned SSM runbook expansion | **Partial** — catalog exists; wire parameters per check before enabling |
| Auditor approve → share UI | **Gap** |
| Repo-aware Terraform beyond S3/KMS patch | **Partial** |
| Docs said vault “scaffold only” | **Fixed** — code was ahead of docs |

**Other planning docs:** day-to-day scope and session history live in [`HANDOFF.md`](HANDOFF.md) (roadmap, working agreements, per-session shipped lists). Product constraints are summarized in [`CLAUDE.md`](CLAUDE.md). Remediation runbook: [`docs/remediation-automation.md`](docs/remediation-automation.md). Vault design: [`docs/evidence-vault.md`](docs/evidence-vault.md).

**Ops hygiene:** Never distribute repo archives with `.env` / `.env.prod`. Use `git archive` or CI artifacts. Rotate any secret that ever appeared in a shared ZIP.

---

## Public site files (`web/public/`)

Served at the web app root (Vite `public/`):

| File | Purpose |
|------|---------|
| `llms.txt` | Product summary for LLM crawlers |
| `robots.txt` | Crawl rules (app routes disallowed; `/login`, `/security` allowed) |
| `sitemap.xml` | Public URLs only — update `SITE_BASE` in file when the production hostname changes |

Default canonical host in sitemap: `https://vigil.cclab.cloud-castles.com`.

---

## License

Source closed.
