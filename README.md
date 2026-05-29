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
| Correlates AWS + GitHub/GitLab into a change timeline | Write to your AWS account (read-only, always) |
| Shows blast radius before you remediate a finding | Generate AI summaries in evidence outputs |
| Documents exceptions with approver + reason + expiry | Run agents or auto-remediate |

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
2. **AWS Accounts** → name it → **Create**.
3. Click **Launch CloudFormation stack** — template URL, ExternalId, and trust principal are pre-filled.
4. Deploy the stack in the customer's AWS console → copy `RoleArn` output.
5. Paste ARN → **Verify**. Vigil calls `sts:AssumeRole` to confirm trust + ExternalId.
6. First scan triggers automatically. Findings appear in ~1–3 min.

---

## Evidence pack

`GET /v1/exports/evidence-pack?framework=soc2&account_id=<id>&period=90`

Returns a ZIP bundle:

```
vigil-evidence-soc2-2026-05-26.zip
  README.txt
  INDEX.csv
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
Before remediating, see what depends on a resource: service usage, last-accessed data, blast radius, policy diff (before/after). Confidence score based on 90-day activity window. Available for all 53 checks.

**Exception workflow**
Flag a finding as a formal documented exception: reason, approver, expiry date. Exceptions appear in evidence packs — auditors see them alongside open findings. Separate from snooze (which is operational deferral, not formal approval).

**Change timeline**
CloudTrail infrastructure events correlated with GitHub PR merges within ±60 minutes. Supports the killer SOC2 CC8.1 story: "Security group opened at 14:32 → PR #347 merged at 14:28 by alice, approved by bob."

**Evidence freshness**
Every evidence item is timestamped with collection time and source API. Evidence packs include raw JSON from AWS/GitHub/GitLab APIs.

---

## AWS permissions

Deployed via [`infra/cfn/hygiene-readonly-role.yaml`](infra/cfn/hygiene-readonly-role.yaml).

**Read-only. No write permissions. Ever.**

Key actions: `iam:Get*` / `iam:List*` · `iam:GenerateServiceLastAccessedDetails` · `s3:GetBucket*` · `s3:ListAllMyBuckets` · `kms:Describe*` / `kms:List*` · `cloudtrail:Describe*` / `cloudtrail:LookupEvents` · `guardduty:List*` / `guardduty:Get*` · `ec2:Describe*` · `rds:Describe*` · `access-analyzer:List*` · `config:Describe*` · `securityhub:Describe*` · `sts:GetCallerIdentity`

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
    collectors/   boto3 → DB upserts (iam, s3, kms, ec2, rds, vpc, cloudtrail, cloudtrail_events, ...)
    checks/       pure functions → FindingDraft (53 checks, registry, persist)
    services/     evidence_pack, pdf_report, github_sync, gitlab_sync
    worker/       celery_app + tasks (run_scan, scan_all_accounts, send_weekly_digests)
  migrations/     Alembic (0001 → 0022)
web/              React + Vite + Tailwind + TanStack Query
infra/cfn/        hygiene-readonly-role.yaml
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
| **CI** | `.github/workflows/ci.yml` — Postgres + Redis + `pytest` on push/PR |

Still manual / planned (not blockers for first design partners):

| Item | Notes |
|------|--------|
| **Long-term evidence vault** | Scaffold: `EVIDENCE_VAULT_S3_URI` + `api/app/services/evidence_vault.py` (not wired). See [docs/evidence-vault.md](docs/evidence-vault.md) |
| **Cryptographic pack signing** | Set `EVIDENCE_PACK_SIGNING_KEY` — packs include `pack_signature.json` (Ed25519 over `checksum_manifest.json`); public key at `GET /v1/meta/evidence-pack-signing-key` |
| **Full CIS v5 parity** | `cis_v5_level1_matrix.json` lists all 40 L1 controls with automated / partial / extended / manual status; ~24 core-mapped in Compliance |
| **IAM history UI** | `GET /v1/accounts/:id/iam-history?as_of=` + Timeline panel (snapshot-based roster) |
| **Control copy template** | Standardize Controls UI blocks: objective → collected → period → findings → exceptions → manual gaps |
| **Narrative audit automation** | Script: narrative sentence ↔ `check_id` / snapshot type registry |
| **Production deploy** | Your hosting choice + nightly DB backups + secrets rotation |

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
