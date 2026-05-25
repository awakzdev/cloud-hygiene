# Cloud Hygiene — session context

This file is auto-loaded by Claude Code on every session. Read it before doing anything.

## What this is

Continuous cloud compliance evidence SaaS for startup engineering teams. Read-only. Connect AWS → daily scan → ranked findings → auditor-ready evidence pack (ZIP + PDF) → weekly digest. Killer feature: one-click evidence pack auditors can sample by date.

**Not** a CSPM (Wiz/Prisma) or GRC suite (Vanta/Drata). Focus: evidence quality, stale access, over-permissive IAM, SOC2/CIS compliance mapping.

## Constraints (do not violate)

- AWS only (no GCP/Azure/k8s in MVP)
- Read-only — CFN role has exact actions enumerated (no SecurityAudit/ViewOnlyAccess)
- One AWS account per org in MVP (schema is multi-account ready)
- Solo founder, Docker Compose, no microservices, no k8s
- FastAPI + Postgres + Celery + React + Tailwind + TanStack Query
- Hetzner VPS + Cloudflare + Caddy auto-TLS for prod
- Pricing: per-account monthly subscription + free trial

## Architecture

```
caddy → api (FastAPI :8000)  →  postgres
       → web (React :5173)        ↑
                                  ↓
                       worker (Celery + beat) ─→ sts:AssumeRole → customer AWS
                                  ↑
                                redis
```

## Repo layout

```
api/
  app/
    core/       config, db, security, aws (sts), passwords
    models/     SQLAlchemy 2.0 tables
    routes/     auth, accounts, findings
    collectors/ boto3 → DB upserts (IAM only so far)
    checks/     pure functions → FindingDraft, registry, persist
    worker/     celery_app + tasks (run_scan, scan_all_accounts)
  migrations/   Alembic (0001_init has full schema)
web/            React + Vite + Tailwind + TanStack Query
infra/cfn/      hygiene-readonly-role.yaml (ExternalId + SecurityAudit + extras)
caddy/          Caddyfile (prod profile)
compose.yml
README.md
HANDOFF.md      detailed status + roadmap (read this for scope)
```

## What works today

- Signup / login (JWT, bcrypt + sha256 prehash — passlib removed due to bcrypt 4.x bug)
- GitHub OAuth + Google OAuth (login + connect/disconnect from Account settings)
- Account settings page: change/set password (SSO-aware), GitHub connect/disconnect
- Create AWS account → CFN launch URL (pre-filled ExternalId + control plane principal)
- Verify role via `sts:AssumeRole`; CFN role has exact actions enumerated (no wildcards)
- Trigger scan → Celery task; re-scan unlocks after 5 min if stuck
- Collectors: IAM users + console password + MFA + access keys + last-used + service last-accessed per role + S3 buckets + KMS keys
- 16 checks across IAM root/users/access keys/roles, S3, KMS (see HANDOFF.md for full list)
- Risk scoring (severity base + age + admin); diff-aware persist (open/refresh/resolve/reopen)
- Findings UI: multi-tag filter with autocomplete + URL-synced `?checks=` param, grouped by check, stat cards, snooze/resolve/ignore
- Finding detail drawer: evidence, Console/CLI remediation, generate least-privilege policy
- Controls/Compliance page: SOC2 + CIS AWS L1 frameworks, pass/fail/no_data per control, evidence pack download (ZIP + PDF)
- Settings page: per-check enable/disable, weekly digest toggle + recipient email
- Weekly email digest via Resend (Celery beat Monday 9am UTC); configurable recipient; test button; `RESEND_API_KEY` + `DIGEST_FROM` in `.env`
- Evidence snapshots per scan run (IAM users, keys, roles, S3, KMS)
- Fernet encryption for `role_arn` + `external_id` at rest
- Cursor pagination on `/v1/findings`; CSV export
- 16 pytest tests passing (botocore Stubber collectors + check unit tests)
- Hot reload: uvicorn --reload (api), watchfiles (worker), Vite HMR (web)
- Service-linked roles excluded from all checks

## Primary differentiator: "What If" blast radius analysis

**This is the key feature that separates Vigil from Orca, Wiz, Checkmarx, Prisma, and every CSPM/CNAPP tool.** They flag findings. Nobody shows what breaks if you actually remediate. Engineers don't fix IAM debt because they're afraid of breaking prod — Vigil removes that fear.

Feature: "What If I fix this?" drawer tab per finding:
- Blast radius — what principals/services depend on this resource right now
- Used vs. unused actions — from `iam_perm_usage` table (data already exists)
- Policy diff — before/after if you scope down to least-privilege (reuses "Generate" button)
- Confidence score — "High confidence: no recorded usage in 90 days" vs. "Warning: used 3× recently"

See HANDOFF.md "Key differentiator: What If blast radius analysis" for full spec + build order.

## Next priorities

See HANDOFF.md for full roadmap.

Immediate unblocked work:
1. "What If" blast radius tab on IAM role findings (uses existing `iam_perm_usage` data — no new collectors needed)
2. Throwaway AWS sandbox with seeded junk (test the full flow end-to-end)
3. Hetzner deploy + domain + Caddy TLS + nightly pg_dump → B2

## Phase 2+ (not now)

GitHub integration (identity + change mgmt) → Google Workspace → Stripe billing → Slack webhook → multi-account AWS Orgs.

## Style + decisions

- Caveman mode: terse replies, fragments OK, drop articles/filler. Code/commits/security written normal.
- Commits: conventional + Co-Authored-By Claude footer
- No emojis in code/docs unless explicitly requested
- Diff-aware findings (don't recreate; reopen)
- Risk score must be hand-verifiable (no ML, no magic)
- "Snooze" first-class — customers will never resolve everything

## Quickstart

```bash
cp .env.example .env
# set TRUST_PRINCIPAL_ARN, JWT_SECRET
docker compose up -d db redis
docker compose run --rm api alembic upgrade head
docker compose up
# http://localhost:5173
```

## Known gaps / shortcuts

- CORS `*` in dev, locked in prod via APP_ENV
- One account per org enforced in route (schema is fine)
- CFN URL pinned to repo `main` — pin to release tag once stable
- No request-id / structured access logging
- `RESEND_API_KEY` in `.env` — rotate before prod; `onboarding@resend.dev` sender only delivers to verified Resend account email
- Digest unsubscribe links to `/settings` — no token-based one-click unsubscribe yet

## Repo

https://github.com/awakzdev/Vigil

Read `HANDOFF.md` for full status + 2-week roadmap. Read `README.md` for onboarding flow.
