# Cloud Hygiene — Handoff

Status as of initial scaffold commit. MVP target: 1 AWS account per org, 3 IAM checks, weekly digest, paid monthly per-account.

---

## ✅ Done (Week 1 scaffold)

### Infra
- `compose.yml` — api, worker, db (postgres 16), redis, web, caddy (prod profile only)
- `.env.example`, `.gitignore`
- `caddy/Caddyfile` (reverse proxy `/api/*` → api, `/` → web)
- `api/Dockerfile`, `web/Dockerfile`

### Backend (FastAPI)
- `app/main.py` — app entry, CORS, healthz, router registration
- `app/core/config.py` — pydantic-settings (env)
- `app/core/db.py` — SQLAlchemy 2.0 engine + session
- `app/core/security.py` — JWT issue + bearer dep
- `app/core/aws.py` — `assume_role` + `verify_account`
- `app/routes/auth.py` — signup, login → JWT
- `app/routes/accounts.py` — create, list, verify, trigger scan
- `app/routes/findings.py` — list, snooze, resolve, ignore

### Models + migration
- `app/models/{org,aws_account,iam,finding}.py`
- `migrations/versions/0001_init.py` — full schema

### Collectors
- `app/collectors/iam.py` — users, MFA, console password, access keys + last-used (paginated, upserts)

### Checks
- `app/checks/base.py` — `FindingDraft` + risk score helper
- `iam_user_inactive.py` (90d)
- `iam_access_key_unused.py` (90d)
- `iam_user_no_mfa.py`
- `registry.py` — `ALL_CHECKS`
- `persist.py` — diff-aware: open new, refresh existing, auto-resolve missing, auto-reopen

### Worker
- `app/worker/celery_app.py` — Celery + Redis, daily beat 06:00 UTC
- `app/worker/tasks.py` — `run_scan`, `scan_all_accounts`

### Frontend (React + Vite + Tailwind + TanStack Query)
- `Login.tsx` (signup/login toggle)
- `Layout.tsx` (auth guard + nav)
- `Accounts.tsx` (create, CFN launch link, paste ARN, verify, scan)
- `Findings.tsx` (filter by status, severity chips, snooze/resolve/ignore)
- `api.ts` — fetch wrapper with bearer token

### CFN
- `infra/cfn/hygiene-readonly-role.yaml` — read-only role with ExternalId, SecurityAudit + ViewOnlyAccess + custom report perms

### Docs
- `README.md` — quickstart, architecture, IAM perms, checks table

---

## 🔧 Required before first run (user actions)

1. **Set `TRUST_PRINCIPAL_ARN`** in `.env` — ARN of control-plane AWS account/role that will assume customer roles. (e.g. `arn:aws:iam::YOUR_ACCT:root` to start; tighten to specific role later.)
2. **Set strong `JWT_SECRET`** and `APP_SECRET` in `.env`.
3. **Confirm CFN template URL** in `api/app/routes/accounts.py` (`CFN_TEMPLATE_URL`) points at correct branch — currently `main`.
4. Bring stack up:
   ```bash
   cp .env.example .env
   docker compose up -d db redis
   docker compose run --rm api alembic upgrade head
   docker compose up api worker web
   ```

---

## 🚧 Left to do

### P0 — blockers to first paying customer

- [ ] **Stripe billing** — Checkout + customer portal, trial → monthly per-account sub, webhook to set `orgs.plan`
- [ ] **Weekly digest email** (Resend) — Monday 9am org TZ, summary of open findings, delta vs last week, CTA link
- [ ] **Onboarding empty states + first-scan UX** — progress feedback during 1–3 min scan (poll `scan_runs` or SSE)
- [ ] **Production deploy** — Hetzner VPS, domain, Caddy auto-TLS, Postgres backup to B2, prod `compose.yml` overrides, systemd unit or compose `restart: always`
- [ ] **Verify CFN flow end-to-end** with real sandbox AWS account (assume role works, perms sufficient)

### P1 — MVP polish

- [ ] **CSV export** of findings (`GET /v1/exports/findings.csv`)
- [ ] **PDF monthly report** (weasyprint or reportlab) — same data as digest, downloadable
- [ ] **Finding detail drawer** — full evidence JSON, history (FindingEvent list), remediation snippets (CLI/Terraform tabs)
- [ ] **Account deletion + role re-test** — UI button to re-verify role anytime
- [ ] **Org TZ + email pref** on user/org model
- [ ] **Slack webhook delivery** for digest
- [ ] **Rate limit + retry on collectors** (boto3 already retries; surface throttle errors to scan_run.error)
- [ ] **Pagination on `/v1/findings`** (currently returns all rows for org)
- [ ] **Audit log table** for account/role assumption events
- [ ] **Sentry** wiring (api + worker)

### P1 — security hardening

- [ ] Encrypt `aws_accounts.role_arn` and `external_id` at rest (pgcrypto or libsodium)
- [ ] Rotate `external_id` capability (regen + CFN re-deploy flow)
- [ ] CSP + secure cookie flags + HSTS on Caddy
- [ ] Refresh-token flow (currently 24h JWT, no refresh)
- [ ] Password complexity + breach-check (have-i-been-pwned k-anonymity API)
- [ ] Public `/security` page documenting perms + retention

### P2 — next checks (after MVP validates)

- [ ] `iam.root.usage` — CloudTrail root events
- [ ] `iam.role.unassumed_90d` — needs role last-assumed (from GenerateServiceLastAccessedDetails or CT)
- [ ] `iam.policy.unattached`
- [ ] `iam.policy.wildcard_action` (`*:*` or `service:*`)
- [ ] `iam.policy.wildcard_resource`
- [ ] `iam.role.trust_wildcard` — `"Principal": "*"` or `"AWS": "*"`
- [ ] `iam.perm.granted_vs_used` — diff Access Analyzer / SLA report against attached policy actions

### P2 — collectors for above
- [ ] `app/collectors/roles.py` — list_roles + GenerateServiceLastAccessedDetails per role
- [ ] `app/collectors/policies.py` — list_policies + get_policy_version + ListEntitiesForPolicy
- [ ] `app/collectors/access_analyzer.py` — pull unused findings if analyzer exists

### Phase 2 (post-MVP)

- [ ] Multi-account via AWS Organizations StackSet
- [ ] S3 hygiene checks (public, encryption, logging, TLS-only)
- [ ] ACM cert expiry
- [ ] Secrets Manager rotation drift
- [ ] CloudTrail/Config/GuardDuty presence checks
- [ ] EIP/SG/EBS unused
- [ ] Tag/ownership inference
- [ ] Terraform remediation diff (GitHub App)
- [ ] Jira/Linear push
- [ ] Kubernetes (RBAC, cert-manager, exposed services)

---

## ⚠️ Known gaps / shortcuts

- **CORS** is `*` in dev — locked to `API_PUBLIC_URL` in prod via `APP_ENV`.
- **No tests** yet. Add pytest with botocore stubber for collectors, plain unit tests for checks.
- **Findings table missing index on `(org_id, status, risk_score)`** — fine until ~50k rows.
- **No request-id / structured logging middleware** — only structlog imported in worker.
- **One account per org** is enforced in `routes/accounts.py:create_account` — change when ready to expand.
- **CFN template lives in repo `main`** — if customer launches stack and you force-push or rename, their launch URL breaks. Pin a release tag once stable.
- **Risk score** is intentionally crude; needs tuning after seeing real data.
- **No `org_id` propagation** to `IamUser`/`IamAccessKey` — they hang off `account_id`. Fine because `aws_accounts.org_id` enforces tenancy, but watch when joining.

---

## 🗺️ Recommended next 2 weeks

**Week 2 (revenue path):**
1. Stripe Checkout + customer portal + webhook
2. Resend weekly digest job (celery beat Monday 09:00 per-org TZ)
3. First end-to-end test against real AWS sandbox
4. Deploy to Hetzner + domain + TLS

**Week 3 (retention):**
5. Finding detail drawer with remediation tabs (Console / CLI / Terraform)
6. CSV + PDF export
7. Slack webhook
8. Add 2 more checks: `policy.wildcard_action`, `role.trust_wildcard`

After week 3 → start outbound to 10 friendly DevOps / platform leads for trial.

---

## 📂 Repo

https://github.com/awakzdev/cloud-hygiene

Initial commit: `feat: initial scaffold for Cloud Hygiene MVP`
