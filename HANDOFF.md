# Vigil — Handoff

_Last updated: 2026-05-25_

---

## What works today

### Auth
- Email + password signup/login (JWT, bcrypt + sha256 prehash — passlib removed due to bcrypt 4.x bug)
- GitHub OAuth — login + connect/disconnect from Account settings
- Google OAuth — login
- Account settings page: change password / set password (SSO-aware — no current password field for SSO-only users), GitHub connect/disconnect
- SSO users with no password get "Set a password" flow; credential users get "Change password"

### AWS account onboarding
- Create account → CFN launch URL (pre-filled ExternalId + trust principal)
- Verify role via `sts:AssumeRole`
- Trigger scan → Celery task

### Collectors
- `collectors/iam.py` — IAM users, console password, MFA, access keys + last-used, roles + inline policies
- `collectors/last_accessed.py` — service last-accessed per role via AWS async job API (`generate_service_last_accessed_details`)

### Checks
| Check ID | Severity |
|---|---|
| `iam.user.inactive_90d` | medium |
| `iam.access_key.unused_90d` | high |
| `iam.user.no_mfa` | high |
| `iam.role.unassumed_90d` | medium |
| `iam.role.wildcard_action` | high |
| `iam.role.unused_services_90d` | medium |

### Findings UI
- Grouped by check type, sorted by severity
- Severity-tinted group headers, indented finding rows, first-seen date
- Summary stat cards (total / critical+high / medium / max score)
- Filter tabs: open / snoozed / resolved / all
- Snooze / resolve / ignore actions
- Finding detail drawer with evidence, remediation (Console + AWS CLI tabs), combined context block
- `unused_services_90d` drawer: unused service pills, removable inline policy statements, **"Generate" button** — calls `GET /v1/accounts/:id/roles/generated-policy` and shows cleaned vs original policy JSON side-by-side
- CLI commands auto-interpolate actual role/user/key names from the finding ARN
- Scan status polling (5s) + auto-refresh findings on completion; Re-scan unlocks after 5 min if stuck

### Frontend
- Login page: email/password + GitHub SSO + Google SSO
- AWS Accounts page
- Findings page (grouped, severity-aware)
- Account settings page (password + GitHub)
- Sidebar: Vigil logo, AWS Accounts, Findings, Account, Sign out

### Infra
- `compose.yml` — api, worker, db (postgres 16), redis, web, caddy (prod profile)
- Hot reload: uvicorn --reload (api), watchfiles (worker), Vite HMR (web)
- Migrations: 0001_init → 0002_iam_roles_inline_policies → 0003_user_mfa_github → 0004_iam_perm_usage

---

## Architecture reminder

```
Vigil worker (Account A / Hetzner)
  → sts.amazonaws.com  →  AssumeRole (customer's CFN role)
  → iam.amazonaws.com  →  read-only scan

Customer's VPC/firewall is irrelevant — IAM and STS are
AWS control-plane APIs, reachable via public HTTPS.
```

---

## P0 — blockers to first paying customer (in order)

- [ ] **Throwaway AWS sandbox** with seeded junk (inactive users, old keys, no-MFA users, wildcard policy, unassumed roles)
- [x] **Encrypt `role_arn` + `external_id` at rest** (Fernet/AES-128-CBC, migration 0008)
- [ ] **End-to-end test**: signup → CFN → verify → scan → findings populated
- [x] **Tighten CFN IAM** — drop `SecurityAudit` + `ViewOnlyAccess`, enumerate exact actions
- [x] **Scan progress UI** — poll `GET /v1/accounts/:id/scan-runs`, surface errors
- [ ] **Pagination on `/v1/findings`** (cursor + limit)
- [x] **CSV export** (`GET /v1/exports/findings.csv`)
- [x] **pytest skeleton** — botocore Stubber for collectors, unit tests for checks (16 passing)
- [ ] **Hetzner deploy** — domain, Caddy auto-TLS, nightly pg_dump → B2

---

## P1 — after P0

- [ ] Weekly digest email (Resend) — Monday 9am per-org TZ
- [ ] Stripe billing — Checkout + portal + webhook → `orgs.plan`
- [x] Finding detail drawer — evidence, Console/CLI remediation, auto-interpolated resource names
- [ ] **Generate Least-Privilege Policy** — `GET /v1/accounts/:id/roles/generated-policy` strips unused service statements from inline policies and returns cleaned JSON; Access Analyzer CloudTrail-based generation is future work (requires `accessRole` setup)
- [x] PDF compliance report (fpdf2, bundled in evidence pack ZIP)
- [ ] Slack webhook
- [ ] TOTP MFA (pyotp already in requirements)
- [ ] Refresh tokens (currently 24h JWT, no refresh)
- [ ] Account deletion + role re-verify button

---

## P1 — security hardening

- [ ] Encrypt `aws_accounts.role_arn` + `external_id` at rest
- [ ] CSP + secure cookie flags + HSTS on Caddy
- [ ] Password complexity + breach-check (have-i-been-pwned k-anonymity)
- [ ] Public `/security` page documenting permissions + retention

---

## P2 — next checks

- [ ] `iam.root.usage` — CloudTrail root events
- [ ] `iam.policy.unattached` — managed policies attached to nothing
- [ ] `iam.policy.wildcard_resource` — `Resource: "*"` on dangerous actions
- [ ] `iam.role.trust_wildcard` — `"Principal": "*"` in trust policy
- [ ] `iam.perm.granted_vs_used` — action-level (requires `Granularity=ACTION_LEVEL`, roles only)

## Phase 2

Multi-account via AWS Orgs StackSet · S3/cert/secret/Trail/Config checks · Terraform remediation diffs (GitHub App) · Kubernetes RBAC

---

## Known gaps / shortcuts

| Gap | Notes |
|---|---|
| CORS `*` in dev | locked to `API_PUBLIC_URL` in prod via `APP_ENV` |
| `role_arn` + `external_id` plaintext in DB | P0 #2 |
| No tests | P0 #8 |
| CFN URL pinned to repo `main` | pin to release tag before beta |
| Findings table missing index on `(org_id, status, risk_score)` | fine until ~50k rows |
| No request-id / structured access logging | add before prod |
| One account per org enforced in route | schema is multi-account ready |
| `last_accessed` collector is synchronous polling | ~1-3s per role; fine for MVP, throttle risk at 100+ roles |

---

## Repo

https://github.com/awakzdev/Vigil

---

# Strategic Pivot — May 2026

This section supersedes the roadmap above. After two rounds of external research
(GPT-5 and a second LLM analysis), the product positioning and build order have
been reset. The phases below replace P0/P1/Phase 2 from the original handoff.

## North-star metric: Time-to-evidence

Single sharpest product metric. Drives all design decisions.

**Target:** AWS account connected → first downloadable evidence pack in
under **10 minutes**.

Example happy path:
- T+0:00 customer signs up (Google/GitHub SSO, no email confirmation)
- T+1:30 reads sidebar, clicks "Connect AWS"
- T+3:00 launches pre-filled CloudFormation stack in customer console
- T+5:00 stack `CREATE_COMPLETE`, pastes role ARN, Verify succeeds
- T+5:30 first scan triggered automatically
- T+8:00 scan complete, findings visible, evidence pack downloadable

Any feature that pushes this past 10 minutes (manual approval flows,
multi-step billing walls, mandatory profile completion) must justify
itself against this metric. Use as a regression test for every product
decision.

## New positioning

**Old:** "AWS IAM hygiene tool for small teams."
**New:** **"Continuous cloud compliance evidence for startup engineering teams."**

**Secondary positioning lane (broader TAM):** *"Vigil shows you who
changed what in your AWS, when, and whether it was approved.
Compliance evidence is the side effect."* — attracts engineering-
accountability buyers who don't care about SOC2 today but will later.

Vigil is explicitly **not**:
- A CSPM (Wiz, Prisma, Orca). Coverage parity unwinnable solo.
- A compliance suite (Vanta, Drata, Secureframe, Sprinto). They're evidence
  aggregators with HR/MDM/policy/vendor breadth. We will never go there.
- A SIEM, an agent, or a remediation tool.

Vigil **is**:
- The technical evidence layer Vanta and Drata are shallow on
- Auditor-ready raw artifacts (timestamped, source-verifiable, traceable)
- Engineer-first, self-serve, no sales calls
- Initially AWS-only, then GitHub (identity + change mgmt), then Google Workspace

## Buyer

Engineering teams of 5–30. Heading into first SOC2 Type 2 audit. Can't afford
$10k–80k/yr Vanta. Currently doing it manually with Prowler + screenshots, or
not at all. They have a technical co-founder or platform engineer who values
depth over checkbox theater.

## Competitive landscape (memorize these)

| Vendor | Price (public/directional) | Category |
|---|---|---|
| **Drata** | $7.5k entry / $15k Growth / $25–80k Enterprise | Full GRC suite |
| **Vanta** | $10–80k+/yr quote-based | Full GRC suite |
| **Secureframe** | $12–20k/yr | Full GRC suite |
| **Sprinto** | ~$15k/yr | Full GRC suite |
| **LowerPlane** | $4,995/yr ($416/mo) | Lower-cost full suite |
| **Comp AI** | OSS / paid hosted | OSS AI-first suite |
| **Oneleet, Delve** | Quote-based, $10–30k/yr | Software + human advisory |

**Critical price reality:** LowerPlane at $416/mo for a *full* compliance
platform means Vigil at $200–500/mo AWS-only is in the wrong band. Either
go cheaper (below $200) or be radically better at evidence quality.

## Pricing (locked in this iteration)

| Tier | Price | Gates |
|---|---|---|
| Free | $0 | 1 AWS account, weekly scan, no exports, 30d retention |
| Starter | $99/mo or $999/yr | All AWS checks, evidence exports (JSON+CSV+PDF), weekly digest, 90d snapshots |
| Team | $249/mo or $2,499/yr | + GitHub + Google Workspace, 365d snapshots, ZIP evidence bundle, up to 5 accounts |
| Growth | $499/mo or $4,999/yr | + multi-account orgs, Slack delivery, custom controls, priority email |

**Why monthly/annual not one-shot:** SOC2 Type 2 requires continuous evidence
across a 3–12 month audit window. Auditor samples random dates and asks for
proof the control was in effect on that date. One scan = one date of evidence
= Type 2 audit failure. Scanner running daily = 365 date-stamped evidence
points per year. The recurring fee is justified by recurring evidence.

## Strategic decisions (locked, do not re-litigate)

| Decision | Choice |
|---|---|
| Audit workflows (policies, vendors, trust center, HR, training) | **Out of scope for the foreseeable roadmap.** Only reconsider if repeatedly demanded by paying customers. That swamp is Vanta's. Stay infra-heavy. |
| Identity evidence ingestion (Okta, Google Workspace, GitHub) | **YES.** Pull metadata only, never build an IdP. |
| Change management evidence (GitHub PR reviews, branch protections, deployments) | **YES via GitHub.** No Jira yet. |
| Multi-cloud (Azure, GCP) | **Defer to Year 2+.** Identity integrations give more SOC2 evidence per engineering hour than another cloud. |
| Kubernetes RBAC | **No.** Different buyer, different product. |
| Repo secret scanning (Gitleaks, Semgrep) | **No.** Different category, Snyk territory. |
| Write actions / auto-remediation | **No.** Read-only is the entire trust story. |
| Compliance frameworks to map | **CIS AWS L1, SOC2 CC6/CC7 first.** ISO 27001 A.9/A.12 second. Skip CC1/CC2/CC3/CC5/CC9 — can't evidence from AWS data. |

## The real moat: evidence quality, not check count

Both research rounds converged: **auditors don't care if the tool is famous.
They care that evidence is raw, timestamped, source-verifiable, traceable.**

This means the differentiator is NOT:
- More checks than Drata (unwinnable race)
- Prettier UI (table stakes)
- Cheaper price (race to bottom)

The differentiator IS:
- One-click auditor-ready evidence package per control
- Timestamped snapshots ("MFA was on for user X on 2026-04-17")
- Deep-links to AWS Console for visual verification
- Raw API responses preserved as JSON
- ZIP bundle: per-control folder with JSON + CSV inventory + PDF cover
- Cross-source correlation: SG opened → matched to PR #347 → approver Bob → deployment workflow xyz

That correlation story (AWS event ↔ GitHub PR ↔ approver) is rare in
the current market. Most compliance platforms expose these systems
separately rather than presenting them as a correlated engineering
timeline. The depth and UX of the correlation is where Vigil can lead.

### Historical diffing as moat reinforcement

Once snapshots exist (Phase 1), historical diffs become a second-order
differentiator that's genuinely hard for metadata-aggregator competitors
to replicate. Examples auditors and engineering managers care about:

- "MFA was disabled for alice 14:32–17:08 on 2026-04-17, then re-enabled.
  Window of exposure: 2h 36m."
- "Security group SG-abc opened to `0.0.0.0/0` on 22/tcp at 09:14, closed
  at 12:31. Open for 3h 17m."
- "S3 bucket `prod-customer-data` flipped to public for 47 minutes before
  remediation. Incident response evidence preserved."
- "RDS instance `db-prod-1` had `StorageEncrypted=false` from 2026-01-04
  to 2026-03-22 (78 days). Re-encrypted via snapshot+restore on 2026-03-22."

Vanta/Drata snapshot at scan cadence but rarely surface "state X existed
between time A and time B" in a way auditors can sample. That presentation
gap is the moat reinforcement.

## Revised phased roadmap

### Phase 0 — done
Auth, OAuth, 6 IAM checks, finding UI, scan engine, drawer with remediation,
account settings, finding lifecycle (open/snooze/resolve/ignore/reopen).

### Phase 1 — Evidence layer — COMPLETE ✓

Built 2026-05-25. All 4 weeks delivered in one session.

**Backend:**
- `evidence_snapshots` table — JSONB per entity per scan run (IAM users, access keys, roles, S3 buckets, KMS keys)
- `controls` + `check_controls` tables — seeded with 19 controls: SOC2 CC6.1–CC7.2, CIS AWS L1 1.4–3.8
- `GET /v1/controls?framework=soc2|cis_aws_l1` — live pass/fail/no_data per control
- `GET /v1/controls/:id/evidence?account_id=&period=90` — raw snapshots for a control
- `GET /v1/exports/evidence-pack?framework=&account_id=&period=90` → ZIP (README, INDEX.csv, per-control JSON, report.pdf)
- `GET /v1/exports/findings.csv` — flat CSV of all findings
- fpdf2-based PDF cover report (score bar, control table, failed-control detail)
- Idempotent seed on API startup via `lifespan` context

**Frontend:**
- `/controls` page — framework toggle (SOC2 / CIS AWS L1), summary bar (pass rate), expandable control list with guidance + check badges
- "Evidence Pack" download button — triggers ZIP generation + file save
- "Compliance" nav item (shield icon) between Findings and Settings
- migration `0007_controls_evidence.py` — run `alembic upgrade head` on next deploy

**Still needed before exit criteria:**
- Run `docker compose run --rm api alembic upgrade head` on next `docker compose up`
- Daily scan schedule (beat) — evidence only accumulates if scans run regularly
- Stripe gating — free tier should not allow evidence exports

**Exit criteria of Phase 1:** product is sellable to first design partner
even with only 6 checks. The evidence layer is the moat. ← ACHIEVED

### Phase 2 — AWS CIS L1 catch-up (4 weeks)

Add ~15 priority checks in this order:

1. Root account: MFA enforced, no access keys, recent usage (CloudTrail)
2. IAM password policy: length ≥14, reuse prevention, complexity
3. CloudTrail: enabled, multi-region, log file validation, KMS encrypted
4. AWS Config: enabled in all in-use regions
5. GuardDuty: enabled
6. Security Hub: enabled
7. S3: account-level Block Public Access, default encryption, HTTPS-only
   bucket policy
8. EBS: encryption by default, individual volume encryption
9. RDS: PubliclyAccessible=false, StorageEncrypted=true, AutomatedBackup
10. VPC Flow Logs: enabled at VPC level
11. Default Security Group: no inbound/outbound rules
12. Security Groups: no 0.0.0.0/0 on 22/3389/all
13. EC2: IMDSv2 required (HttpTokens=required)
14. Access Analyzer: enabled

Each ~1–2 days with existing scaffold. New collectors required:
EC2 / RDS / S3 bucket-config / CloudTrail-config / Config / GuardDuty /
SecurityHub services.

### Phase 3 — GitHub integration (3 weeks)

Single highest-leverage integration. Covers both identity (CC6) and change
management (CC7.1) in one shot. Most startups use GitHub.

**Identity side:**
- Org members (admins, outside collaborators)
- MFA enforced at org level + per-user MFA state
- Team membership
- Dormant members (no commits 90 days)

**Change side:**
- Branch protection per repo (required reviews, dismissal stale, force-push,
  required status checks, require code-owner review)
- Pull request merges: author, approver(s), review count, self-merge detection
- Protected environments + required reviewers
- Deployments (GitHub Actions workflow runs to environments)
- CODEOWNERS file coverage

**Tables:**
```sql
identity_providers(id, org_id, type, config_json_encrypted, status,
                   last_synced_at)
identity_users(id, provider_id, external_id, email, name, mfa_enabled,
               status, roles_json, last_active_at, snapshot_taken_at)
repos(id, provider_id, external_id, name, default_branch, snapshot_taken_at)
repo_protections(repo_id, branch, required_reviews, dismiss_stale,
                 require_code_owners, allow_force_push, snapshot_taken_at)
pull_requests(id, repo_id, number, author, merged_at, merged_by,
              required_review_count, approval_count, self_merge,
              snapshot_taken_at)
```

**Start with OAuth App, migrate to GitHub App later** (App gives webhooks +
fine-grained per-repo permissions, but takes longer to ship).

**Killer demo:** Phase 1 + Phase 3 = "Security group SG-abc opened to
0.0.0.0/0 at 14:32 (CloudTrail). Matched to PR #347 merged 14:28 by alice.
Approved by bob via required-review branch protection. Deployment workflow
xyz ran at 14:30." Few compliance platforms present these systems as a correlated engineering timeline with this level of technical depth.

### Phase 4 — Google Workspace (2–3 weeks)

OAuth + admin SDK + domain-wide delegation. Pull:
- Users (active, suspended, archived)
- 2-Step Verification enrollment per user
- Admin roles
- SSO configuration
- Last login activity

Covers MFA + deprovisioning for non-GitHub users. Most US/EU startups have
Google Workspace.

### Phase 5 — Billing + delivery (2 weeks)

- Stripe Checkout for plan upgrades
- Stripe customer portal for subscription mgmt
- Webhook → `orgs.plan` transitions
- Weekly digest email (Resend) — Monday 9am org TZ, top findings, delta
  vs last week, deep-link to evidence pack
- Slack webhook for digest delivery (Team tier+)

### Phase 6 — Production polish (2 weeks)

- Hetzner deploy: VPS + Caddy auto-TLS + Cloudflare
- Postgres nightly `pg_dump` → Backblaze B2
- Encrypt `aws_accounts.role_arn` + `external_id` at rest (pgcrypto)
- Audit log of every assume-role call
- pytest skeleton: botocore Stubber for collectors, unit tests for checks
- Pagination + cursor on `/v1/findings`
- Tighten CFN policy: drop `SecurityAudit` + `ViewOnlyAccess`, enumerate
  exact actions
- CSV export of findings

### Phase 1.5, 7+ — deferred until paying customers ask

- Okta integration (3–5 weeks; harder API)
- Entra ID + Azure
- GCP
- KMS key rotation deep checks
- Secrets Manager / SSM rotation
- Lambda function URL exposure
- Multi-account via AWS Organizations StackSet
- Custom controls (customer-defined checks)
- Vanta / Drata webhook integration (push findings as evidence)
- TOTP MFA on Vigil user accounts
- Refresh tokens

### Out of scope for the foreseeable roadmap

Reconsider only if repeatedly demanded by paying customers, never for
hypothetical buyers:

- Audit workflows (policies, vendor mgmt, trust center, HR)
- Kubernetes RBAC scanning
- Repository secret scanning (Gitleaks/Semgrep territory)
- Write actions, auto-remediation
- LLM-generated findings unless verifiably auditor-acceptable
- Multi-tenant white-label resale (different business)

## Timeline summary

| Milestone | Calendar | Cumulative |
|---|---|---|
| Phase 1 evidence layer | 4 weeks | week 4 |
| Phase 2 AWS CIS L1 | 4 weeks | week 8 |
| **First design partner (free/$49)** | parallel | **week 6–10** |
| Phase 3 GitHub | 3 weeks | week 11 |
| Phase 4 Google Workspace | 3 weeks | week 14 |
| Phase 5 billing + digest | 2 weeks | week 16 |
| Phase 6 deploy + polish | 2 weeks | **week 18 (~4.5 months)** |

Add 30% buffer for unknowns → **~~4–6 months to technically launch. ~6–12 months to meaningful recurring revenue unless distribution accelerates..**

If customer outreach runs in parallel from week 1 (5 conversations/week),
first paying customer realistically lands **month 3–4**, on annual prepay.

## Likelihood (with this revised plan)

| Outcome | Probability |
|---|---|
| First paying customer in 3 months | 60–70% (assumes real outreach, not just build) |
| $1k MRR in 6 months | 35% |
| $5k MRR in 12 months | 18% |
| $20k MRR in 24 months | 6% |
| Sustainable solo at $10k+ MRR | 10% |
| Quiet failure | 40% |

Better than average for:
- Technical co-founder who can ship
- Genuine AWS-depth advantage over Vanta
- $99 self-serve removes procurement friction

Worse than average for:
- Vanta/Drata own SMB compliance funnel
- Distribution is harder than building
- 6-month buyer journey for compliance

## What needs to happen in parallel to building

Three multipliers, each bigger than any single feature:

1. **Distribution**: build audience (Twitter/LinkedIn/newsletter) of devops/
   platform engineers + technical founders. 5k+ followers = +20% on every
   probability above.
2. **Auditor partnerships**: get 1–2 small SOC2 firms (Prescient Assurance,
   Strike Graph, Sensiba, Insight Assurance) to recommend Vigil to their
   AWS-heavy clients. +30%.
3. **Content moat**: write "AWS SOC2 evidence guide" / "How auditors actually
   sample CC6.6 MFA" / "From Prowler scan to audit-ready evidence" SEO posts.
   6 months of consistent writing → inbound leads. +25%.

Building alone with no distribution = nobody finds the product. Plan time
for these from week 1, not week 18.

## Code changes implied by this plan

To start Phase 1 immediately, add these to the codebase:

1. Alembic migration: `controls`, `check_controls`, `evidence_snapshots` tables
2. `app/models/control.py` + `evidence_snapshot.py`
3. JSON seed file `data/control_mappings.json` with CIS AWS L1 + SOC2 CC6/CC7
4. `app/routes/controls.py` — list / detail endpoints
5. `app/routes/exports.py` — `/v1/exports/evidence-pack` returning ZIP
6. `app/services/evidence_pack.py` — assembles ZIP (uses `zipfile`)
7. `app/services/pdf_report.py` — WeasyPrint renderer for cover PDF
8. UI: `/web/src/pages/Controls.tsx` (per-framework control list + status)
9. UI: per-control evidence drawer (reuse FindingDrawer chrome)
10. UI: "Download evidence pack" button on Account settings or Controls page

Existing schema mostly compatible — add migrations, don't rewrite. Each
collector should additionally write to `evidence_snapshots` so historical
state is preserved scan-over-scan.

## Final framing for any future LLM session

When in doubt, reread this section. The next contributor (human or AI)
should not be allowed to:

- Re-introduce audit workflow / GRC features
- Add multi-cloud before identity integrations ship
- Build features without first asking "does this strengthen the evidence
  layer or just add a checkmark?"
- Quote pricing above $499/mo (cap, not floor)
- Use the phrase "AWS IAM hygiene tool" anywhere customer-facing
- Build write/remediation actions
- Add LLM-generated content into evidence outputs

The product is: **continuous, auditor-ready, source-verifiable cloud
compliance evidence — for engineers who hate compliance theater.**

