# Vigil — Handoff

_Last updated: 2026-05-28 (session 26 release-readiness + drawer docs)_

---

## Session 26 (2026-05-28) — shipped

- **Release readiness:** `evidence_class` (benchmark / supporting / hygiene), `account_summary` snapshots for `iam.root.*`, CIS coverage matrix in packs/PDF, `checksum_manifest.json`, GitHub Actions CI (`.github/workflows/ci.yml`).
- **Optional check:** `github.repo.no_codeowners` (off by default, not framework-mapped).
- **Audit Q2/Q3:** Identity Center, GuardDuty findings, Config rule compliance, AMI age, external trust, `iam.role.full_admin_policy`; migration `0030`.
- **Drawer docs:** `web/src/data/checkDocumentation.ts` — per-check “what Vigil checks” + “why flagged” on Overview/Remediation (default SG, external trust, MFA so far).
- **External trust:** skip `VigilReadOnly` + trust-only to `TRUST_PRINCIPAL_ARN`; extended tier; trust policy JSON in Resources tab.
- **MFA What If:** no “disable user” / key-deactivation noise; remediation tab shows full `rem.why` + role-aware CLI fallbacks.
- **Docs:** no Hetzner/Caddy as prescribed stack; `web/public/llms.txt`, `robots.txt`, `sitemap.xml`.

---

## Working agreements — read first, do not re-raise these

Future LLMs / sessions: **do not propose, ask about, or "remind" the founder of
any item in this list.** They are settled decisions, not gaps. Several past
sessions wasted turns suggesting these.

- **No deployment work.** Hosting/TLS is your choice — not prescribed in-repo.
  setup, no production rollout planning. The founder will raise deployment
  when she wants to deploy. Until then, treat the app as dev-only.
- **No "throwaway AWS sandbox" planning.** A real scanned AWS account
  already exists and is in use for development. Stop suggesting we provision
  one. If something needs sandbox-level testing, use that account.
- **No Stripe / billing work** unless the founder explicitly asks. It is
  deferred indefinitely, not pending-discovery.
- **No emojis in code, docs, or commits** unless explicitly requested.

If you find yourself wanting to add one of the above to a TODO, gap list,
"next priorities" list, or commit message: stop. It belongs in this section
only, and only to say it's out of scope.

---

## What works today

### Auth
- Email + password signup/login (JWT, bcrypt + sha256 prehash — passlib removed due to bcrypt 4.x bug)
- GitHub OAuth — login + connect/disconnect from Account settings
- GitLab OAuth — login + connect/disconnect from Account settings (separate from the GitLab evidence integration)
- Google OAuth — login
- TOTP MFA (pyotp) — enable/disable from Account settings; Redis-backed lockout (5 failures → 10 min, repeat → 30 min)
- Account settings page: change password / set password (SSO-aware — no current password field for SSO-only users), GitHub + GitLab connect/disconnect, MFA setup
- SSO users with no password get "Set a password" flow; credential users get "Change password"
- OAuth link flow re-issues session tokens on success so connecting a provider never drops the active session

### AWS account onboarding
- Create account → CFN launch URL (pre-filled ExternalId + trust principal)
- Verify role via `sts:AssumeRole`
- Trigger scan → Celery task

### Collectors
- `collectors/iam.py` — IAM users, console password, MFA, access keys + last-used, roles + inline policies + **attached policies** (statements fetched via `GetPolicyVersion`), account password policy
- `collectors/last_accessed.py` — service last-accessed per role via AWS async job API (`generate_service_last_accessed_details`)
- `collectors/account.py` — S3 buckets (encryption, versioning, logging, public access, HTTPS policy) + KMS keys (rotation, state, aliases)
- `collectors/s3_account_public_access_block.py` — account-level S3 Block Public Access setting
- `collectors/cloudtrail.py` — trails (multi-region, logging, log validation, KMS key) — all enabled regions
- `collectors/guardduty.py` — detectors per region; synthetic "DISABLED" record when none exists
- `collectors/vpc.py` — VPCs (flow logs), security groups (SSH/RDP/default ingress rules, default-group flag) — all enabled regions
- `collectors/rds.py` — RDS instances (encryption, public access, engine, backup retention) — all enabled regions
- `collectors/ec2.py` — EC2 instances (type, state, IMDSv2, VPC/subnet, SG ids, tags), EBS volumes (encrypted, state, size, type, attached instances), EBS encryption-by-default — all enabled regions
- `collectors/access_analyzer.py` — IAM Access Analyzer status per region
- `collectors/config_service.py` — AWS Config recorder + delivery channel status per region
- `collectors/securityhub.py` — Security Hub enablement per region

### Checks
| Check ID | Severity |
|---|---|
| `iam.root.has_access_keys` | critical |
| `iam.root.no_mfa` | critical |
| `iam.user.no_mfa` | high |
| `iam.user.direct_policy_attachment` | medium |
| `iam.user.inactive_90d` | medium |
| `iam.access_key.unused_90d` | high |
| `iam.access_key.no_rotation_90d` | medium |
| `iam.access_key.multiple_active` | medium |
| `iam.role.unassumed_90d` | medium |
| `iam.role.wildcard_action` | high |
| `iam.role.unused_services_90d` | medium |
| `iam.role.trust_wildcard` | critical |
| `s3.bucket.public_access_not_blocked` | high |
| `s3.account.public_access_not_blocked` | high |
| `s3.bucket.no_https_policy` | medium |
| `s3.bucket.no_kms` | medium |
| `s3.bucket.no_logging` | low |
| `kms.key.no_rotation` | medium |
| `cloudtrail.trail.not_enabled` | high |
| `cloudtrail.trail.no_log_validation` | medium |
| `cloudtrail.trail.no_kms` | medium |
| `guardduty.detector.not_enabled` | high |
| `aws.securityhub.not_enabled` | medium |
| `vpc.flow_logs.not_enabled` | medium |
| `ec2.security_group.unrestricted_ssh` | high |
| `ec2.security_group.unrestricted_rdp` | high |
| `rds.instance.publicly_accessible` | high |
| `rds.instance.no_encryption` | high |
| `rds.instance.no_automated_backup` | medium |
| `ec2.security_group.default_allows_traffic` | medium |
| `ec2.instance.imdsv2_not_required` | medium |
| `ec2.ebs.encryption_not_default` | medium |
| `ec2.ebs.volume_unencrypted` | high |
| `iam.account.password_policy_weak` | medium |
| `aws.access_analyzer.not_enabled` | medium |
| `aws.config.not_enabled` | low |
| `github.org.mfa_not_enforced` | high |
| `github.org.dormant_members` | medium |
| `github.org.outside_collaborators` | medium |
| `github.repo.no_branch_protection` | high |
| `github.repo.no_codeowners` | medium |
| `github.repo.no_env_protection` | high |
| `github.repo.self_merge_allowed` | high |
| `github.repo.insufficient_reviews` | high |
| `iam.perm.granted_vs_used` | medium |
| `iam.policy.wildcard_resource` | high |
| `iam.policy.unattached` | low |
| `gitlab.org.mfa_not_enforced` | high |
| `gitlab.org.dormant_members` | medium |
| `gitlab.repo.no_branch_protection` | high |
| `gitlab.repo.self_merge_allowed` | high |
| `gitlab.repo.insufficient_reviews` | high |

### Findings UI
- Grouped by check type, sorted by severity
- Severity-tinted group headers, indented finding rows, first-seen date
- Summary stat cards (total / critical+high / medium / max score)
- Filter tabs: open / snoozed / resolved / all
- Snooze / resolve / ignore actions
- Multi-tag filter with autocomplete + URL-synced `?checks=` param
- Finding detail drawer: 3 tabs — Overview (context + evidence), Remediation (Console + AWS CLI), What If?
- Evidence section: scalars + object arrays rendered as tables (not raw JSON)
- `unused_services_90d` drawer: unused service pills, removable inline policy statements, **"Generate" button** — shows cleaned vs original policy JSON
- **What If? tab**: blast radius analysis for IAM role/user/key findings — confidence score, service usage pills (active=red/unused=gray), per-attached-policy breakdown (removable vs keep, AWS/Custom badge, detach+replace vs edit action)
- **What If? for SG findings**: shows affected instances list with instance type + state (running=red), running count, VPC/region metadata.
- CLI commands auto-interpolate actual role/user/key names from the finding ARN
- Scan status polling (3s while active) + `useTriggeredScan` hook — progress persists across page navigation (sessionStorage + in-memory pending); Accounts page background-polls; Re-scan unlocks after 5 min if stuck
- Onboarding empty state when no account connected — 3-step guide + link to AWS Accounts
- CSV export (`GET /v1/exports/findings.csv`)
- Update role ARN in connected state (expandable panel, reuses verify mutation)

### Notifications
- Weekly email digest via Resend (Celery beat, Monday 9am UTC)
- Per-org enable/disable toggle + configurable recipient email in Settings
- Fallback: sends to account email if no recipient configured
- "Send test email" button fires immediately from Settings UI
- Unsubscribe link in email → `/settings`
- Slack webhook: configurable per-org incoming webhook URL, test button, weekly digest also posts to Slack

### Frontend
- Login page: email/password + GitHub SSO + Google SSO
- AWS Accounts page — multi-account support, per-account findings + compliance metric strips, scan progress on card, official AWS logo (`/aws.png`), styled remove-account confirm dialog, pending-account UX
- Findings page (grouped, severity-aware, multi-tag filter, URL-synced `?checks=`, smooth accordion animation, severity-tinted expanded rows)
- Controls/Compliance page (SOC2 + CIS AWS L1 + ISO 27001; pass-rate cards, status filters, questionnaire template copy, evidence preview, mapped checks — no Re-scan/Refresh in header; scan only from Accounts/Findings)
- Settings page (check enable/disable per group, weekly digest toggle + recipient email)
- Account settings page (password + GitHub)
- Reference page (`/reference`) — searchable table of all supported search keys, resource types, check IDs, ARN patterns
- Sidebar: Vigil logo, AWS Accounts, Findings, Compliance, Timeline, Integrations, Settings, Account, Sign out

### Security
- Rate limiting: signup 5/min, login 10/min (slowapi); MFA verify locks the account after 5 failures (10 min, escalating to 30 min)
- Password minimum 12 chars enforced at signup + change password
- Fernet encryption for `role_arn` + `external_id` at rest
- Auto-scan triggered on role verify (no manual trigger needed). GitHub/GitLab sync no longer triggers AWS scans as a side effect.
- Scan dedup: `POST /v1/accounts/{id}/scan` returns the running scan if one started within the last 30 min instead of queueing a duplicate
- Stuck-scan reaper: worker marks `running` ScanRuns as `error` on startup (kills zombies from hot-reload) and every 15 min (anything > 30 min old)
- Refresh tokens: 30-day signed JWT, auto-retry on 401, OAuth callbacks store both tokens
- GitLab API tokens auto-refresh: `app/services/gitlab_tokens.py` swaps expired access tokens via `refresh_token` before each API call

### Infra
- `compose.yml` — api, worker, db (postgres 16), redis, web
- Hot reload: uvicorn --reload (api), watchfiles (worker), Vite HMR (web)
- Migrations: 0001_init → … → 0029_iam_user_policies (latest)
- CFN role: exact actions enumerated (no wildcards), includes CloudTrail/GuardDuty/EC2/RDS/SecurityHub/Config/AccessAnalyzer/S3Control read permissions
- pytest: 140+ tests (check unit tests + botocore Stubber collector tests)
- Checks: registry + optional hygiene (`iam.policy.unattached`, `github.repo.no_codeowners` off by default)
- Per-check drawer documentation: `web/src/data/checkDocumentation.ts` (extend for more `check_id`s)
- Evidence pack v2.1: `check_evidence_classes.json`, `checksum_manifest.json`, `cis_benchmark_coverage.json` (CIS packs)

---

## Architecture reminder

```
Vigil worker (control plane)
  → sts.amazonaws.com  →  AssumeRole (customer's CFN role)
  → iam.amazonaws.com  →  read-only scan

Customer's VPC/firewall is irrelevant — IAM and STS are
AWS control-plane APIs, reachable via public HTTPS.
```

---

## P0 — blockers to first paying customer (in order)

- [x] **AWS account for development scans** — real connected account in use (no throwaway sandbox needed; see Working agreements above)
- [x] **Encrypt `role_arn` + `external_id` at rest** (Fernet/AES-128-CBC, migration 0008)
- [x] **End-to-end test**: signup → CFN → verify → scan → findings populated (runs against the connected dev account)
- [x] **Tighten CFN IAM** — drop `SecurityAudit` + `ViewOnlyAccess`, enumerate exact actions
- [x] **Scan progress UI** — poll `GET /v1/accounts/:id/scan-runs`, surface errors (now also surfaces `failed_at`/`error_type`)
- [x] **Pagination on `/v1/findings`** (cursor + limit, migration 0009 composite index)
- [x] **CSV export** (`GET /v1/exports/findings.csv`)
- [x] **pytest skeleton** — botocore Stubber for collectors + check unit tests (75 passing as of session 17)

Deployment work is intentionally out of scope per "Working agreements".

## Next unblocked work

See **"Canonical remaining work"** below — that's the live list.

---

## P1 — after P0

- [x] Weekly digest email (Resend) — Monday 9am UTC, configurable recipient, test button
- [ ] Stripe billing — Checkout + portal + webhook → `orgs.plan`
- [x] Finding detail drawer — evidence, Console/CLI remediation, auto-interpolated resource names
- [x] **Generate Least-Privilege Policy** — `GET /v1/accounts/:id/roles/generated-policy` strips unused service statements from inline policies and returns cleaned JSON; Access Analyzer CloudTrail-based generation is future work (requires `accessRole` setup)
- [x] PDF compliance report (fpdf2, bundled in evidence pack ZIP)
- [x] Slack webhook (settings + `POST /v1/settings/test-slack` + weekly digest integration)
- [x] TOTP MFA (pyotp) — Account settings setup flow, Redis-backed lockout (5/10min → 30min on repeat)
- [x] Refresh tokens (30-day JWT, auto-retry on 401, OAuth callbacks updated)
- [x] Account deletion + role re-verify button

---

## P1 — security hardening

- [x] Encrypt `aws_accounts.role_arn` + `external_id` at rest (Fernet, migration 0008)
- [x] CSP + secure headers (X-Content-Type-Options, X-Frame-Options, HSTS, CSP) via FastAPI SecurityHeadersMiddleware; HSTS+CSP only in prod APP_ENV
- [x] Password complexity + breach-check (have-i-been-pwned k-anonymity)
- [x] Public `/security` page documenting permissions + retention

---

## P2 — next checks

- [x] `iam.root.usage` — CloudTrail root events
- [x] `iam.policy.unattached` — managed policies attached to nothing
- [x] `iam.policy.wildcard_resource` — `Resource: "*"` on dangerous actions
- [x] `iam.role.trust_wildcard` — `"Principal": "*"` in trust policy (already existed)
- [x] `iam.perm.granted_vs_used` — action-level (requires `Granularity=ACTION_LEVEL`, roles only); collector upgraded to ACTION_LEVEL, `actions_json` stored in `iam_perm_usage`, migration 0019

## Phase 2

Multi-account via AWS Orgs StackSet · S3/cert/secret/Trail/Config checks · Terraform remediation diffs (GitHub App) · Kubernetes RBAC

---

## Known gaps / shortcuts

| Gap | Notes |
|---|---|
| CORS `*` in dev | locked to `API_PUBLIC_URL` in prod via `APP_ENV` |
| CFN URL pinned to repo `main` | pin to release tag before beta (`CFN_TEMPLATE_URL` env now exists) |
| Multi-account support | One-account limit removed; schema was already multi-account ready |
| `last_accessed` collector is synchronous polling | ~1-3s per role; fine for MVP, throttle risk at 100+ roles |
| `RESEND_API_KEY` in `.env` | rotate before prod; `onboarding@resend.dev` sender only works for verified account email |
| Digest unsubscribe | one-click via `/v1/public/digest/unsubscribe?token=` (token issued when digest enabled) |

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

## Key differentiator: "What If" blast radius analysis

**Identified 2026-05-25. This is the primary product differentiator.**

Most CSPM/CNAPP tools (Orca, Wiz, Checkmarx, Prisma, Lacework) flag findings.
None show you what breaks if you actually fix them. This is why IAM debt
accumulates: engineers are afraid to touch stale roles and access keys because
they don't know what depends on them.

**The feature:** before remediating a finding, the user can click "What If I fix this?"
and get:

### Blast radius — what depends on this resource?

For a stale access key:
- Which services have seen API calls from this key in the last 90 days (via CloudTrail or IAM last-accessed)?
- Which IAM policies grant it access to what resources?
- Is it the only key for this user, or is there a backup?

For an over-permissive role:
- Which principals (services, users, other roles) trust this role?
- Which of its granted services has actually been used in the last 90 days vs. which are dead weight?
- If you remove `Action: *`, which specific actions would be blocked that are currently in use?
- Cross-account trust: does removing this role affect external accounts?

For a public S3 bucket:
- What objects are in it (count, last modified)?
- Are there CloudFront distributions or presigned URL patterns that depend on public access?
- Is it referenced in any role's resource policy?

### Remediation simulation

Before applying a fix, show a diff of the "before" vs "after" policy state:
- Current policy JSON vs. scoped-down policy (stripped to used actions/services only)
- Highlight which statements are being removed and whether they've been used
- Confidence score: "High confidence — these actions have no recorded usage in 90 days"
- Risk flags: "Warning — this service was used 3 times in the last 90 days, verify before removing"

### Why competitors don't have this

- Orca, Wiz, Prisma: agentless CSPM — they scan, they flag, they stop. No remediation intelligence.
- Checkmarx: code scanning focus — CNAPP is a bolt-on.
- Vanta/Drata: evidence aggregators — no technical depth on IAM graph.
- AWS IAM Access Analyzer: shows external access, not blast radius of removal.
- Prowler: CLI scanner, no UX, no "what if."

The insight the cybersecurity advisor surfaced: **the gap is not more checks, it's
remediation confidence**. The reason IAM debt compounds is that engineers are
correct to be afraid — removing the wrong thing breaks prod. Vigil solves this by
answering "what actually uses this?" before you touch it.

### Data already available to build this

- `iam_perm_usage` table — service last-accessed per role (90-day window)
- `evidence_snapshots` — full role policy JSON, trust policy, all inline statements
- `iam_access_keys` — `last_used_at` per key
- IAM Access Analyzer API — can enumerate resource policies and trust chains
- CloudTrail (future) — action-level usage, not just service-level

### Build order (when to tackle this)

Phase 2.5 — after CIS L1 checks, before GitHub integration:
1. "What if" drawer tab on IAM role findings — shows used vs. unused actions from `iam_perm_usage`
2. Blast radius panel for access key findings — last-used date + which services it touched
3. Policy diff view — before/after for "generate least-privilege" (already scaffolded in drawer)
4. Confidence scoring on generated policies

This can be shipped incrementally: start with the data Vigil already collects
(step 1 + 2), before building anything new. Step 3 reuses the existing
"Generate" button output. Step 4 is a one-liner on top of step 3.

---

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
Auth, OAuth, IAM checks, finding UI, scan engine, drawer with remediation,
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

### Phase 2 — AWS CIS L1 catch-up — COMPLETE ✓

Delivered session 3 (2026-05-25). 8 new checks, 5 new collectors, multi-region
scanning, rate limiting, password policy, What If? blast radius with attached
policy analysis, onboarding empty state.

**Session 4 additions (2026-05-25):**
- control_mappings.json: CC6.6 + CC6.8 duplicate entries merged (checks now unified per control)
- Snooze UI: `POST /v1/findings/:id/snooze` wired with 7/30/90d dropdown
- Re-verify (update role ARN) panel on connected Accounts page
- FindingDrawer typography cleanup: no more uppercase tracking labels, ARN in code container, segmented tab control, unified type scale throughout
- GuardDuty finding consolidated to 1 per account (was 1 per region = 18 findings for a fresh account); `disabled_regions` list in evidence
- Policy name tooltip in What If attached policy rows
- Blast radius: overlap fix for Custom badge + action label
- Search help + `/reference` page added for supported finding/resource lookup terms
- Individual EBS volume encryption added: `ec2.ebs.volume_unencrypted`, `ebs_volumes` table, `DescribeVolumes` collector, evidence snapshots, SOC2/CIS mappings, Settings/Findings/Drawer copy
- Daily scan schedule already exists via Celery beat: `scan_all_accounts` at 06:00 UTC

**Session 5 additions (2026-05-26):**
- SG What If tab: fully functional — shows affected instances list (instance_id, type, state), running count, VPC/region metadata
- EC2 collector: `DescribeInstances` added (instance type, state, IMDSv2, VPC/subnet/SG ids, tags)
- EBS volumes: `DescribeVolumes`, `ebs_volumes` table, `ec2.ebs.volume_unencrypted` check
- Multi-account: removed one-account limit, added DELETE route, rewrote Accounts.tsx with `AccountCard` per-account component
- ISO 27001 Annex A: 10 controls (A.9.2, A.9.4, A.10.1, A.12.4, A.12.6, A.13.1, A.13.2) mapped to existing checks, wired to Compliance page toggle, evidence pack export, and Account posture score bars
- Test coverage: expanded to 33 tests (up from 16), new tests cover all Phase 2 checks
- Reference page (`/reference`): searchable 22-row table of all supported search keys, resource types, check IDs

**Session 6 additions (2026-05-26):**
- **What If? tab — full 38-check coverage**: every check in the product now has a What If? tab. `BLAST_RADIUS_CHECKS` set in FindingDrawer covers all resource types; backend `GET /v1/accounts/{id}/blast-radius` handles all 38 check prefixes
- **What If? blast radius handlers added**: RDS instance, EC2 instance (IMDSv2), EBS volume (unencrypted + attached instance list), EBS encryption default, CloudTrail trail, VPC flow logs, IAM root (static), IAM password policy, S3 account block, GuardDuty, Security Hub, AWS Config, Access Analyzer
- **buildVerdict() coverage**: synthesises blast radius data → `{ text, type: "safe"|"caution"|"warning" }` for all 16 resource shapes; displayed as colored callout card in What If? tab
- **PolicyDiffView**: statement-level diff between original/cleaned inline policies with red strikethrough for removed statements; 3-way toggle (diff / cleaned / original)
- **PDF report fixes**: ARN truncation bug fixed (`[-45:]` → `[:65]` forward slice); empty "Score" column removed, Title column widened 20pt
- **Evidence pack synthetic snapshots**: when `snapshots.json` would be empty (resource absent — e.g. CloudTrail not enabled), evidence pack now synthesises snapshot entries from finding evidence with `_synthetic: true` flag + explanatory note. Auditors no longer see `[]`.
- **What If? tab UI polish**: amber icon (`text-amber-400`) restored, trailing `?` dropped from label; "Blast radius" header weight/size bumped; policy chip borders removed, fill-only chips

**Remaining gaps after session 6:**

1. `iam.root.usage` — root account activity check via CloudTrail `LookupEvents` (needs `cloudtrail:LookupEvents` added to CFN role + migration for root_activity table)
2. End-to-end AWS sandbox validation: signup → CFN → verify → scan → evidence pack
3. Production deploy + nightly pg_dump backups
4. GitHub integration for identity and change-management evidence (Phase 3)
5. Stripe gating for Free vs paid plan evidence export limits (deferred per founder decision)

**Session 7 additions (2026-05-26):**
- **GitLab integration shipped (Phase 3b)**: full OAuth flow, groups/repos API, sync service, scope editor UI, Integrations hub page, GitLabIntegration + GitLabIntegrationEdit pages — orange `#e24329` branding, self-hosted URL support
- **Integration UI bug fixes** (both GitHub and GitLab pages):
  - Connect error displayed inline when OAuth not configured (e.g., `GITLAB_CLIENT_ID` not set)
  - Checklist items (access review / approvals / self-merge / branch protections) show "—" instead of "Collected" before first sync
  - Branch protection remediation state shows "—" and "No data collected yet." when no repos scanned yet (was incorrectly showing "Complete" when 0/0)
- **10 GitHub/GitLab compliance checks** — all 46 checks now available:
  - `github/gitlab.org.mfa_not_enforced` (high) — org members without MFA
  - `github/gitlab.org.dormant_members` (medium) — members inactive 90+ days
  - `github/gitlab.repo.no_branch_protection` (high) — repos with no protection on default branch
  - `github/gitlab.repo.self_merge_allowed` (high) — repos with self-merged PRs in last 90 days
  - `github/gitlab.repo.insufficient_reviews` (high) — repos with under-reviewed merged PRs
  - All run as part of existing `run_scan(account_id)` — no new task type needed; checks look up providers via `org_id`
  - Shared logic in `checks/_identity_helpers.py`, 10 thin wrappers maintain one CHECK_ID per module
- **SOC2 CC8.1 added** to control_mappings.json — Change Management control mapping all repo checks
- **Control mappings updated**: CC6.1, CC6.2, CC6.3, CC6.6 now include GitHub + GitLab identity checks

**Remaining gaps after session 7:**

1. `iam.root.usage` — root account activity check (CloudTrail `LookupEvents`)
2. End-to-end AWS sandbox validation
3. Production deploy + nightly pg_dump backups
4. Stripe gating for evidence export limits

**Session 8 additions (2026-05-26):**
- **`iam.policy.wildcard_resource` check**: scans attached + inline policies on IAM roles for dangerous write actions on `Resource: "*"`; skips AWS managed policies and read-only prefixes; evidence includes `role_arn`, `policy_names`, per-policy dangerous actions; mapped to CC6.3/CC6.6/SOC2
- **`iam.policy.unattached` check**: flags customer-managed IAM policies with `attachment_count == 0`; collector extension to `collectors/iam.py` via `_collect_managed_policies()` using `list_policies(Scope=Local)` + `get_policy_version`; `iam:ListPolicies` added to CFN role
- **`iam.root.usage` check**: already implemented — calls `cloudtrail:LookupEvents` for root events in last 90 days; `cloudtrail:LookupEvents` already in CFN role
- **Refresh tokens**: 30-day signed JWT (`type: refresh`); `POST /v1/auth/refresh` endpoint; `api.ts` auto-retries 401 with refreshed token before redirecting; OAuth callbacks (Google + GitHub) now include `refresh_token` in redirect URL; `AuthCallback.tsx` stores both tokens via `storeTokens()`
- **Slack webhook**: `notifications.slack_webhook_url` in org settings; `POST /v1/settings/test-slack` fires test message; weekly digest task (`send_weekly_digests`) also POSTs to Slack if configured; Settings page has Slack webhook URL field + Test button
- **GitHub/GitLab human-readable labels**: all 10 identity check IDs mapped to display names in `Findings.tsx` and `FindingDrawer.tsx`; Overview tab shows platform-specific Why/Risk; Remediation tab hides Console/CLI toggle for identity checks
- **Identity evidence in evidence pack**: `_build_identity_snapshots()` pulls from identity tables and synthesises `github_identity`/`gitlab_identity` snapshot entries for evidence pack ZIP
- **Auto-scan after identity sync**: GitHub + GitLab sync routes trigger `run_scan.delay()` for all connected AWS accounts in the org
- **`iam.perm.granted_vs_used` check**: collector upgraded to `ACTION_LEVEL` granularity (superset of SERVICE_LEVEL — existing unused_services check still works); `actions_json` column added to `iam_perm_usage` (migration 0019); check flags roles where ≥40% of granted write/mutating actions have no recorded usage in 90 days
- **HIBP k-anonymity breach check**: `pwned_count()` in `passwords.py` blocks breached passwords at signup + change-password; network failure non-blocking
- **Public `/security` page**: documents AWS permissions, data retention, encryption, auth; accessible without login at `/security`

**Remaining gaps after session 8:**

1. End-to-end AWS sandbox validation (needs throwaway AWS account with seeded junk)
2. Production deploy + nightly pg_dump backups
3. Stripe gating for evidence export limits (deferred per founder decision)
4. TOTP MFA (deferred to Phase 1.5 / paying customers ask)

**Session 9 additions (2026-05-26):**
- **GitHub CODEOWNERS check** (`github.repo.no_codeowners`, medium): GitHub sync now checks for CODEOWNERS in /, .github/, docs/; `has_codeowners` column in repos (migration 0020)
- **GitHub environment protection check** (`github.repo.no_env_protection`, high): sync collects environments + required_reviewers from GitHub environments API; `protected_envs` JSONB in repos (migration 0020); flags envs with no required reviewers
- **CSP + security headers**: `SecurityHeadersMiddleware` in FastAPI — X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy; HSTS + CSP only in prod APP_ENV
- **pg_dump backup service**: `backup` service in compose.yml (prod profile); dumps to Backblaze B2 via S3-compatible API if `B2_KEY_ID`+`B2_APPLICATION_KEY`+`B2_BUCKET` configured; run manually or via host cron
- 50 total checks (was 48)

**Session 10 additions (2026-05-26):**
- **`github.org.outside_collaborators` check** (medium): non-org members with direct repo access; collected via GitHub `/orgs/{owner}/outside_collaborators` API; stored in provider `config_json_encrypted`; finder drawer has full remediation copy; Settings + Findings + FindingDrawer all wired
- **CloudTrail write-event collector** (`collectors/cloudtrail_events.py`): 50 tracked event names across IAM/SG/S3/EC2/KMS/CloudTrail/Config/GuardDuty; uses `LookupEvents` paginator for last 90 days (max 1000/run); upserts into `cloudtrail_events` table (migration 0021); runs as part of every scan
- **`cloudtrail_events` table** (migration 0021): `id`, `account_id` FK, `event_id`, `event_name`, `event_source`, `event_time`, `actor`, `source_ip`, `resources` JSONB, `raw` JSONB, `last_seen`; unique on `(account_id, event_id)`; index on `(account_id, event_time)`
- **`GET /v1/accounts/{id}/timeline`**: CloudTrail events correlated with GitHub PR merges within ±60 minutes; returns `event_id`, `event_name`, `actor`, `source_ip`, `resources`, `correlated_prs[]` (number, repo, merged_at, merged_by, author, approval_count, self_merge, delta_seconds); filters by `?days=30&limit=200`
- **Timeline page** (`/timeline`): expandable event rows (click to reveal detail); sky-blue badge + highlight for events with correlated PRs; PR detail cards show before/after delta, self-merge badge, approval counts; correlation banner when matches exist; 7d/30d/90d toggle; added to sidebar nav
- **control_mappings**: `outside_collaborators` → CC6.2; `no_codeowners` + `no_env_protection` → CC6.6 + CC8.1; `iam.perm.granted_vs_used` → CC6.6 + ISO A.9.2.5
- 53 total checks (was 50)

**Session 10 continued — additional work:**
- **GitHub team membership**: `_collect_team_memberships()` in github_sync — calls `/orgs/{owner}/teams` + `/orgs/{owner}/teams/{slug}/members`; stores as `roles_json["teams"]` on each `IdentityUser`; no schema change needed
- **control_mappings gaps closed**: `ec2.instance.imdsv2_not_required` added to CC6.6 + A.12.6.1; `s3.bucket.no_logging` added to CC7.2 + A.12.4.1; all 53 checks now mapped
- **Reference page updated**: github.org/github.repo descriptions include outside_collaborators/no_codeowners/no_env_protection; new `iam.perm` entry added
- **evidence_pack bug fixed**: `generated_at` was used before assignment (NameError in production); moved to before first use
- **evidence_pack CC8.1 enhancement**: CloudTrail write events (last 200 within evidence period) now included in snapshots for all `github.*` and `gitlab.*` controls — auditors see infra changes alongside change-management evidence
- **blast radius: iam.policy.wildcard_resource**: shows `affected_policies` list with scoping warnings
- **blast radius: iam.policy.unattached**: high-confidence safe-to-delete
- **blast radius: iam.perm.granted_vs_used**: shows used_services vs unused_services from `iam_perm_usage` with 90-day window; `buildVerdict` cases added for all 3
- **42 tests passing** (was 33, then 2 stubs broken; 9 new tests + 2 fixes)

**Remaining gaps after session 10:**

1. `alembic upgrade head` needed to apply migrations 0019 (actions_json), 0020 (has_codeowners/protected_envs), 0021 (cloudtrail_events)
2. End-to-end AWS sandbox validation (needs throwaway AWS account with seeded junk)
3. Production deploy (deferred)
4. Stripe gating for evidence export limits (deferred per founder decision)
5. TOTP MFA (deferred to Phase 1.5)
6. GitHub Actions deployments/workflow runs (Phase 3 item — tracks workflow runs to environments for CC8.1)

**Session 11 additions (2026-05-26):**
- **Exception workflow**: formal documented exceptions separate from snooze — `POST /v1/findings/{id}/exception` with `{reason, approved_by, expires_at}`; status `excepted` added to Finding model; migration 0022 adds `exception_reason`, `exception_approved_by`, `exception_expires_at` columns; `ExceptionButton` in FindingDrawer opens modal form (reason textarea, approver, optional expiry date); `excepted` tab added to Findings page status filter
- **Exception in evidence packs**: excepted findings included alongside open findings in evidence pack ZIP; per-control `exceptions.json` file lists approved exceptions with reason/approver/expiry; `finding_count` = open only, `exception_count` tracked separately; evidence pack query now fetches `status IN ('open', 'excepted')`
- **Sample evidence pack**: `GET /v1/exports/sample-evidence-pack?framework=soc2|cis_aws_l1` — no auth required; returns synthetic ZIP with realistic SOC2/CIS sample data including one excepted finding with approver; designed for landing page "Download sample" CTA
- **README rewrite**: full rewrite with current positioning ("Continuous SOC2 CC6/CC7 and CIS evidence automation"), current check count (53), all three integrations (AWS/GitHub/GitLab), exception workflow, sample pack endpoint, pricing table, architecture layout
- **Product repositioning (note for next sessions)**: Vigil is NOT a CSPM. Primary surface = Controls/Evidence, not Findings. The buyer problem is "prove CC6/CC7 controls operated continuously across the audit period." Evidence pack + exceptions + timeline are the moat.

**Remaining gaps after session 11:**

1. `alembic upgrade head` — migrations 0019–0022 (run on next deploy)
2. Nav reorder: Controls before Findings (sidebar order change — 10 min, high demo value)
3. Audit period selector on evidence pack UI (currently hardcoded 90d in the frontend)
4. Control narrative text per control (copy-paste paragraph for questionnaire responses)
5. End-to-end sandbox validation (deferred — needs throwaway AWS account)
6. Production deploy (deferred)
7. Stripe (deferred)
8. TOTP MFA (deferred to Phase 1.5)
9. GitHub Actions deployments/workflow runs (Phase 3 last item)

**Session 12 additions (2026-05-26):**
- **Nav reorder**: Compliance now above Findings in sidebar — controls are the product surface, findings are supporting detail
- **Audit period selector**: 30d / 90d / 180d / 365d toggle on Compliance page, wired to evidence pack download URL; was hardcoded 90d; SOC2 Type 2 requires period-based evidence
- **Control narrative text**: `api/app/data/control_narratives.py` — pre-written audit response paragraph for 28 controls across SOC2 CC6/CC7/CC8, CIS, ISO 27001; exposed as `narrative` field on `ControlOut`; shown in expanded control row with one-click copy-to-clipboard for questionnaire responses; `NarrativeBlock` component (violet, matches exception/exception palette)

**Remaining gaps after session 12:**

1. `alembic upgrade head` — migrations 0019–0022 (run on next deploy)
2. End-to-end sandbox validation (deferred — needs throwaway AWS account)
3. Production deploy (deferred)
4. Stripe (deferred)
5. TOTP MFA (deferred to Phase 1.5)
6. GitHub Actions deployments/workflow runs (Phase 3 last item — tracks workflow runs to environments for CC8.1)

**Session 13 additions (2026-05-26):**
- **GitHub Actions workflow run collection**: `_collect_workflow_runs()` in `github_sync.py` — fetches last 50 runs on default branch + last 20 deployment-event runs; correlates SHA→environment via `/repos/{owner}/{repo}/deployments`; stores in `workflow_runs` table (migration 0023, `WorkflowRun` model); `workflow_runs: int` counter in `GitHubSyncStats`
- **GitLab CI/CD pipeline collection**: `_collect_ci_pipelines()` in `gitlab_sync.py` — fetches last 50 pipelines on default branch; stores in `ci_pipelines` table (migration 0024, `CiPipeline` model); `ci_pipelines: int` counter in `GitLabSyncStats`
- **Models**: `WorkflowRun` (repo_id, run_id unique — name, workflow_path, event, status, conclusion, branch, actor, environment, run_started_at, run_completed_at) and `CiPipeline` (repo_id, pipeline_id unique — ref, status, source, actor, created_at, finished_at, duration) added to `github.py` + exported from `models/__init__.py`
- **Evidence pack CC8.1 wired**: `_build_cicd_snapshots(db, org_id, since)` queries `WorkflowRun` (github providers) and `CiPipeline` (gitlab providers) and returns `{"workflow_run": [...], "ci_pipeline": [...]}`; called in `build_evidence_pack()` after identity + CloudTrail snapshots; `_entity_types_for_checks()` updated to emit `workflow_run` for `github.*` checks and `ci_pipeline` for `gitlab.*` checks
- **Period selector UI redesign**: moved from header toolbar (was crammed next to SOC2/CIS/ISO tabs) to a dedicated "Evidence Pack" row below the summary bar; period buttons (30d/90d/180d/365d) sit inline with the Download button; header now has framework tabs only

**Remaining gaps after session 13:**

1. `alembic upgrade head` — migrations 0019–0024 (run on next deploy)
2. End-to-end sandbox validation (deferred — needs throwaway AWS account)
3. Production deploy (deferred)
4. Stripe (deferred)
5. TOTP MFA (deferred to Phase 1.5)
6. Phase 3 is now **complete** — all GitHub/GitLab checks, identity evidence, change management evidence, timeline correlation, and CI/CD pipeline collection are shipped

**Session 14 additions (2026-05-27):**
- **Finding drawer / What If polish**: deduplicated verdict vs warning vs info boxes (S3 HTTPS, EBS default encryption, AWS Config, default SG); green verdict + zinc info pattern (VPC flow logs cost, service-enable costs); SG metadata shows `sg-` id + Default badge with separate VPC and Region fields
- **IAM least-privilege policy generation**: wildcard `Action: *` narrows to per-action grants from IAM last-accessed (`actions_json` with service prefix fix); `iam_usage.py` helper; collector poll wait increased; Generate/What If cache busts on `last_seen`
- **What If console links**: attached-policy "Edit policy" / "Detach + replace" open IAM Console
- **CloudTrail account blast radius**: account-level handler for synthetic trail ARN
- **Findings UX**: removed Snooze/Ignored tabs; scan progress bar; Compliance/Accounts/Integrations polish
- **S3 HTTPS finding**: severity lowered to low; messaging reframed as defense-in-depth
- **Timeline period selector**: replaced cramped 7d/30d/90d button group with Compliance-matching dropdown ("Last 7/30/90 days")
- **Tests**: `test_policy_clean.py`, `test_iam_usage.py` (46+ checks passing)

**Remaining gaps after session 14:**

1. `alembic upgrade head` — migrations 0019–0024 (run on next deploy)
2. End-to-end sandbox validation (deferred — needs throwaway AWS account)
3. Production deploy (deferred)
4. Stripe (deferred)
5. TOTP MFA (deferred to Phase 1.5)
6. Re-scan production account to populate action-level `actions_json` after collector fix

**Session 15 additions (2026-05-27):**
- **TOTP MFA shipped** (was deferred): `app/core/mfa_lockout.py` Redis-backed counter, 5 failures → 10 min lock, repeat offence → 30 min; wired into `mfa_verify`; `test_mfa_lockout.py` (4 tests passing)
- **GitLab OAuth sign-in** (separate from the existing GitLab evidence integration): `auth_oauth.py` handles `/v1/auth/gitlab/*`; `gitlab_id` column on `User` via migration `0025_user_gitlab_id.py`; Account page now has GitLab connect/disconnect alongside GitHub; `/v1/auth/me` exposes `gitlab_id`; `DELETE /v1/auth/me/gitlab` disconnects
- **OAuth link session fix**: `_oauth_link_redirect()` re-issues access + refresh tokens on successful link and redirects to `/auth/callback?next=/account?gitlab=linked` so connecting a provider mid-session never logs the user out; `AuthCallback.tsx` honours the `next` param
- **GitLab token refresh service**: `app/services/gitlab_tokens.py` — stores `refresh_token` + `token_expires_at` in provider `config_json_encrypted`, exchanges expired tokens before each GitLab API call; wired into `gitlab_integration.py` + `gitlab_sync.py`; `test_gitlab_tokens.py` covers refresh + expiry paths
- **Sync no longer triggers AWS scans**: `_trigger_scans_for_org` removed from `POST /v1/integrations/github/sync` and `POST /v1/integrations/gitlab/sync` — this was the "scans keep re-running by themselves" report. Sync now syncs evidence and stops there.
- **Scan dedup**: `POST /v1/accounts/{id}/scan` checks for a `running` `scan_runs` row started within the last 30 min for the same account and returns it instead of queueing a duplicate (`{"job_id": <existing>, "deduped": true}`)
- **Stuck-scan reaper**: `reap_stuck_scan_runs` Celery task marks `running` rows older than `max_age_minutes` as `error` with `scan interrupted (worker restart or timeout)`; fires on `worker_ready` with `max_age_minutes=0` to clear zombies after hot-reloads, and every 15 min via beat with the 30 min default; cleared 21 stuck rows on first deploy
- **Login UX**: MFA verify returns `400` (not `401`) for "invalid code" / "session expired" so the auto-401-refresh interceptor doesn't bounce the user out mid-MFA; shared `formatApiError` helper; GitLab button added to Login + Signup
- **Account page Posture Snapshot polish**: panel `self-stretch`es to match the account card height instead of leaving a dead gap; stat tiles centered with `text-[26px]` numbers; compliance rows collapsed to a single line (`label | bar | %`) with `h-1.5` bars; smaller header label and tighter padding so the panel fits without overflowing
- **Add account button**: padding fix (`px-5 py-2.5`)

**Remaining gaps after session 15:**

1. `alembic upgrade head` — migrations 0019–0025 (run on next deploy; **0025 adds `users.gitlab_id`** and is required for GitLab sign-in)
2. GitLab OAuth app must list both `/v1/auth/gitlab/callback` (login/link) and `/v1/integrations/gitlab/callback` (evidence) as redirect URIs, with scopes `read_user` + `read_api`
3. End-to-end sandbox validation (deferred — needs throwaway AWS account)
4. Production deploy (deferred)
5. Stripe (deferred)
6. Re-scan production account to populate action-level `actions_json` after collector fix
7. Some scan_runs still drop into `error` immediately on first start with no detail — needs root-cause once a stable AWS sandbox exists

**Session 16 additions (2026-05-27):**
- **Google OAuth fully linkable** (was login-only): `users.google_id` column via migration `0026_user_google_id.py` (unique); `User` model + `MeOut` exposes `google_id`; `_remaining_signin_methods` counts Google so disconnect lockout works correctly; `DELETE /v1/auth/me/google` endpoint; Account page now has Connect Google / Disconnect Google section mirroring GitHub/GitLab
- **Orphan-IdP auto-claim on link**: when linking a provider that's already owned by another user with no AWS accounts (an "orphan" from a prior login-flow signup), the orphan user/org is deleted and the IdP is freed onto the current user; uses SQL-level `DELETE FROM orgs WHERE id = ...` to leverage DB-level `ON DELETE CASCADE` on `User.org_id` — ORM `db.delete(org)` was crashing with NotNullViolation because the default relationship cascade tried to `SET users.org_id = NULL` before the delete
- **Link-flow errors no longer bounce to `/login`**: state-aware `_callback_error(state, provider, error)` routes link failures to `/account?provider=<p>&error=<code>` (user stays logged in) and login failures to `/login?error=<code>`; provider hint in the URL lets the frontend target the right card's message
- **Unified toast feedback**: replaced per-provider inline red banners and the success-only toast with a single dark-pill toast at bottom-center — emerald check for success (4s) and red `×` for errors (6s); applies to OAuth link/unlink + URL error params; "Only one sign-in method" warning banner shows on Account page when the user has just one way to log in
- **GitLab token exchange hardened**: tries form-body credentials first, falls back to HTTP Basic Auth on 401 (RFC 6749 §2.3.1); both auth styles supported

**Remaining gaps after session 16:**

1. `alembic upgrade head` — migrations 0019–0026 (run on next deploy; **0026 adds `users.google_id`**, required for proper Google link/disconnect)
2. End-to-end sandbox validation (deferred — needs throwaway AWS account)
3. Production deploy (deferred)
4. Stripe (deferred)
5. Re-scan production account to populate action-level `actions_json` after collector fix
6. Some scan_runs drop into `error` immediately on first start with no detail — root-cause once a stable AWS sandbox exists
7. Login-flow orphan creation: signing in via GitLab/Google with an email that doesn't match an existing user still creates a brand-new user+org. Auto-claim only fires on the *link* flow. Consider gating login-flow signup behind explicit "create new account" intent (low priority — orphan-claim already mops up the symptom)

**Session 17 additions (2026-05-27)** — pre-prod hygiene pass (end-to-end):
- **Scan error capture**: every collector + check phase in `run_scan` is now tagged with a `step` name; on failure the step + truncated traceback land in `scan_runs.error` and `scan_runs.stats.failed_at`/`error_type`. Per-check failures are isolated (one bad check no longer kills the whole scan — error is appended to `stats.check_errors` and the rest of the checks still run). Latest scan-runs API exposes `failed_at` + `error_type`; Accounts + Findings pages render `Last scan failed at step <collector_name> (<ErrorType>):` instead of an opaque traceback.
- **Request-id middleware**: every HTTP request gets an `X-Request-Id` (honours inbound headers from a proxy; otherwise generates a UUID4 hex). The id is bound to structlog's contextvars so every log line emitted during the request carries `request_id=`. Single `http.request` log line per request with `method/path/status/duration_ms/remote`; `/healthz` is silenced. Response carries the same id so clients and your reverse proxy can correlate. Trusts `X-Forwarded-For` only in non-dev.
- **CFN template URL configurable**: `settings.CFN_TEMPLATE_URL` (env: `CFN_TEMPLATE_URL`) replaces the hard-coded constant in `accounts.py`. Default still points at the dev S3 location; production should pin to a versioned object so launched-yesterday vs launched-today stacks reference the same template. `.env.example` updated with a comment.
- **AssumeRole audit log**: new `assume_role_audit` table (migration `0027`) — one row per `sts:AssumeRole` call with `org_id`, `aws_account_id`, `role_arn`, `session_name`, `purpose`, `success`, `error_code`, `error_message`, `called_at`. `app/core/aws.py` writes to it on every call (success or failure) using an isolated session so the audit row survives even when the caller rolls back. All 16 collector/check call sites pass `aws_account=acc, purpose="..."`. Customer-facing endpoint `GET /v1/accounts/{id}/assume-role-audit` returns the latest events (default 100, max 500). Accounts page now has an expandable "AWS activity" panel per account that renders the last 50 events in a compact table. Migration applied locally. Daily Celery task `prune_assume_role_audit` (beat: 04:30 UTC) deletes rows older than `retention_days` (default 365).
- **SSO signup logging + gate**: every login-flow that creates a new user+org for GitHub/GitLab/Google emits `oauth.signup.new_org` (provider, email, IdP id, org id, user id). Email-match → IdP attach is logged as `oauth.idp_attached_by_email`. New config flag `ALLOW_SSO_SIGNUP` (default `True`) — when set to `False`, the login-flow returns `?error=no_account_for_idp` instead of creating a new user+org. Login page has a friendly message for the new error code.
- **Tests**: 7 new (75 total passing). Coverage: assume_role audit success/ClientError/generic-exception/audit-write-failure-swallowed paths, run_scan invalid-UUID + account-not-found early bailouts, per-check failure isolation.

**Remaining gaps after session 17 — see the canonical list below.** Per
"Working agreements" above, deployment / sandbox / Stripe items are out of
scope and intentionally absent from that list.

**Session 18 additions (2026-05-27)** — AWS gap checks + evidence export fixes:
- **21 new AWS checks** (73 total across AWS + GitHub + GitLab): S3 default
  encryption + MFA delete; EBS snapshot public/unencrypted; EC2 public AMI;
  CloudTrail S3 bucket public / no CloudWatch / no access logging; ACM cert
  expiring within 30d; Lambda deprecated runtime + no DLQ; RDS no deletion
  protection + no Multi-AZ (when backups enabled); Secrets Manager no rotation;
  SSM plaintext sensitive params; ELB no access logs + weak TLS; DynamoDB no
  PITR + no encryption; SNS/SQS no KMS encryption.
- **Migration `0028`**: new tables (`ebs_snapshots`, `ec2_amis`, `acm_certificates`,
  `lambda_functions`, `secrets_manager_secrets`, `ssm_parameters`,
  `elb_load_balancers`, `dynamodb_tables`, `sns_topics`, `sqs_queues`) +
  extended columns on `s3_buckets`, `cloudtrail_trails`, `rds_instances`.
- **`collectors/extended.py`**: ACM, Lambda, Secrets Manager, SSM, ELBv2,
  DynamoDB, SNS, SQS collectors. EC2 collector extended for snapshots + AMIs.
  S3/CloudTrail/RDS collectors extended for new fields.
- **CFN role** (`infra/cfn/vigil-readonly-role.yaml`): new read-only actions
  for all new collectors. **Existing connected accounts must update their
  CloudFormation stack** to pick up these permissions or new collectors will
  silently skip (ClientError → empty).
- **Control mappings**: 5 new CIS L1 controls (2.1.2, 2.1.3, 3.3, 3.4, 3.6)
  + new checks wired into SOC2 CC6.6/CC6.8/CC7.1 and ISO A.10/A.12/A.9.
- **Evidence pack fixes** (auditor-facing):
  - `exceptions.json` now written per control folder (was computed but dropped)
  - Excepted findings no longer fail a control — only `open` findings do
  - `INDEX.csv` columns aligned: `control_id,title,status,open_findings,exceptions`
  - ISO 27001 added to `/v1/exports/evidence-pack` frameworks (was UI-only before)
  - Findings CSV export adds exception columns (`exception_reason`,
    `exception_approved_by`, `exception_expires_at`)
- **Tests**: 79 passing (+4 evidence/gap check tests).

**Remaining gaps after session 18 — see canonical list below.**

**Session 19 additions (2026-05-27):**
- **Nav reorder**: Findings above Compliance in sidebar — Findings is the stronger daily-driver surface; Compliance page is functional but minimal UI until a dedicated polish pass

**Session 21 additions (2026-05-27):**
- **What If**: all AWS + session-18 gap + GitHub/GitLab checks in `blastRadiusChecks.ts`; `iam.user.no_mfa`; identity blast-radius backend; gap-resource detail in drawer
- **Accounts**: two metric strips (findings | compliance)
- **Scan progress**: removed `finish ~TIME` from progress bar
- **Minor**: Vite `manualChunks`; `.env.example` notes for `ALLOW_SSO_SIGNUP` + `CFN_TEMPLATE_URL`

**Session 22 additions (2026-05-27):**
- **CIS 1.16** (`iam.user.direct_policy_attachment`): collector reads attached + inline user policies (migration `0029`); check flags direct user policy attachments; mapped to CIS 1.16 + What If tab
- **Removed stale-CFN heuristic**: dropped `cfn_permissions_stale` flag, banner, and session-18 “all zeros” guess — empty Lambda/DynamoDB/etc. is normal when those services aren't used; CFN health is visible per-collector in scan stats if needed

**Session 20 additions (2026-05-27)** — merged to `staging`:
- **Compliance polish** (`feat/compliance-polish` → `staging`): framework pass-rate cards, status filters, questionnaire template (pass/fail/no_data), evidence preview, mapped checks grouping, duplicate summary line removed; Re-scan + Refresh removed from Compliance header
- **Scan progress** (`useTriggeredScan`): cross-page persistence via sessionStorage; no longer clears pending state on stale `ok` scan row; `refetchOnMount: always` on scan-runs query
- **Findings drawer**: collapsible granted/unused services, Action vs Resource wildcard notes, CloudTrail-aware copy, `iam.policy.wildcard_resource` skips Vigil scan role + IAM last-accessed APIs
- **Accounts UX**: compact header layout, `ConfirmDialog` for remove, AWS wordmark asset (`web/public/aws.png`), separate findings vs compliance metric strips
- **Settings**: alert email placeholder → `Email Address`
- **Nav**: Findings 2nd in sidebar (after Accounts)

---

## Canonical remaining work

Single source of truth. Older session notes are historical — when they
conflict with this section, this section wins.

**State as of session 27 (2026-05-28):** audit-evidence readiness shipped
(Session 26). Session 27 adds check docs fallback, remediation gaps,
Controls audit template, mapping/narrative CI tests, access-roster API,
digest one-click unsubscribe, `/reference` route, sample pack
`check_evidence_classes.json`.

**Shipped (do not re-open as bugs):**
- Core check → framework mappings complete (`test_check_mappings_registry.py`)
- `iam.policy.wildcard_resource` mapped; `github.repo.no_codeowners` optional hygiene (unmapped by design)
- Evidence class API + ZIP `checksum_manifest.json` + CIS coverage matrix
- GuardDuty open findings, Config rule compliance, AMI age, IC roster in packs
- Evidence coverage indicator (Compliance + `evidence_coverage.json` in pack)
- `GET /accounts/:id/access-roster?as_of=` (latest collection as of date)
- Digest unsubscribe token URL (`/v1/public/digest/unsubscribe?token=`)
- Finding drawer: check docs from `remediationSummaries` + hand-authored overrides
- Controls expanded row: 5-part audit evidence summary block

**Founder-blocking (click, not code):**
- Re-scan connected accounts after deploy so new collectors (IC, GuardDuty findings, Config compliance) populate

**Type II / release hardening (README “planned” items):**
- WORM / immutable evidence storage
- Signed evidence packs (checksum manifest exists; no crypto signing yet)
- CIS AWS v5 benchmark pack (v1.5 matrix is honest partial coverage today)
- Historical snapshot query UI (“state at date X” beyond roster + rolling pack window)
- Google Workspace identity
- Prod deploy + Stripe billing

**Product backlog (not blocking demo):**
- “What If” blast radius tab (HANDOFF differentiator — uses `iam_perm_usage`)
- Throwaway AWS sandbox for e2e
- Deeper point-in-time IAM from per-scan evidence snapshots (roster is latest collection today)

**Optional hygiene (off by default, unmapped):** `iam.policy.unattached`, `github.repo.no_codeowners`

**AWS coverage:** ~80 registered checks (AWS + GitHub + GitLab). Full CIS L1 still has manual-only items.

**Optional when deploying prod:** `ALLOW_SSO_SIGNUP=False`, pin `CFN_TEMPLATE_URL` to release tag.

### Session 25 audit-readiness review (2026-05-28)

**Evidence pack sufficiency (CC6/CC7):**
- **Strong:** per-control folder structure, `timeline.csv` with open/close lifecycle, exceptions with approver, source manifest.
- **Weak for Type II:** no "as-of date" export, snapshot displays capped without total-count context, CloudTrail sample cap can be low for active accounts.
- **Verdict:** sufficient for Type I and readiness conversations; borderline for strict Type II sampling until date-specific export + coverage indicator land.

**Audit narratives (keep, but adjust):**
- Keep narratives (high value differentiator vs scanner-only tools).
- Fix control specificity:
  - CC6.3 narrative should focus deprovisioning/access removal (not generic permissive scopes).
  - Add coverage statement to narratives ("evidence collected daily; retention window starts at account connection").
  - CC6.2 should explicitly call out manual provisioning-process attestation gap.
  - CC7.2 should explicitly call out that GuardDuty incident-response workflow evidence is manual today.
  - CC8.1 should explain auditor interpretation of `self_merge=true` and `approval_count < required_review_count`.

**Market / positioning notes (for GTM):**
- Direct day-1 competition for this buyer is often **Prowler + manual evidence assembly**, not Vanta.
- Best-fit buyer: 5–15 person AWS-native startup, technical founder/platform lead, price-sensitive, first SOC2 push.
- Initial sales motion should prioritize technical operators (platform/devops/CTO at seed), auditor partnerships, and proof content ("download sample evidence pack", long-form CC6/CC7 AWS evidence guide) over broad CISO cold outreach.

### Phase 3 — GitHub integration (3 weeks)

Single highest-leverage integration. Covers both identity (CC6) and change
management (CC7.1) in one shot. Most startups use GitHub.

**Session 7 kickoff (2026-05-26):**
- Added migration `0018_github_integration.py` with the locked Phase 3 tables:
  `identity_providers`, `identity_users`, `repos`, `repo_protections`, `pull_requests`
- Added SQLAlchemy models for those tables; provider config is encrypted with the
  existing `EncryptedString` Fernet helper
- Added OAuth App integration routes under `/v1/integrations/github`:
  connect URL, callback, provider summary, sync, disconnect
- Added GitHub sync service for the first vertical slice:
  org/user identity records, repositories, default-branch protection, merged PRs,
  approver counts, required review counts, and self-merge detection
- Added `/integrations/github` UI page and sidebar entry
- Fixed integration OAuth redirect handling to reuse the existing GitHub login
  callback path (`/v1/auth/github/callback`) by default, so one OAuth App
  callback registration can handle both login and evidence integration states
- Applied migration to the running dev DB; `docker compose exec -T api python -m pytest -q`
  passes (33 tests), and `npm run build` passes

**Still needed in Phase 3:**
- [x] CODEOWNERS coverage (`github.repo.no_codeowners` check + sync)
- [x] Protected environments and required reviewers (`github.repo.no_env_protection` check + sync)
- [x] Outside collaborators (`github.org.outside_collaborators` check + sync)
- [x] AWS CloudTrail event ↔ GitHub PR correlation timeline (`GET /v1/accounts/{id}/timeline` + `/timeline` UI page)
- [x] Team membership (`_collect_team_memberships()` in github_sync; stored in `roles_json["teams"]`)
- [x] GitHub Actions deployments/workflow runs (migrations 0023/0024, WorkflowRun + CiPipeline models, _build_cicd_snapshots in evidence_pack)
- [x] GitHub-derived controls/checks and evidence-pack wiring (checks exist, evidence-pack wired for identity snapshots + CloudTrail events + workflow_run/ci_pipeline)

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

### Phase 3b — GitLab integration (2–3 weeks, after GitHub ships)

Same evidence surface as GitHub — covers teams that use GitLab exclusively (common in EU + enterprise).

**Schema reuse:** `identity_providers` already has `type` column. Add `type = "gitlab"`. All existing tables (`identity_users`, `repos`, `repo_protections`, `pull_requests`) map 1:1 — no new migrations needed.

**API mapping:**
| GitHub | GitLab equivalent |
|---|---|
| Orgs | Groups (`/groups`) |
| Repos | Projects (`/groups/:id/projects`) |
| Branch protection rules | Protected branches (`/projects/:id/protected_branches`) + push rules |
| PR reviews + approvals | MR approvals (`approvals_before_merge`, `/merge_requests/:id/approvals`) |
| Self-merge detection | MR `author.id == merged_by.id` |
| Org MFA enforcement | Group `require_two_factor_authentication` |
| Dormant members | Group members `last_activity_on` |

**Auth:** Personal access token or OAuth app (`read_api` scope). GitLab OAuth flow mirrors GitHub — add `GITLAB_CLIENT_ID` + `GITLAB_CLIENT_SECRET` to `.env`.

**Checks to add** (same slugs pattern as GitHub):
- `gitlab.group.mfa_not_enforced`
- `gitlab.group.dormant_members`
- `gitlab.repo.no_branch_protection`
- `gitlab.repo.self_merge_allowed`
- `gitlab.repo.insufficient_reviews`

**UI:** Reuse the GitHub integration page component — parameterise by provider type, swap GitLab logo. "View findings" filter pre-wire: `?checks=gitlab.group.*,gitlab.repo.*`.

**Note:** GitLab self-hosted instances need a `base_url` field in `config_json_encrypted` — account for this in the OAuth connect flow.

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

- Production deploy: your host + TLS + DNS
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
