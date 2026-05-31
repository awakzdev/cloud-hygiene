# Deepsearch v4 — codebase map

Source: `deepsearch/v4.txt` (architecture review, 2026-05). Use this to track what shipped vs deferred.  
Read-only / policy-gen posture: [deepsearch-v6-map.md](./deepsearch-v6-map.md).

## Executive alignment (v4 → Vigil spine)

| v4 recommendation | Repo decision |
|-------------------|---------------|
| EventBridge + fixed-role Lambda for MVP remediation | **Superseded** — SSM Automation is now preferred |
| SSM Automation for enterprise | **Current** — `vigil-remediation-ssm.yaml`, `runner_type: ssm` |
| No Terraform `null_resource` / local-exec live remediation | **Aligned** — customer repo PR + automation only |
| No runtime IAM attach/detach | **Aligned** — fixed inline policies per family in runner |
| PR IaC only when resource match is deterministic | **Partial** — `tools/hclpatch`, S3 PAB + KMS rotation |
| WORM evidence in S3 Object Lock | **Wired** when `EVIDENCE_VAULT_ENABLED` |
| Demote raw Timeline as primary nav | **Partial** — `/history` compliance timeline; `/timeline` still exists |

## Feature inventory

| Area | Key paths | v4 status |
|------|-----------|-----------|
| Remediation plan + dispatch | `remediation_plan.py`, `remediation_dispatch.py`, `findings.py` | **Done** v2 fields; **dispatch** now seals `approval` block |
| Read-only generated policies | `accounts.py` | **Done** |
| Customer SSM Automation | `infra/cfn/vigil-remediation-ssm.yaml`, `remediation_dispatch.py` | **Done** for SG exact revoke + SSM plaintext secret |
| Terraform PR / hclpatch | `terraform_pr.py`, `hcl_patch.py`, `tools/hclpatch` | **Partial** — S3/KMS patch; SG scan-only |
| GitHub PR route | `POST …/iac/terraform-pr` | **Callable** (UI may still say automation-only for SG) |
| SSM remediation | `vigil-remediation-ssm.yaml` | **Done** for first modules |
| Evidence vault | `evidence_vault.py`, `evidence_pack.py` | **Done** upload + presign; docs synced in `evidence-vault.md` |
| Export audit trail | `evidence_exports` table | **Extended** — `report_id` + vault columns (migration 0034) |
| Compliance timeline | `compliance_scan_timeline.py`, `ComplianceHistory.tsx`, `HistoryDashboard.tsx` | **Partial** — KPI dashboard + charts shipped; see [history-dashboard.md](./history-dashboard.md) |
| Raw activity timeline | `Timeline.tsx`, `timeline_filters.py` | **Done** but not primary auditor story |
| Auditor share UI | presign in vault service | **Gap** — no approve-auditor → share record flow |
| LLM remediation | — | **None** (by design); `llms.txt` only |

## Remediation gaps (v4 § Event schema)

| Field / behavior | Status |
|----------------|--------|
| `approval_token`, `approved_by`, `approved_at` on dispatched plan | **Done** — `build_approved_remediation_plan()` on `POST …/remediation/dispatch` |
| GET `…/remediation-plan` preview | **No approval** (unsigned preview body unchanged) |
| `runner_type: ssm` | **Done** |
| Runner validates approval token | **Partial** — SSM validates schema/expiry/checksum; approval block is recorded in plan |
| Idempotency `plan_id` + execution store | **Done** — `remediation_executions` |

## Evidence vault gaps (v4 § storage model)

| v4 Postgres fields | Status |
|--------------------|--------|
| `report_id` | **Done** on `evidence_exports` |
| `s3_key` / URI, `version_id`, `object_lock_mode`, `retain_until` | **Done** on export row when vault upload succeeds |
| `shared_with`, `last_accessed_at` | **Gap** — auditor share flow |
| Customer bucket Option B | **Partial** — `org.settings["evidence_vault"]["customer_s3_uri"]` override in vault planner |

## CIS v5 — 40 Level 1 controls (high priority)

**Full spec:** [cis-v5-40-controls.md](./cis-v5-40-controls.md)

| Goal | Status |
|------|--------|
| 42 controls in `control_mappings.json` (matches `cis_v5_level1_matrix.json`) | **Done** |
| Scannable 1.1, 1.2, 1.18, 1.21 | **Done** — collectors + `run_scan` + CFN perms |
| **1 missing** automated parity | **1.11** partial (90d vs CIS 45d) — deepsearch should suggest next |
| 1.5, 1.10, 1.17 | **Manual** — documented; not scannable honestly today |
| Detection page CIS banner | **Removed** — matrix still in packs via `cis_benchmark_coverage.json` |

## History dashboard (UX — high priority)

**Full spec:** [history-dashboard.md](./history-dashboard.md)

| Shipped | Gap (deepsearch should suggest) |
|---------|--------------------------------|
| KPI cards, control status bar, change sparkline, posture trend chart | Per-control sparklines, scan cadence heatmap, framework overlay, PNG export |
| `scan_count` on timeline API | Collapsible timeline on mobile; infra events as chart series |

## Compliance control expand (UX)

**Search terms:** Controls page, expanded control, Auditor summary, Short answer, CC6.3

Expanded failing/passing controls use a single-audience flow (no SOC2 textbook paste):

| Section | Purpose |
|---------|---------|
| **Control status** | Pass/fail, finding count, scan coverage |
| **How Vigil evaluates** | Mapped check labels (what runs each scan) |
| **Evidence sources** | Snapshot / integration sources |
| **Findings** | Open findings by check (fail only) |
| **Auditor response** | Copyable Vigil-focused text (not `NARRATIVES` long form) |

Removed from UI: **Auditor summary**, **Short answer** (duplicated SOC2 boilerplate).

Code: `web/src/pages/Controls.tsx` — `ControlStatusBlock`, `ControlEvaluationBlock`, `buildQuestionnaireDraft()`.

## Policy generator (IAM last-accessed) — issue map

**Full write-up:** [policy-generator-iam-last-accessed.md](./policy-generator-iam-last-accessed.md)

| Topic | Summary |
|-------|---------|
| **Symptom** | Explorer shows service used (e.g. DynamoDB); generated policy omits it; Route53 may appear (has action telemetry). |
| **Cause** | Two IAM signals: `last_authenticated` (service) vs `actions_json` (per-action). Narrowing `Action: *` used only action-level → dropped service-only rows. |
| **Wrong fix** | Invent `service:*` (e.g. `dynamodb:*`) — rejected. |
| **Right fix** | (1) Collector: `TrackedActionsLastAccessed` + `ActionLastAccessed`; don’t null `actions_json` on sparse upsert. (2) Policy: `augment_used_actions_with_granted_for_service_only()` — keep **granted** APIs for service-only use; `policy_warnings` if only wildcards. (3) UI: `service_only_signal` badge. |
| **Code** | `iam_usage.py`, `accounts.py` (`generate_role_policy`), `last_accessed.py` |
| **User action** | Re-scan after collector fix; regenerate policy. |

---

## Docs drift (fixed in session 29)

| Doc | Was | Now |
|-----|-----|-----|
| `docs/evidence-vault.md` | "scaffold only" | Reflects wired upload + export metadata |
| `README.md` | v3 table only | v4 table added |
| Sample pack `vault_upload_plan.json` | `not_wired` | Notes real vault when enabled |

## MVP roadmap (from v4 — not all in one sprint)

1. **Done this pass:** vault docs, export vault columns, dispatch approval block, UI "Generate Audit Package" labels.
2. **Next:** History dashboard v2 (per-control trends, scan heatmap); auditor share record + read-only viewer; expand hclpatch beyond S3/KMS.
3. **Later:** SSM runbook packs; Terraform modules for customer remediation deploy (optional; CFN is fine today).

See also: [policy-generator-iam-last-accessed.md](./policy-generator-iam-last-accessed.md), [remediation-automation.md](./remediation-automation.md), [evidence-vault.md](./evidence-vault.md), [HANDOFF.md](../HANDOFF.md) session 29.
