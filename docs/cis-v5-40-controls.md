# CIS AWS Foundations v5 — 40 Level 1 controls (high priority)

**Search terms:** CIS 40, Detection coverage, `control_mappings.json`, `cis_v5_level1_matrix.json`, automated vs manual, CIS 1.1 1.2 1.18 1.21

**Priority:** Product goal is **40 v5 L1 controls mapped** in Compliance with **maximum scannable coverage**. Full CIS parity on every sub-requirement is not the same as 40 mapped controls.

## Targets

| Metric | Source | Goal |
|--------|--------|------|
| **40** | `CIS_V5_LEVEL1_TOTAL` in `cis_benchmark_coverage.py` | Official L1 control count (reference) |
| **Mapped** | Unique `control_id` in `api/data/control_mappings.json` (`framework: cis_aws_l1`) | **40** rows (deduped by control_id) |
| **Automated** | `cis_v5_level1_matrix.json` → `vigil_status: automated` | Scannable via Vigil checks (re-scan after deploy) |
| **Manual** | `vigil_status: manual` + `checks: []` | Listed for auditors; no scan finding |

## Recently added scannable checks (session)

| CIS | Check ID | Collector |
|-----|----------|-----------|
| 1.1 | `aws.account.contact_incomplete` | `collect_account_governance` (`account:GetContactInformation`) |
| 1.2 | `aws.account.security_contact_missing` | `collect_account_governance` (`account:GetAlternateContact` SECURITY) |
| 1.18 | `iam.server_certificate.expired` | `collect_iam_server_certificates` |
| 1.21 | `iam.cloudshell_full_access_granted` | IAM user/role attachments (existing `collect_iam`) |

CFN: `infra/cfn/vigil-readonly-role.yaml` — `AccountContacts`, `IamServerCertificates`.

Migration: `0035_cis_governance_checks.py` — `account_governance`, `iam_server_certificates`.

## Still manual (honest)

| CIS | Why |
|-----|-----|
| 1.5 | Hardware MFA vs virtual — IAM does not expose token type |
| 1.10 | No access keys at user **creation** — process/CloudTrail, not config snapshot |
| 1.17 | Instance roles for resource access — architecture review |

These remain in `control_mappings.json` with `checks: []` where mapped, or manual-only in matrix.

## UI

**Detection coverage** (`web/src/pages/DetectionCoverage.tsx`): no CIS banner in UI (packs/PDF still include `cis_benchmark_coverage.json`). Matrix today: **39** automated, **0** partial, **3** manual. CIS **1.11** uses dedicated 45-day checks (`iam.user.credentials_unused_45d`, `iam.access_key.unused_45d`); 90-day hygiene checks remain for SOC2/ISO only.

## After deploy

1. `alembic upgrade head` (0035)
2. Update customer CFN stack (new IAM + account API actions)
3. Re-scan accounts
4. `seed_controls` / scan loads `control_mappings.json` into DB

## Related

- [deepsearch-v4-map.md](./deepsearch-v4-map.md)
- [deepsearch-v6-map.md](./deepsearch-v6-map.md) — CIS 1.11 detection vs remediation split
- [policy-generator-iam-last-accessed.md](./policy-generator-iam-last-accessed.md)
