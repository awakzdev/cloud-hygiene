# Evidence vault (WORM / immutable archive)

## Where WORM should live

WORM is **not** a feature inside the Postgres database or the downloadable ZIP alone. It is **object storage with Object Lock** (or an equivalent immutable store) written **once** when an evidence pack is finalized.

```
Scan → findings DB → build ZIP (+ checksum + optional signature)
                          ↓
              [evidence vault — optional, not wired yet]
                          ↓
         S3 object (Object Lock) + auditor read reference
```

### Option A — Vigil-operated vault (default env target)

- **Bucket:** your account, `EVIDENCE_VAULT_S3_URI=s3://vigil-evidence-vault/prod/`
- **WORM:** S3 Object Lock (Compliance or Governance mode) + retention days
- **Pros:** One-click for customers; auditors get a stable **object key** per export (`report_id`), not a mutable file.
- **Cons:** You operate retention, cost, and legal hold; data leaves customer AWS.

### Option B — Customer-owned bucket (enterprise)

- Customer creates a bucket with Object Lock; scan role gets **write-only** `PutObject` to `s3://customer-bucket/vigil/{org_id}/…`
- **Pros:** Data residency; customer owns immutability.
- **Cons:** CFN + policy work per account; harder onboarding.

### Option C — “Constant link” for auditors (usually **not** enough alone)

| Pattern | WORM? | Verdict |
|---------|-------|---------|
| Same HTTPS URL overwritten each week | No | Weak for Type II — auditor cannot prove what existed on sample date |
| New URL per export (`…/packs/{report_id}.zip`) | Only if bucket has Object Lock | Good **if** object is immutable |
| Presigned URL after customer clicks “Share with auditor” | Depends on object | Good **process**; pair with locked object + expiry on the URL, not on the object |
| Permanent public link | No | Do not use |

**Recommended auditor flow (when implemented):**

1. Customer exports pack → Vigil writes **immutable** object to vault S3.
2. Customer **approves** an auditor (email/domain) in Settings → Vigil mints a **time-limited** read token or presigned URL pointing at that **fixed** `s3_key` / `report_id`.
3. Auditor opens link → read-only GET; object behind it does not change.

The “constant link” is constant **per export** (per `report_id`), not one URL that always shows “latest”.

## Configuration (scaffold only)

See `api/app/services/evidence_vault.py` and `.env.example`:

- `EVIDENCE_VAULT_ENABLED` — master switch (default off)
- `EVIDENCE_VAULT_S3_URI` — base location for vault writes, e.g. `s3://my-bucket/vigil-evidence/`
- `EVIDENCE_VAULT_S3_REGION` — optional region override
- `EVIDENCE_VAULT_OBJECT_LOCK_MODE` — `GOVERNANCE` | `COMPLIANCE` (for future PutObject retention)
- `EVIDENCE_VAULT_RETENTION_DAYS` — retention hint for Object Lock
- `EVIDENCE_VAULT_AUDITOR_ACCESS_MODE` — `none` | `presigned` | `approved_link` (future)

Org-level override (future): `org.settings["evidence_vault"]["customer_s3_uri"]` for Option B.

## Implementation status

**Scaffold only** — parsing, key layout, and upload plans. No boto3 upload, no routes, no worker hook. Wire after bucket + IAM + legal review.
