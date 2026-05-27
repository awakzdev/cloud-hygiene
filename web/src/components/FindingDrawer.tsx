import { useState, useEffect, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { BLAST_RADIUS_CHECKS } from "../data/blastRadiusChecks";

type Finding = {
  id: string;
  check_id: string;
  resource_arn: string;
  title: string;
  severity: string;
  risk_score: number;
  status: string;
  evidence: Record<string, unknown>;
  first_seen: string;
  last_seen: string;
  exception_reason?: string | null;
  exception_approved_by?: string | null;
  exception_expires_at?: string | null;
};

const sevHeaderBadge: Record<string, string> = {
  critical: "bg-red-50 text-red-700 border-red-200",
  high: "bg-red-50 text-red-600 border-red-200",
  medium: "bg-amber-50 text-amber-700 border-amber-200",
  low: "bg-zinc-100 text-zinc-500 border-zinc-200",
};

const sevWash: Record<string, string> = {
  critical: "from-red-100 to-stone-50",
  high: "from-red-50 to-stone-50",
  medium: "from-amber-50 to-stone-50",
  low: "from-slate-50 to-stone-50",
};

const sevStep: Record<string, string> = {
  critical: "bg-stone-700 text-white",
  high: "bg-stone-700 text-white",
  medium: "bg-stone-700 text-white",
  low: "bg-stone-700 text-white",
};

type Remediation = {
  why: string;
  console: string[];
  cli: string;
  risk: string;
};

const remediations: Record<string, Remediation> = {
  "iam.user.no_mfa": {
    why: "Users without MFA can be fully compromised with only a stolen password. A second factor an attacker must physically control is the single most effective control against credential phishing.",
    console: ["Open IAM → Users → select the user", 'Click "Security credentials" tab', 'Under "Multi-factor authentication", click "Assign MFA device"', "Follow the wizard to register a virtual or hardware MFA"],
    cli: `aws iam create-virtual-mfa-device --virtual-mfa-device-name <name> --outfile /tmp/qr.png --bootstrap-method QRCodePNG

aws iam enable-mfa-device --user-name <user> --serial-number <arn> --authentication-code1 <code1> --authentication-code2 <code2>`,
    risk: "Until MFA is enabled, a leaked password can be enough to sign in to the console.",
  },
  "iam.user.inactive_90d": {
    why: "Inactive accounts have no baseline of normal activity, making compromise invisible. Attackers who obtain credentials can operate undetected for months.",
    console: ["Open IAM → Users → select the user", 'Click "Security credentials" tab', 'Under "Console sign-in", click "Disable console access"', "Confirm with the team, then delete the user if no longer needed"],
    cli: `# Disable console access
aws iam delete-login-profile --user-name <user>

# Or delete the user entirely (remove keys + policies first)
aws iam delete-user --user-name <user>`,
    risk: "Stale console users should be disabled or removed after ownership is confirmed.",
  },
  "iam.access_key.unused_90d": {
    why: "Unused access keys are typically abandoned in scripts, CI config, or developer machines — often forgotten and never rotated. They're persistent credentials with no expiry.",
    console: ["Open IAM → Users → select the user", 'Click "Security credentials" tab', "Find the key under Access Keys", 'Click "Deactivate" first to verify nothing breaks, then "Delete"'],
    cli: `# Deactivate first, confirm nothing breaks, then delete
aws iam update-access-key --access-key-id <key-id> --status Inactive --user-name <user>

aws iam delete-access-key --access-key-id <key-id> --user-name <user>`,
    risk: "Forgotten keys are long-lived credentials. Deactivate first, then delete after confirming nothing still depends on them.",
  },
  "iam.access_key.no_rotation_90d": {
    why: "This access key is older than the configured key-age threshold. Long-lived keys are harder to reason about because they may be stored in old scripts, CI secrets, or developer machines.",
    console: ["Open IAM → Users → select the user", 'Click "Security credentials" tab', "Create a replacement access key for the current workload", "Update the workload secret, then deactivate and delete the old key"],
    cli: `# Create a replacement key, update the workload, then retire the old one
aws iam create-access-key --user-name <user>

aws iam update-access-key --access-key-id <key-id> --status Inactive --user-name <user>

aws iam delete-access-key --access-key-id <key-id> --user-name <user>`,
    risk: "This is a key hygiene finding. Validate where the key is used before rotation or deletion.",
  },
  "iam.access_key.multiple_active": {
    why: "The user has more than one active access key. That can be valid during rotation, but persistent duplicate keys make ownership and cleanup harder.",
    console: ["Open IAM → Users → select the user", 'Click "Security credentials" tab', "Review both active access keys, including creation and last-used dates", "Deactivate and delete the key that is no longer needed"],
    cli: `# Review active keys for the user
aws iam list-access-keys --user-name <user>

# Deactivate the unused key first, then delete it
aws iam update-access-key --access-key-id <key-id> --status Inactive --user-name <user>
aws iam delete-access-key --access-key-id <key-id> --user-name <user>`,
    risk: "Treat this as a review item unless the extra key is clearly stale or unauthorized.",
  },
  "iam.role.unassumed_90d": {
    why: "Roles not assumed in 90+ days are often orphaned. They add attack surface and may carry policies that nobody actively owns.",
    console: ["Open IAM → Roles → select the role", "Review the trust policy and attached policies", "Confirm with the owning team whether the role is still needed", 'If not needed, click "Delete" at the top of the role page'],
    cli: `# Check last activity
aws iam get-role --role-name <role-name> --query 'Role.RoleLastUsed'

# Delete if confirmed unused
aws iam delete-role --role-name <role-name>`,
    risk: "Unused roles should be removed after ownership and service dependencies are confirmed.",
  },
  "iam.role.wildcard_action": {
    why: 'Action: "*" in an inline policy is admin-like unless constrained by resource, condition, or permissions boundary. It should be reviewed and scoped to the actions the role actually needs.',
    console: ["Open IAM → Roles → select the role", 'Click "Permissions" tab → find the inline policy', 'Click "Edit" on the inline policy', 'Replace `"Action": "*"` with the specific actions the role actually needs', "Use IAM Access Analyzer to generate a minimal policy from CloudTrail history"],
    cli: `# Review the inline policy
aws iam get-role-policy --role-name <role-name> --policy-name <policy-name>

# Replace with scoped policy
aws iam put-role-policy --role-name <role-name> --policy-name <policy-name> --policy-document file://scoped-policy.json`,
    risk: "Broad wildcard permissions increase blast radius if the role is compromised or misused.",
  },
  "iam.perm.granted_vs_used": {
    why: "This role has write or mutating actions in its policies that have no recorded usage in the last 90 days (action-level data from IAM last-accessed). Removing unused write permissions reduces the blast radius if the role is compromised.",
    console: [
      "Open IAM → Roles → select the role → Permissions tab",
      "Review the actions listed in the finding evidence",
      "For each unused action, remove it from the role's inline or attached policies",
      "Use the 'Generate' button in the What If? tab to produce a least-privilege policy based on recorded usage",
      "Test the workload after each change to confirm functionality",
    ],
    cli: `# View current role policy
aws iam get-role-policy --role-name <role-name> --policy-name <policy-name>

# Update with unused write actions removed
aws iam put-role-policy --role-name <role-name> --policy-name <policy-name> --policy-document file://scoped-policy.json`,
    risk: "Roles with unused write actions can modify or delete resources they have no business touching — removing them shrinks the attack surface with no operational impact.",
  },
  "iam.policy.unattached": {
    why: "Customer-managed policies that are not attached to any user, group, or role are dead weight. They may contain overly permissive statements written for a workload that no longer exists, and they clutter the policy namespace making access reviews harder.",
    console: [
      "Open IAM → Policies → filter to Customer managed",
      "Sort by Attached entities to find policies with 0 attachments",
      "Review each policy — confirm it is no longer needed",
      'Click the policy → "Delete" (IAM will block deletion if it has any attachments)',
    ],
    cli: `# List customer-managed policies with 0 attachments
aws iam list-policies --scope Local --query 'Policies[?AttachmentCount==\`0\`].[PolicyName,Arn]' --output table

# Delete a specific unattached policy (fails if still attached)
aws iam delete-policy --policy-arn <policy-arn>`,
    risk: "Stale policies are low-risk but add noise to access reviews and may be accidentally re-attached with broad permissions later.",
  },
  "iam.policy.wildcard_resource": {
    why: "This policy grants write or sensitive actions on Resource: \"*\" — meaning they apply to every resource in the account. Even when the action list is explicit, a wildcard resource makes the permission unreasonably broad and hard to audit.",
    console: [
      "Open IAM → Roles → select the role → Permissions tab",
      "Find the policy listed in the finding evidence",
      "For each flagged statement, replace Resource: '*' with the specific ARN(s) the role actually needs",
      "If specific ARNs are unknown, use IAM Access Analyzer to generate a least-privilege policy from CloudTrail history",
      "Save the updated policy and verify the workload still functions",
    ],
    cli: `# Review the flagged policy
aws iam get-role-policy --role-name <role-name> --policy-name <policy-name>

# Replace with scoped version (Resource narrowed to specific ARNs)
aws iam put-role-policy --role-name <role-name> --policy-name <policy-name> --policy-document file://scoped-policy.json

# For customer-managed attached policies
aws iam get-policy-version --policy-arn <policy-arn> --version-id v1
aws iam create-policy-version --policy-arn <policy-arn> --policy-document file://scoped-policy.json --set-as-default`,
    risk: "Wildcard resources on write actions mean the role can modify or delete any resource of that type in the account — not just the ones it should own.",
  },
  "iam.role.unused_services_90d": {
    why: "This role has permissions to services it has not recently used according to IAM service-last-accessed data. Those permissions may be removable, but should be validated against workload behavior and data freshness.",
    console: ["Open IAM → Roles → select the role", 'Click "Permissions" tab → find inline policies under "Permissions policies"', "Review each inline policy and remove statements for the unused services listed below", "Save the updated policy (or delete it entirely if all its services are unused)"],
    cli: `# List inline policies on the role
aws iam list-role-policies --role-name <role-name>

# Get a specific inline policy
aws iam get-role-policy --role-name <role-name> --policy-name <policy-name>

# Replace with scoped version (unused service statements removed)
aws iam put-role-policy --role-name <role-name> --policy-name <policy-name> --policy-document file://scoped-policy.json

# Or delete entirely if all permissions are unused
aws iam delete-role-policy --role-name <role-name> --policy-name <policy-name>`,
    risk: "Unused service permissions increase blast radius. Removing them improves least privilege after validation.",
  },
  "iam.role.trust_wildcard": {
    why: 'This role trust policy allows any AWS principal. That is high risk unless strong conditions narrow who can assume the role.',
    console: ["Open IAM → Roles → select the role", 'Click "Trust relationships"', "Review the principal and any conditions", "Replace wildcard principals with specific AWS accounts, roles, services, or federated identities"],
    cli: `# Review the role trust policy
aws iam get-role --role-name <role-name> --query 'Role.AssumeRolePolicyDocument'

# Update the trust policy after scoping Principal and Conditions
aws iam update-assume-role-policy --role-name <role-name> --policy-document file://trust-policy.json`,
    risk: "Wildcard trust can expose a role to unintended principals, especially when conditions are missing or weak.",
  },

  "iam.root.has_access_keys": {
    why: "Root account access keys bypass all IAM policies and have unrestricted access to every service and resource. There is no legitimate use case for programmatic root credentials.",
    console: ["Sign in as root", "Open IAM → Security credentials (via account menu top-right)", 'Under "Access keys", delete all active keys', "Create an IAM admin user for any automation that previously used root credentials"],
    cli: `# List root access keys (requires root credentials or AWS Support)
aws iam list-access-keys

# Delete each active root key
aws iam delete-access-key --access-key-id <key-id>`,
    risk: "Root access keys cannot be scoped with policies. Anyone with these credentials has full, unrevokable control of the account.",
  },

  "iam.root.no_mfa": {
    why: "The root account has no IAM policy restrictions. If its password is compromised without MFA, an attacker has unrestricted access to the entire account.",
    console: ["Sign in as root", "Open IAM → Security credentials (via account menu top-right)", 'Under "Multi-factor authentication", click "Assign MFA device"', "Register a hardware MFA device — virtual MFA is acceptable but hardware is preferred for root"],
    cli: `# MFA for root must be configured via the console — the AWS CLI cannot enable root MFA directly.
# Sign in as root and use the Security credentials page.`,
    risk: "Root without MFA is the highest-severity finding possible. Prioritise this above everything else.",
  },

  "iam.root.usage": {
    why: "Root is the most privileged identity in AWS — all IAM policies and SCPs are bypassed. Any API call using root credentials is a red flag. Engineers should never use root for day-to-day work.",
    console: ["Sign in as root → open CloudTrail → Event history", "Identify the event(s) that triggered this finding — review the event name, source IP, and user agent", "Determine whether the action required root or could have been done with an IAM user/role", "Create an IAM admin user or role for those operations and use root only for tasks that explicitly require it (e.g. closing the account, managing root MFA, changing account plan)"],
    cli: `# View recent root-initiated CloudTrail events
aws cloudtrail lookup-events \\
  --lookup-attributes AttributeKey=Username,AttributeValue=root \\
  --start-time $(date -u -d "90 days ago" +%Y-%m-%dT%H:%M:%SZ) \\
  --query 'Events[*].{Time:EventTime,Event:EventName,IP:CloudTrailEvent}' \\
  --output table`,
    risk: "Root activity should be extremely rare. Recurring root use indicates a process gap — automate those tasks with scoped IAM roles instead.",
  },

  "s3.bucket.public_access_not_blocked": {
    why: "S3 Block Public Access is an account and bucket-level guard against accidentally making objects public via ACLs or bucket policies. One or more of the four settings is currently off.",
    console: ["Open S3 → select the bucket", 'Click "Permissions" tab', 'Under "Block public access", click "Edit"', "Enable all four settings and save"],
    cli: `# Enable all four Block Public Access settings
aws s3api put-public-access-block \\
  --bucket <bucket-name> \\
  --public-access-block-configuration '{
    "BlockPublicAcls": true,
    "IgnorePublicAcls": true,
    "BlockPublicPolicy": true,
    "RestrictPublicBuckets": true
  }'`,
    risk: "Without this, a misconfigured ACL or bucket policy can silently expose objects to the internet.",
  },

  "s3.account.public_access_not_blocked": {
    why: "Account-level S3 Block Public Access is the broad guardrail that prevents accidental public bucket ACLs or policies across the entire account.",
    console: ["Open S3 → Block Public Access settings for this account", 'Click "Edit"', "Enable all four Block Public Access settings", "Save changes"],
    cli: `aws s3control put-public-access-block \\
  --account-id <account-id> \\
  --public-access-block-configuration \\
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`,
    risk: "Without the account-level guardrail, a single bucket policy or ACL mistake can expose data publicly.",
  },

  "s3.bucket.no_https_policy": {
    why: "A deny-HTTP bucket policy is defense in depth — it blocks the rare client that still uses http:// even though AWS SDKs, CLI, and Terraform default to HTTPS. Auditors often expect this as evidence of encryption in transit.",
    console: ["Open S3 → select the bucket", 'Click "Permissions" tab → "Bucket policy"', "Add or update the policy to include a Deny statement with the condition below", "Save the policy"],
    cli: `# Apply an HTTPS-only bucket policy
aws s3api put-bucket-policy --bucket <bucket-name> --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyHTTP",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": [
      "arn:aws:s3:::<bucket-name>",
      "arn:aws:s3:::<bucket-name>/*"
    ],
    "Condition": {
      "Bool": { "aws:SecureTransport": "false" }
    }
  }]
}'`,
    risk: "Low practical blast radius for modern apps. Main value is compliance (CIS/SOC2) and blocking misconfigured legacy scripts that hard-code http:// URLs.",
  },

  "s3.bucket.no_kms": {
    why: "Server-side encryption with KMS (SSE-KMS) uses a customer-managed key, giving you control over key rotation, access policies, and audit logs. SSE-S3 uses an AWS-managed key you cannot audit or revoke.",
    console: ["Open S3 → select the bucket", 'Click "Properties" tab', 'Under "Default encryption", click "Edit"', 'Select "SSE-KMS", choose an existing CMK or create a new one, and save'],
    cli: `# Enable SSE-KMS with an existing CMK
aws s3api put-bucket-encryption --bucket <bucket-name> \\
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "<kms-key-arn>"
      },
      "BucketKeyEnabled": true
    }]
  }'`,
    risk: "SSE-S3 protects data at rest but the key is fully managed by AWS — you cannot restrict, rotate, or audit it independently.",
  },

  "s3.bucket.no_logging": {
    why: "Server access logging records every request made to a bucket — who accessed what, when, and from where. Without it there is no audit trail for forensics or compliance.",
    console: [
      "Create a central logging bucket (e.g. my-access-logs-<account-id>) if one does not exist",
      "On the logging bucket, set ownership to 'Bucket owner preferred' under Object Ownership",
      "Open the source bucket → Properties tab",
      'Under "Server access logging", click Edit',
      "Enable logging and set the target bucket and a prefix (e.g. the source bucket name)",
    ],
    cli: `# 1. Create a dedicated logging bucket (skip if it already exists)
aws s3api create-bucket --bucket my-access-logs-<account-id> --region us-east-1

# 2. Set object ownership so the log delivery service can write
aws s3api put-bucket-ownership-controls \\
  --bucket my-access-logs-<account-id> \\
  --ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerPreferred}]'

# 3. Enable access logging on the source bucket
aws s3api put-bucket-logging \\
  --bucket <bucket-name> \\
  --bucket-logging-status '{
    "LoggingEnabled": {
      "TargetBucket": "my-access-logs-<account-id>",
      "TargetPrefix": "<bucket-name>/"
    }
  }'`,
    risk: "Without access logs you cannot detect data exfiltration, unauthorized access, or misconfigured permissions after the fact.",
  },

  "kms.key.no_rotation": {
    why: "Automatic key rotation replaces the backing key material annually. If the key material is ever exposed, rotation limits the window of exposure.",
    console: ["Open KMS → Customer managed keys", "Select the key", 'Click "Key rotation" tab', 'Enable "Automatically rotate this KMS key every year"'],
    cli: `# Enable annual automatic rotation
aws kms enable-key-rotation --key-id <key-id>

# Confirm rotation is enabled
aws kms get-key-rotation-status --key-id <key-id>`,
    risk: "Keys that never rotate accumulate exposure over time. AWS retains old backing keys so existing ciphertexts remain decryptable after rotation.",
  },
  "cloudtrail.trail.not_enabled": {
    why: "Without CloudTrail, there is no record of API calls. Incidents cannot be investigated, compliance cannot be proven, and unauthorized access may go undetected.",
    console: ["Open CloudTrail → Trails → Create trail", "Set a name, enable logging in all regions (multi-region trail)", "Select or create an S3 bucket for log delivery", 'Enable "Log file validation" and save'],
    cli: `# Create a multi-region trail
aws cloudtrail create-trail \\
  --name vigil-audit \\
  --s3-bucket-name <your-log-bucket> \\
  --is-multi-region-trail \\
  --enable-log-file-validation

# Start logging
aws cloudtrail start-logging --name vigil-audit`,
    risk: "Without audit logs, compromise may go undetected and incident response is severely hampered.",
  },
  "cloudtrail.trail.no_log_validation": {
    why: "Without log file validation, CloudTrail logs can be silently modified or deleted. Attackers who compromise log storage can erase evidence of their activity.",
    console: ["Open CloudTrail → Trails → select the trail", 'Under "General details", click "Edit"', 'Enable "Log file validation"', "Save changes"],
    cli: `# Enable log file integrity validation on an existing trail
aws cloudtrail update-trail \\
  --name <trail-name> \\
  --enable-log-file-validation

# Verify
aws cloudtrail get-trail --name <trail-name>`,
    risk: "Tampered logs are indistinguishable from authentic ones without validation enabled.",
  },
  "cloudtrail.trail.no_kms": {
    why: "CloudTrail log files should be encrypted with a customer-managed KMS key so access to audit history can be controlled, monitored, and revoked independently from the S3 bucket.",
    console: [
      "Open CloudTrail → Trails → select the trail",
      'Under "General details", click "Edit"',
      "Enable SSE-KMS encryption",
      "Choose a customer-managed KMS key for log encryption",
      "Save changes",
    ],
    cli: `aws cloudtrail update-trail \\
  --name <trail-name> \\
  --kms-key-id <kms-key-arn>`,
    risk: "Unencrypted audit logs weaken evidence integrity and make it harder to prove tight access control over security history.",
  },
  "guardduty.detector.not_enabled": {
    why: "GuardDuty is AWS's threat detection service. Without it, there is no automated detection of port scans, credential abuse, crypto-mining, or data exfiltration.",
    console: ["Open GuardDuty in each affected region listed in Scan details", 'Click "Get Started" then "Enable GuardDuty"', "Alternatively, use AWS Organizations to enable GuardDuty in all regions centrally"],
    cli: `# Enable GuardDuty in each disabled region (repeat per region)
aws guardduty create-detector --enable --region <region>

# Or enable across all regions using a loop
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  aws guardduty create-detector --enable --region $region
done`,
    risk: "Threats such as compromised credentials, unusual API calls, and lateral movement go undetected.",
  },
  "vpc.flow_logs.not_enabled": {
    why: "VPC flow logs capture accepted and rejected network traffic. Without them, lateral movement, port scans, and data exfiltration are invisible at the network layer.",
    console: ["Open VPC → Your VPCs → select the VPC", 'Click "Flow logs" tab → "Create flow log"', 'Set filter to "All", destination to CloudWatch Logs or S3', "Select or create an IAM role for delivery and save"],
    cli: `# Create a flow log to CloudWatch Logs
aws ec2 create-flow-logs \\
  --resource-type VPC \\
  --resource-ids <vpc-id> \\
  --traffic-type ALL \\
  --log-destination-type cloud-watch-logs \\
  --log-group-name /aws/vpc/flowlogs \\
  --deliver-logs-permission-arn <delivery-role-arn>`,
    risk: "Network-level attacks and lateral movement are invisible without flow logs.",
  },
  "ec2.security_group.unrestricted_ssh": {
    why: "SSH open to 0.0.0.0/0 exposes instances to brute-force and credential-stuffing attacks from the entire internet.",
    console: ["Open EC2 → Security Groups → select the group", 'Click "Inbound rules" tab → "Edit inbound rules"', "Find the rule for port 22 with source 0.0.0.0/0 or ::/0", "Replace with a specific IP range, or remove and use Systems Manager Session Manager instead"],
    cli: `# Remove the unrestricted SSH rule
aws ec2 revoke-security-group-ingress \\
  --group-id <sg-id> \\
  --protocol tcp \\
  --port 22 \\
  --cidr 0.0.0.0/0

# Optionally restrict to a known IP
aws ec2 authorize-security-group-ingress \\
  --group-id <sg-id> \\
  --protocol tcp \\
  --port 22 \\
  --cidr <your-ip>/32`,
    risk: "Open SSH is continuously probed. A single weak credential or leaked key is sufficient for full instance compromise.",
  },
  "ec2.security_group.unrestricted_rdp": {
    why: "RDP open to 0.0.0.0/0 is a primary attack vector for Windows instances and is actively exploited by ransomware operators.",
    console: ["Open EC2 → Security Groups → select the group", 'Click "Inbound rules" tab → "Edit inbound rules"', "Find the rule for port 3389 with source 0.0.0.0/0 or ::/0", "Replace with a specific IP range, or use AWS Fleet Manager for browser-based RDP"],
    cli: `# Remove the unrestricted RDP rule
aws ec2 revoke-security-group-ingress \\
  --group-id <sg-id> \\
  --protocol tcp \\
  --port 3389 \\
  --cidr 0.0.0.0/0

# Optionally restrict to a known IP
aws ec2 authorize-security-group-ingress \\
  --group-id <sg-id> \\
  --protocol tcp \\
  --port 3389 \\
  --cidr <your-ip>/32`,
    risk: "Exposed RDP is a leading cause of ransomware incidents. The port is constantly scanned by automated attackers.",
  },
  "rds.instance.publicly_accessible": {
    why: "A publicly accessible RDS instance can be reached directly from the internet. Combined with weak credentials or an unpatched vulnerability, this is a direct path to data exfiltration.",
    console: ["Open RDS → Databases → select the instance", 'Click "Modify"', 'Under "Connectivity", set "Publicly accessible" to No', 'Click "Continue" and apply immediately or during the next maintenance window'],
    cli: `# Disable public accessibility
aws rds modify-db-instance \\
  --db-instance-identifier <instance-id> \\
  --no-publicly-accessible \\
  --apply-immediately`,
    risk: "Direct internet exposure combines with database credentials — one exposure is enough for a full data breach.",
  },
  "rds.instance.no_encryption": {
    why: "RDS encryption cannot be enabled on a running instance. An unencrypted instance stores data as plaintext on disk — a snapshot or EBS volume leak exposes raw data.",
    console: [
      "Open RDS → Databases → select the instance",
      'Click "Actions" → "Take snapshot" to create a backup',
      "Open RDS → Snapshots → select the snapshot",
      'Click "Actions" → "Copy snapshot", enable encryption, choose a KMS key',
      'Restore the encrypted snapshot via "Actions" → "Restore snapshot"',
      "Validate the new instance, update application connection strings, then delete the old instance",
    ],
    cli: `# Step 1: snapshot the current instance
aws rds create-db-snapshot \\
  --db-instance-identifier <instance-id> \\
  --db-snapshot-identifier <snapshot-id>

# Step 2: copy with encryption enabled
aws rds copy-db-snapshot \\
  --source-db-snapshot-identifier <snapshot-id> \\
  --target-db-snapshot-identifier <encrypted-snapshot-id> \\
  --kms-key-id <kms-key-arn>

# Step 3: restore to a new encrypted instance
aws rds restore-db-instance-from-db-snapshot \\
  --db-instance-identifier <new-instance-id> \\
  --db-snapshot-identifier <encrypted-snapshot-id>`,
    risk: "Unencrypted storage means any physical disk access or snapshot leak exposes plaintext database contents.",
  },
  "rds.instance.no_automated_backup": {
    why: "Automated backups provide point-in-time recovery. Without them, accidental deletion, bad migrations, or data corruption can become permanent data loss.",
    console: [
      "Open RDS → Databases → select the instance",
      'Click "Modify"',
      "Set Backup retention period to at least 7 days",
      "Choose a backup window that avoids peak traffic",
      'Click "Continue" and apply during the next maintenance window unless urgent',
    ],
    cli: `aws rds modify-db-instance \\
  --db-instance-identifier <instance-id> \\
  --backup-retention-period 7 \\
  --preferred-backup-window 03:00-04:00`,
    risk: "No automated backups means no point-in-time recovery. Operational mistakes or corruption may require manual snapshot rollback, if any snapshot exists.",
  },
  "dynamodb.table.no_encryption": {
    why: "Tables without explicit encryption at rest rely on legacy defaults. Enabling SSE-KMS or AWS-owned encryption protects item data on disk and satisfies auditor expectations for data-at-rest controls.",
    console: [
      "Open DynamoDB → Tables → select the table",
      'Open the "Additional settings" tab',
      'Under "Encryption at rest", click "Manage encryption"',
      'Choose "Owned by Amazon DynamoDB" or "AWS managed key (aws/dynamodb)" for the simplest path',
      "For a customer-managed key, select your KMS key and confirm IAM roles can use it",
      "Save — the table stays online during the update",
    ],
    cli: `# Enable encryption in place (AWS managed DynamoDB key)
aws dynamodb update-table \\
  --table-name <table-name> \\
  --region <region> \\
  --sse-specification Enabled=true,SSEType=KMS,KMSMasterKeyId=alias/aws/dynamodb

# Or use AWS-owned encryption (AES256)
aws dynamodb update-table \\
  --table-name <table-name> \\
  --region <region> \\
  --sse-specification Enabled=true,SSEType=AES256`,
    risk: "Unencrypted tables store data without explicit at-rest protection. Encryption can be enabled in place, but customer-managed KMS keys require kms:Decrypt on consuming roles.",
  },
  "dynamodb.table.no_pitr": {
    why: "Point-in-time recovery (PITR) provides continuous backups and restore to any second within the last 35 days. Without it, accidental deletes or bad writes require manual on-demand backups — if any exist.",
    console: [
      "Open DynamoDB → Tables → select the table",
      'Open the "Backups" tab',
      'Under "Point-in-time recovery (PITR)", click "Edit"',
      "Enable PITR and save",
    ],
    cli: `aws dynamodb update-continuous-backups \\
  --table-name <table-name> \\
  --region <region> \\
  --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true`,
    risk: "Without PITR, table data loss from accidental deletes or application bugs may be irreversible.",
  },
  "s3.bucket.no_default_encryption": {
    why: "Without default encryption, objects uploaded without an explicit encryption header are stored unencrypted. Default bucket encryption applies SSE to every new object automatically.",
    console: [
      "Open S3 → select the bucket",
      'Open the "Properties" tab → "Default encryption" → Edit',
      "Enable SSE-S3 (AES-256) or SSE-KMS with your preferred key",
      "Save — only affects new uploads; existing objects are unchanged",
    ],
    cli: `aws s3api put-bucket-encryption \\
  --bucket <bucket-name> \\
  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"},"BucketKeyEnabled":true}]}'`,
    risk: "Existing objects are not retroactively encrypted. Re-upload or use S3 Batch Operations if you need to encrypt historical data.",
  },
  "s3.bucket.no_mfa_delete": {
    why: "With versioning enabled but MFA Delete off, a compromised IAM principal can permanently delete all object versions without a second factor. MFA Delete requires root credentials to enable or disable.",
    console: [
      "Sign in as the root user (MFA Delete cannot be enabled by IAM users)",
      "Open S3 → select the bucket → Properties",
      'Under "Bucket Versioning", click Edit',
      "Enable MFA Delete and provide your root MFA device serial and two consecutive codes",
    ],
    cli: `# MFA Delete requires root credentials
aws s3api put-bucket-versioning \\
  --bucket <bucket-name> \\
  --versioning-configuration Status=Enabled,MFADelete=Enabled \\
  --mfa "<root-mfa-serial> <code1> <code2>"`,
    risk: "Disabling MFA Delete later also requires root MFA. Treat this as a permanent hardening step once enabled.",
  },
  "ec2.ebs.snapshot_public": {
    why: "Public EBS snapshots can be copied or mounted by any AWS account worldwide. They may contain full disk images with credentials, keys, or customer data.",
    console: [
      "Open EC2 → Snapshots → select the snapshot",
      'Click "Actions" → "Modify snapshot permissions"',
      'Remove any "Groups" entry (e.g. all) and confirm only your account ID is listed',
      "If the snapshot is no longer needed, delete it",
    ],
    cli: `# Remove public access — allow only this account
aws ec2 modify-snapshot-attribute \\
  --snapshot-id <snapshot-id> \\
  --region <region> \\
  --attribute createVolumePermission \\
  --operation-type remove \\
  --group-names all

# Verify permissions
aws ec2 describe-snapshot-attribute \\
  --snapshot-id <snapshot-id> \\
  --region <region> \\
  --attribute createVolumePermission`,
    risk: "Public snapshots may already have been copied by external accounts — removing access stops new copies but not existing ones.",
  },
  "ec2.ebs.snapshot_unencrypted": {
    why: "Unencrypted snapshots store block data in plaintext. Anyone with snapshot access (including after a cross-account share) can read the full disk contents.",
    console: [
      "Open EC2 → Snapshots → select the snapshot",
      'Click "Actions" → "Copy snapshot"',
      "Enable encryption and choose a KMS key",
      "After validating the encrypted copy, delete the original unencrypted snapshot",
    ],
    cli: `aws ec2 copy-snapshot \\
  --source-region <region> \\
  --source-snapshot-id <snapshot-id> \\
  --region <region> \\
  --description "Encrypted copy" \\
  --encrypted \\
  --kms-key-id alias/aws/ebs

# After validation, delete the original
aws ec2 delete-snapshot --snapshot-id <snapshot-id> --region <region>`,
    risk: "Copying large snapshots takes time and incurs storage cost for both copies until the original is deleted.",
  },
  "ec2.ami.public": {
    why: "A public AMI exposes your machine image to every AWS account. Images may contain hardcoded secrets, internal tooling, or proprietary code.",
    console: [
      "Open EC2 → AMIs → select the AMI",
      'Click "Actions" → "Modify image permissions"',
      'Set visibility to "Private" (remove all and add only your account if needed)',
      "Deregister the AMI if it was shared accidentally and is no longer needed",
    ],
    cli: `# Make AMI private (this account only)
aws ec2 modify-image-attribute \\
  --image-id <image-id> \\
  --region <region> \\
  --launch-permission '{"Remove":[{"Group":"all"}]}'

# Verify
aws ec2 describe-image-attribute \\
  --image-id <image-id> \\
  --region <region> \\
  --attribute launchPermission`,
    risk: "If the AMI was public, assume it may have been copied — rotate any secrets baked into the image.",
  },
  "cloudtrail.trail.s3_bucket_public": {
    why: "CloudTrail logs contain every API call in your account. A public S3 bucket receiving those logs exposes your full operational history to the internet.",
    console: [
      "Identify the S3 bucket receiving CloudTrail logs (CloudTrail → Trails → select trail → Storage location)",
      "Open S3 → select that bucket → Permissions",
      "Enable all four Block Public Access settings",
      "Review the bucket policy — remove any Principal: * grants",
      "Confirm the bucket is not listed as publicly accessible in S3 → Access Points or ACLs",
    ],
    cli: `# Block all public access on the CloudTrail log bucket
aws s3api put-public-access-block \\
  --bucket <bucket-name> \\
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`,
    risk: "Audit logs may already have been downloaded if the bucket was public. Treat this as a potential data breach and rotate sensitive credentials.",
  },
  "cloudtrail.trail.no_cloudwatch_logs": {
    why: "CloudWatch Logs integration enables real-time alerting on suspicious API activity. S3-only delivery delays detection until logs are delivered and queried.",
    console: [
      "Open CloudTrail → Trails → select the trail",
      'Click "Edit" → expand "CloudWatch Logs"',
      "Create or select a CloudWatch Logs log group",
      "Attach the CloudTrail service role (or create one with logs:CreateLogStream and logs:PutLogEvents)",
      "Save and verify events appear in the log group within a few minutes",
    ],
    cli: `# Create log group and enable CloudWatch delivery (requires CloudTrail service role)
aws logs create-log-group --log-group-name CloudTrail/<trail-name> --region <region>

aws cloudtrail update-trail \\
  --name <trail-name> \\
  --cloud-watch-logs-log-group-arn arn:aws:logs:<region>:<account-id>:log-group:CloudTrail/<trail-name>:* \\
  --cloud-watch-logs-role-arn <cloudtrail-cloudwatch-role-arn> \\
  --region <region>`,
    risk: "CloudWatch Logs ingestion adds cost (~$0.50/GB). Set a retention period on the log group to control spend.",
  },
  "cloudtrail.trail.s3_bucket_no_logging": {
    why: "The S3 bucket storing CloudTrail logs should have server access logging enabled. Without it, access to your audit trail itself is not recorded.",
    console: [
      "Identify the S3 bucket receiving CloudTrail logs",
      "Create a separate logging target bucket (do not log the log bucket into itself)",
      "Open the CloudTrail bucket → Properties → Server access logging → Edit",
      "Enable logging to the target bucket with a clear prefix (e.g. cloudtrail-access-logs/)",
    ],
    cli: `aws s3api put-bucket-logging \\
  --bucket <bucket-name> \\
  --bucket-logging-status '{"LoggingEnabled":{"TargetBucket":"<logging-bucket>","TargetPrefix":"cloudtrail-access-logs/"}}'`,
    risk: "Low operational risk — logging adds a small storage cost to the target bucket.",
  },
  "acm.certificate.expiring": {
    why: "An expiring TLS certificate will break HTTPS for any service using it — load balancers, CloudFront, API Gateway. Browsers will show certificate errors and API clients will fail TLS handshakes.",
    console: [
      "Open ACM → Certificates → select the certificate",
      "Confirm the expiry date and associated services (ELB, CloudFront, etc.)",
      "If DNS-validated and auto-renewal eligible, verify the CNAME validation record still exists in Route 53",
      "If not auto-renewing, request a new certificate and update the listener/distribution before expiry",
    ],
    cli: `# Check certificate status and expiry
aws acm describe-certificate \\
  --certificate-arn <certificate-arn> \\
  --region <region>

# Request a replacement (DNS validation recommended)
aws acm request-certificate \\
  --domain-name <domain-name> \\
  --validation-method DNS \\
  --region <region>`,
    risk: "Replacing a certificate on a live listener requires updating the attachment — plan a brief maintenance window if auto-renewal cannot be restored.",
  },
  "lambda.function.deprecated_runtime": {
    why: "Deprecated Lambda runtimes no longer receive security patches. AWS will eventually block creates/updates and then disable invocation on unsupported runtimes.",
    console: [
      "Open Lambda → Functions → select the function",
      'Click "Configuration" → "General configuration" → Edit',
      "Select a supported runtime (e.g. python3.12, nodejs20.x, java21)",
      "Test thoroughly in a staging alias before updating production",
    ],
    cli: `# Update runtime
aws lambda update-function-configuration \\
  --function-name <function-name> \\
  --region <region> \\
  --runtime python3.12

# Test with a dry-run invocation
aws lambda invoke \\
  --function-name <function-name> \\
  --region <region> \\
  --payload '{}' /tmp/out.json`,
    risk: "Runtime upgrades can break dependencies — test in non-prod. Python 3.12 and Node 20 may require dependency updates.",
  },
  "lambda.function.no_dlq": {
    why: "Without a dead-letter queue (DLQ), failed async invocations are retried until they expire silently. You lose visibility into poison messages and cannot replay failures.",
    console: [
      "Create an SQS queue or SNS topic to use as the DLQ",
      "Open Lambda → Functions → select the function",
      'Click "Configuration" → "Asynchronous invocation" → Edit',
      "Set the dead-letter queue ARN and a maximum retry attempt count (e.g. 2)",
      "Save and trigger a test failure to confirm messages arrive in the DLQ",
    ],
    cli: `# Create DLQ queue
aws sqs create-queue --queue-name <function-name>-dlq --region <region>

# Attach DLQ to function
aws lambda update-function-configuration \\
  --function-name <function-name> \\
  --region <region> \\
  --dead-letter-config TargetArn=<dlq-arn>`,
    risk: "Low risk — adding a DLQ does not change successful invocation behaviour. Monitor DLQ depth after enabling.",
  },
  "rds.instance.no_deletion_protection": {
    why: "Without deletion protection, a mistaken `delete-db-instance` call (human error, bad automation, or compromised credentials) permanently destroys the database.",
    console: [
      "Open RDS → Databases → select the instance",
      'Click "Modify"',
      "Enable Deletion protection",
      'Apply immediately or during the next maintenance window',
    ],
    cli: `aws rds modify-db-instance \\
  --db-instance-identifier <instance-id> \\
  --region <region> \\
  --deletion-protection \\
  --apply-immediately`,
    risk: "Deletion protection must be disabled before intentional deletion — this is the intended safety trade-off.",
  },
  "rds.instance.no_multi_az": {
    why: "Single-AZ RDS has no automatic failover during host failure or maintenance. Multi-AZ provides synchronous standby replication and automatic failover, typically within 60–120 seconds.",
    console: [
      "Open RDS → Databases → select the instance",
      'Click "Modify"',
      "Enable Multi-AZ deployment",
      "Review the maintenance window — conversion causes a brief failover (~60s downtime)",
      'Apply during a planned maintenance window',
    ],
    cli: `aws rds modify-db-instance \\
  --db-instance-identifier <instance-id> \\
  --region <region> \\
  --multi-az \\
  --apply-immediately`,
    risk: "Enabling Multi-AZ doubles instance cost and triggers a failover with brief downtime. Plan a maintenance window.",
  },
  "secretsmanager.secret.no_rotation": {
    why: "Secrets without automatic rotation stay static indefinitely. Long-lived database passwords and API keys are harder to revoke and more valuable if leaked.",
    console: [
      "Open Secrets Manager → select the secret",
      'Click "Edit rotation"',
      "Enable automatic rotation and choose an interval (e.g. 30 days)",
      "Select or create a Lambda rotation function for the secret type",
      "Run a test rotation to confirm the secret updates and downstream apps reconnect",
    ],
    cli: `# Enable rotation (requires a rotation Lambda — use AWS-managed templates where available)
aws secretsmanager rotate-secret \\
  --secret-id <secret-name> \\
  --region <region> \\
  --rotation-lambda-arn <rotation-lambda-arn> \\
  --rotation-rules AutomaticallyAfterDays=30`,
    risk: "First rotation updates the live secret — verify applications read the latest version from Secrets Manager, not a cached copy.",
  },
  "ssm.parameter.plaintext_secret": {
    why: "This SSM parameter is stored as plaintext String type but its name suggests it holds a secret. Plaintext parameters appear in API responses, CloudTrail logs, and console views without decryption controls.",
    console: [
      "Open Systems Manager → Parameter Store → select the parameter",
      "Create a new SecureString parameter with the same value (KMS-encrypted)",
      "Update applications to read the SecureString parameter",
      "Delete the plaintext parameter after migration",
    ],
    cli: `# Read current value, write as SecureString, then delete original
VALUE=$(aws ssm get-parameter --name <parameter-name> --region <region> --query Parameter.Value --output text)

aws ssm put-parameter \\
  --name <parameter-name> \\
  --region <region> \\
  --type SecureString \\
  --value "$VALUE" \\
  --overwrite`,
    risk: "Rotating to SecureString changes the parameter type in place with --overwrite, but verify apps handle SecureString decryption (kms:Decrypt may be required).",
  },
  "elb.load_balancer.no_access_logs": {
    why: "Load balancer access logs record every request — source IP, path, response code, and TLS cipher. Without them, investigating abuse or debugging routing issues requires guesswork.",
    console: [
      "Create an S3 bucket to receive access logs (separate from application data)",
      "Open EC2 → Load Balancers → select the load balancer",
      'Click "Attributes" → Edit → Access logs',
      "Enable logging, specify the S3 bucket and prefix",
      "Ensure the bucket policy grants ELB log delivery permission for your region",
    ],
    cli: `aws elbv2 modify-load-balancer-attributes \\
  --load-balancer-arn <load-balancer-arn> \\
  --region <region> \\
  --attributes Key=access_logs.s3.enabled,Value=true Key=access_logs.s3.bucket,Value=<bucket-name> Key=access_logs.s3.prefix,Value=elb-logs/`,
    risk: "Low risk — logging adds S3 storage cost. Set a lifecycle policy on the log bucket to expire old logs.",
  },
  "elb.load_balancer.weak_tls_policy": {
    why: "The load balancer uses a legacy SSL/TLS policy that allows outdated cipher suites (TLS 1.0/1.1, weak ciphers). Modern clients and compliance frameworks require TLS 1.2+.",
    console: [
      "Open EC2 → Load Balancers → select the load balancer",
      'Open the "Listeners" tab → select the HTTPS/TLS listener → Edit',
      "Change the security policy to ELBSecurityPolicy-TLS13-1-2-2021-06 or TLS-1-2-2017-01 minimum",
      "Save and verify client connectivity from your oldest supported browsers/API clients",
    ],
    cli: `aws elbv2 modify-listener \\
  --listener-arn <listener-arn> \\
  --region <region> \\
  --ssl-policy ELBSecurityPolicy-TLS13-1-2-2021-06`,
    risk: "Stricter TLS policies break legacy clients still on TLS 1.0/1.1 — test with your oldest production clients before applying.",
  },
  "sns.topic.no_encryption": {
    why: "SNS topics without KMS encryption deliver messages in plaintext at rest. Any principal with sns:Subscribe or CloudWatch log access can read message contents.",
    console: [
      "Open SNS → Topics → select the topic",
      'Click "Edit" → expand "Encryption"',
      "Enable encryption with the AWS managed key (alias/aws/sns) or a customer-managed KMS key",
      "Update publisher/subscriber IAM policies to include kms:Decrypt and kms:GenerateDataKey if using a CMK",
    ],
    cli: `aws sns set-topic-attributes \\
  --topic-arn <topic-arn> \\
  --region <region> \\
  --attribute-name KmsMasterKeyId \\
  --attribute-value alias/aws/sns`,
    risk: "Enabling encryption requires publishers and subscribers to have KMS permissions — test publish/subscribe after enabling.",
  },
  "sqs.queue.no_encryption": {
    why: "SQS queues without KMS encryption store messages in plaintext at rest. Queue contents may include PII, tokens, or job payloads visible to anyone with sqs:ReceiveMessage.",
    console: [
      "Open SQS → Queues → select the queue",
      'Click "Edit" → expand "Encryption"',
      "Enable server-side encryption with the AWS managed key (alias/aws/sqs) or a customer-managed KMS key",
      "Update producer/consumer IAM roles with kms:Decrypt and kms:GenerateDataKey if using a CMK",
    ],
    cli: `aws sqs set-queue-attributes \\
  --queue-url <queue-url> \\
  --region <region> \\
  --attributes KmsMasterKeyId=alias/aws/sqs`,
    risk: "Enabling encryption on a live queue requires KMS permissions on all producers and consumers — test end-to-end after enabling.",
  },
  "iam.account.password_policy_weak": {
    why: "A weak account password policy means IAM users can set short, simple, or reused passwords. Attackers who obtain one password may rotate through accounts trivially.",
    console: [
      "Open IAM → Account settings",
      'Under "Password policy", click "Edit"',
      "Set minimum length to 14, enable uppercase, lowercase, numbers, and symbols",
      "Set password expiration to 90 days and password reuse prevention to 24",
      'Click "Save changes"',
    ],
    cli: `aws iam update-account-password-policy \\
  --minimum-password-length 14 \\
  --require-uppercase-characters \\
  --require-lowercase-characters \\
  --require-numbers \\
  --require-symbols \\
  --allow-users-to-change-password \\
  --max-password-age 90 \\
  --password-reuse-prevention 24`,
    risk: "Weak password policy increases the blast radius of credential-stuffing attacks on console users.",
  },
  "aws.access_analyzer.not_enabled": {
    why: "IAM Access Analyzer continuously monitors resource policies to identify when resources are shared with external principals. Without it, over-permissive cross-account access goes undetected.",
    console: [
      "Open IAM → Access Analyzer",
      'Click "Create analyzer"',
      'Set Zone of trust to "Current account", provide a name',
      'Click "Create analyzer"',
      "Repeat for each region where you have resources",
    ],
    cli: `# Enable in each region
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  aws accessanalyzer create-analyzer \\
    --analyzer-name vigil-analyzer \\
    --type ACCOUNT \\
    --region $region 2>/dev/null || true
done`,
    risk: "Without Access Analyzer you have no automated detection when S3 buckets, KMS keys, or IAM roles are made accessible to external accounts.",
  },
  "aws.config.not_enabled": {
    why: "AWS Config records configuration changes to AWS resources over time. Without it there is no change history — auditors cannot verify that a control was in place before an incident, and you cannot roll back to a known-good state.",
    console: [
      "Open AWS Config → Get started",
      "Select 'Record all resources supported in this region'",
      "Create or select an S3 bucket for Config history storage",
      "Create an SNS topic for delivery notifications (optional)",
      'Click "Next" → "Confirm"',
      "Repeat for each active region",
    ],
    cli: `# Create S3 bucket for Config delivery
aws s3 mb s3://config-history-$(aws sts get-caller-identity --query Account --output text)

# Create a Config recorder and delivery channel
aws configservice put-configuration-recorder \\
  --configuration-recorder name=default,roleARN=<config-role-arn>

aws configservice put-delivery-channel \\
  --delivery-channel name=default,s3BucketName=<bucket>

aws configservice start-configuration-recorder --configuration-recorder-name default`,
    risk: "No Config means no configuration change history — a gap auditors will flag and a blocker for SOC 2 CC6.1.",
  },
  "aws.securityhub.not_enabled": {
    why: "Security Hub centralizes AWS security findings and posture checks across regions. Without it, security signals stay fragmented across services and are harder to evidence consistently.",
    console: [
      "Open Security Hub in each affected region listed in Scan details",
      'Click "Go to Security Hub" or "Enable Security Hub"',
      "Enable the AWS Foundational Security Best Practices standard",
      "Repeat for each active region, or enable centrally with AWS Organizations",
    ],
    cli: `# Enable Security Hub in each region
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  aws securityhub enable-security-hub --region $region 2>/dev/null || true
done`,
    risk: "Without Security Hub, posture checks and service findings are not centralized, making investigation and audit evidence weaker.",
  },
  "ec2.security_group.default_allows_traffic": {
    why: "The default security group is automatically assigned to new instances and network interfaces if no explicit group is specified. If it has rules, any accidentally unconfigured resource inherits inbound or outbound access — often unintentionally.",
    console: [
      "Open EC2 → Security Groups, filter for 'default'",
      "Select the default security group for each VPC",
      'Under "Inbound rules", select all rules → "Delete"',
      'Under "Outbound rules", select all rules → "Delete"',
      "Assign traffic to named security groups on your existing instances",
    ],
    cli: `# List rules on the default SG
SG_ID=$(aws ec2 describe-security-groups \\
  --filters Name=group-name,Values=default Name=vpc-id,Values=<vpc-id> \\
  --query 'SecurityGroups[0].GroupId' --output text)

# Remove all inbound rules
aws ec2 revoke-security-group-ingress --group-id $SG_ID \\
  --ip-permissions "$(aws ec2 describe-security-groups --group-ids $SG_ID \\
    --query 'SecurityGroups[0].IpPermissions' --output json)"

# Remove all outbound rules
aws ec2 revoke-security-group-egress --group-id $SG_ID \\
  --ip-permissions "$(aws ec2 describe-security-groups --group-ids $SG_ID \\
    --query 'SecurityGroups[0].IpPermissionsEgress' --output json)"`,
    risk: "Removing rules from the default SG affects instances that rely on it — verify instance SG assignments before making changes.",
  },
  "ec2.instance.imdsv2_not_required": {
    why: "IMDSv1 is vulnerable to Server-Side Request Forgery (SSRF): an attacker who exploits a web app can request http://169.254.169.254/ and retrieve temporary IAM credentials. IMDSv2 requires a session token obtained via PUT, breaking this attack.",
    console: [
      "Open EC2 → Instances → select the instance",
      'Click "Actions" → "Instance settings" → "Modify instance metadata options"',
      'Set "IMDSv2" to "Required"',
      'Set "Metadata response hop limit" to 1',
      'Click "Save"',
    ],
    cli: `aws ec2 modify-instance-metadata-options \\
  --instance-id <instance-id> \\
  --http-tokens required \\
  --http-put-response-hop-limit 1 \\
  --http-endpoint enabled`,
    risk: "Requiring IMDSv2 only breaks applications that use the old IMDSv1 path without a session token — test in non-prod first.",
  },
  "ec2.ebs.encryption_not_default": {
    why: "Without the default encryption setting, any EBS volume created without an explicit KMS key is unencrypted. Developers and launch templates that omit the encryption flag silently create unencrypted volumes.",
    console: [
      "Open EC2 → Settings (under Account attributes)",
      'Under "EBS encryption", click "Manage"',
      'Check "Enable" and select a default KMS key',
      'Click "Update EBS encryption"',
      "Repeat for each region where you launch EC2 instances",
    ],
    cli: `# Enable default encryption in each region
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  aws ec2 enable-ebs-encryption-by-default --region $region
  echo "Enabled in $region"
done`,
    risk: "This only affects new volumes — existing unencrypted volumes require a snapshot copy with encryption enabled to remediate.",
  },
  "ec2.ebs.volume_unencrypted": {
    why: "Existing unencrypted EBS volumes keep data at rest outside your encryption baseline. Enabling encryption by default does not retrofit current volumes.",
    console: [
      "Open EC2 → Volumes and select the affected volume",
      'Click "Actions" → "Create snapshot"',
      "Open Snapshots, select the new snapshot, then copy it with encryption enabled",
      "Create a new volume from the encrypted snapshot",
      "Detach the old volume and attach the encrypted replacement during a maintenance window",
    ],
    cli: `# Snapshot, copy encrypted, then create a replacement volume
aws ec2 create-snapshot --volume-id <volume-id> --description "Encrypt <volume-id>"
aws ec2 copy-snapshot \\
  --source-region <region> \\
  --source-snapshot-id <snapshot-id> \\
  --encrypted
aws ec2 create-volume \\
  --snapshot-id <encrypted-snapshot-id> \\
  --availability-zone <az>`,
    risk: "Replacing an attached volume can require downtime. Confirm the attachment, mount point, filesystem, and backup plan before cutover.",
  },
};

const identityRemediations: Record<string, Remediation> = {
  "github.org.mfa_not_enforced": {
    why: "Without MFA enforcement, any compromised GitHub account password gives an attacker full write access to your repositories. A single phished developer can push malicious code or delete branches with no second factor stopping them.",
    console: [
      "Go to your GitHub organization page",
      'Click "Settings" → "Authentication security"',
      'Enable "Require two-factor authentication for everyone in your organization"',
      "Members without MFA will be removed and must re-enroll to rejoin",
    ],
    cli: "",
    risk: "Without org-level MFA enforcement, individual members can disable their own MFA and retain full access.",
  },
  "github.org.dormant_members": {
    why: "Dormant members hold valid tokens and SSH keys even when they've left the project or company. Attackers who obtain stale credentials can act as a legitimate insider with no unusual login pattern to detect.",
    console: [
      "Go to your GitHub organization → People",
      'Filter by "Dormant members" or sort by last activity',
      "Review each member and confirm whether they still need access",
      'Remove members who are no longer active via "Remove from organization"',
    ],
    cli: "",
    risk: "Stale memberships are a common vector in insider-threat and ex-employee compromise scenarios.",
  },
  "github.org.outside_collaborators": {
    why: "Outside collaborators are non-organization members who have been granted direct repository access. Unlike org members, their activity is less visible to administrators — they don't appear in org-level member lists and may retain access after a project ends or after they change employers.",
    console: [
      "Go to your GitHub organization → People → Outside collaborators",
      "Review each collaborator — confirm they still need access and which repos they can access",
      "To remove a collaborator: click the three-dot menu → Remove from all repositories",
      "If they still need access, consider inviting them as an org member for better visibility",
    ],
    cli: "",
    risk: "Outside collaborators with stale access can push code, read sensitive repositories, and exfiltrate data without appearing in standard member audit reports.",
  },
  "github.repo.no_branch_protection": {
    why: "Without branch protection, any contributor can push directly to the default branch — bypassing code review, CI checks, and deployment gates. This makes it trivial to introduce unauthorized changes or backdoors.",
    console: [
      "Go to the repository → Settings → Branches",
      'Click "Add rule" under "Branch protection rules"',
      'Enter the default branch name (e.g. "main")',
      'Enable "Require a pull request before merging" and "Require approvals"',
      'Optionally enable "Require status checks" and "Restrict who can push"',
    ],
    cli: "",
    risk: "Unprotected branches allow unauthorized commits to reach production without review or audit trail.",
  },
  "github.repo.no_codeowners": {
    why: "Without a CODEOWNERS file, GitHub cannot automatically request reviews from the right team when code in a particular area is changed. Code reviews end up assigned ad-hoc, making it easy for sensitive paths (auth, payments, infra) to be reviewed by people unfamiliar with the area — or not reviewed at all.",
    console: [
      "Create a file named CODEOWNERS in the repo root, .github/, or docs/",
      "Map file paths to GitHub teams or individuals, e.g.: /* @org/platform-team",
      "Add more specific rules for sensitive directories, e.g.: /src/auth/ @org/security",
      "Commit the file to the default branch",
      "In branch protection settings, enable 'Require review from Code Owners'",
    ],
    cli: "",
    risk: "Sensitive code paths may be reviewed by people without the context to spot security issues, undermining the control value of required reviews.",
  },
  "github.repo.no_env_protection": {
    why: "GitHub deployment environments without required reviewers allow workflows to deploy to production without any human approval gate. This bypasses the change management control that ensures at least one person signs off before code reaches production.",
    console: [
      "Go to the repository → Settings → Environments",
      "Click on the environment (e.g. 'production', 'staging')",
      'Enable "Required reviewers" and add the team or individuals who must approve deployments',
      "Set a wait timer if appropriate to prevent immediate re-runs",
      "Save the protection rules",
    ],
    cli: "",
    risk: "Without required reviewers on deployment environments, any GitHub Actions workflow can ship to production without human sign-off — violating SOC2 CC8.1 change management controls.",
  },
  "github.repo.self_merge_allowed": {
    why: "Allowing authors to merge their own pull requests removes the peer review step that catches bugs, backdoors, and security regressions. It is the single most common change-management gap flagged in SOC2 CC8.1 audits.",
    console: [
      "Go to the repository → Settings → Branches",
      "Edit the branch protection rule for your default branch",
      'Enable "Require approvals" and set minimum reviewers to at least 1',
      'Enable "Dismiss stale pull request approvals when new commits are pushed"',
      "Confirm the PR author cannot satisfy the approval requirement",
    ],
    cli: "",
    risk: "Self-merged code bypasses the peer review control required by SOC2 CC8.1 and most change management policies.",
  },
  "github.repo.insufficient_reviews": {
    why: "Merging with fewer approvals than required means the review policy is either misconfigured or being bypassed. Each approval gap is a break in the change-management evidence chain auditors will sample.",
    console: [
      "Go to the repository → Settings → Branches",
      "Edit the branch protection rule for your default branch",
      'Increase "Required approving reviews" to at least 1 (ideally 2)',
      'Enable "Dismiss stale pull request approvals when new commits are pushed"',
      "Review recent merges that bypassed the policy and document exceptions",
    ],
    cli: "",
    risk: "Each under-reviewed merge is a gap in change-management evidence and an opportunity for unauthorized code to reach production.",
  },
  "gitlab.org.mfa_not_enforced": {
    why: "Without group-level MFA enforcement, any compromised GitLab account password gives full write access to your projects. A single phished developer can push malicious code or bypass protected branch rules.",
    console: [
      "Go to your GitLab group → Settings → General",
      'Expand "Permissions and group features"',
      'Enable "Require all users in this group to set up two-factor authentication"',
      "Set a grace period, then enforce — non-compliant members will be locked out until they enroll",
    ],
    cli: "",
    risk: "Without group-level MFA, individual members can remove their own 2FA and retain full repository access.",
  },
  "gitlab.org.dormant_members": {
    why: "Dormant group members retain valid tokens and SSH keys even after leaving the project. Stale access tokens have no expiry by default in GitLab and can be used by an attacker indefinitely.",
    console: [
      "Go to your GitLab group → Members",
      "Sort by 'Last activity' to identify inactive members",
      "Review each dormant member and confirm whether they still need access",
      'Remove inactive members via "Remove member"',
      "Consider enabling token expiration policies for personal access tokens",
    ],
    cli: "",
    risk: "Dormant accounts with persistent tokens are a high-value target for credential-stuffing and ex-employee access.",
  },
  "gitlab.repo.no_branch_protection": {
    why: "Without protected branches, any developer with Maintainer or Owner access can push directly to the default branch, bypassing code review and CI pipelines. This breaks the change-management control chain.",
    console: [
      "Go to the project → Settings → Repository → Protected branches",
      'Click "Protect a branch"',
      'Enter the default branch name (e.g. "main")',
      'Set "Allowed to merge" to "Maintainers" and "Allowed to push" to "No one"',
      'Enable "Code owner approval" if CODEOWNERS is configured',
    ],
    cli: "",
    risk: "Unprotected branches allow direct pushes to production branches without review or audit evidence.",
  },
  "gitlab.repo.self_merge_allowed": {
    why: "When MR authors can merge their own requests, the peer review step that catches bugs and unauthorized changes is eliminated. GitLab's approval rules must explicitly prevent author self-approval to satisfy SOC2 CC8.1.",
    console: [
      "Go to the project → Settings → Merge requests",
      'Enable "Merge request approvals" and set "Required approvals" to at least 1',
      'Enable "Prevent approval by the author" under approval settings',
      'Enable "Prevent approvals by users who add commits"',
      "Save the settings and re-review any pending MRs",
    ],
    cli: "",
    risk: "Author self-approval bypasses the segregation-of-duties control and will fail a SOC2 CC8.1 evidence review.",
  },
  "gitlab.repo.insufficient_reviews": {
    why: "MRs merged below the required approval threshold mean the policy is being bypassed or is misconfigured. Each under-approved merge is a gap in the change-management evidence chain.",
    console: [
      "Go to the project → Settings → Merge requests",
      'Set "Required approvals" to at least 1 (ideally 2 for critical branches)',
      'Enable "Reset approvals on push" to prevent stale approvals',
      "Review the approval rules to ensure they cannot be overridden by project members",
      "Audit recent MRs and document any approved exceptions",
    ],
    cli: "",
    risk: "Under-reviewed merges are evidence gaps that auditors will flag during SOC2 CC8.1 sampling.",
  },
};

const fallbackRemediation: Remediation = {
  why: "Review this finding and take corrective action based on your security policy.",
  console: ["Open the AWS Console", "Navigate to IAM", "Locate the affected resource and review its configuration"],
  cli: "# Review with AWS CLI\naws iam get-user --user-name <user>",
  risk: "Unresolved findings increase your attack surface.",
};

type RemovableStatement = { policy: string; sid: string; actions: string[]; resources: string[] };

function ServicePills({ services }: { services: string[] }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {services.map((s) => (
        <span
          key={s}
          className="inline-flex items-center rounded border border-amber-200 bg-amber-50 px-2 py-0.5 font-mono text-xs font-medium text-amber-700"
        >
          {s}
        </span>
      ))}
    </div>
  );
}

const SERVICE_PILL_COLLAPSED_LIMIT = 24;

function ServiceListExpandToggle({
  expanded,
  total,
  hiddenCount,
  onToggle,
}: {
  expanded: boolean;
  total: number;
  hiddenCount: number;
  onToggle: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onToggle}
      className="mb-2 text-xs font-medium text-zinc-500 transition-colors hover:text-zinc-800"
    >
      {expanded ? "Show less" : `Show all ${total} services (${hiddenCount} more)`}
    </button>
  );
}

function CollapsibleServicePills({ services }: { services: string[] }) {
  const [expanded, setExpanded] = useState(false);
  const collapsible = services.length > SERVICE_PILL_COLLAPSED_LIMIT;
  const visible = collapsible && !expanded ? services.slice(0, SERVICE_PILL_COLLAPSED_LIMIT) : services;
  const hiddenCount = services.length - SERVICE_PILL_COLLAPSED_LIMIT;

  return (
    <div>
      {collapsible && (
        <ServiceListExpandToggle
          expanded={expanded}
          total={services.length}
          hiddenCount={hiddenCount}
          onToggle={() => setExpanded((v) => !v)}
        />
      )}
      <ServicePills services={visible} />
    </div>
  );
}

type GrantedServicePill = {
  name: string;
  last_used: string | null;
  days_ago: number | null;
  active: boolean;
};

function GrantedServicePills({ services }: { services: GrantedServicePill[] }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {services.map((s) => (
        <span
          key={s.name}
          title={s.last_used ? `Last used ${s.days_ago}d ago` : "Never used"}
          className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium ${
            s.active ? "border-red-200 bg-red-50 text-red-700" : "border-zinc-200 bg-zinc-50 text-zinc-500"
          }`}
        >
          <span className={`h-1.5 w-1.5 rounded-full ${s.active ? "bg-red-400" : "bg-zinc-300"}`} />
          {s.name}
          {s.days_ago !== null && <span className="opacity-60">{s.days_ago}d</span>}
        </span>
      ))}
    </div>
  );
}

function CollapsibleGrantedServices({ services }: { services: GrantedServicePill[] }) {
  const [expanded, setExpanded] = useState(false);
  const collapsible = services.length > SERVICE_PILL_COLLAPSED_LIMIT;
  const visible = collapsible && !expanded ? services.slice(0, SERVICE_PILL_COLLAPSED_LIMIT) : services;
  const hiddenCount = services.length - SERVICE_PILL_COLLAPSED_LIMIT;

  return (
    <div>
      {collapsible && (
        <ServiceListExpandToggle
          expanded={expanded}
          total={services.length}
          hiddenCount={hiddenCount}
          onToggle={() => setExpanded((v) => !v)}
        />
      )}
      <GrantedServicePills services={visible} />
    </div>
  );
}

function resourceWildcardNote(cloudTrailLogging: boolean) {
  if (cloudTrailLogging) {
    return "Account-wide scope in this export. CloudTrail is enabled — use IAM Access Analyzer policy generation for ARN-level least privilege; Vigil Generate still scopes actions only.";
  }
  return "Account-wide scope. IAM last-accessed shows which API calls were used, not which ARNs were touched. Enable CloudTrail to unlock resource-level narrowing.";
}

function generatePolicyIntro(cloudTrailLogging: boolean) {
  const action =
    "Vigil narrows action wildcards to the API calls recorded in the last 90 days.";
  const resource = cloudTrailLogging
    ? "Resource scope still shows * in this output (actions only) — use Access Analyzer with your CloudTrail logs for ARN-level scope."
    : "Resource scope is left as-is — IAM last-accessed does not record which ARNs were used.";
  return `${action} ${resource}`;
}

const ACTION_WILDCARD_NOTE =
  "Wildcard action — narrow to the API calls recorded in the last 90 days.";

function isActionWildcardLabel(value: string) {
  return value === "*" || value.includes("wildcard");
}

function IamPolicyScopePill({ value, kind }: { value: string; kind: "action" | "resource" | "resource-wildcard" }) {
  const styles =
    kind === "action"
      ? "border-red-200 bg-red-50 text-red-700"
      : kind === "resource-wildcard"
        ? "border-amber-200 bg-amber-50 text-amber-800"
        : "border-zinc-200 bg-white text-zinc-700";
  const mono = kind === "resource" && value.startsWith("arn:");
  return (
    <span className={`rounded border px-1.5 py-0.5 text-[11px] leading-relaxed ${mono ? "font-mono" : ""} ${styles}`}>
      {value}
    </span>
  );
}

function IamPolicyScopeField({
  label,
  tone,
  children,
  note,
}: {
  label: string;
  tone: "action" | "resource";
  children: ReactNode;
  note?: string;
}) {
  const boxTone = tone === "action" ? "border-red-100 bg-red-50/50" : "border-amber-100 bg-amber-50/50";
  const noteTone = tone === "action" ? "text-red-800/80" : "text-amber-900/80";
  return (
    <div className={`rounded-md border ${boxTone} px-2.5 py-2`}>
      <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wide text-zinc-500">{label}</div>
      {children}
      {note && <p className={`mt-1.5 text-[11px] leading-relaxed ${noteTone}`}>{note}</p>}
    </div>
  );
}

function RemovableStatementsBlock({
  statements,
  cloudTrailLogging,
}: {
  statements: RemovableStatement[];
  cloudTrailLogging: boolean;
}) {
  if (!statements.length) return null;
  return (
    <div>
      <div className="mb-2 text-sm font-semibold text-zinc-700">
        Removable statements
        <span className="ml-1.5 text-xs font-normal text-zinc-400">from inline policies</span>
      </div>
      <div className="space-y-2">
        {statements.map((stmt, i) => {
          const resourceWildcard = stmt.resources.length === 1 && stmt.resources[0] === "*";
          const actionWildcards = stmt.actions.filter(isActionWildcardLabel);
          const concreteActions = stmt.actions.filter((a) => !isActionWildcardLabel(a));
          return (
            <div key={i} className="overflow-hidden rounded-lg border border-zinc-200 text-xs">
              <div className="flex items-center gap-2 border-b border-zinc-200 bg-zinc-50 px-3 py-2">
                <span className="font-mono font-medium text-zinc-800">{stmt.policy}</span>
                {stmt.sid && <span className="text-zinc-400">· {stmt.sid}</span>}
              </div>
              <div className="space-y-2 px-3 py-2.5">
                {(actionWildcards.length > 0 || concreteActions.length > 0) && (
                  <IamPolicyScopeField
                    label="Actions"
                    tone="action"
                    note={actionWildcards.length > 0 ? ACTION_WILDCARD_NOTE : undefined}
                  >
                    <div className="flex flex-wrap gap-1">
                      {actionWildcards.map((a) => (
                        <IamPolicyScopePill key={a} value="*" kind="action" />
                      ))}
                      {concreteActions.map((a) => (
                        <IamPolicyScopePill key={a} value={a} kind="action" />
                      ))}
                    </div>
                  </IamPolicyScopeField>
                )}
                <IamPolicyScopeField label="Resources" tone="resource">
                  {resourceWildcard ? (
                    <>
                      <IamPolicyScopePill value="*" kind="resource-wildcard" />
                      <p className="mt-1.5 text-[11px] leading-relaxed text-amber-900/80">
                        {resourceWildcardNote(cloudTrailLogging)}
                      </p>
                    </>
                  ) : (
                    <div className="flex flex-wrap gap-1">
                      {stmt.resources.map((r) => (
                        <IamPolicyScopePill key={r} value={r} kind="resource" />
                      ))}
                    </div>
                  )}
                </IamPolicyScopeField>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function ObjectListTable({ items }: { items: Record<string, unknown>[] }) {
  if (!items.length) return null;
  const cols = Object.keys(items[0]);
  function renderCell(column: string, value: unknown) {
    if (value == null) return "—";
    const text = String(value);
    if (column === "dangerous_actions" || column === "actions") {
      const actions = text.split(",").map((part) => part.trim()).filter(Boolean);
      if (actions.length > 0) {
        return (
          <div className="max-w-[26rem] space-y-1">
            {actions.map((action) => (
              <div key={action} className="font-mono text-xs leading-snug text-zinc-700 break-all">
                {action}
              </div>
            ))}
          </div>
        );
      }
    }
    return <span className="whitespace-pre-wrap break-words">{text}</span>;
  }
  return (
    <div className="overflow-x-auto rounded-lg border border-zinc-200">
      <table className="w-full text-xs">
        <thead>
          <tr className="bg-zinc-50 border-b border-zinc-200">
            {cols.map((c) => (
              <th key={c} className="px-3 py-2 text-left font-semibold text-zinc-500 whitespace-nowrap">
                {c.replace(/_/g, " ")}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-100">
          {items.map((row, i) => (
            <tr key={i} className="bg-white">
              {cols.map((c) => (
                <td key={c} className="max-w-[300px] px-3 py-2 font-mono leading-relaxed text-zinc-800 align-middle">
                  {renderCell(c, row[c])}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function PolicyEvidenceList({ items }: { items: Record<string, unknown>[] }) {
  function serviceLabel(raw: string) {
    const normalized = raw.toLowerCase();
    if (normalized === "iam") return "IAM";
    if (normalized === "ec2") return "EC2";
    if (normalized === "shield") return "Shield";
    if (normalized === "elasticloadbalancing") return "ELB";
    if (normalized === "wafv2") return "WAFv2";
    if (normalized === "waf-regional") return "WAF Regional";
    return raw.length <= 3 ? raw.toUpperCase() : raw.charAt(0).toUpperCase() + raw.slice(1);
  }

  return (
    <div className="space-y-3">
      {items.map((row, i) => {
        const policyName = String(row.policy ?? row.policy_name ?? "Unnamed policy");
        const policyType = String(row.type ?? row.policy_type ?? "policy");
        const raw = String(row.dangerous_actions ?? row.actions ?? "");
        const actions = raw.split(",").map((a) => a.trim()).filter(Boolean);
        const serviceCounts = new Map<string, number>();
        actions.forEach((action) => {
          const service = action.split(":")[0] || "other";
          serviceCounts.set(service, (serviceCounts.get(service) ?? 0) + 1);
        });
        return (
          <details key={`${policyName}-${i}`} className="group overflow-hidden rounded-lg border border-zinc-200 bg-white open:bg-zinc-50/40">
            <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-3.5">
              <div className="min-w-0">
                <div className="truncate text-sm font-semibold leading-5 text-zinc-900">{policyName}</div>
                <div className="mt-1 flex flex-wrap items-center gap-2 text-xs leading-5 text-zinc-500">
                  <span className="rounded border border-zinc-200 bg-zinc-50 px-1.5 py-0.5 uppercase tracking-wide">{policyType.replace("_", " ")}</span>
                  <span>{actions.length} dangerous action{actions.length === 1 ? "" : "s"}</span>
                </div>
              </div>
              <svg className="h-4 w-4 flex-shrink-0 text-zinc-400 transition group-open:rotate-180" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
              </svg>
            </summary>
            <div className="border-t border-zinc-200 px-4 py-4">
              <div className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-zinc-400">
                Grouped dangerous actions
              </div>
              <div className="mb-3.5 flex flex-wrap gap-1.5">
                {Array.from(serviceCounts.entries()).map(([service, count]) => (
                  <span key={service} className="rounded-full border border-amber-200 bg-amber-50 px-2.5 py-0.5 text-xs font-medium text-amber-700">
                    {serviceLabel(service)} · {count} action{count === 1 ? "" : "s"}
                  </span>
                ))}
              </div>
              <div className="max-h-40 space-y-1.5 overflow-auto rounded-md border border-zinc-200 bg-zinc-50/70 p-2.5">
                {actions.map((action) => (
                  <div key={action} className="font-mono text-xs leading-5 text-zinc-500 break-all">{action}</div>
                ))}
              </div>
            </div>
          </details>
        );
      })}
    </div>
  );
}

function KeyActivityCard({ keyData }: { keyData: { key_id: string; last_used: string | null; days_ago: number | null; last_used_service: string | null; last_used_region: string | null; active: boolean } }) {
  const service = keyData.last_used_service ?? "unknown service";
  const region = keyData.last_used_region ?? "unknown region";
  const age = keyData.days_ago != null ? `${keyData.days_ago}d ago` : "recently";

  return (
    <div className={`rounded-lg border px-3 py-2.5 text-xs ${keyData.active ? "border-red-100 bg-red-50" : "border-zinc-200 bg-zinc-50"}`}>
      <div className="font-mono font-semibold text-zinc-700">{keyData.key_id}</div>
      {keyData.last_used ? (
        <>
          <div className="mt-1 text-[11px] font-semibold uppercase tracking-wide text-zinc-400">Last API activity</div>
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            <span className="rounded-md border border-zinc-200 bg-white px-1.5 py-0.5 text-zinc-600">{service}</span>
            <span className="rounded-md border border-zinc-200 bg-white px-1.5 py-0.5 text-zinc-600">{region}</span>
            <span className="rounded-md border border-zinc-200 bg-white px-1.5 py-0.5 text-zinc-600">{age}</span>
          </div>
        </>
      ) : (
        <div className="mt-1 text-zinc-500">No recorded API activity</div>
      )}
    </div>
  );
}

function evidenceFieldLabel(key: string) {
  return key.replace(/_/g, " ");
}

const EVIDENCE_LABELS: Record<string, string> = {
  disabled_regions: "Disabled regions",
  enabled_regions: "Enabled regions",
  region_count: "Regions",
  inline_policies_with_wildcard: "Inline policies",
  attached_policies_with_wildcard: "Attached policies",
  sources: "Sources",
  account_id: "Account ID",
  bucket_name: "Bucket",
  trail_name: "Trail",
  home_region: "Home region",
  key_id: "Key ID",
  user_name: "User",
  group_id: "Security group",
  group_name: "Group name",
  vpc_id: "VPC",
  db_instance_id: "DB instance",
  volume_id: "Volume",
  role_arn: "Role ARN",
  block_public_acls: "Block public ACLs",
  ignore_public_acls: "Ignore public ACLs",
  block_public_policy: "Block public policy",
  restrict_public_buckets: "Restrict public buckets",
};

const AWS_REGION_LABELS: Record<string, string> = {
  "af-south-1": "Cape Town",
  "ap-east-1": "Hong Kong",
  "ap-northeast-1": "Tokyo",
  "ap-northeast-2": "Seoul",
  "ap-northeast-3": "Osaka",
  "ap-south-1": "Mumbai",
  "ap-south-2": "Hyderabad",
  "ap-southeast-1": "Singapore",
  "ap-southeast-2": "Sydney",
  "ap-southeast-3": "Jakarta",
  "ap-southeast-4": "Melbourne",
  "ca-central-1": "Canada",
  "ca-west-1": "Calgary",
  "eu-central-1": "Frankfurt",
  "eu-central-2": "Zurich",
  "eu-north-1": "Stockholm",
  "eu-south-1": "Milan",
  "eu-south-2": "Spain",
  "eu-west-1": "Ireland",
  "eu-west-2": "London",
  "eu-west-3": "Paris",
  "il-central-1": "Tel Aviv",
  "me-central-1": "UAE",
  "me-south-1": "Bahrain",
  "mx-central-1": "Mexico",
  "sa-east-1": "São Paulo",
  "us-east-1": "N. Virginia",
  "us-east-2": "Ohio",
  "us-west-1": "N. California",
  "us-west-2": "Oregon",
};

function evidenceLabel(key: string, evidence: Record<string, unknown>) {
  if (key === "disabled_regions" && Array.isArray(evidence.disabled_regions)) {
    return `Disabled regions (${evidence.disabled_regions.length})`;
  }
  const base = EVIDENCE_LABELS[key] ?? evidenceFieldLabel(key);
  return base.charAt(0).toUpperCase() + base.slice(1);
}

function isIsoDateString(value: string) {
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value);
}

function formatEvidenceDate(value: string) {
  if (!isIsoDateString(value)) return value;
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  const datePart = new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric", year: "numeric", timeZone: "UTC" }).format(d);
  const timePart = new Intl.DateTimeFormat("en-US", { hour: "2-digit", minute: "2-digit", hour12: false, timeZone: "UTC" }).format(d);
  return `${datePart} at ${timePart} UTC`;
}

function evidenceValueIsRich(key: string, value: unknown) {
  return Array.isArray(value) && value.length > 0;
}

function RegionPills({ regions }: { regions: string[] }) {
  const [expanded, setExpanded] = useState(false);
  const previewLimit = 8;
  const sorted = [...regions].sort((a, b) => (AWS_REGION_LABELS[a] ?? a).localeCompare(AWS_REGION_LABELS[b] ?? b));
  const hidden = sorted.length - previewLimit;
  const visible = expanded || hidden <= 0 ? sorted : sorted.slice(0, previewLimit);

  return (
    <div className="space-y-2">
      <div className="grid grid-cols-2 gap-2">
        {visible.map((code) => {
          const name = AWS_REGION_LABELS[code];
          return (
            <div
              key={code}
              title={code}
              className="flex min-w-0 items-center justify-between gap-2 rounded-lg border border-zinc-200 bg-zinc-50/80 px-2.5 py-2"
            >
              <span className="truncate text-xs font-medium text-zinc-800">{name ?? code}</span>
              {name && <span className="shrink-0 font-mono text-[10px] tabular-nums text-zinc-400">{code}</span>}
            </div>
          );
        })}
      </div>
      {hidden > 0 && (
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          className="text-xs font-medium text-indigo-600 hover:text-indigo-700"
        >
          {expanded ? "Show fewer regions" : `Show all ${sorted.length} regions`}
        </button>
      )}
    </div>
  );
}

function StringPills({ items, tone = "neutral" }: { items: string[]; tone?: "neutral" | "warn" }) {
  const cls =
    tone === "warn"
      ? "border-amber-200 bg-amber-50 text-amber-900"
      : "border-zinc-200 bg-zinc-50 text-zinc-700";
  return (
    <div className="flex flex-wrap gap-2">
      {items.map((item) => (
        <span key={item} className={`inline-flex max-w-full items-center rounded-lg border px-2.5 py-1.5 text-xs font-medium leading-snug ${cls}`}>
          <span className="break-words">{item}</span>
        </span>
      ))}
    </div>
  );
}

function EvidenceValue({ fieldKey, value }: { fieldKey: string; value: unknown }) {
  if (value === null || value === undefined) {
    const isDateField = fieldKey.includes("last") || fieldKey.includes("date") || fieldKey.includes("used") || fieldKey.includes("inactive");
    return <span className="text-sm text-zinc-400">{isDateField ? "Never" : "None"}</span>;
  }

  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="text-sm text-zinc-400">None</span>;
    if (fieldKey.includes("region")) return <RegionPills regions={value as string[]} />;
    if (typeof value[0] === "string") {
      const tone = fieldKey.includes("wildcard") || fieldKey === "sources" ? "warn" : "neutral";
      return <StringPills items={value as string[]} tone={tone} />;
    }
  }

  if (typeof value === "boolean") {
    return (
      <span className={`text-sm font-medium ${value ? "text-emerald-700" : "text-red-600"}`}>
        {value ? "Yes" : "No"}
      </span>
    );
  }

  const text = formatEvidenceDate(String(value));
  const mono = /arn|_id$|(^|_)id$|key_id|region/i.test(fieldKey);
  return <span className={`text-sm leading-5 text-zinc-700 ${mono ? "font-mono break-all" : ""}`}>{text}</span>;
}

function evidenceSectionTitle(key: string) {
  const label = evidenceFieldLabel(key);
  return label.charAt(0).toUpperCase() + label.slice(1);
}

function EvidenceSection({
  evidence,
  checkId,
  cloudTrailLogging,
}: {
  evidence: Record<string, unknown>;
  checkId: string;
  cloudTrailLogging: boolean;
}) {
  const skip = new Set(["removable_statements", "unused_services", "role_arn"]);
  const entries = Object.entries(evidence).filter(([k]) => !skip.has(k));
  const scalars = entries
    .filter(([, v]) => !Array.isArray(v) || typeof v[0] !== "object" || v[0] === null)
    .filter(([k]) => !(k === "region_count" && Array.isArray(evidence.disabled_regions)));
  const objectLists = entries.filter(([, v]) => Array.isArray(v) && typeof v[0] === "object" && v[0] !== null) as [string, Record<string, unknown>[]][];
  const unusedServices = evidence.unused_services as string[] | undefined;
  const removable = evidence.removable_statements as RemovableStatement[] | undefined;

  return (
    <div className="space-y-5">
      {unusedServices && unusedServices.length > 0 && (
        <div>
          <div className="mb-2 text-sm font-semibold text-zinc-700">
            Unused services
            <span className="ml-1.5 text-xs font-normal text-zinc-400">
              {unusedServices.length} of {(evidence.total_granted_services as number) ?? "?"} granted
            </span>
          </div>
          <CollapsibleServicePills services={unusedServices} />
        </div>
      )}
      {scalars.length > 0 && (
        <div className="divide-y divide-zinc-100 overflow-hidden rounded-lg border border-zinc-200 bg-white">
          {scalars.map(([k, v]) => {
            const rich = evidenceValueIsRich(k, v);
            if (rich) {
              return (
                <div key={k} className="px-4 py-3.5">
                  <div className="mb-2.5 text-xs font-medium text-zinc-500">{evidenceLabel(k, evidence)}</div>
                  <EvidenceValue fieldKey={k} value={v} />
                </div>
              );
            }
            return (
              <div key={k} className="grid grid-cols-[9rem_minmax(0,1fr)] items-center gap-x-4 px-4 py-3.5">
                <span className="text-xs font-medium leading-5 text-zinc-500">{evidenceLabel(k, evidence)}</span>
                <EvidenceValue fieldKey={k} value={v} />
              </div>
            );
          })}
        </div>
      )}
      {objectLists.map(([k, items]) => (
        <div key={k}>
          <div className="mb-2.5 text-sm font-semibold text-zinc-700">{evidenceSectionTitle(k)}</div>
          {k === "policies" ? <PolicyEvidenceList items={items} /> : <ObjectListTable items={items} />}
        </div>
      ))}
      {removable && <RemovableStatementsBlock statements={removable} cloudTrailLogging={cloudTrailLogging} />}
    </div>
  );
}

function resolvedCli(finding: Finding): string {
  const arn = finding.resource_arn;
  const roleMatch = arn.match(/:role\/(.+)$/);
  const roleName = roleMatch ? (roleMatch[1].split("/").pop() ?? "") : "";
  const userMatch = arn.match(/:user\/(.+)$/);
  const userName = userMatch ? (userMatch[1].split("/").pop() ?? "") : "";
  const keyId = (finding.evidence.key_id as string | undefined) ?? "<key-id>";
  const removable = finding.evidence.removable_statements as RemovableStatement[] | undefined;
  const hasInline = removable && removable.length > 0;
  if (finding.check_id === "iam.role.unused_services_90d" && !hasInline && roleName) return `# Permissions come from managed/attached policies — inline policies have no matching statements.

# 1. See what's attached
aws iam list-attached-role-policies --role-name ${roleName}

# 2. For each attached policy, review its document
aws iam get-policy-version --policy-arn <policy-arn> --version-id v1

# 3. Use Access Analyzer to generate a least-privilege replacement policy from CloudTrail
aws accessanalyzer start-policy-generation \\
  --policy-generation-details '{"principalArn":"${arn}"}'

# 4. Poll for the generated policy (takes ~30s)
aws accessanalyzer get-generated-policy --job-id <job-id>`;
  const rem = remediations[finding.check_id] ?? fallbackRemediation;
  const policyNames = removable ? [...new Set(removable.map((s) => s.policy))] : [];
  const policyName = policyNames.length === 1 ? policyNames[0] : "<policy-name>";
  const ev = finding.evidence;
  const arnRegion = arn.match(/^arn:aws:[^:]+:([^:*]+)/)?.[1] ?? "<region>";
  const bucketName =
    (ev.bucket_name as string | undefined) ??
    (ev.name as string | undefined) ??
    arn.match(/^arn:aws:s3:::([^/]+)$/)?.[1] ??
    "<bucket-name>";
  const tableName =
    (ev.table_name as string | undefined) ??
    arn.match(/:table\/([^/]+)$/)?.[1] ??
    "<table-name>";
  const instanceId =
    (ev.db_instance_id as string | undefined) ??
    arn.match(/:db:([^:/]+)/)?.[1] ??
    "<instance-id>";
  const functionName =
    (ev.function_name as string | undefined) ??
    arn.match(/:function:([^:+/]+)/)?.[1] ??
    "<function-name>";
  const snapshotId =
    (ev.snapshot_id as string | undefined) ??
    arn.match(/snapshot\/(snap-[^/]+)/)?.[1] ??
    "<snapshot-id>";
  const imageId =
    (ev.image_id as string | undefined) ??
    arn.match(/(ami-[a-f0-9]+)/)?.[1] ??
    "<image-id>";
  const trailName = (ev.name as string | undefined) ?? "<trail-name>";
  const parameterName = (ev.parameter_name as string | undefined) ?? "<parameter-name>";
  const secretName = (ev.name as string | undefined) ?? "<secret-name>";
  const loadBalancerArn = arn.includes(":loadbalancer/") ? arn : "<load-balancer-arn>";
  const domainName = (ev.domain_name as string | undefined) ?? "<domain-name>";
  const certificateArn = arn.includes(":acm:") ? arn : "<certificate-arn>";
  const topicArn = arn.includes(":sns:") ? arn : "<topic-arn>";
  const queueArnMatch = arn.match(/^arn:aws:sqs:([^:]+):(\d+):(.+)$/);
  const queueUrl = queueArnMatch
    ? `https://sqs.${queueArnMatch[1]}.amazonaws.com/${queueArnMatch[2]}/${queueArnMatch[3]}`
    : "<queue-url>";
  const region = (ev.region as string | undefined) ?? arnRegion;
  const kmsKeyId = (ev.key_id as string | undefined) ?? "<key-id>";
  const accountId = arn.match(/^arn:aws:[^:]+:[^:]+:\d+:/)?.[0]?.match(/:(\d+):/)?.[1] ?? "<account-id>";
  return rem.cli
    .replace(/<role-name>/g, roleName || "<role-name>")
    .replace(/<user>/g, userName || "<user>")
    .replace(/<key-id>/g, kmsKeyId)
    .replace(/<policy-name>/g, policyName)
    .replace(/<bucket-name>/g, bucketName)
    .replace(/<table-name>/g, tableName)
    .replace(/<region>/g, region)
    .replace(/<instance-id>/g, instanceId)
    .replace(/<function-name>/g, functionName)
    .replace(/<snapshot-id>/g, snapshotId)
    .replace(/<image-id>/g, imageId)
    .replace(/<trail-name>/g, trailName)
    .replace(/<parameter-name>/g, parameterName)
    .replace(/<secret-name>/g, secretName)
    .replace(/<load-balancer-arn>/g, loadBalancerArn)
    .replace(/<domain-name>/g, domainName)
    .replace(/<certificate-arn>/g, certificateArn)
    .replace(/<topic-arn>/g, topicArn)
    .replace(/<queue-url>/g, queueUrl)
    .replace(/<account-id>/g, accountId);
}

type AttachedPolicyAnalysis = {
  policy_arn: string;
  policy_name: string;
  policy_type: "aws_managed" | "customer_managed";
  granted_services: string[];
  unused_services: string[];
  active_services: string[];
  has_wildcard_action: boolean;
  action: "detach_and_replace" | "edit";
};

function iamPolicyConsoleUrl(policyArn: string): string {
  return `https://console.aws.amazon.com/iam/home#/policies/details/${encodeURIComponent(policyArn)}`;
}

function iamRolePermissionsConsoleUrl(roleArn: string): string {
  const match = roleArn.match(/:role\/(.+)$/);
  const roleName = match ? match[1] : "";
  return `https://console.aws.amazon.com/iam/home#/roles/details/${encodeURIComponent(roleName)}?section=permissions`;
}

function ConsoleLink({ href, children, title }: { href: string; children: React.ReactNode; title: string }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      title={title}
      className="inline-flex flex-shrink-0 items-center gap-1 text-xs font-medium text-sky-600 hover:text-sky-800 hover:underline"
    >
      {children}
      <svg className="h-3 w-3 opacity-70" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
        <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25" />
      </svg>
    </a>
  );
}

type BlastRadiusData = {
  resource_type: string;
  confidence: "high" | "medium" | "low";
  // role fields
  days_since_last_assumed?: number | null;
  trust_principals?: string[];
  services?: { name: string; last_used: string | null; days_ago: number | null; active: boolean; in_policy: boolean }[];
  active_service_count?: number;
  unused_service_count?: number;
  has_inline_policies?: boolean;
  attached_policies?: AttachedPolicyAnalysis[];
  // access key fields
  keys?: { key_id: string; last_used: string | null; days_ago: number | null; last_used_service: string | null; last_used_region: string | null; active: boolean }[];
  // user fields
  has_console_password?: boolean;
  days_inactive?: number | null;
  active_key_count?: number;
  // security group fields
  group_id?: string;
  group_name?: string;
  vpc_id?: string;
  region?: string;
  is_default?: boolean;
  affected_instances?: { instance_id: string; instance_type: string | null; state: string; vpc_id: string | null; name: string }[];
  running_count?: number;
  total_count?: number;
  // kms key fields
  key_id?: string;
  alias?: string | null;
  key_state?: string | null;
  rotation_enabled?: boolean;
  dependent_trails?: { name: string; arn: string; region: string; is_multi_region: boolean }[];
  dependent_trail_count?: number;
  // s3 bucket fields
  bucket_name?: string;
  encrypted?: boolean;
  kms_encrypted?: boolean;
  versioning_enabled?: boolean;
  public_access_blocked?: boolean;
  https_only?: boolean;
  logging_enabled?: boolean;
  // rds instance fields
  db_instance_id?: string;
  engine?: string | null;
  storage_encrypted?: boolean;
  publicly_accessible?: boolean;
  backup_retention_period?: number;
  // dynamodb table fields
  table_name?: string;
  pitr_enabled?: boolean;
  // ec2 instance fields
  instance_id?: string;
  instance_type?: string | null;
  state?: string;
  imdsv2_required?: boolean;
  // ebs volume fields
  volume_id?: string;
  size_gib?: number | null;
  volume_type?: string | null;
  attached_instances?: { instance_id: string; state: string; name: string; instance_type: string | null }[];
  // ebs encryption default fields
  existing_unencrypted_count?: number;
  // cloudtrail trail fields
  trail_name?: string;
  home_region?: string;
  is_multi_region?: boolean;
  is_logging?: boolean;
  log_validation_enabled?: boolean;
  kms_key_id?: string | null;
  trail_count?: number;
  existing_trails?: { name: string; home_region: string; is_multi_region: boolean; is_logging: boolean }[];
  // vpc fields (vpc_id and region reused from security_group fields above)
  instance_count?: number;
  // iam root / password policy fields
  min_length?: number | null;
  max_age?: number | null;
  password_reuse_prevention?: number | null;
  // s3 account block fields
  public_bucket_count?: number;
  public_bucket_names?: string[];
  // guardduty fields
  disabled_regions?: string[];
  // identity (GitHub/GitLab)
  provider_type?: string;
  org?: string;
  username?: string;
  source?: string;
  email?: string | null;
  mfa_enabled?: boolean | null;
  repo?: string;
  default_branch?: string;
  has_branch_protection?: boolean;
  required_reviews?: number;
  recent_merge_count?: number;
  active_member_count?: number;
  outside_collaborator_count?: number;
  // session-18 resource detail
  snapshot_id?: string;
  is_public?: boolean;
  image_id?: string;
  domain_name?: string;
  expires_at?: string | null;
  days_until_expiry?: number | null;
  function_name?: string;
  runtime?: string | null;
  has_dlq?: boolean;
  access_logs_enabled?: boolean;
  ssl_policy?: string | null;
  lb_type?: string | null;
  name?: string;
  warnings: string[];
};

const confidenceConfig = {
  high: { label: "Safe to remediate", color: "bg-emerald-50 text-emerald-700 border-emerald-200", dot: "bg-emerald-500", desc: "No active usage detected in the past 90 days." },
  medium: { label: "Review first", color: "bg-amber-50 text-amber-700 border-amber-200", dot: "bg-amber-400", desc: "Some recent activity detected — verify before making changes." },
  low: { label: "Active — proceed with caution", color: "bg-red-50 text-red-700 border-red-200", dot: "bg-red-500", desc: "Resource was actively used in the last 30 days." },
};

function buildVerdict(data: BlastRadiusData, checkId?: string): { text: string; type: "safe" | "caution" | "warning" } {
  const { resource_type, confidence } = data;

  if (resource_type === "iam_role") {
    const active = data.active_service_count ?? 0;
    if (confidence === "high") {
      const never = data.days_since_last_assumed == null;
      return never
        ? { text: "Safe to remove — role has never been assumed and no active service usage detected.", type: "safe" }
        : { text: `Safe to remove — unassumed for ${data.days_since_last_assumed} days with no active service usage.`, type: "safe" };
    }
    if (confidence === "medium") {
      return { text: `Review before removing — ${active} service${active !== 1 ? "s" : ""} show recent activity. Verify the workload before making changes.`, type: "caution" };
    }
    return { text: `Do not remove without verification — ${active} service${active !== 1 ? "s" : ""} were actively used in the last 30 days.`, type: "warning" };
  }

  if (resource_type === "iam_access_key") {
    const key = data.keys?.[0];
    if (confidence === "high") {
      return key?.days_ago != null
        ? { text: `Safe to delete — key unused for ${key.days_ago} days.`, type: "safe" }
        : { text: "Safe to delete — key has never been used.", type: "safe" };
    }
    if (key?.last_used_service && key?.days_ago != null) {
      return { text: `Active key — last used ${key.days_ago} days ago via ${key.last_used_service}. Rotate carefully.`, type: "warning" };
    }
    return { text: "Active key — verify usage before rotating or deleting.", type: "warning" };
  }

  if (resource_type === "iam_user") {
    if (checkId === "iam.user.no_mfa") {
      return {
        text: "Safe to require — MFA applies to console sign-in only; IAM access keys and programmatic access are unchanged until keys are rotated separately.",
        type: "safe",
      };
    }
    if (confidence === "high") {
      return data.days_inactive != null
        ? { text: `Safe to disable — user inactive for ${data.days_inactive} days.`, type: "safe" }
        : { text: "Safe to disable — no recorded activity for this user.", type: "safe" };
    }
    if (confidence === "low") return { text: "Active user — verify ownership and dependencies before disabling.", type: "warning" };
    return { text: "Review before disabling — some recent activity detected.", type: "caution" };
  }

  if (resource_type === "security_group") {
    const running = data.running_count ?? 0;
    const total = data.total_count ?? 0;
    if (running > 0) {
      return {
        text: `Restrict with care — ${running} running instance${running !== 1 ? "s" : ""} use this group (${total} total).`,
        type: "warning",
      };
    }
    if (total > 0) {
      if (data.is_default) {
        return {
          text: `${total} instance${total !== 1 ? "s" : ""} attached to this default SG (none running) — confirm explicit SG assignments before clearing rules.`,
          type: "caution",
        };
      }
      return {
        text: `${total} instance${total !== 1 ? "s" : ""} attached, none running — safe to modify.`,
        type: "caution",
      };
    }
    if (data.is_default) {
      return {
        text: "Safe to clear rules — no instances use this VPC's default security group. An empty default SG is recommended so future launches without an explicit group stay locked down.",
        type: "safe",
      };
    }
    return { text: "No instances attached to this security group — safe to update.", type: "safe" };
  }

  if (resource_type === "kms_key") {
    const state = (data.key_state ?? "").toLowerCase();
    if (state === "pendingdeletion") return { text: "Key is pending deletion — cancel deletion before enabling rotation.", type: "caution" };
    if (state === "disabled") return { text: "Key is disabled — re-enable the key before enabling rotation.", type: "caution" };
    return { text: "Safe to enable — KMS key rotation is transparent to applications. AWS retains old key material; no application changes required.", type: "safe" };
  }

  if (resource_type === "s3_bucket") {
    if (checkId === "s3.bucket.no_https_policy") {
      return {
        text: "Safe to enable — AWS SDKs, CLI, and Terraform already use HTTPS. Only clients with explicit http:// URLs would be denied.",
        type: "safe",
      };
    }
    if (confidence === "high") return { text: "Safe to enable — enabling S3 access logging has no impact on bucket access or application behaviour.", type: "safe" };
    if (confidence === "low") return { text: "Review before applying — bucket may have public access patterns that depend on current settings.", type: "warning" };
    return { text: "Verify before applying — this change may affect applications accessing the bucket. See warnings below.", type: "caution" };
  }

  if (resource_type === "rds_instance") {
    if (checkId === "rds.instance.no_multi_az") {
      return { text: "Enabling Multi-AZ causes a brief failover (~60s) and doubles cost — plan a maintenance window.", type: "caution" };
    }
    if (checkId === "rds.instance.no_deletion_protection") {
      return { text: "Safe to enable — deletion protection only blocks accidental deletes; intentional deletion requires disabling it first.", type: "safe" };
    }
    if (confidence === "low") return { text: "High blast radius — encrypting an RDS instance requires creating a new instance from an encrypted snapshot. Plan a maintenance window.", type: "warning" };
    if (confidence === "high") return { text: "Safe to enable — automated backups have no impact on application availability and can be enabled at any time.", type: "safe" };
    return { text: "Verify connectivity before applying — disabling public access removes the external endpoint. Ensure your app connects via VPC.", type: "caution" };
  }

  if (resource_type === "dynamodb_table") {
    if (checkId === "dynamodb.table.no_pitr") {
      return { text: "Safe to enable — point-in-time recovery is turned on in place with no downtime or application changes.", type: "safe" };
    }
    return { text: "Safe to enable — DynamoDB encryption at rest updates in place with no downtime. Reads and writes continue during the update.", type: "safe" };
  }

  if (resource_type === "ebs_snapshot") {
    if (checkId === "ec2.ebs.snapshot_public") {
      return { text: "Remove public access immediately — assume the snapshot may already have been copied externally.", type: "warning" };
    }
    return { text: "Safe to encrypt via snapshot copy — no running instances affected.", type: "safe" };
  }

  if (resource_type === "ec2_ami") {
    return { text: "Make private immediately — assume the image may have been copied. Rotate any secrets baked into the AMI.", type: "warning" };
  }

  if (resource_type === "acm_certificate") {
    if (confidence === "low") return { text: "Urgent — certificate expires within a week. Renew now to avoid HTTPS outages.", type: "warning" };
    return { text: "Plan renewal before expiry — update listeners/distributions after issuing a replacement certificate.", type: "caution" };
  }

  if (resource_type === "lambda_function") {
    if (checkId === "lambda.function.deprecated_runtime") {
      return { text: "Test runtime upgrade in a staging alias first — dependency incompatibilities are common.", type: "caution" };
    }
    return { text: "Safe to add — DLQ only captures failed async invocations; successful calls are unaffected.", type: "safe" };
  }

  if (resource_type === "secrets_manager_secret") {
    return { text: "First rotation updates the live secret — verify applications fetch the latest version from Secrets Manager.", type: "caution" };
  }

  if (resource_type === "ssm_parameter") {
    return { text: "Converting to SecureString is low-risk if apps already use the SSM API — confirm kms:Decrypt on consuming roles.", type: "caution" };
  }

  if (resource_type === "elb_load_balancer") {
    if (checkId === "elb.load_balancer.weak_tls_policy") {
      return { text: "Test with your oldest TLS clients before tightening the listener policy.", type: "caution" };
    }
    return { text: "Safe to enable — access logs add S3 storage cost only; no impact on traffic.", type: "safe" };
  }

  if (resource_type === "sns_topic" || resource_type === "sqs_queue") {
    return { text: "Verify publishers/subscribers have KMS permissions after enabling encryption.", type: "caution" };
  }

  if (resource_type === "ec2_instance") {
    return { text: "Verify application compatibility first — apps using IMDSv1 without a session token will fail. Test in non-prod before applying.", type: "caution" };
  }

  if (resource_type === "ebs_volume") {
    const running = data.running_count ?? 0;
    if (running > 0) return { text: `High blast radius — ${running} running instance(s) attached. Replacing the volume requires downtime unless it is a non-root, remountable volume.`, type: "warning" };
    if (confidence === "high") return { text: "No instances attached — safe to encrypt via snapshot copy with no downtime risk.", type: "safe" };
    return { text: "Instances attached but not running — plan volume replacement during maintenance.", type: "caution" };
  }

  if (resource_type === "ebs_encryption_default") {
    return { text: "Safe to enable — only affects volumes created after this change.", type: "safe" };
  }

  if (resource_type === "cloudtrail_trail") {
    if (checkId === "cloudtrail.trail.s3_bucket_public") {
      return { text: "Remove public access immediately — assume audit logs may have been exposed while the bucket was public.", type: "warning" };
    }
    if (checkId === "cloudtrail.trail.s3_bucket_no_logging") {
      return { text: "Safe to enable — S3 access logging on the log bucket adds visibility with no impact on CloudTrail delivery.", type: "safe" };
    }
    if (checkId === "cloudtrail.trail.no_cloudwatch_logs") {
      return { text: "Safe to enable — real-time alerting only; does not change existing S3 log delivery.", type: "safe" };
    }
    if (confidence === "high") return { text: "Safe to enable — no application impact. Note: CloudTrail storage in S3 incurs a small ongoing cost.", type: "safe" };
    return { text: "Verify CloudTrail's delivery role has the required KMS permissions before applying.", type: "caution" };
  }

  if (resource_type === "cloudtrail_account") {
    if ((data.trail_count ?? 0) === 0) {
      return { text: "No CloudTrail trails found — safe to create a new multi-region trail. No existing logging to disrupt.", type: "safe" };
    }
    return { text: "Existing trails don't meet the multi-region + logging requirement — enable a compliant trail or fix the ones below.", type: "caution" };
  }

  if (resource_type === "vpc") {
    const count = data.instance_count ?? 0;
    return count > 0
      ? { text: "Safe to enable — flow logs add visibility without affecting network traffic.", type: "safe" }
      : { text: "Safe to enable — no instances in this VPC yet.", type: "safe" };
  }

  if (resource_type === "iam_root") {
    if (confidence === "low") return { text: "Check all automation for root credentials before deleting — any process using these keys will immediately break.", type: "warning" };
    return { text: "Safe to apply — no application impact. This change only affects the root identity itself.", type: "safe" };
  }

  if (resource_type === "iam_password_policy") {
    if (confidence === "medium") return { text: "Users with passwords older than the new maximum age will be forced to reset at next login.", type: "caution" };
    return { text: "Safe to update — no current max age policy set, so no forced password resets will occur.", type: "safe" };
  }

  if (resource_type === "s3_account_block") {
    const count = data.public_bucket_count ?? 0;
    if (count > 0) return { text: `${count} bucket(s) are not yet blocking public access at the bucket level — enabling the account block will override them and may break public-read buckets or static websites.`, type: "warning" };
    return { text: "Safe to enable — all buckets already block public access at the bucket level. Account-level block adds a belt-and-suspenders guard.", type: "safe" };
  }

  if (resource_type === "guardduty" || resource_type === "aws_config" || resource_type === "securityhub" || resource_type === "access_analyzer") {
    return { text: "Safe to enable — adds security visibility without impacting existing resources or applications.", type: "safe" };
  }

  if (resource_type === "iam_policy_wildcard_resource") {
    return { text: "Scoping down Resource: * requires knowing which specific ARNs each action needs — test in non-prod before applying to production roles.", type: "caution" };
  }

  if (resource_type === "iam_policy_unattached") {
    return { text: "Safe to delete — policy is not attached to any principal and grants no access.", type: "safe" };
  }

  if (resource_type === "iam_perm_granted_vs_used") {
    if (confidence === "high") return { text: "No service usage recorded in 90 days — high confidence unused permissions can be removed safely.", type: "safe" };
    return { text: "Some services were recently used — verify application behaviour before removing unused permission grants.", type: "caution" };
  }

  if (resource_type === "identity_org") {
    if (checkId?.endsWith("outside_collaborators")) {
      return { text: "Review each outside collaborator — revoking access may break contractors, auditors, or CI bots using personal accounts.", type: "caution" };
    }
    if (checkId?.endsWith("mfa_not_enforced")) {
      return { text: "Org-wide MFA enforcement blocks password-only logins — members must enroll before next sign-in.", type: "caution" };
    }
    return { text: "Removing dormant members revokes access to all org repositories — confirm with owners first.", type: "caution" };
  }

  if (resource_type === "identity_user") {
    if (checkId?.endsWith("mfa_not_enforced")) {
      return { text: "Safe to require MFA — affects console login only; personal access tokens and SSH keys keep working until rotated.", type: "safe" };
    }
    return { text: "Suspending this member immediately revokes repository access — verify they are not on-call or release owner.", type: "caution" };
  }

  if (resource_type === "identity_repo") {
    if (checkId?.endsWith("no_branch_protection")) {
      return { text: "Branch protection blocks direct pushes to the default branch — coordinate with teams using hotfix workflows.", type: "caution" };
    }
    if (checkId?.endsWith("no_env_protection")) {
      return { text: "Environment protection pauses production deploys until approved — align with release managers before enabling.", type: "caution" };
    }
    if (checkId?.endsWith("self_merge_allowed") || checkId?.endsWith("insufficient_reviews")) {
      return { text: "Tighter review rules slow merges but reduce unreviewed code reaching default branch.", type: "caution" };
    }
    return { text: "Low risk — adding CODEOWNERS or review rules does not rewrite history or block existing open PRs.", type: "safe" };
  }

  if (confidence === "high") return { text: "No active usage detected — safe to remediate.", type: "safe" };
  if (confidence === "medium") return { text: "Some recent activity detected — review before making changes.", type: "caution" };
  return { text: "Active resource — proceed with caution.", type: "warning" };
}

const verdictStyle = {
  safe: { card: "border-emerald-200 bg-emerald-50", text: "text-emerald-900", icon: "text-emerald-500" },
  caution: { card: "border-amber-200 bg-amber-50", text: "text-amber-900", icon: "text-amber-500" },
  warning: { card: "border-red-200 bg-red-50", text: "text-red-900", icon: "text-red-500" },
};

function VerdictIcon({ type }: { type: "safe" | "caution" | "warning" }) {
  if (type === "safe") return (
    <svg className="h-4 w-4 flex-shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
    </svg>
  );
  if (type === "caution") return (
    <svg className="h-4 w-4 flex-shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
    </svg>
  );
  return (
    <svg className="h-4 w-4 flex-shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
    </svg>
  );
}

function InfoNote({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-2 rounded-lg border border-zinc-200 bg-zinc-50 px-3 py-2.5 text-xs leading-relaxed text-zinc-600">
      <svg className="mt-0.5 h-3.5 w-3.5 flex-shrink-0 text-zinc-400" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
        <path strokeLinecap="round" strokeLinejoin="round" d="m11.25 11.25.041-.02a.75.75 0 0 1 1.063.852l-.708 2.836a.75.75 0 0 0 1.063.853l.041-.021M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-9-3.75h.008v.008H12V8.25Z" />
      </svg>
      <span>{children}</span>
    </div>
  );
}

function BlastRadiusSection({ accountId, finding }: { accountId: string; finding: Finding }) {
  const [enabled, setEnabled] = useState(false);
  const { data, isLoading, error } = useQuery<BlastRadiusData>({
    queryKey: ["blast-radius", accountId, finding.resource_arn, finding.check_id, finding.last_seen],
    queryFn: () => api(`/v1/accounts/${accountId}/blast-radius?resource_arn=${encodeURIComponent(finding.resource_arn)}&check_id=${encodeURIComponent(finding.check_id)}`),
    enabled,
    staleTime: 0,
  });

  if (!enabled) {
    return (
      <div className="rounded-xl border border-zinc-200 bg-white p-4 space-y-2">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-sm font-semibold text-zinc-900">What If I fix this?</div>
            <div className="text-xs text-zinc-400 mt-0.5">Analyse what currently depends on this resource before remediating.</div>
          </div>
          <button
            onClick={() => setEnabled(true)}
            className="rounded-lg border border-zinc-200 bg-zinc-50 px-5 py-2.5 text-xs font-semibold text-zinc-700 hover:bg-zinc-100 transition-colors"
          >
            Analyse
          </button>
        </div>
      </div>
    );
  }

  if (isLoading) return <div className="rounded-xl border border-zinc-200 bg-white p-4 text-xs text-zinc-400">Analysing blast radius…</div>;
  if (error) return <div className="rounded-xl border border-red-100 bg-red-50 p-4 text-xs text-red-500">{String(error)}</div>;
  if (!data) return null;

  const verdict = buildVerdict(data, finding.check_id);
  const conf = confidenceConfig[
    finding.check_id === "s3.bucket.no_https_policy" || verdict.type === "safe"
      ? "high"
      : data.confidence
  ];
  const vs = verdictStyle[verdict.type];
  const normalizedVerdict = verdict.text.toLowerCase().replace(/\s+/g, " ").trim();
  function warningKey(text: string) {
    const n = text.toLowerCase().replace(/\s+/g, " ").trim();
    if ((n.includes("scoping down resource: *") || n.includes("scoping resource: *")) && (n.includes("specific arn") || n.includes("specific resource"))) {
      return "scope-resource-star";
    }
    if (n.includes("running instance") && (n.includes("downtime") || n.includes("replacing") || n.includes("detaching"))) {
      return "ebs-running-downtime";
    }
    if (n.includes("bucket") && n.includes("public access") && n.includes("account") && n.includes("block")) {
      return "s3-public-bucket-block";
    }
    return n;
  }
  const verdictKey = warningKey(normalizedVerdict);
  const seen = new Set<string>();
  const baseWarnings = (data.resource_type === "iam_access_key" ? [] : data.warnings).filter((warning) => {
    if (data.resource_type !== "iam_user") return true;
    const normalized = warning.toLowerCase();
    return !(normalized.startsWith("access key ") && normalized.includes(" used ") && normalized.includes(" deactivate keys before disabling user"));
  });
  const keyUsageWarnings = data.resource_type === "iam_user" && data.keys
    ? data.keys
        .filter((k) => k.last_used && k.days_ago != null)
        .map((k) => `Access key ${k.key_id} shows API activity ${k.days_ago} days ago via ${k.last_used_service ?? "unknown service"}${k.last_used_region ? ` (${k.last_used_region})` : ""} — deactivate keys before disabling user`)
    : [];
  const allNotices = [...baseWarnings, ...keyUsageWarnings];
  const infoRows = verdict.type === "safe" ? allNotices : [];
  const warningRows = verdict.type === "safe" ? [] : allNotices.filter((warning) => {
    const key = warningKey(warning);
    if (key === verdictKey) return false;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return (
    <div className="rounded-xl border border-zinc-200 bg-white overflow-hidden">
      <div className="px-4 py-3.5 border-b border-zinc-100 flex items-center justify-between">
        <span className="text-[15px] font-semibold text-zinc-900">Blast radius</span>
        <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold ${conf.color}`}>
          <span className={`h-1.5 w-1.5 rounded-full ${conf.dot}`} />
          {conf.label}
        </span>
      </div>

      <div className="p-4 space-y-4">
        <div className={`flex items-start gap-2.5 rounded-lg border px-3.5 py-3 ${vs.card}`}>
          <span className={vs.icon}><VerdictIcon type={verdict.type} /></span>
          <p className={`text-sm font-medium leading-snug ${vs.text}`}>{verdict.text}</p>
        </div>

        {data.resource_type === "vpc" && (
          <InfoNote>
            {(data.instance_count ?? 0) === 0
              ? "Log volume and cost are negligible until workloads are added."
              : `${data.instance_count} instance${data.instance_count !== 1 ? "s" : ""} in this VPC will be covered. Flow logs deliver to CloudWatch Logs or S3 — budget ~$0.50/GB for CloudWatch ingestion.`}
          </InfoNote>
        )}

        {infoRows.map((note, i) => (
          <InfoNote key={i}>{note}</InfoNote>
        ))}

        {/* Warnings */}
        {warningRows.length > 0 && (
          <div className="space-y-1.5">
            {warningRows.map((w, i) => (
              <div key={i} className="flex items-start gap-2 rounded-lg border border-amber-100 bg-amber-50 px-3 py-2 text-xs text-amber-800">
                <svg className="mt-0.5 h-3.5 w-3.5 flex-shrink-0 text-amber-500" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126z" />
                </svg>
                {w}
              </div>
            ))}
          </div>
        )}

        {/* Role: services */}
        {data.resource_type === "iam_role" && data.services && data.services.length > 0 && (
          <div>
            <div className="text-sm font-semibold text-zinc-700 mb-2">Granted services ({data.services.length})</div>
            <CollapsibleGrantedServices services={data.services} />
            <div className="mt-2 flex gap-3 text-xs text-zinc-400">
              <span><span className="font-semibold text-red-600">{data.active_service_count}</span> active</span>
              <span><span className="font-semibold text-zinc-600">{data.unused_service_count}</span> unused</span>
            </div>
          </div>
        )}

        {/* Role: trust principals */}
        {data.resource_type === "iam_role" && data.trust_principals && data.trust_principals.length > 0 && (
          <div>
            <div className="text-sm font-semibold text-zinc-700 mb-2">Trusted by</div>
            <div className="space-y-1">
              {data.trust_principals.map((p, i) => (
                <div key={i} className="rounded-md bg-zinc-50 border border-zinc-200 px-2.5 py-1.5 font-mono text-xs text-zinc-600 break-all">{p}</div>
              ))}
            </div>
          </div>
        )}

        {/* Role: attached policies breakdown */}
        {data.resource_type === "iam_role" && data.attached_policies && data.attached_policies.length > 0 && (
          <div>
            <div className="text-sm font-semibold text-zinc-700 mb-2">Attached policies ({data.attached_policies.length})</div>
            <div className="space-y-2">
              {data.attached_policies.map((pol) => (
                <div key={pol.policy_arn} className="rounded-lg border border-zinc-200 bg-zinc-50 overflow-hidden">
                  <div className="flex items-center gap-2 px-3 py-2 border-b border-zinc-200 bg-white">
                    <div className="flex flex-1 items-center gap-2 min-w-0 overflow-hidden">
                      <span className="group/pname relative min-w-0">
                        <span className="block font-mono text-xs font-medium text-zinc-800 truncate">{pol.policy_name}</span>
                        <div className="pointer-events-none absolute bottom-full left-0 z-50 mb-2 hidden max-w-xs rounded-lg border border-zinc-200 bg-white px-3 py-2 shadow-lg group-hover/pname:block">
                          <p className="break-all font-mono text-xs text-zinc-700 leading-relaxed">{pol.policy_name}</p>
                        </div>
                      </span>
                      <span className={`flex-shrink-0 rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${
                        pol.policy_type === "aws_managed"
                          ? "border-blue-200 bg-blue-50 text-blue-700"
                          : "border-violet-200 bg-violet-50 text-violet-700"
                      }`}>
                        {pol.policy_type === "aws_managed" ? "AWS" : "Custom"}
                      </span>
                      {pol.has_wildcard_action && (
                        <span className="flex-shrink-0 rounded border border-red-200 bg-red-50 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-red-700">
                          wildcard
                        </span>
                      )}
                    </div>
                    <ConsoleLink
                      href={
                        pol.action === "detach_and_replace"
                          ? iamRolePermissionsConsoleUrl(finding.resource_arn)
                          : iamPolicyConsoleUrl(pol.policy_arn)
                      }
                      title={
                        pol.action === "detach_and_replace"
                          ? "Open role permissions in AWS Console to detach this managed policy"
                          : "Open policy in AWS Console to edit"
                      }
                    >
                      {pol.action === "detach_and_replace" ? "Detach + replace" : "Edit policy"}
                    </ConsoleLink>
                  </div>
                  <div className="px-3 py-2.5 space-y-2">
                    {pol.unused_services.length > 0 && (
                      <div>
                        <div className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-zinc-400">Removable</div>
                        <div className="flex flex-wrap gap-1">
                          {pol.unused_services.map((s) => (
                            <span key={s} className="rounded bg-zinc-100 px-1.5 py-0.5 font-mono text-[11px] text-zinc-500">{s}</span>
                          ))}
                        </div>
                      </div>
                    )}
                    {pol.active_services.length > 0 && (
                      <div>
                        <div className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-zinc-400">Keep (active)</div>
                        <div className="flex flex-wrap gap-1">
                          {pol.active_services.map((s) => (
                            <span key={s} className="rounded bg-red-50 px-1.5 py-0.5 font-mono text-[11px] text-red-600">{s}</span>
                          ))}
                        </div>
                      </div>
                    )}
                    {pol.unused_services.length === 0 && pol.active_services.length === 0 && pol.granted_services.length > 0 && (
                      <span className="text-xs text-zinc-400">No usage data yet — run a scan, then check back once service last-accessed data populates.</span>
                    )}
                    {pol.granted_services.length === 0 && (
                      <span className="text-xs text-zinc-400">No parseable service grants found.</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Role: last assumed */}
        {data.resource_type === "iam_role" && (
          <div className="text-xs text-zinc-400">
            {data.days_since_last_assumed !== null && data.days_since_last_assumed !== undefined
              ? `Last assumed ${data.days_since_last_assumed} days ago`
              : "Never assumed"}
          </div>
        )}

        {/* Access key: key list */}
        {data.resource_type === "iam_access_key" && data.keys && data.keys.length > 0 && (
          <div className="space-y-2">
            {data.keys.map((k) => (
              <KeyActivityCard key={k.key_id} keyData={k} />
            ))}
          </div>
        )}

        {/* User: summary */}
        {data.resource_type === "iam_user" && (
          <div className="overflow-hidden rounded-lg border border-zinc-200 bg-zinc-50">
            <div className="px-3 py-2 text-xs text-zinc-600">
              {data.active_key_count} active access key{data.active_key_count !== 1 ? "s" : ""}
            </div>
            {data.has_console_password && (
              <div className="border-t border-zinc-200 px-3 py-2 text-xs text-zinc-600">
                Has console password
              </div>
            )}
          </div>
        )}

        {/* RDS instance: metadata grid */}
        {data.resource_type === "rds_instance" && (
          <div className="grid grid-cols-3 gap-2 text-xs">
            {([
              ["Instance", data.db_instance_id ?? "—", null],
              ["Engine", data.engine ?? "—", null],
              ["Region", data.region ?? "—", null],
              ["Encrypted", data.storage_encrypted ? "Yes" : "No", data.storage_encrypted],
              ["Public access", data.publicly_accessible ? "Enabled" : "Disabled", !data.publicly_accessible],
              ["Backup retention", data.backup_retention_period != null ? `${data.backup_retention_period}d` : "—", (data.backup_retention_period ?? 0) > 0],
            ] as [string, string, boolean | null][]).map(([label, val, ok]) => (
              <div key={label} className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
                <div className="font-medium text-zinc-400 mb-0.5">{label}</div>
                <div className={`font-mono font-medium truncate ${ok === true ? "text-emerald-700" : ok === false ? "text-red-600" : "text-zinc-700"}`}>{val}</div>
              </div>
            ))}
          </div>
        )}

        {/* DynamoDB table: metadata grid */}
        {data.resource_type === "dynamodb_table" && (
          <div className="grid grid-cols-2 gap-2 text-xs">
            {([
              ["Table", data.table_name ?? "—", null],
              ["Region", data.region ?? "—", null],
              ["Encrypted", data.kms_encrypted ? "Yes" : "No", data.kms_encrypted],
              ["PITR", data.pitr_enabled ? "Enabled" : "Disabled", data.pitr_enabled],
            ] as [string, string, boolean | null][]).map(([label, val, ok]) => (
              <div key={label} className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
                <div className="font-medium text-zinc-400 mb-0.5">{label}</div>
                <div className={`font-mono font-medium truncate ${ok === true ? "text-emerald-700" : ok === false ? "text-red-600" : "text-zinc-700"}`}>{val}</div>
              </div>
            ))}
          </div>
        )}

        {/* EC2 instance: metadata grid */}
        {data.resource_type === "ec2_instance" && (
          <div className="grid grid-cols-2 gap-2 text-xs">
            {([
              ["Instance", data.instance_id ?? "—", null],
              ["Type", data.instance_type ?? "—", null],
              ["State", data.state ?? "—", data.state === "running"],
              ["Region", data.region ?? "—", null],
            ] as [string, string, boolean | null][]).map(([label, val, ok]) => (
              <div key={label} className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
                <div className="font-medium text-zinc-400 mb-0.5">{label}</div>
                <div className={`font-mono font-medium ${ok === true ? "text-emerald-700" : ok === false ? "text-zinc-500" : "text-zinc-700"}`}>{val}</div>
              </div>
            ))}
          </div>
        )}

        {/* EBS volume: metadata + attached instances */}
        {data.resource_type === "ebs_volume" && (
          <div className="space-y-3">
            <div className="grid grid-cols-3 gap-2 text-xs">
              {([
                ["Volume", data.volume_id ?? "—", null],
                ["Size", data.size_gib != null ? `${data.size_gib} GiB` : "—", null],
                ["Type", data.volume_type ?? "—", null],
                ["State", data.state ?? "—", null],
                ["Region", data.region ?? "—", null],
                ["Attached", `${(data.attached_instances ?? []).length}`, null],
              ] as [string, string, null][]).map(([label, val]) => (
                <div key={label} className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
                  <div className="font-medium text-zinc-400 mb-0.5">{label}</div>
                  <div className="font-mono font-medium text-zinc-700 truncate">{val}</div>
                </div>
              ))}
            </div>
            {data.attached_instances && data.attached_instances.length > 0 && (
              <div>
                <div className="text-sm font-semibold text-zinc-700 mb-2">
                  Attached instances
                  {(data.running_count ?? 0) > 0 && <span className="ml-2 text-xs font-medium text-red-500">{data.running_count} running</span>}
                </div>
                <div className="space-y-1.5">
                  {data.attached_instances.map((inst) => (
                    <div key={inst.instance_id} className={`flex items-center justify-between rounded-md border px-3 py-2 text-xs ${inst.state === "running" ? "border-red-100 bg-red-50" : "border-zinc-200 bg-zinc-50"}`}>
                      <div className="flex items-center gap-2 min-w-0">
                        <span className={`h-1.5 w-1.5 flex-shrink-0 rounded-full ${inst.state === "running" ? "bg-red-400" : "bg-zinc-300"}`} />
                        <span className="font-mono text-zinc-700 truncate">{inst.name !== inst.instance_id ? inst.name : inst.instance_id}</span>
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0 pl-2">
                        {inst.instance_type && <span className="text-zinc-400">{inst.instance_type}</span>}
                        <span className={`font-medium ${inst.state === "running" ? "text-red-600" : "text-zinc-400"}`}>{inst.state}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* EBS encryption default: unencrypted volume count */}
        {data.resource_type === "ebs_encryption_default" && (
          <div className="rounded-md border border-zinc-200 bg-zinc-50 px-3 py-3 text-xs">
            <div className="font-medium text-zinc-400 mb-0.5">Existing unencrypted volumes</div>
            <div className={`text-2xl font-bold tabular-nums ${(data.existing_unencrypted_count ?? 0) > 0 ? "text-amber-600" : "text-emerald-600"}`}>
              {data.existing_unencrypted_count ?? 0}
            </div>
            <p className="mt-1.5 text-zinc-400 leading-relaxed">Enabling default encryption only affects volumes created <em>after</em> this change. Each existing unencrypted volume must be migrated separately via snapshot copy.</p>
          </div>
        )}

        {/* CloudTrail account: existing non-compliant trails */}
        {data.resource_type === "cloudtrail_account" && (data.trail_count ?? 0) > 0 && (
          <div className="space-y-2">
            <div className="space-y-1.5">
              {(data.existing_trails ?? []).map((trail) => (
                <div key={trail.name} className="flex items-center justify-between gap-3 rounded-lg border border-zinc-200 bg-zinc-50 px-3 py-2.5 text-xs">
                  <div className="min-w-0">
                    <div className="truncate font-mono font-medium text-zinc-800">{trail.name}</div>
                    <div className="mt-0.5 text-zinc-400">{trail.home_region}</div>
                  </div>
                  <div className="flex shrink-0 flex-wrap justify-end gap-1">
                    <span className={`rounded border px-1.5 py-0.5 font-medium ${trail.is_logging ? "border-emerald-200 bg-emerald-50 text-emerald-700" : "border-zinc-200 bg-white text-zinc-500"}`}>
                      {trail.is_logging ? "Logging" : "Stopped"}
                    </span>
                    <span className={`rounded border px-1.5 py-0.5 font-medium ${trail.is_multi_region ? "border-blue-200 bg-blue-50 text-blue-700" : "border-amber-200 bg-amber-50 text-amber-800"}`}>
                      {trail.is_multi_region ? "Multi-region" : "Single-region"}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* CloudTrail trail: metadata grid */}
        {data.resource_type === "cloudtrail_trail" && (
          <div className="grid grid-cols-2 gap-2 text-xs">
            {([
              ["Trail", data.trail_name ?? "—", null],
              ["Region", data.home_region ?? "—", null],
              ["Logging", data.is_logging ? "Active" : "Stopped", data.is_logging],
              ["Multi-region", data.is_multi_region ? "Yes" : "No", data.is_multi_region],
              ["Log validation", data.log_validation_enabled ? "Enabled" : "Off", data.log_validation_enabled],
              ["KMS encrypted", data.kms_key_id ? "Yes" : "No", !!data.kms_key_id],
            ] as [string, string, boolean | null][]).map(([label, val, ok]) => (
              <div key={label} className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
                <div className="font-medium text-zinc-400 mb-0.5">{label}</div>
                <div className={`font-mono font-medium ${ok === true ? "text-emerald-700" : ok === false ? "text-zinc-500" : "text-zinc-700"}`}>{val}</div>
              </div>
            ))}
          </div>
        )}

        {/* VPC: metadata */}
        {data.resource_type === "vpc" && (
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
              <div className="font-medium text-zinc-400 mb-0.5">VPC</div>
              <div className="font-mono font-medium text-zinc-700">{data.vpc_id ?? "—"}</div>
            </div>
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
              <div className="font-medium text-zinc-400 mb-0.5">Region</div>
              <div className="font-mono font-medium text-zinc-700">{data.region ?? "—"}</div>
            </div>
            <div className="col-span-2 rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
              <div className="font-medium text-zinc-400 mb-0.5">Instances in VPC</div>
              <div className="text-2xl font-bold tabular-nums text-zinc-700">{data.instance_count ?? 0}</div>
            </div>
          </div>
        )}

        {/* IAM root: static info */}
        {data.resource_type === "iam_root" && (
          <p className="text-xs text-zinc-500 leading-relaxed">Root is the most privileged identity in AWS — all IAM policies and SCPs are bypassed. Changes to root identity settings have no effect on workloads or IAM users.</p>
        )}

        {/* IAM password policy: current settings */}
        {data.resource_type === "iam_password_policy" && (
          <div className="grid grid-cols-3 gap-2 text-xs">
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
              <div className="font-medium text-zinc-400 mb-0.5">Min length</div>
              <div className="font-mono font-medium text-zinc-700">{data.min_length ?? "none"}</div>
            </div>
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
              <div className="font-medium text-zinc-400 mb-0.5">Max age</div>
              <div className={`font-mono font-medium ${data.max_age ? "text-amber-700" : "text-zinc-400"}`}>{data.max_age ? `${data.max_age}d` : "none"}</div>
            </div>
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
              <div className="font-medium text-zinc-400 mb-0.5">Reuse prevention</div>
              <div className="font-mono font-medium text-zinc-700">{data.password_reuse_prevention ?? "none"}</div>
            </div>
          </div>
        )}

        {/* S3 account-level block: affected buckets */}
        {data.resource_type === "s3_account_block" && (data.public_bucket_count ?? 0) > 0 && (
          <div>
            <div className="mb-2.5 text-xs font-medium text-zinc-500">
              Affected buckets ({data.public_bucket_count})
            </div>
            <div className="flex flex-wrap gap-2">
              {(data.public_bucket_names ?? []).map((name) => (
                <span key={name} className="inline-flex max-w-full items-center rounded-lg border border-zinc-200 bg-zinc-50 px-2.5 py-1.5 font-mono text-xs text-zinc-700">
                  <span className="truncate">{name}</span>
                </span>
              ))}
            </div>
          </div>
        )}

        {/* GuardDuty: disabled regions */}
        {data.resource_type === "guardduty" && data.disabled_regions && data.disabled_regions.length > 0 && (
          <div>
            <div className="mb-2.5 text-xs font-medium text-zinc-500">
              Disabled regions ({data.disabled_regions.length})
            </div>
            <RegionPills regions={data.disabled_regions} />
          </div>
        )}

        {/* S3 bucket: posture grid */}
        {data.resource_type === "s3_bucket" && (
          <div className="space-y-3">
            <div className="grid grid-cols-3 gap-2 text-xs">
              {([
                ["Encryption", data.encrypted ? "Enabled" : "None", data.encrypted],
                ["KMS", data.kms_encrypted ? "Enabled" : "SSE-S3 / None", data.kms_encrypted],
                ["Public access", data.public_access_blocked ? "Blocked" : "Open", data.public_access_blocked],
                ["HTTPS-only", data.https_only ? "Enforced" : "Not enforced", data.https_only],
                ["Versioning", data.versioning_enabled ? "Enabled" : "Off", data.versioning_enabled],
                ["Logging", data.logging_enabled ? "Enabled" : "Off", data.logging_enabled],
              ] as [string, string, boolean | undefined][]).map(([label, val, ok]) => (
                <div key={label} className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
                  <div className="font-medium text-zinc-400 mb-0.5">{label}</div>
                  <div className={`font-mono font-medium ${ok ? "text-emerald-700" : "text-zinc-500"}`}>{val}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* KMS key: metadata + dependent trails */}
        {data.resource_type === "kms_key" && (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
                <div className="font-medium text-zinc-400 mb-0.5">Alias</div>
                <div className="font-mono text-zinc-700 truncate">{data.alias ?? "no alias"}</div>
              </div>
              <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
                <div className="font-medium text-zinc-400 mb-0.5">Key state</div>
                <div className={`font-mono font-medium ${data.key_state === "Enabled" ? "text-emerald-700" : "text-amber-700"}`}>
                  {data.key_state ?? "unknown"}
                </div>
              </div>
            </div>

            {data.dependent_trails && data.dependent_trails.length > 0 ? (
              <div>
                <div className="text-sm font-semibold text-zinc-700 mb-2">
                  Used by CloudTrail ({data.dependent_trail_count})
                </div>
                <div className="space-y-1.5">
                  {data.dependent_trails.map((trail) => (
                    <div key={trail.arn} className="flex items-center justify-between rounded-md border border-zinc-200 bg-zinc-50 px-3 py-2 text-xs">
                      <span className="font-mono text-zinc-700 truncate">{trail.name}</span>
                      <div className="flex items-center gap-2 flex-shrink-0 pl-2">
                        <span className="text-zinc-400">{trail.region}</span>
                        {trail.is_multi_region && <span className="rounded border border-blue-200 bg-blue-50 px-1.5 py-0.5 text-[10px] font-semibold text-blue-700">multi-region</span>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <p className="text-xs text-zinc-400">No CloudTrail trails reference this key. Note: S3, RDS, and EBS key associations are not yet tracked per-key in Vigil.</p>
            )}
          </div>
        )}

        {/* Security group: metadata + affected instances */}
        {data.resource_type === "security_group" && (
          <div className="space-y-3">
            <div className="grid grid-cols-3 gap-2 text-xs">
              <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2 min-w-0">
                <div className="font-medium text-zinc-400 mb-0.5">Security group</div>
                <div className="font-mono text-zinc-700 truncate" title={data.group_id}>{data.group_id}</div>
                {data.is_default && (
                  <div className="mt-1">
                    <span className="rounded border border-violet-200 bg-violet-50 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-violet-700">
                      Default
                    </span>
                  </div>
                )}
              </div>
              <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2 min-w-0">
                <div className="font-medium text-zinc-400 mb-0.5">VPC</div>
                <div className="font-mono text-zinc-700 truncate" title={data.vpc_id ?? undefined}>{data.vpc_id ?? "—"}</div>
              </div>
              <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2 min-w-0">
                <div className="font-medium text-zinc-400 mb-0.5">Region</div>
                <div className="text-zinc-700 truncate" title={data.region}>{AWS_REGION_LABELS[data.region ?? ""] ?? data.region}</div>
                {data.region && AWS_REGION_LABELS[data.region] && (
                  <div className="mt-0.5 font-mono text-[10px] text-zinc-400 truncate">{data.region}</div>
                )}
              </div>
            </div>

            {data.affected_instances && data.affected_instances.length > 0 ? (
              <div>
                <div className="text-sm font-semibold text-zinc-700 mb-2">
                  Exposed instances ({data.total_count})
                  {data.running_count !== undefined && data.running_count > 0 && (
                    <span className="ml-2 text-xs font-medium text-red-500">{data.running_count} running</span>
                  )}
                </div>
                <div className="space-y-1.5">
                  {data.affected_instances.map((inst) => (
                    <div
                      key={inst.instance_id}
                      className={`flex items-center justify-between rounded-md border px-3 py-2 text-xs ${
                        inst.state === "running"
                          ? "border-red-100 bg-red-50"
                          : "border-zinc-200 bg-zinc-50"
                      }`}
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <span className={`h-1.5 w-1.5 flex-shrink-0 rounded-full ${inst.state === "running" ? "bg-red-400" : "bg-zinc-300"}`} />
                        <span className="font-mono text-zinc-700 truncate">{inst.name !== inst.instance_id ? inst.name : inst.instance_id}</span>
                        {inst.name !== inst.instance_id && <span className="font-mono text-zinc-400 truncate">{inst.instance_id}</span>}
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0 pl-2">
                        {inst.instance_type && <span className="text-zinc-400">{inst.instance_type}</span>}
                        <span className={`font-medium ${inst.state === "running" ? "text-red-600" : "text-zinc-400"}`}>{inst.state}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="text-xs text-zinc-400">
                {data.is_default
                  ? "No instances in this region are attached to this VPC's default security group."
                  : "No instances currently attached to this security group."}
              </div>
            )}
          </div>
        )}

        {data.resource_type === "ebs_snapshot" && (
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
              <div className="font-medium text-zinc-400 mb-0.5">Snapshot</div>
              <div className="font-mono font-medium text-zinc-700 truncate">{data.snapshot_id ?? "—"}</div>
            </div>
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
              <div className="font-medium text-zinc-400 mb-0.5">Encrypted</div>
              <div className={`font-mono font-medium ${data.encrypted ? "text-emerald-700" : "text-red-600"}`}>{data.encrypted ? "Yes" : "No"}</div>
            </div>
          </div>
        )}

        {data.resource_type === "ec2_ami" && (
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2 col-span-2">
              <div className="font-medium text-zinc-400 mb-0.5">AMI</div>
              <div className="font-mono font-medium text-zinc-700 truncate">{data.image_id ?? data.name ?? "—"}</div>
            </div>
          </div>
        )}

        {data.resource_type === "acm_certificate" && (
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2 col-span-2">
              <div className="font-medium text-zinc-400 mb-0.5">Domain</div>
              <div className="font-mono font-medium text-zinc-700 truncate">{data.domain_name ?? "—"}</div>
            </div>
            {data.days_until_expiry != null && (
              <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
                <div className="font-medium text-zinc-400 mb-0.5">Expires in</div>
                <div className={`font-mono font-medium ${data.days_until_expiry <= 7 ? "text-red-600" : "text-amber-700"}`}>{data.days_until_expiry}d</div>
              </div>
            )}
          </div>
        )}

        {data.resource_type === "lambda_function" && (
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2 col-span-2">
              <div className="font-medium text-zinc-400 mb-0.5">Function</div>
              <div className="font-mono font-medium text-zinc-700 truncate">{data.function_name ?? "—"}</div>
            </div>
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
              <div className="font-medium text-zinc-400 mb-0.5">Runtime</div>
              <div className="font-mono font-medium text-zinc-700">{data.runtime ?? "—"}</div>
            </div>
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
              <div className="font-medium text-zinc-400 mb-0.5">DLQ</div>
              <div className={`font-mono font-medium ${data.has_dlq ? "text-emerald-700" : "text-zinc-500"}`}>{data.has_dlq ? "Yes" : "No"}</div>
            </div>
          </div>
        )}

        {data.resource_type === "elb_load_balancer" && (
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2 col-span-2">
              <div className="font-medium text-zinc-400 mb-0.5">Load balancer</div>
              <div className="font-mono font-medium text-zinc-700 truncate">{data.name ?? "—"}</div>
            </div>
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
              <div className="font-medium text-zinc-400 mb-0.5">Access logs</div>
              <div className={`font-mono font-medium ${data.access_logs_enabled ? "text-emerald-700" : "text-zinc-500"}`}>{data.access_logs_enabled ? "On" : "Off"}</div>
            </div>
            {data.ssl_policy && (
              <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
                <div className="font-medium text-zinc-400 mb-0.5">TLS policy</div>
                <div className="font-mono text-[10px] text-zinc-700 truncate">{data.ssl_policy}</div>
              </div>
            )}
          </div>
        )}

        {(data.resource_type === "sns_topic" || data.resource_type === "sqs_queue") && (
          <div className="rounded-md border border-zinc-200 bg-zinc-50 px-3 py-2.5 text-xs text-zinc-600">
            Region <span className="font-mono font-medium text-zinc-800">{data.region ?? "—"}</span>
            {" · "}
            KMS <span className={`font-mono font-medium ${data.kms_encrypted ? "text-emerald-700" : "text-zinc-500"}`}>{data.kms_encrypted ? "enabled" : "not enabled"}</span>
          </div>
        )}

        {data.resource_type === "identity_repo" && (
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2 col-span-2">
              <div className="font-medium text-zinc-400 mb-0.5">Repository</div>
              <div className="font-mono font-medium text-zinc-700 truncate">{data.repo ?? "—"}</div>
            </div>
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
              <div className="font-medium text-zinc-400 mb-0.5">Default branch</div>
              <div className="font-mono font-medium text-zinc-700">{data.default_branch ?? "main"}</div>
            </div>
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
              <div className="font-medium text-zinc-400 mb-0.5">Protection</div>
              <div className={`font-mono font-medium ${data.has_branch_protection ? "text-emerald-700" : "text-zinc-500"}`}>
                {data.has_branch_protection ? `${data.required_reviews ?? 0} reviews` : "None"}
              </div>
            </div>
          </div>
        )}

        {data.resource_type === "identity_user" && (
          <div className="rounded-md border border-zinc-200 bg-zinc-50 px-3 py-2.5 text-xs text-zinc-600">
            <span className="font-mono font-medium text-zinc-800">{data.username}</span>
            {data.source && <> @ {data.source}</>}
            {data.days_inactive != null && <> · inactive {data.days_inactive}d</>}
          </div>
        )}

        {data.resource_type === "identity_org" && (
          <div className="rounded-md border border-zinc-200 bg-zinc-50 px-3 py-2.5 text-xs text-zinc-600">
            {data.provider_type === "github" ? "GitHub" : "GitLab"} org{" "}
            <span className="font-mono font-medium text-zinc-800">{data.org}</span>
            {(data.outside_collaborator_count ?? 0) > 0 && (
              <> · {data.outside_collaborator_count} outside collaborator(s)</>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

type Tab = "overview" | "remediation" | "whatif";
type GeneratedPolicy = { has_inline_policies: boolean; unused_services: string[]; used_services: string[]; used_actions?: string[]; granularity?: "action" | "service"; statements_removed?: number; statements_modified?: number; original_policies?: Record<string, unknown>; cleaned_policies?: Record<string, unknown>; note?: string };

const MISLEADING_INLINE_POLICY_NAMES = new Set([
  "AdministratorAccess",
  "PowerUserAccess",
  "ReadOnlyAccess",
  "IAMFullAccess",
  "IAMUserChangePassword",
  "SecurityAudit",
  "ViewOnlyAccess",
]);

function roleShortName(roleArn: string): string {
  const match = roleArn.match(/:role\/(.+)$/);
  return match ? (match[1].split("/").pop() ?? "role") : "role";
}

function suggestedInlinePolicyName(roleArn: string): string {
  const base = roleShortName(roleArn).replace(/[^a-zA-Z0-9+=,.@-]/g, "-");
  return `${base}-scoped`;
}

function policyRenameHint(policyName: string, roleArn: string, narrowed: boolean): string | null {
  if (!narrowed && !MISLEADING_INLINE_POLICY_NAMES.has(policyName)) return null;
  if (MISLEADING_INLINE_POLICY_NAMES.has(policyName)) {
    return `Inline policy name "${policyName}" no longer matches its scope. Consider renaming to ${suggestedInlinePolicyName(roleArn)} when you apply.`;
  }
  if (narrowed && /admin/i.test(policyName)) {
    return `Policy "${policyName}" was narrowed — rename on apply so the name reflects least privilege.`;
  }
  return null;
}

function policyChangeSummary(data: GeneratedPolicy) {
  const removed = data.statements_removed ?? 0;
  const modified = data.statements_modified ?? 0;
  const usedActions = data.used_actions?.length ?? 0;
  const usedServices = data.used_services?.length ?? 0;
  const parts: string[] = [];
  if (removed) parts.push(`${removed} statement${removed !== 1 ? "s" : ""} removed`);
  if (modified) {
    if (data.granularity === "action" && usedActions) {
      parts.push(`${modified} action wildcard${modified !== 1 ? "s" : ""} narrowed to ${usedActions} used action${usedActions !== 1 ? "s" : ""}`);
    } else {
      parts.push(`${modified} action wildcard${modified !== 1 ? "s" : ""} narrowed to ${usedServices} used service${usedServices !== 1 ? "s" : ""}`);
    }
  }
  return parts.length ? parts.join(" · ") : "No changes";
}

type PolicyStatement = { Sid?: string; Effect?: string; Action?: string | string[]; Resource?: string | string[]; [k: string]: unknown };

function PolicyDiffView({
  original,
  cleaned,
  granularity,
  hideUnchangedResources,
}: {
  original: Record<string, unknown>;
  cleaned: Record<string, unknown>;
  granularity?: "action" | "service";
  hideUnchangedResources?: boolean;
}) {
  const sections = Object.entries(original).map(([name, origDoc]) => {
    const origStmts: PolicyStatement[] = (origDoc as any)?.Statement ?? [];
    const cleanStmts: PolicyStatement[] = (cleaned as any)?.[name]?.Statement ?? [];
    const statements = origStmts.map((stmt, i) => {
      const clean = cleanStmts[i];
      const origJson = JSON.stringify(stmt);
      const cleanJson = clean ? JSON.stringify(clean) : null;
      if (!clean) return { kind: "removed" as const, stmt, clean: null };
      if (origJson === cleanJson) return { kind: "unchanged" as const, stmt, clean };
      return { kind: "modified" as const, stmt, clean };
    });
    return { name, statements };
  });

  return (
    <div className="space-y-4">
      {sections.map(({ name, statements }) => (
        <div key={name}>
          {sections.length > 1 && <div className="mb-2 font-mono text-[11px] font-medium text-zinc-400">{name}</div>}
          <div className="space-y-2">
            {statements.map((s, i) => {
              const actions = s.stmt.Action ? (Array.isArray(s.stmt.Action) ? s.stmt.Action : [s.stmt.Action]) : [];
              const resources = s.stmt.Resource ? (Array.isArray(s.stmt.Resource) ? s.stmt.Resource : [s.stmt.Resource]) : [];
              const cleanActions = s.clean?.Action ? (Array.isArray(s.clean.Action) ? s.clean.Action : [s.clean.Action]) : [];
              const border =
                s.kind === "removed" ? "border-red-200 bg-red-50" : s.kind === "modified" ? "border-amber-200 bg-amber-50" : "border-zinc-200 bg-zinc-50";
              return (
                <div key={i} className={`rounded-lg border px-3 py-2.5 text-xs ${border}`}>
                  {s.kind === "removed" && (
                    <div className="mb-2 flex items-center gap-1.5">
                      <span className="h-1.5 w-1.5 rounded-full bg-red-400 flex-shrink-0" />
                      <span className="text-[10px] font-semibold uppercase tracking-wide text-red-500">Removed — no usage in 90 days</span>
                    </div>
                  )}
                  {s.kind === "modified" && (
                    <div className="mb-2 flex items-center gap-1.5">
                      <span className="h-1.5 w-1.5 rounded-full bg-amber-400 flex-shrink-0" />
                      <span className="text-[10px] font-semibold uppercase tracking-wide text-amber-600">
                        Narrowed — scoped to used {granularity === "action" ? "actions" : "services"}
                      </span>
                    </div>
                  )}
                  <div className="space-y-1">
                    {s.stmt.Sid && <div><span className="text-zinc-400">Sid: </span><span className={`font-medium ${s.kind === "removed" ? "text-red-600 line-through" : "text-zinc-700"}`}>{s.stmt.Sid}</span></div>}
                    <div><span className="text-zinc-400">Effect: </span><span className={`font-medium ${s.kind === "removed" ? "text-red-600 line-through" : "text-zinc-700"}`}>{s.stmt.Effect}</span></div>
                    {actions.length > 0 && (
                      <div>
                        <span className="text-zinc-400">Actions: </span>
                        <span className={`font-mono break-all ${s.kind === "removed" ? "text-red-600 line-through" : s.kind === "modified" ? "text-zinc-500 line-through" : "text-zinc-700"}`}>{actions.join(", ")}</span>
                        {s.kind === "modified" && cleanActions.length > 0 && (
                          <div className="mt-1 font-mono break-all text-amber-800">{cleanActions.join(", ")}</div>
                        )}
                      </div>
                    )}
                    {resources.length > 0 && !(hideUnchangedResources && s.kind === "modified" && resources.length === 1 && resources[0] === "*") && (
                      <div>
                        <span className="text-zinc-400">Resources: </span>
                        <span className={`font-mono break-all ${s.kind === "removed" ? "text-red-600 line-through" : "text-zinc-600"}`}>
                          {resources.join(", ")}
                        </span>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

function GeneratePolicySection({
  accountId,
  finding,
  cloudTrailLogging,
}: {
  accountId: string;
  finding: Finding;
  cloudTrailLogging: boolean;
}) {
  const [enabled, setEnabled] = useState(false);
  const [view, setView] = useState<"diff" | "cleaned" | "original">("diff");
  const { data, isLoading, error } = useQuery<GeneratedPolicy>({
    queryKey: ["generated-policy", accountId, finding.resource_arn, finding.last_seen],
    queryFn: () => api(`/v1/accounts/${accountId}/roles/generated-policy?role_arn=${encodeURIComponent(finding.resource_arn)}`),
    enabled,
    staleTime: 0,
  });

  return (
    <div>
      <div className="mb-3 flex items-center justify-between">
        <div className="text-sm font-semibold text-zinc-700">Suggested policy</div>
        {!enabled && <button onClick={() => setEnabled(true)} className="rounded border border-zinc-300 bg-white px-3 py-1 text-xs font-medium text-zinc-700 transition-colors hover:bg-zinc-50 hover:text-zinc-900">Generate</button>}
      </div>
      {!enabled && (
        <p className="text-xs leading-relaxed text-zinc-400">{generatePolicyIntro(cloudTrailLogging)}</p>
      )}
      {enabled && isLoading && <div className="py-3 text-xs text-zinc-400">Generating…</div>}
      {enabled && error && <div className="py-2 text-xs text-red-500">{String(error)}</div>}
      {enabled && data && !data.has_inline_policies && (
        <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-xs leading-relaxed text-amber-800">{data.note ?? "No inline policies found. Permissions come from attached managed policies."}</div>
      )}
      {enabled && data && data.has_inline_policies && data.original_policies && data.cleaned_policies && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs text-zinc-500">
              {policyChangeSummary(data)}
            </span>
            <div className="flex gap-1 rounded-lg bg-zinc-100 p-0.5">
              {(["diff", "cleaned", "original"] as const).map((v) => (
                <button key={v} onClick={() => setView(v)} className={`rounded-md px-2.5 py-1 text-xs font-medium capitalize transition-colors ${view === v ? "bg-white text-zinc-900 shadow-sm" : "text-zinc-500 hover:text-zinc-700"}`}>
                  {v}
                </button>
              ))}
            </div>
          </div>
          {Object.keys(data.cleaned_policies).map((policyName) => {
            const hint = policyRenameHint(policyName, finding.resource_arn, (data.statements_modified ?? 0) > 0);
            if (!hint) return null;
            return (
              <div key={policyName} className="rounded-lg border border-indigo-200 bg-indigo-50 px-3 py-2.5 text-xs leading-relaxed text-indigo-900">
                {hint}
              </div>
            );
          })}
          {view === "diff" && (
            <PolicyDiffView
              original={data.original_policies}
              cleaned={data.cleaned_policies}
              granularity={data.granularity}
              hideUnchangedResources={finding.check_id === "iam.role.unused_services_90d"}
            />
          )}
          {view !== "diff" && <CliBlock code={JSON.stringify(view === "cleaned" ? data.cleaned_policies : data.original_policies, null, 2)} />}
          {data.granularity === "service" && (
            <p className="text-xs leading-relaxed text-zinc-400">
              Per-action usage not available yet — scoped to services with recorded activity. Run another scan to refresh, or use Access Analyzer for action-level generation on wildcard policies.
            </p>
          )}
        </div>
      )}
    </div>
  );
}

function CliBlock({ code }: { code: string }) {
  const [copied, setCopied] = useState(false);
  function copy() {
    const executable = code
      .split("\n")
      .filter((l) => !l.trimStart().startsWith("#"))
      .join("\n")
      .replace(/\n{3,}/g, "\n\n")
      .trim();
    navigator.clipboard.writeText(executable).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    });
  }
  return (
    <div className="rounded-lg border border-zinc-200 bg-zinc-50 overflow-hidden">
      <div className="flex justify-end border-b border-zinc-200 bg-white px-3 py-1.5">
        <button
          onClick={copy}
          className={`rounded-md border px-2.5 py-1 text-[11px] font-medium transition-all ${
            copied
              ? "border-emerald-200 bg-emerald-50 text-emerald-700"
              : "border-zinc-200 bg-zinc-50 text-zinc-500 hover:border-zinc-300 hover:bg-white hover:text-zinc-800"
          }`}
        >
          {copied ? "✓ Copied" : "Copy"}
        </button>
      </div>
      <pre className="overflow-x-auto whitespace-pre-wrap px-4 py-3 font-mono text-xs leading-relaxed text-zinc-800">{code}</pre>
    </div>
  );
}

function ExceptionButton({ findingId, onDone }: { findingId: string; onDone: () => void }) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [approvedBy, setApprovedBy] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [done, setDone] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!reason.trim() || !approvedBy.trim()) return;
    setSubmitting(true);
    try {
      await api(`/v1/findings/${findingId}/exception`, {
        method: "POST",
        body: JSON.stringify({
          reason: reason.trim(),
          approved_by: approvedBy.trim(),
          expires_at: expiresAt || null,
        }),
      });
      setDone(true);
      setTimeout(() => { setOpen(false); onDone(); }, 800);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        className={`flex-1 rounded-lg border px-4 py-2.5 text-sm font-semibold transition ${done ? "border-violet-200 bg-violet-50 text-violet-700" : "border-zinc-300 bg-white text-zinc-700 hover:bg-zinc-100"}`}
      >
        {done ? "Approved" : "Exception"}
      </button>
      {open && (
        <div className="fixed inset-0 z-[70] flex items-end justify-end">
          <div className="absolute inset-0 bg-black/20 backdrop-blur-[1px]" onClick={() => setOpen(false)} />
          <div className="relative w-full max-w-[560px] rounded-t-2xl bg-white shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-semibold text-zinc-900">Document exception</h3>
              <button onClick={() => setOpen(false)} className="text-zinc-400 hover:text-zinc-600">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <p className="text-sm text-zinc-500">
              Exceptions are retained in the evidence pack. Auditors can review the reason, approver, and expiry.
            </p>
            <form onSubmit={submit} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-zinc-700 mb-1">Reason <span className="text-red-500">*</span></label>
                <textarea
                  value={reason}
                  onChange={e => setReason(e.target.value)}
                  rows={3}
                  placeholder="e.g. Internal sandbox repo — no production code. Risk accepted by CTO."
                  className="w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm text-zinc-800 placeholder:text-zinc-400 focus:outline-none focus:ring-2 focus:ring-zinc-900/10"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-zinc-700 mb-1">Approved by <span className="text-red-500">*</span></label>
                <input
                  type="text"
                  value={approvedBy}
                  onChange={e => setApprovedBy(e.target.value)}
                  placeholder="e.g. Alice Smith (CTO)"
                  className="w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm text-zinc-800 placeholder:text-zinc-400 focus:outline-none focus:ring-2 focus:ring-zinc-900/10"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-zinc-700 mb-1">Expires (optional)</label>
                <input
                  type="date"
                  value={expiresAt}
                  onChange={e => setExpiresAt(e.target.value)}
                  className="w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm text-zinc-800 focus:outline-none focus:ring-2 focus:ring-zinc-900/10"
                />
              </div>
              <div className="flex gap-2 pt-1">
                <button
                  type="submit"
                  disabled={submitting || !reason.trim() || !approvedBy.trim()}
                  className="flex-1 rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-zinc-700 disabled:opacity-50"
                >
                  {submitting ? "Saving…" : "Save exception"}
                </button>
                <button type="button" onClick={() => setOpen(false)} className="flex-1 rounded-lg border border-zinc-200 bg-white px-4 py-2.5 text-sm font-semibold text-zinc-700 hover:bg-zinc-50 transition">
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  );
}

export function FindingDrawer({ finding, accountId, onClose, onAction, resolved, verifying }: { finding: Finding | null; accountId: string | null; onClose: () => void; onAction: (id: string, action: "recheck" | "resolve") => void; resolved?: boolean; verifying?: boolean }) {
  const [tab, setTab] = useState<Tab>("overview");
  const [remTab, setRemTab] = useState<"console" | "cli">("console");
  const [countdown, setCountdown] = useState(5);

  const { data: accountMeta } = useQuery({
    queryKey: ["account-cloudtrail", accountId],
    queryFn: () =>
      api<{ meta: { cloudtrail_logging: boolean } }>(`/v1/accounts/${accountId}/timeline?days=1&limit=1`),
    enabled: !!accountId && !!finding,
    staleTime: 300_000,
  });
  const cloudTrailLogging = accountMeta?.meta?.cloudtrail_logging ?? false;

  useEffect(() => { setTab("overview"); setRemTab("console"); }, [finding?.id]);

  useEffect(() => {
    if (!resolved) { setCountdown(5); return; }
    setCountdown(5);
    const tick = setInterval(() => setCountdown((c) => c - 1), 1000);
    const close = setTimeout(onClose, 5000);
    return () => { clearInterval(tick); clearTimeout(close); };
  }, [resolved]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!finding) return null;

  const rem = identityRemediations[finding.check_id] ?? remediations[finding.check_id] ?? fallbackRemediation;
  const isIdentityCheck = finding.check_id.startsWith("github.") || finding.check_id.startsWith("gitlab.");
  const headerBadge = sevHeaderBadge[finding.severity] ?? sevHeaderBadge.low;
  const wash = sevWash[finding.severity] ?? sevWash.low;
  const step = sevStep[finding.severity] ?? sevStep.low;
  const hasEvidence = Object.keys(finding.evidence).length > 0;
  const categoryLabel: Record<string, string> = {
    "iam.root": "Root Account",
    "iam.user": "IAM User",
    "iam.access_key": "Access Key",
    "iam.role": "IAM Role",
    "s3.bucket": "S3 Bucket",
    "kms.key": "KMS Key",
    "dynamodb.table": "DynamoDB Table",
    "lambda.function": "Lambda Function",
    "acm.certificate": "ACM Certificate",
    "secretsmanager.secret": "Secrets Manager",
    "ssm.parameter": "SSM Parameter",
    "elb.load_balancer": "Load Balancer",
    "sns.topic": "SNS Topic",
    "sqs.queue": "SQS Queue",
    "ec2.ami": "EC2 AMI",
    "ec2.ebs.snapshot": "EBS Snapshot",
    "github.org": "GitHub Organization",
    "github.repo": "GitHub Repository",
    "gitlab.org": "GitLab Group",
    "gitlab.repo": "GitLab Project",
  };
  const category = Object.entries(categoryLabel).find(([prefix]) => finding.check_id.startsWith(prefix))?.[1] ?? "Finding";
  const showPolicyGen = finding.check_id === "iam.role.unused_services_90d" && !!accountId;
  const showBlastRadius = BLAST_RADIUS_CHECKS.has(finding.check_id) && !!accountId;

  const tabs: { id: Tab; label: string }[] = [
    { id: "overview", label: "Overview" },
    { id: "remediation", label: "Remediation" },
    ...(showBlastRadius ? [{ id: "whatif" as Tab, label: "What If" }] : []),
  ];

  return <><div className="fixed inset-0 z-40 bg-black/25 backdrop-blur-[2px]" onClick={onClose} /><div className="fixed right-0 top-0 z-50 flex h-full w-full max-w-[560px] flex-col overflow-hidden bg-white shadow-2xl">
    <div className={`relative bg-gradient-to-b ${wash} px-7 pt-6 pb-4`}>
      <button onClick={onClose} className="absolute right-5 top-5 rounded-md p-1 text-zinc-300 transition hover:bg-white/70 hover:text-zinc-600"><svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg></button>
      <div className="flex items-center gap-2.5 pr-10"><span className="text-xs font-medium text-zinc-500">{category}</span><span className="text-zinc-300">·</span><span className={`inline-flex items-center rounded border px-2 py-0.5 text-[11px] font-bold uppercase tracking-wide ${headerBadge}`}>{finding.severity}</span></div>
      <h2 className="mt-2 pr-8 text-[17px] font-semibold leading-snug text-zinc-900">{finding.title}</h2>
      <div className="mt-4 rounded-lg border border-black/[0.07] bg-white/60 px-3 py-2.5">
        <div className="text-[11px] font-medium text-zinc-400 mb-0.5">Resource</div>
        <div className="group relative">
          <p className="truncate font-mono text-xs text-zinc-700">{finding.resource_arn}</p>
          <div className="pointer-events-none absolute bottom-full left-0 z-50 mb-2 hidden max-w-xs rounded-lg border border-zinc-200 bg-white px-3 py-2 shadow-lg group-hover:block"><p className="break-all font-mono text-xs text-zinc-700 leading-relaxed">{finding.resource_arn}</p></div>
        </div>
      </div>
      {/* Segmented tab control */}
      <div className="mt-4 flex gap-0.5 rounded-xl bg-black/[0.06] p-1">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`flex flex-1 items-center justify-center gap-1.5 rounded-lg py-1.5 text-[13px] font-medium transition-all ${
              tab === t.id ? "bg-white text-zinc-900 shadow-sm" : "text-zinc-500 hover:text-zinc-700"
            }`}
          >
            {t.id === "whatif" && (
              <svg className="h-3.5 w-3.5 text-amber-400" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M9.879 7.519c1.171-1.025 3.071-1.025 4.242 0 1.172 1.025 1.172 2.687 0 3.712-.203.179-.43.326-.67.442-.745.361-1.45.999-1.45 1.827v.75M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9 5.25h.008v.008H12v-.008z" />
              </svg>
            )}
            {t.label}
          </button>
        ))}
      </div>
    </div>
    <div className="flex-1 space-y-4 overflow-y-auto bg-stone-50 px-7 pb-6 pt-5">
      {tab === "overview" && <>
        <div className="grid grid-cols-2 gap-3">
          <div className="rounded-lg border border-zinc-200 bg-white p-4 shadow-sm"><div className="mb-1.5 text-sm font-semibold text-zinc-800">Why it matters</div><p className="text-sm leading-6 text-zinc-600">{rem.why}</p></div>
          <div className="rounded-lg border border-zinc-200 bg-white p-4 shadow-sm"><div className="mb-1.5 text-sm font-semibold text-zinc-800">Risk</div><p className="text-sm leading-6 text-zinc-600">{rem.risk}</p></div>
        </div>
        {hasEvidence && <div>
          <div className="mb-2 text-sm font-semibold text-zinc-700">Scan details</div>
          <EvidenceSection
            evidence={finding.evidence}
            checkId={finding.check_id}
            cloudTrailLogging={cloudTrailLogging}
          />
        </div>}
        {showPolicyGen && (
          <GeneratePolicySection
            accountId={accountId!}
            finding={finding}
            cloudTrailLogging={cloudTrailLogging}
          />
        )}
        <div className="flex items-center gap-3 border-t border-zinc-200/70 pt-4 pb-1 text-xs text-zinc-400">
          <span>First seen {new Date(finding.first_seen).toLocaleDateString()}</span>
          <span className="text-zinc-300">·</span>
          <span>Last seen {new Date(finding.last_seen).toLocaleDateString()}</span>
          <span className="text-zinc-300">·</span>
          <span>Score <span className="font-semibold text-zinc-500">{finding.risk_score}</span></span>
        </div>
      </>}
      {tab === "remediation" && (
        <div className="rounded-xl border border-zinc-200 bg-white overflow-hidden shadow-sm">
          <div className="flex items-center justify-between border-b border-zinc-100 px-4 py-3">
            <span className="text-sm font-semibold text-zinc-700">Steps</span>
            {!isIdentityCheck && (
              <div className="flex gap-0.5 rounded-full border border-zinc-200 bg-zinc-50 p-0.5">{(["console", "cli"] as const).map((t) => <button key={t} onClick={() => setRemTab(t)} className={`rounded-full px-3.5 py-1 text-[13px] font-medium transition-all ${remTab === t ? "bg-zinc-900 text-white shadow-sm" : "text-zinc-400 hover:text-zinc-600"}`}>{t === "cli" ? "AWS CLI" : "Console"}</button>)}</div>
            )}
          </div>
          <div className="bg-zinc-50/70 p-5">
            {(isIdentityCheck || remTab === "console") && <ol className="space-y-3">{rem.console.map((item, i) => <li key={i} className="flex gap-3 text-sm leading-6 text-zinc-700"><span className={`mt-0.5 flex h-5 w-5 flex-shrink-0 items-center justify-center rounded-full text-[11px] font-bold ${step}`}>{i + 1}</span>{item}</li>)}</ol>}
            {!isIdentityCheck && remTab === "cli" && <CliBlock code={resolvedCli(finding)} />}
          </div>
        </div>
      )}
      {tab === "whatif" && showBlastRadius && (
        <BlastRadiusSection accountId={accountId!} finding={finding} />
      )}
    </div>
    <div className="flex gap-2 border-t border-stone-200 bg-stone-50 px-7 py-5">
      <button onClick={() => { onAction(finding.id, "resolve"); onClose(); }} className="flex-1 rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-zinc-700">Resolve</button>
      <button disabled={verifying} onClick={() => onAction(finding.id, "recheck")} className="flex-1 inline-flex items-center justify-center gap-2 rounded-lg border border-zinc-300 bg-white px-4 py-2.5 text-sm font-semibold text-zinc-700 transition hover:bg-zinc-100 disabled:opacity-50">{verifying && <svg className="h-3.5 w-3.5 animate-spin" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>}{verifying ? "Verifying…" : "Verify"}</button>
      <ExceptionButton findingId={finding.id} onDone={onClose} />
    </div>
    {resolved && (
      <div className="fixed right-0 top-0 z-[60] flex h-full w-full max-w-[560px] flex-col items-center justify-center bg-white/85 backdrop-blur-md">
        <div className="relative flex items-center justify-center">
          <div className="absolute h-36 w-36 animate-ping rounded-full bg-emerald-400 opacity-10" style={{ animationDuration: "1.4s" }} />
          <div className="relative flex h-32 w-32 items-center justify-center rounded-full bg-emerald-500" style={{ boxShadow: "0 0 0 12px rgba(16,185,129,0.12), 0 0 60px rgba(16,185,129,0.45)" }}>
            <svg className="h-16 w-16 text-white" fill="none" stroke="currentColor" strokeWidth={2.5} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
            </svg>
          </div>
        </div>
        <p className="mt-8 text-2xl font-bold tracking-tight text-zinc-900">Issue resolved</p>
        <p className="mt-2 text-sm text-zinc-500">Closing in {countdown}s</p>
        <button
          onClick={onClose}
          className="mt-5 rounded-full border border-zinc-200 bg-white px-5 py-2 text-sm font-medium text-zinc-600 shadow-sm transition hover:bg-zinc-50 hover:text-zinc-900"
        >
          Close now
        </button>
      </div>
    )}
  </div></>;
}
