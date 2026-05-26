import { useState, useEffect, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api";

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
    why: "Without a deny-HTTP bucket policy, clients can request objects over unencrypted HTTP. Data in transit is exposed to interception.",
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
    risk: "HTTP requests transmit credentials and data in plaintext. Even internal traffic should be encrypted in transit.",
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

const fallbackRemediation: Remediation = {
  why: "Review this finding and take corrective action based on your security policy.",
  console: ["Open the AWS Console", "Navigate to IAM", "Locate the affected resource and review its configuration"],
  cli: "# Review with AWS CLI\naws iam get-user --user-name <user>",
  risk: "Unresolved findings increase your attack surface.",
};

type RemovableStatement = { policy: string; sid: string; actions: string[]; resources: string[] };

function ServicePills({ services }: { services: string[] }) {
  return <div className="flex flex-wrap gap-1.5">{services.map((s) => <span key={s} className="inline-flex items-center rounded border border-amber-200 bg-amber-50 px-2 py-0.5 font-mono text-xs font-medium text-amber-700">{s}</span>)}</div>;
}

function RemovableStatementsBlock({ statements }: { statements: RemovableStatement[] }) {
  if (!statements.length) return null;
  return <div><div className="mb-2 text-sm font-semibold text-zinc-700">Removable statements<span className="ml-1.5 text-xs font-normal text-zinc-400">from inline policies</span></div><div className="space-y-2">{statements.map((stmt, i) => <div key={i} className="overflow-hidden rounded-lg border border-zinc-200 text-xs"><div className="flex items-center gap-2 border-b border-zinc-200 bg-zinc-50 px-3 py-2"><span className="font-mono font-medium text-zinc-800">{stmt.policy}</span>{stmt.sid && <span className="text-zinc-400">· {stmt.sid}</span>}</div><div className="space-y-2 px-3 py-2.5"><div className="flex flex-wrap gap-1">{stmt.actions.map((a) => <span key={a} className="rounded border border-red-200 bg-red-50 px-1.5 py-0.5 font-mono text-red-700">{a}</span>)}</div><div className="font-mono text-xs text-zinc-400">on: {stmt.resources.join(", ")}</div></div></div>)}</div></div>;
}

function ObjectListTable({ items }: { items: Record<string, unknown>[] }) {
  if (!items.length) return null;
  const cols = Object.keys(items[0]);
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
                <td key={c} className="px-3 py-2 font-mono text-zinc-800 break-all max-w-[200px]">
                  {row[c] == null ? "—" : String(row[c])}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function EvidenceSection({ evidence, checkId }: { evidence: Record<string, unknown>; checkId: string }) {
  const skip = new Set(["removable_statements", "unused_services", "role_arn"]);
  const entries = Object.entries(evidence).filter(([k]) => !skip.has(k));
  const scalars = entries.filter(([, v]) => !Array.isArray(v) || typeof v[0] !== "object" || v[0] === null);
  const objectLists = entries.filter(([, v]) => Array.isArray(v) && typeof v[0] === "object" && v[0] !== null) as [string, Record<string, unknown>[]][];
  const unusedServices = evidence.unused_services as string[] | undefined;
  const removable = evidence.removable_statements as RemovableStatement[] | undefined;
  function renderScalar(k: string, v: unknown): string {
    if (v === null || v === undefined) {
      const isDateField = k.includes("last") || k.includes("date") || k.includes("used") || k.includes("inactive");
      return isDateField ? "Never" : "—";
    }
    if (Array.isArray(v)) return v.join(", ");
    return String(v);
  }
  return (
    <div className="space-y-4">
      {unusedServices && unusedServices.length > 0 && (
        <div>
          <div className="mb-2 text-sm font-semibold text-zinc-700">
            Unused services
            <span className="ml-1.5 text-xs font-normal text-zinc-400">
              {unusedServices.length} of {(evidence.total_granted_services as number) ?? "?"} granted
            </span>
          </div>
          <ServicePills services={unusedServices} />
        </div>
      )}
      {scalars.length > 0 && (
        <div className="overflow-hidden rounded-lg border border-zinc-200">
          {scalars.map(([k, v], i) => (
            <div key={k} className={`flex gap-4 px-4 py-2.5 text-sm ${i % 2 === 0 ? "bg-white" : "bg-zinc-50"}`}>
              <span className="w-36 flex-shrink-0 text-sm text-zinc-500">{k.replace(/_/g, " ")}</span>
              <span className="break-all font-mono text-sm text-zinc-700">{renderScalar(k, v)}</span>
            </div>
          ))}
        </div>
      )}
      {objectLists.map(([k, items]) => (
        <div key={k}>
          <div className="mb-2 text-sm font-semibold text-zinc-700">{k.replace(/_/g, " ")}</div>
          <ObjectListTable items={items} />
        </div>
      ))}
      {removable && <RemovableStatementsBlock statements={removable} />}
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
  const bucketName = (finding.evidence.bucket_name as string | undefined) ?? "<bucket-name>";
  const kmsKeyId = (finding.evidence.key_id as string | undefined) ?? "<key-id>";
  return rem.cli
    .replace(/<role-name>/g, roleName || "<role-name>")
    .replace(/<user>/g, userName || "<user>")
    .replace(/<key-id>/g, kmsKeyId)
    .replace(/<policy-name>/g, policyName)
    .replace(/<bucket-name>/g, bucketName);
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
  // key fields
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
  warnings: string[];
};

const confidenceConfig = {
  high: { label: "Safe to remediate", color: "bg-emerald-50 text-emerald-700 border-emerald-200", dot: "bg-emerald-500", desc: "No active usage detected in the past 90 days." },
  medium: { label: "Review first", color: "bg-amber-50 text-amber-700 border-amber-200", dot: "bg-amber-400", desc: "Some recent activity detected — verify before making changes." },
  low: { label: "Active — proceed with caution", color: "bg-red-50 text-red-700 border-red-200", dot: "bg-red-500", desc: "Resource was actively used in the last 30 days." },
};

function buildVerdict(data: BlastRadiusData): { text: string; type: "safe" | "caution" | "warning" } {
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
    if (running > 0) return { text: `Restrict with care — ${running} running instance${running !== 1 ? "s" : ""} will be affected (${total} total).`, type: "warning" };
    if (total > 0) return { text: `${total} instance${total !== 1 ? "s" : ""} attached, none running — safe to modify.`, type: "caution" };
    return { text: "No instances attached to this security group — safe to update.", type: "safe" };
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

function BlastRadiusSection({ accountId, finding }: { accountId: string; finding: Finding }) {
  const [enabled, setEnabled] = useState(false);
  const { data, isLoading, error } = useQuery<BlastRadiusData>({
    queryKey: ["blast-radius", accountId, finding.resource_arn, finding.check_id],
    queryFn: () => api(`/v1/accounts/${accountId}/blast-radius?resource_arn=${encodeURIComponent(finding.resource_arn)}&check_id=${encodeURIComponent(finding.check_id)}`),
    enabled,
    staleTime: Infinity,
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

  const conf = confidenceConfig[data.confidence];

  return (
    <div className="rounded-xl border border-zinc-200 bg-white overflow-hidden">
      <div className="px-4 py-3 border-b border-zinc-100 flex items-center justify-between">
        <span className="text-sm font-semibold text-zinc-700">Blast radius</span>
        <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold ${conf.color}`}>
          <span className={`h-1.5 w-1.5 rounded-full ${conf.dot}`} />
          {conf.label}
        </span>
      </div>

      <div className="p-4 space-y-4">
        {(() => {
          const verdict = buildVerdict(data);
          const vs = verdictStyle[verdict.type];
          return (
            <div className={`flex items-start gap-2.5 rounded-lg border px-3.5 py-3 ${vs.card}`}>
              <span className={vs.icon}><VerdictIcon type={verdict.type} /></span>
              <p className={`text-sm font-medium leading-snug ${vs.text}`}>{verdict.text}</p>
            </div>
          );
        })()}

        {/* Warnings */}
        {data.warnings.length > 0 && (
          <div className="space-y-1.5">
            {data.warnings.map((w, i) => (
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
            <div className="flex flex-wrap gap-1.5">
              {data.services.map((s) => (
                <span
                  key={s.name}
                  title={s.last_used ? `Last used ${s.days_ago}d ago` : "Never used"}
                  className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium ${
                    s.active
                      ? "border-red-200 bg-red-50 text-red-700"
                      : "border-zinc-200 bg-zinc-50 text-zinc-500"
                  }`}
                >
                  <span className={`h-1.5 w-1.5 rounded-full ${s.active ? "bg-red-400" : "bg-zinc-300"}`} />
                  {s.name}
                  {s.days_ago !== null && <span className="opacity-60">{s.days_ago}d</span>}
                </span>
              ))}
            </div>
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
                    <span className={`flex-shrink-0 text-xs font-medium ${
                      pol.action === "detach_and_replace" ? "text-amber-600" : "text-sky-600"
                    }`}>
                      {pol.action === "detach_and_replace" ? "Detach + replace" : "Edit policy"}
                    </span>
                  </div>
                  <div className="px-3 py-2.5 space-y-1.5">
                    {pol.unused_services.length > 0 && (
                      <div className="flex flex-wrap gap-1">
                        <span className="text-xs font-medium text-zinc-400 w-full mb-0.5">Removable</span>
                        {pol.unused_services.map((s) => (
                          <span key={s} className="rounded border border-zinc-200 bg-white px-1.5 py-0.5 font-mono text-[11px] text-zinc-500">{s}</span>
                        ))}
                      </div>
                    )}
                    {pol.active_services.length > 0 && (
                      <div className="flex flex-wrap gap-1">
                        <span className="text-xs font-medium text-zinc-400 w-full mb-0.5">Keep (active)</span>
                        {pol.active_services.map((s) => (
                          <span key={s} className="rounded border border-red-200 bg-red-50 px-1.5 py-0.5 font-mono text-[11px] text-red-600">{s}</span>
                        ))}
                      </div>
                    )}
                    {pol.unused_services.length === 0 && pol.active_services.length === 0 && pol.granted_services.length > 0 && (
                      <span className="text-xs text-zinc-400">No usage data yet — run a scan, then check back in a few minutes once service last-accessed data populates.</span>
                    )}
                    {pol.granted_services.length === 0 && (
                      <span className="text-xs text-zinc-400">No parseable service grants found (may use conditions or resource-specific ARNs).</span>
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
              <div key={k.key_id} className={`rounded-lg border px-3 py-2.5 text-xs ${k.active ? "border-red-100 bg-red-50" : "border-zinc-200 bg-zinc-50"}`}>
                <div className="font-mono font-semibold text-zinc-700">{k.key_id}</div>
                <div className="mt-1 text-zinc-500">
                  {k.last_used
                    ? `Last used ${k.days_ago}d ago · ${k.last_used_service ?? "unknown service"} · ${k.last_used_region ?? ""}`
                    : "Never used"}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* User: summary */}
        {data.resource_type === "iam_user" && (
          <div className="space-y-1.5 text-xs text-zinc-500">
            <div>{data.days_inactive !== null && data.days_inactive !== undefined ? `Inactive for ${data.days_inactive} days` : "No recorded activity"}</div>
            <div>{data.active_key_count} active access key{data.active_key_count !== 1 ? "s" : ""}</div>
            {data.has_console_password && <div>Has console password</div>}
          </div>
        )}

        {/* Security group: metadata + affected instances */}
        {data.resource_type === "security_group" && (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
                <div className="font-medium text-zinc-400 mb-0.5">Group</div>
                <div className="font-mono text-zinc-700">{data.group_name ?? data.group_id}</div>
              </div>
              <div className="rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-2">
                <div className="font-medium text-zinc-400 mb-0.5">VPC · Region</div>
                <div className="font-mono text-zinc-700 truncate">{data.vpc_id ?? "—"} · {data.region}</div>
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
              <div className="text-xs text-zinc-400">No instances currently attached to this security group.</div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

type Tab = "overview" | "remediation" | "whatif";
type GeneratedPolicy = { has_inline_policies: boolean; unused_services: string[]; used_services: string[]; statements_removed?: number; original_policies?: Record<string, unknown>; cleaned_policies?: Record<string, unknown>; note?: string };

type PolicyStatement = { Sid?: string; Effect?: string; Action?: string | string[]; Resource?: string | string[]; [k: string]: unknown };

function PolicyDiffView({ original, cleaned }: { original: Record<string, unknown>; cleaned: Record<string, unknown> }) {
  const sections = Object.entries(original).map(([name, origDoc]) => {
    const origStmts: PolicyStatement[] = (origDoc as any)?.Statement ?? [];
    const cleanStmts: PolicyStatement[] = (cleaned as any)?.[name]?.Statement ?? [];
    const cleanSet = new Set(cleanStmts.map((s) => JSON.stringify(s)));
    return { name, statements: origStmts.map((stmt) => ({ stmt, removed: !cleanSet.has(JSON.stringify(stmt)) })) };
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
              return (
                <div key={i} className={`rounded-lg border px-3 py-2.5 text-xs ${s.removed ? "border-red-200 bg-red-50" : "border-zinc-200 bg-zinc-50"}`}>
                  {s.removed && (
                    <div className="mb-2 flex items-center gap-1.5">
                      <span className="h-1.5 w-1.5 rounded-full bg-red-400 flex-shrink-0" />
                      <span className="text-[10px] font-semibold uppercase tracking-wide text-red-500">Removed — no usage in 90 days</span>
                    </div>
                  )}
                  <div className="space-y-1">
                    {s.stmt.Sid && <div><span className="text-zinc-400">Sid: </span><span className={`font-medium ${s.removed ? "text-red-600 line-through" : "text-zinc-700"}`}>{s.stmt.Sid}</span></div>}
                    <div><span className="text-zinc-400">Effect: </span><span className={`font-medium ${s.removed ? "text-red-600 line-through" : "text-zinc-700"}`}>{s.stmt.Effect}</span></div>
                    {actions.length > 0 && (
                      <div><span className="text-zinc-400">Actions: </span><span className={`font-mono break-all ${s.removed ? "text-red-600 line-through" : "text-zinc-700"}`}>{actions.join(", ")}</span></div>
                    )}
                    {resources.length > 0 && (
                      <div><span className="text-zinc-400">Resource: </span><span className={`font-mono break-all ${s.removed ? "text-red-600 line-through" : "text-zinc-600"}`}>{resources.join(", ")}</span></div>
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

function GeneratePolicySection({ accountId, finding }: { accountId: string; finding: Finding }) {
  const [enabled, setEnabled] = useState(false);
  const [view, setView] = useState<"diff" | "cleaned" | "original">("diff");
  const { data, isLoading, error } = useQuery<GeneratedPolicy>({ queryKey: ["generated-policy", accountId, finding.resource_arn], queryFn: () => api(`/v1/accounts/${accountId}/roles/generated-policy?role_arn=${encodeURIComponent(finding.resource_arn)}`), enabled, staleTime: Infinity });

  return (
    <div>
      <div className="mb-3 flex items-center justify-between">
        <div className="text-sm font-semibold text-zinc-700">Suggested policy</div>
        {!enabled && <button onClick={() => setEnabled(true)} className="rounded border border-zinc-300 bg-white px-3 py-1 text-xs font-medium text-zinc-700 transition-colors hover:bg-zinc-50 hover:text-zinc-900">Generate</button>}
      </div>
      {!enabled && <p className="text-xs leading-relaxed text-zinc-400">Vigil will strip unused service statements from inline policies and show you the cleaned version, ready to apply.</p>}
      {enabled && isLoading && <div className="py-3 text-xs text-zinc-400">Generating…</div>}
      {enabled && error && <div className="py-2 text-xs text-red-500">{String(error)}</div>}
      {enabled && data && !data.has_inline_policies && (
        <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-xs leading-relaxed text-amber-800">{data.note ?? "No inline policies found. Permissions come from attached managed policies."}</div>
      )}
      {enabled && data && data.has_inline_policies && data.original_policies && data.cleaned_policies && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs text-zinc-500">
              {data.statements_removed} statement{data.statements_removed !== 1 ? "s" : ""} removed
            </span>
            <div className="flex gap-1 rounded-lg bg-zinc-100 p-0.5">
              {(["diff", "cleaned", "original"] as const).map((v) => (
                <button key={v} onClick={() => setView(v)} className={`rounded-md px-2.5 py-1 text-xs font-medium capitalize transition-colors ${view === v ? "bg-white text-zinc-900 shadow-sm" : "text-zinc-500 hover:text-zinc-700"}`}>
                  {v}
                </button>
              ))}
            </div>
          </div>
          {view === "diff" && <PolicyDiffView original={data.original_policies} cleaned={data.cleaned_policies} />}
          {view !== "diff" && <CliBlock code={JSON.stringify(view === "cleaned" ? data.cleaned_policies : data.original_policies, null, 2)} />}
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

function SnoozeButton({ findingId, onDone }: { findingId: string; onDone: () => void }) {
  const [open, setOpen] = useState(false);
  const [snoozed, setSnoozed] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function handler(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [open]);

  async function snooze(days: number) {
    await api(`/v1/findings/${findingId}/snooze`, { method: "POST", body: JSON.stringify({ days }) });
    setSnoozed(true);
    setOpen(false);
    setTimeout(onDone, 800);
  }

  return (
    <div ref={ref} className="relative flex-1">
      <button
        onClick={() => setOpen((o) => !o)}
        className={`w-full rounded-lg border px-4 py-2.5 text-sm font-semibold transition ${snoozed ? "border-amber-200 bg-amber-50 text-amber-700" : "border-zinc-300 bg-white text-zinc-700 hover:bg-zinc-100"}`}
      >
        {snoozed ? "Snoozed" : "Snooze"}
      </button>
      {open && (
        <div className="absolute bottom-full mb-1.5 right-0 z-10 min-w-[140px] rounded-xl border border-zinc-200 bg-white shadow-lg overflow-hidden">
          {([7, 30, 90] as const).map((d) => (
            <button key={d} onClick={() => snooze(d)} className="block w-full px-4 py-2.5 text-left text-sm text-zinc-700 hover:bg-zinc-50 transition-colors">
              {d} days
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export function FindingDrawer({ finding, accountId, onClose, onAction, resolved, verifying }: { finding: Finding | null; accountId: string | null; onClose: () => void; onAction: (id: string, action: "recheck" | "resolve" | "ignore") => void; resolved?: boolean; verifying?: boolean }) {
  const [tab, setTab] = useState<Tab>("overview");
  const [remTab, setRemTab] = useState<"console" | "cli">("console");
  const [countdown, setCountdown] = useState(5);

  useEffect(() => { setTab("overview"); setRemTab("console"); }, [finding?.id]);

  useEffect(() => {
    if (!resolved) { setCountdown(5); return; }
    setCountdown(5);
    const tick = setInterval(() => setCountdown((c) => c - 1), 1000);
    const close = setTimeout(onClose, 5000);
    return () => { clearInterval(tick); clearTimeout(close); };
  }, [resolved]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!finding) return null;
  const rem = remediations[finding.check_id] ?? fallbackRemediation;
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
  };
  const category = Object.entries(categoryLabel).find(([prefix]) => finding.check_id.startsWith(prefix))?.[1] ?? "Finding";
  const showPolicyGen = finding.check_id === "iam.role.unused_services_90d" && !!accountId;
  const BLAST_RADIUS_CHECKS = new Set([
    "iam.role.unassumed_90d",
    "iam.role.wildcard_action",
    "iam.role.unused_services_90d",
    "iam.role.trust_wildcard",
    "iam.access_key.unused_90d",
    "iam.access_key.no_rotation_90d",
    "iam.access_key.multiple_active",
    "iam.user.inactive_90d",
    "ec2.security_group.unrestricted_ssh",
    "ec2.security_group.unrestricted_rdp",
    "ec2.security_group.default_allows_traffic",
  ]);
  const showBlastRadius = BLAST_RADIUS_CHECKS.has(finding.check_id) && !!accountId;

  const tabs: { id: Tab; label: string }[] = [
    { id: "overview", label: "Overview" },
    { id: "remediation", label: "Remediation" },
    ...(showBlastRadius ? [{ id: "whatif" as Tab, label: "What If?" }] : []),
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
              <svg className="h-3.5 w-3.5 text-amber-500" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
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
          <div className="mb-2 pl-0.5 text-sm font-semibold text-zinc-700">Scan details</div>
          <EvidenceSection evidence={finding.evidence} checkId={finding.check_id} />
        </div>}
        {showPolicyGen && <GeneratePolicySection accountId={accountId!} finding={finding} />}
        <div className="flex items-center gap-3 border-t border-zinc-200/70 pt-3 pb-1 text-xs text-zinc-400">
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
            <div className="flex gap-0.5 rounded-full border border-zinc-200 bg-zinc-50 p-0.5">{(["console", "cli"] as const).map((t) => <button key={t} onClick={() => setRemTab(t)} className={`rounded-full px-3.5 py-1 text-[13px] font-medium transition-all ${remTab === t ? "bg-zinc-900 text-white shadow-sm" : "text-zinc-400 hover:text-zinc-600"}`}>{t === "cli" ? "AWS CLI" : "Console"}</button>)}</div>
          </div>
          <div className="bg-zinc-50/70 p-5">
            {remTab === "console" && <ol className="space-y-3">{rem.console.map((item, i) => <li key={i} className="flex gap-3 text-sm leading-6 text-zinc-700"><span className={`mt-0.5 flex h-5 w-5 flex-shrink-0 items-center justify-center rounded-full text-[11px] font-bold ${step}`}>{i + 1}</span>{item}</li>)}</ol>}
            {remTab === "cli" && <CliBlock code={resolvedCli(finding)} />}
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
      <button onClick={() => { onAction(finding.id, "ignore"); onClose(); }} className="flex-1 rounded-lg border border-zinc-300 bg-white px-4 py-2.5 text-sm font-semibold text-zinc-700 transition hover:bg-zinc-100">Ignore</button>
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
