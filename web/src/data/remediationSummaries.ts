/** Short operational copy for drawer overview — full steps stay in FindingDrawer remediations. */
export type RemediationSummary = {
  impact: string;
  risk: string;
  fix: string;
};

export const remediationSummaries: Record<string, RemediationSummary> = {
  "iam.user.no_mfa": {
    impact: "Console user has no MFA.",
    risk: "Stolen password = full console access.",
    fix: "Assign MFA in IAM.",
  },
  "iam.user.inactive_90d": {
    impact: "IAM user inactive 90+ days.",
    risk: "Stale accounts hide compromise.",
    fix: "Disable console access or delete the user.",
  },
  "iam.user.direct_policy_attachment": {
    impact: "Policies attached directly to the user.",
    risk: "Harder to audit and revoke at scale.",
    fix: "Move permissions to groups or roles.",
  },
  "iam.access_key.unused_90d": {
    impact: "Access key unused 90+ days.",
    risk: "Long-lived credential with no owner.",
    fix: "Deactivate, verify, then delete the key.",
  },
  "iam.access_key.no_rotation_90d": {
    impact: "Access key older than rotation threshold.",
    risk: "Key may live in old scripts or CI secrets.",
    fix: "Rotate: create new key, update workload, retire old.",
  },
  "iam.access_key.multiple_active": {
    impact: "User has multiple active access keys.",
    risk: "Duplicate keys complicate ownership.",
    fix: "Review keys and delete the unused one.",
  },
  "iam.role.unassumed_90d": {
    impact: "Role not assumed in 90+ days.",
    risk: "Orphan role may still carry broad policies.",
    fix: "Confirm with owner, then delete if unused.",
  },
  "iam.role.wildcard_action": {
    impact: 'Inline policy uses Action: "*".',
    risk: "Admin-like scope if role is compromised.",
    fix: "Scope actions to what the role actually needs.",
  },
  "iam.perm.granted_vs_used": {
    impact: "Write actions granted but not used in 90 days.",
    risk: "Unused write perms expand blast radius.",
    fix: "Remove unused actions from role policies.",
  },
  "iam.policy.unattached": {
    impact: "Customer-managed policy has zero attachments.",
    risk: "Stale policy may be re-attached with broad grants.",
    fix: "Review and delete if no longer needed.",
  },
  "iam.policy.wildcard_resource": {
    impact: 'Write actions on Resource: "*".',
    risk: "Role can touch every resource of that type.",
    fix: "Replace wildcards with specific ARNs.",
  },
  "iam.role.unused_services_90d": {
    impact: "Role has permissions to unused services.",
    risk: "Extra services widen compromise impact.",
    fix: "Remove unused service statements from policies.",
  },
  "iam.role.trust_wildcard": {
    impact: "Trust policy allows any AWS principal.",
    risk: "Unintended principals may assume the role.",
    fix: "Scope Principal to specific accounts or roles.",
  },
  "iam.root.has_access_keys": {
    impact: "Root account has active access keys.",
    risk: "Root keys bypass all IAM policies.",
    fix: "Delete root keys; use IAM users for automation.",
  },
  "iam.root.no_mfa": {
    impact: "Root account has no MFA.",
    risk: "Highest-severity identity exposure.",
    fix: "Enable hardware MFA on root immediately.",
  },
  "iam.root.usage": {
    impact: "Root credentials used for API activity.",
    risk: "Root bypasses all IAM and SCP controls.",
    fix: "Move tasks to IAM admin; reserve root for account tasks.",
  },
  "s3.bucket.public_access_not_blocked": {
    impact: "S3 Block Public Access not fully enabled.",
    risk: "Misconfigured ACL or policy can expose objects.",
    fix: "Enable all four Block Public Access settings.",
  },
  "s3.account.public_access_not_blocked": {
    impact: "Account-level S3 public access block off.",
    risk: "One bucket mistake can expose data publicly.",
    fix: "Enable account-wide Block Public Access.",
  },
  "s3.bucket.no_https_policy": {
    impact: "No deny-insecure-transport bucket policy.",
    risk: "Legacy http:// clients could read objects.",
    fix: "Add Deny when aws:SecureTransport is false.",
  },
  "s3.bucket.no_kms": {
    impact: "Bucket not using SSE-KMS.",
    risk: "No customer control over encryption keys.",
    fix: "Enable default SSE-KMS on the bucket.",
  },
  "s3.bucket.no_logging": {
    impact: "S3 server access logging disabled.",
    risk: "No audit trail for bucket access.",
    fix: "Enable logging to a dedicated log bucket.",
  },
  "kms.key.no_rotation": {
    impact: "KMS key rotation disabled.",
    risk: "Longer exposure window if key material leaks.",
    fix: "Enable annual automatic key rotation.",
  },
  "cloudtrail.trail.not_enabled": {
    impact: "No CloudTrail logging in this region.",
    risk: "API activity is invisible to investigation.",
    fix: "Create a multi-region trail with S3 delivery.",
  },
  "cloudtrail.trail.no_log_validation": {
    impact: "CloudTrail log file validation off.",
    risk: "Tampered logs look authentic.",
    fix: "Enable log file validation on the trail.",
  },
  "cloudtrail.trail.no_kms": {
    impact: "CloudTrail logs not SSE-KMS encrypted.",
    risk: "Weaker control over audit log access.",
    fix: "Enable KMS encryption on the trail.",
  },
  "guardduty.open_findings": {
    impact: "GuardDuty has active findings.",
    risk: "Unresolved threats may indicate compromise.",
    fix: "Triage, remediate, or archive with justification.",
  },
  "aws.config.rules_non_compliant": {
    impact: "Config rules report non-compliant resources.",
    risk: "Baseline drift hidden until audit.",
    fix: "Remediate resources or document exceptions.",
  },
  "ec2.ami.aged": {
    impact: "AMI exceeds patch-age threshold.",
    risk: "Instances may lack current OS patches.",
    fix: "Refresh workloads onto a newer AMI.",
  },
  "iam.access_inventory_gap": {
    impact: "IAM inventory incomplete after scan.",
    risk: "Access roster may omit principals.",
    fix: "Fix role permissions and re-scan.",
  },
  "iam.role.full_admin_policy": {
    impact: "Role has customer-managed Action:* / Resource:*.",
    risk: "Full account compromise if assumed.",
    fix: "Replace with least-privilege policies.",
  },
  "github.repo.no_codeowners": {
    impact: "No CODEOWNERS file (optional check).",
    risk: "No code-owner review rules possible.",
    fix: "Add CODEOWNERS or disable the check.",
  },
  "guardduty.detector.not_enabled": {
    impact: "GuardDuty disabled in region.",
    risk: "Threats go undetected automatically.",
    fix: "Enable GuardDuty in affected regions.",
  },
  "vpc.flow_logs.not_enabled": {
    impact: "VPC flow logs not enabled.",
    risk: "Network attacks invisible at VPC layer.",
    fix: "Create flow log to CloudWatch or S3.",
  },
  "ec2.security_group.unrestricted_ssh": {
    impact: "SSH (22) open to 0.0.0.0/0.",
    risk: "Internet-wide brute force on SSH.",
    fix: "Restrict source IP or use SSM Session Manager.",
  },
  "ec2.security_group.unrestricted_rdp": {
    impact: "RDP (3389) open to 0.0.0.0/0.",
    risk: "Common ransomware entry point.",
    fix: "Restrict source IP or use Fleet Manager.",
  },
  "rds.instance.publicly_accessible": {
    impact: "RDS instance reachable from internet.",
    risk: "Direct path to database exfiltration.",
    fix: 'Set "Publicly accessible" to No.',
  },
  "rds.instance.no_encryption": {
    impact: "RDS storage not encrypted.",
    risk: "Snapshot or disk leak exposes plaintext.",
    fix: "Snapshot, copy encrypted, restore new instance.",
  },
  "rds.instance.no_automated_backup": {
    impact: "Automated RDS backups disabled.",
    risk: "No point-in-time recovery.",
    fix: "Set backup retention to at least 7 days.",
  },
  "dynamodb.table.no_encryption": {
    impact: "DynamoDB table encryption not explicit.",
    risk: "Data at rest not clearly protected.",
    fix: "Enable encryption at rest on the table.",
  },
  "dynamodb.table.no_pitr": {
    impact: "Point-in-time recovery disabled.",
    risk: "Accidental deletes may be permanent.",
    fix: "Enable PITR on the table.",
  },
  "s3.bucket.no_default_encryption": {
    impact: "Default bucket encryption off.",
    risk: "New uploads may land unencrypted.",
    fix: "Enable default SSE-S3 or SSE-KMS.",
  },
  "s3.bucket.no_mfa_delete": {
    impact: "Versioning on without MFA Delete.",
    risk: "Compromised IAM can wipe all versions.",
    fix: "Enable MFA Delete (requires root).",
  },
  "ec2.ebs.snapshot_public": {
    impact: "EBS snapshot shared publicly.",
    risk: "Disk image may contain secrets or data.",
    fix: "Remove public createVolumePermission.",
  },
  "ec2.ebs.snapshot_unencrypted": {
    impact: "EBS snapshot stored unencrypted.",
    risk: "Full disk readable from snapshot access.",
    fix: "Copy snapshot with encryption enabled.",
  },
  "ec2.ami.public": {
    impact: "AMI shared with all AWS accounts.",
    risk: "Image may contain secrets or IP.",
    fix: "Set AMI visibility to private.",
  },
  "cloudtrail.trail.s3_bucket_public": {
    impact: "CloudTrail log bucket is public.",
    risk: "Full API history exposed to internet.",
    fix: "Block public access on log bucket immediately.",
  },
  "cloudtrail.trail.no_cloudwatch_logs": {
    impact: "Trail not shipping to CloudWatch Logs.",
    risk: "Delayed detection of suspicious API use.",
    fix: "Enable CloudWatch Logs on the trail.",
  },
  "cloudtrail.trail.s3_bucket_no_logging": {
    impact: "CloudTrail S3 bucket has no access logs.",
    risk: "Access to audit trail itself unlogged.",
    fix: "Enable server access logging on log bucket.",
  },
  "acm.certificate.expiring": {
    impact: "TLS certificate expiring soon.",
    risk: "HTTPS breaks for attached services.",
    fix: "Renew or replace cert before expiry.",
  },
  "lambda.function.deprecated_runtime": {
    impact: "Lambda on unsupported runtime.",
    risk: "No security patches; invocation may stop.",
    fix: "Upgrade to a supported runtime and test.",
  },
  "lambda.function.no_dlq": {
    impact: "Async Lambda has no dead-letter queue.",
    risk: "Failed invocations disappear silently.",
    fix: "Attach SQS/SNS DLQ with retry limit.",
  },
  "rds.instance.no_deletion_protection": {
    impact: "RDS deletion protection off.",
    risk: "One API call can destroy the database.",
    fix: "Enable deletion protection on instance.",
  },
  "rds.instance.no_multi_az": {
    impact: "RDS single-AZ deployment.",
    risk: "No automatic failover on host failure.",
    fix: "Enable Multi-AZ during maintenance window.",
  },
  "secretsmanager.secret.no_rotation": {
    impact: "Secret has no automatic rotation.",
    risk: "Static credentials harder to revoke.",
    fix: "Enable rotation with a Lambda function.",
  },
  "ssm.parameter.plaintext_secret": {
    impact: "Secret stored as plaintext SSM String.",
    risk: "Value visible in API and CloudTrail.",
    fix: "Migrate to SecureString parameter.",
  },
  "elb.load_balancer.no_access_logs": {
    impact: "Load balancer access logging off.",
    risk: "No request-level audit for abuse.",
    fix: "Enable access logs to S3.",
  },
  "elb.load_balancer.weak_tls_policy": {
    impact: "Load balancer allows legacy TLS/ciphers.",
    risk: "Weak encryption on client connections.",
    fix: "Upgrade listener to TLS 1.2+ policy.",
  },
  "sns.topic.no_encryption": {
    impact: "SNS topic not KMS-encrypted.",
    risk: "Messages readable at rest.",
    fix: "Enable SSE-KMS on the topic.",
  },
  "sqs.queue.no_encryption": {
    impact: "SQS queue not KMS-encrypted.",
    risk: "Queue payloads readable at rest.",
    fix: "Enable SSE-KMS on the queue.",
  },
  "iam.account.no_support_role": {
    impact: "No IAM role with AWSSupportAccess.",
    risk: "Support cases may require root or ad-hoc elevated access.",
    fix: "Create a dedicated support role with AWSSupportAccess.",
  },
  "iam.account.password_policy_weak": {
    impact: "IAM password policy below baseline.",
    risk: "Weak passwords easier to crack.",
    fix: "Strengthen length, complexity, and rotation.",
  },
  "aws.access_analyzer.not_enabled": {
    impact: "IAM Access Analyzer not enabled.",
    risk: "External resource sharing undetected.",
    fix: "Create an analyzer in each active region.",
  },
  "aws.config.not_enabled": {
    impact: "AWS Config not recording changes.",
    risk: "No configuration history for audits.",
    fix: "Enable Config recorder and delivery channel.",
  },
  "aws.securityhub.not_enabled": {
    impact: "Security Hub disabled in region.",
    risk: "Findings fragmented across services.",
    fix: "Enable Security Hub and FSBP standard.",
  },
  "ec2.security_group.default_allows_traffic": {
    impact: "VPC default security group has inbound or outbound rules.",
    risk: "Resources launched without an explicit SG inherit those rules.",
    fix: "Delete rules on the default SG; use named SGs on instances.",
  },
  "iam.role.external_account_trust": {
    impact: "Role trust policy allows another AWS account to assume it.",
    risk: "External account can use this role's permissions in your account.",
    fix: "Review trust policy; remove unapproved cross-account principals.",
  },
  "ec2.instance.imdsv2_not_required": {
    impact: "IMDSv1 still allowed on instance.",
    risk: "SSRF can steal instance IAM credentials.",
    fix: "Require IMDSv2 on instance metadata.",
  },
  "ec2.ebs.encryption_not_default": {
    impact: "EBS encryption by default off.",
    risk: "New volumes may launch unencrypted.",
    fix: "Enable default EBS encryption per region.",
  },
  "ec2.ebs.volume_unencrypted": {
    impact: "Existing EBS volume unencrypted.",
    risk: "Data at rest outside encryption baseline.",
    fix: "Snapshot, encrypt copy, attach new volume.",
  },
  "github.org.mfa_not_enforced": {
    impact: "Org does not require MFA.",
    risk: "Phished password = full repo write access.",
    fix: "Require 2FA for all org members.",
  },
  "github.org.dormant_members": {
    impact: "Dormant org members still present.",
    risk: "Stale tokens act as insider access.",
    fix: "Remove members with no recent activity.",
  },
  "github.org.outside_collaborators": {
    impact: "Outside collaborators on repositories.",
    risk: "Access persists after projects end.",
    fix: "Review and revoke stale collaborators.",
  },
  "github.repo.no_branch_protection": {
    impact: "Default branch has no protection rules.",
    risk: "Direct pushes skip review and CI.",
    fix: "Add branch protection with required reviews.",
  },
  "github.repo.no_env_protection": {
    impact: "Deployment environment lacks reviewers.",
    risk: "Workflows can deploy without approval.",
    fix: "Add required reviewers on production env.",
  },
  "github.repo.self_merge_allowed": {
    impact: "Authors can merge their own PRs.",
    risk: "Peer review control bypassed.",
    fix: "Require external approval on default branch.",
  },
  "github.repo.insufficient_reviews": {
    impact: "PRs merged below required review count.",
    risk: "Gap in change-management evidence.",
    fix: "Raise required approvals and enforce policy.",
  },
  "gitlab.org.mfa_not_enforced": {
    impact: "Group does not require 2FA.",
    risk: "Phished password = full project access.",
    fix: "Require 2FA for all group members.",
  },
  "gitlab.org.dormant_members": {
    impact: "Dormant group members still present.",
    risk: "Stale tokens usable indefinitely.",
    fix: "Remove inactive members from the group.",
  },
  "gitlab.repo.no_branch_protection": {
    impact: "Default branch not protected.",
    risk: "Direct pushes skip MR review and CI.",
    fix: "Protect default branch; block direct push.",
  },
  "gitlab.repo.self_merge_allowed": {
    impact: "MR authors can approve own changes.",
    risk: "Segregation of duties broken.",
    fix: "Prevent author self-approval in settings.",
  },
  "gitlab.repo.insufficient_reviews": {
    impact: "MRs merged below approval threshold.",
    risk: "Change-management evidence gap.",
    fix: "Increase required approvals and reset on push.",
  },
};

export const fallbackRemediationSummary: RemediationSummary = {
  impact: "Configuration does not meet this check.",
  risk: "Unresolved finding increases attack surface.",
  fix: "Review the resource and apply your security baseline.",
};

export function remediationSummaryFor(checkId: string): RemediationSummary {
  return remediationSummaries[checkId] ?? fallbackRemediationSummary;
}
