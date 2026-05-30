/**
 * Auditor-facing evidence guidance + detection narrative per check (drawer Compliance tab).
 * Kept separate from terse remediationSummaries impact/risk lines.
 *
 * Evidence guidance style (first string passed to copy(); UI label "Guidance"):
 * Single sentence: "Verify that …" — what the control checks (no manual auditor steps).
 * Strings may still use an "Evidence:" prefix; copy() strips it (UI adds "Guidance:").
 *
 * Detection Logic style (second string; UI badge "Detection Logic"):
 * Plain, factual: what data Vigil reads and what condition triggers the finding.
 * Present tense, third person: "Vigil reads…", "Vigil flags…", "Vigil compares…".
 * No auditor instructions, screenshots, or scary hypotheticals unless the check is
 * explicitly about compromise or active threat findings.
 * Do not duplicate Guidance ("Verify that…"); Guidance is what to verify, Detection Logic is how Vigil flags it.
 * Prefer 1–2 sentences.
 */
import { remediationSummaries, type RemediationSummary } from "./remediationSummaries";

export type CheckComplianceCopy = {
  evidenceGuidance: string;
  auditNarrative: string;
};

function copy(
  evidenceGuidance: string,
  auditNarrative: string,
): CheckComplianceCopy {
  // UI labels this block "Guidance:" — drop duplicate prefix from copy strings.
  const guidance = evidenceGuidance.replace(/^Evidence:\s*/i, "");
  return { evidenceGuidance: guidance, auditNarrative };
}

function iamAccessKey(checkId: string, _s: RemediationSummary): CheckComplianceCopy {
  switch (checkId) {
    case "iam.access_key.unused_90d":
      return copy(
        "Verify that IAM access keys with no API activity in the last 90 days are deactivated or removed.",
        "Vigil reads IAM GetAccessKeyLastUsed for each active key. Keys with no recorded API use within the 90-day lookback are flagged as unused.",
      );
    case "iam.access_key.unused_45d":
      return copy(
        "Verify that IAM access keys with no API activity in the last 45 days are deactivated or removed.",
        "Vigil reads IAM GetAccessKeyLastUsed for each active key. Keys with no recorded API use within the 45-day lookback are flagged as unused.",
      );
    case "iam.access_key.no_rotation_90d":
      return copy(
        "Verify that IAM access keys are rotated before exceeding your configured age threshold.",
        "Vigil reads each access key's create date from IAM. Keys older than the configured rotation-age threshold are flagged.",
      );
    case "iam.access_key.multiple_active":
      return copy(
        "Verify that each IAM user has at most one active access key unless a rotation is in progress.",
        "Vigil lists active access keys per IAM user. Users with more than one key in Active status are flagged.",
      );
    default:
      return copy(
        "Verify that IAM programmatic credentials meet your access-key hygiene policy.",
        "Vigil evaluates IAM access keys using AWS last-used timestamps and key status on each scan.",
      );
  }
}

function iamUser(checkId: string, _s: RemediationSummary): CheckComplianceCopy {
  switch (checkId) {
    case "iam.user.no_mfa":
      return copy(
        "Verify that console-capable IAM users have an MFA device assigned.",
        "Vigil lists IAM users with console password enabled and checks for registered MFA devices. Users without MFA are flagged.",
      );
    case "iam.user.inactive_90d":
      return copy(
        "Verify that IAM users with no sign-in or API activity in the inactivity window are disabled or removed.",
        "Vigil reads sign-in and API last-activity timestamps per IAM user. Users with no activity within the inactivity window are flagged.",
      );
    case "iam.user.credentials_unused_45d":
      return copy(
        "Verify that IAM users with no console sign-in in the last 45 days are disabled or removed.",
        "Vigil reads console password last-used per IAM user. Users with no sign-in within the 45-day lookback are flagged.",
      );
    case "iam.user.direct_policy_attachment":
      return copy(
        "Verify that IAM permissions are assigned through groups rather than direct user policy attachments.",
        "Vigil lists IAM user policy attachments. Users with customer-managed or inline policies attached directly (not via groups) are flagged.",
      );
    default:
      return copy(
        "Verify that IAM user identity controls meet your baseline policy.",
        "Vigil evaluates IAM user MFA, activity, and policy attachment posture on each scan.",
      );
  }
}

function iamRole(checkId: string, _s: RemediationSummary): CheckComplianceCopy {
  switch (checkId) {
    case "iam.role.unassumed_90d":
      return copy(
        "Verify that IAM roles not assumed within the lookback period are removed or justified.",
        "Vigil reads role last-used data from IAM. Roles with no AssumeRole use within the lookback period are flagged.",
      );
    case "iam.role.wildcard_action":
      return copy(
        "Verify that inline IAM role policies do not grant Action \"*\" across services.",
        "Vigil parses inline role policies. Policies with Action \"*\" are flagged.",
      );
    case "iam.role.full_admin_policy":
      return copy(
        "Verify that attached customer-managed policies do not grant unrestricted Action \"*\" on Resource \"*\".",
        "Vigil parses attached customer-managed policies. Policies granting Action \"*\" on Resource \"*\" are flagged.",
      );
    case "iam.role.unused_services_90d":
      return copy(
        "Verify that IAM role policies do not grant services with no recorded usage in the lookback window.",
        "Vigil compares each role's granted IAM services against service last-accessed data. Services with no recorded use in the lookback window are flagged.",
      );
    case "iam.role.trust_wildcard":
      return copy(
        "Verify that IAM role trust policies do not allow any principal (\"*\") to attempt AssumeRole.",
        "Vigil parses role trust policies. Trust allowing Principal \"*\" for sts:AssumeRole is flagged.",
      );
    case "iam.role.external_account_trust":
      return copy(
        "Verify that cross-account AssumeRole trust is limited to approved external account principals.",
        "Vigil parses role trust policies for sts:AssumeRole. Grants to principals outside the scanned account are flagged.",
      );
    default:
      return copy(
        "Verify that IAM role trust and permission scope meet your baseline policy.",
        "Vigil evaluates IAM role trust policies and attached permission scope on each scan.",
      );
  }
}

function iamPolicy(checkId: string, _s: RemediationSummary): CheckComplianceCopy {
  switch (checkId) {
    case "iam.policy.wildcard_resource":
      return copy(
        "Verify that write-capable IAM policy statements do not target all resources (Resource \"*\").",
        "Vigil parses customer-managed and inline policy statements. Write-capable statements with Resource \"*\" are flagged.",
      );
    case "iam.policy.unattached":
      return copy(
        "Verify that customer-managed IAM policies without attachments are removed or intentionally retained.",
        "Vigil lists customer-managed policies and attachment targets. Policies with no principals attached are flagged when this optional check is enabled.",
      );
    default:
      return copy(
        "Verify that customer-managed IAM policies meet attachment and scope expectations.",
        "Vigil lists customer-managed policies and evaluates attachments and statement scope on each scan.",
      );
  }
}

function iamRoot(checkId: string, _s: RemediationSummary): CheckComplianceCopy {
  switch (checkId) {
    case "iam.root.no_mfa":
      return copy(
        "Verify that the AWS root account has an active MFA device configured.",
        "Vigil reads root MFA configuration from the account summary. Root without a registered MFA device is flagged.",
      );
    case "iam.root.has_access_keys":
      return copy(
        "Verify that the AWS root account has no active access keys.",
        "Vigil reads root access key status from the account summary. Any active root access key is flagged.",
      );
    case "iam.root.usage":
      return copy(
        "Verify that the AWS root account is not used for routine API operations.",
        "Vigil reads credential-report and CloudTrail data for recent root API activity. Recent root API use is flagged.",
      );
    default:
      return copy(
        "Verify that AWS root account credential and usage controls meet baseline expectations.",
        "Vigil reads root credential configuration and recent root API activity on each scan.",
      );
  }
}

function s3(checkId: string, _s: RemediationSummary): CheckComplianceCopy {
  const bucket =
    checkId === "s3.account.public_access_not_blocked"
      ? "account-level S3 Block Public Access"
      : "bucket Block Public Access settings";
  if (checkId.includes("public_access")) {
    return copy(
      `Verify that all four S3 Block Public Access settings are enabled at ${checkId.startsWith("s3.account") ? "account" : "bucket"} scope.`,
      `Vigil reads S3 Block Public Access settings at ${checkId.startsWith("s3.account") ? "account" : "bucket"} scope. Any of the four block settings disabled is flagged.`,
    );
  }
  if (checkId === "s3.bucket.no_https_policy") {
    return copy(
      "Verify that S3 bucket policies deny unencrypted HTTP access (aws:SecureTransport).",
      "Vigil parses bucket policies for a Deny on aws:SecureTransport false. Buckets without that statement are flagged.",
    );
  }
  if (checkId === "s3.bucket.no_kms" || checkId === "s3.bucket.no_default_encryption") {
    return copy(
      "Verify that S3 buckets have default encryption at rest enabled (SSE-S3 or SSE-KMS).",
      "Vigil reads bucket default encryption configuration. Buckets without default encryption at rest are flagged.",
    );
  }
  if (checkId === "s3.bucket.no_logging") {
    return copy(
      "Verify that S3 server access logging is enabled on data buckets.",
      "Vigil reads bucket logging configuration. Buckets without server access logging enabled are flagged.",
    );
  }
  if (checkId === "s3.bucket.no_mfa_delete") {
    return copy(
      "Verify that versioned S3 buckets have MFA Delete enabled where required.",
      "Vigil reads versioning and MFA Delete settings. Versioned buckets without MFA Delete enabled are flagged.",
    );
  }
  return copy(
    `Verify that S3 ${bucket} configuration meets your baseline policy.`,
    "Vigil reads S3 encryption, public access, and logging configuration per bucket on each scan.",
  );
}

function cloudtrail(checkId: string, _s: RemediationSummary): CheckComplianceCopy {
  switch (checkId) {
    case "cloudtrail.trail.not_enabled":
      return copy(
        "Verify that a multi-region CloudTrail trail is enabled with management events and S3 log delivery.",
        "Vigil lists CloudTrail trails per region. Regions without an active trail recording management events are flagged.",
      );
    case "cloudtrail.trail.no_log_validation":
      return copy(
        "Verify that CloudTrail log file validation is enabled on production trails.",
        "Vigil reads trail log file validation settings. Trails without validation enabled are flagged.",
      );
    case "cloudtrail.trail.no_kms":
      return copy(
        "Verify that CloudTrail trails encrypt log files with a customer-managed KMS key.",
        "Vigil reads trail KMS encryption settings. Trails without KMS log encryption are flagged.",
      );
    case "cloudtrail.trail.s3_bucket_public":
      return copy(
        "Verify that the CloudTrail S3 log bucket is not publicly accessible.",
        "Vigil reads Block Public Access and bucket policy on the trail S3 bucket. Publicly accessible trail buckets are flagged.",
      );
    case "cloudtrail.trail.no_cloudwatch_logs":
      return copy(
        "Verify that CloudTrail trails deliver logs to CloudWatch Logs where real-time review is expected.",
        "Vigil reads CloudWatch Logs integration on trails. Trails without CloudWatch delivery are flagged.",
      );
    case "cloudtrail.trail.s3_bucket_no_logging":
      return copy(
        "Verify that server access logging is enabled on the CloudTrail S3 log bucket.",
        "Vigil reads S3 access logging on the trail log bucket. Trail buckets without access logging are flagged.",
      );
    default:
      return copy(
        "Verify that CloudTrail trail coverage and log integrity settings meet baseline expectations.",
        "Vigil evaluates CloudTrail trail coverage and log integrity settings per region on each scan.",
      );
  }
}

function ec2SecurityGroup(checkId: string, _s: RemediationSummary): CheckComplianceCopy {
  switch (checkId) {
    case "ec2.security_group.unrestricted_ssh":
      return copy(
        "Verify that security groups do not expose SSH (tcp/22) to the entire internet (0.0.0.0/0 or ::/0).",
        "Vigil reads security group ingress rules. Rules allowing tcp/22 from 0.0.0.0/0 or ::/0 are flagged.",
      );
    case "ec2.security_group.unrestricted_rdp":
      return copy(
        "Verify that security groups do not expose RDP (tcp/3389) to the entire internet.",
        "Vigil reads security group ingress rules. Rules allowing tcp/3389 from 0.0.0.0/0 or ::/0 are flagged.",
      );
    case "ec2.security_group.default_allows_traffic":
      return copy(
        "Verify that VPC default security groups have no custom inbound or outbound rules.",
        "Vigil reads the VPC default security group. Non-empty inbound or outbound rule sets are flagged.",
      );
    default:
      return copy(
        "Verify that EC2 security group ingress rules meet your network baseline.",
        "Vigil evaluates security group ingress against sensitive port baselines on each scan.",
      );
  }
}

function github(checkId: string, _s: RemediationSummary): CheckComplianceCopy {
  if (checkId === "github.repo.no_codeowners" || checkId === "gitlab.repo.no_codeowners") {
    return copy(
      "Verify that repositories define code ownership for change-management review.",
      "Vigil reads repository CODEOWNERS file presence. Repositories without CODEOWNERS are flagged when this optional check is enabled.",
    );
  }
  if (checkId.startsWith("github.org.")) {
    return copy(
      "Verify that GitHub organization security settings meet your identity baseline.",
      "Vigil syncs GitHub organization security settings via the GitHub API and flags values outside the configured baseline.",
    );
  }
  return copy(
    "Verify that GitHub repository branch protection and required review settings meet your change-management baseline.",
    "Vigil reads branch protection and required-review settings per repository via the GitHub API and flags noncompliant repos.",
  );
}

function gitlab(checkId: string, _s: RemediationSummary): CheckComplianceCopy {
  if (checkId.startsWith("gitlab.org.")) {
    return copy(
      "Verify that GitLab group security settings meet your identity baseline.",
      "Vigil syncs GitLab group security settings via the GitLab API and flags values outside the configured baseline.",
    );
  }
  return copy(
    "Verify that GitLab protected branches and merge request approval settings meet your change-management baseline.",
    "Vigil reads protected-branch and merge-request approval rules per project via the GitLab API and flags noncompliant projects.",
  );
}

function defaultCopy(checkId: string, s: RemediationSummary): CheckComplianceCopy {
  const topic = checkId.split(".")[0] ?? "resource";
  return copy(
    `Verify that ${s.impact.replace(/\.$/, "").toLowerCase()}.`,
    `Vigil evaluates ${topic} configuration on each scan and flags resources that match this check's failure criteria.`,
  );
}

const BUILDERS: Record<string, (s: RemediationSummary) => CheckComplianceCopy> = {
  "iam.access_key.": iamAccessKey,
  "iam.user.": iamUser,
  "iam.role.": iamRole,
  "iam.policy.": iamPolicy,
  "iam.root.": iamRoot,
  "s3.": s3,
  "cloudtrail.": cloudtrail,
  "ec2.security_group.": ec2SecurityGroup,
  "github.": github,
  "gitlab.": gitlab,
};

const SPECIFIC: Record<string, (s: RemediationSummary) => CheckComplianceCopy> = {
  "iam.perm.granted_vs_used": () =>
    copy(
      "Verify that IAM role policies do not grant write permissions on services with no recorded usage.",
      "Vigil compares each role's granted write actions against service last-accessed data. Write permissions on services with no recorded use in the lookback window are flagged.",
    ),
  "iam.access_inventory_gap": () =>
    copy(
      "Verify that the IAM user inventory scan completes successfully so access roster evidence is complete.",
      "Vigil records a scan failure when the IAM user inventory collector cannot complete. No per-user findings are produced until a later scan succeeds.",
    ),
  "iam.account.no_support_role": () =>
    copy(
      "Verify that a dedicated IAM role exists for AWS Support access instead of using root.",
      "Vigil lists IAM roles and flags the account when no role matches the configured support-access pattern.",
    ),
  "iam.account.password_policy_weak": () =>
    copy(
      "Verify that the IAM account password policy meets your minimum length, complexity, reuse, and expiration requirements.",
      "Vigil reads the account password policy and compares length, complexity, reuse, and expiration settings to configured thresholds.",
    ),
  "aws.account.contact_incomplete": () =>
    copy(
      "Verify that AWS account primary contact information is complete (address, city, country, phone).",
      "Vigil reads account primary contact fields via the scan role. Missing address, city, country, or phone is flagged.",
    ),
  "aws.account.security_contact_missing": () =>
    copy(
      "Verify that a SECURITY alternate contact with email and phone is registered on the AWS account.",
      "Vigil reads alternate contact data for type SECURITY. Missing email or phone on that contact is flagged.",
    ),
  "iam.server_certificate.expired": () =>
    copy(
      "Verify that expired IAM server certificates are removed from the account.",
      "Vigil lists IAM server certificates via ListServerCertificates. Certificates past their expiration date are flagged.",
    ),
  "iam.cloudshell_full_access_granted": () =>
    copy(
      "Verify that AWSCloudShellFullAccess is not attached to non-break-glass IAM principals.",
      "Vigil lists IAM policy attachments. Principals with AWSCloudShellFullAccess attached are flagged.",
    ),
  "kms.key.policy_wildcard_principal": () =>
    copy(
      "Verify that KMS key policies do not allow wildcard (\"*\") principals.",
      "Vigil parses KMS key policies. Policies allowing Principal \"*\" are flagged.",
    ),
  "kms.key.no_rotation": () =>
    copy(
      "Verify that customer-managed symmetric KMS keys have automatic annual rotation enabled.",
      "Vigil reads rotation status on customer-managed symmetric keys. Keys without automatic rotation enabled are flagged.",
    ),
  "guardduty.open_findings": () =>
    copy(
      "Verify that active GuardDuty findings are triaged or remediated.",
      "Vigil lists active GuardDuty findings via the GuardDuty API. Findings not archived or suppressed are surfaced.",
    ),
  "guardduty.detector.not_enabled": () =>
    copy(
      "Verify that GuardDuty detectors are enabled in each in-scope region.",
      "Vigil reads GuardDuty detector status per region. Disabled or missing detectors are flagged.",
    ),
  "aws.config.rules_non_compliant": () =>
    copy(
      "Verify that AWS Config rules in NON_COMPLIANT state are remediated or approved as exceptions.",
      "Vigil lists AWS Config rule evaluation results. Rules in NON_COMPLIANT state are flagged.",
    ),
  "aws.config.not_enabled": () =>
    copy(
      "Verify that AWS Config recorder and delivery channel are active.",
      "Vigil reads Config recorder and delivery channel status. Accounts without an active recorder are flagged.",
    ),
  "aws.access_analyzer.not_enabled": () =>
    copy(
      "Verify that IAM Access Analyzer is enabled in active regions.",
      "Vigil lists Access Analyzer instances per scanned region. Regions without an active analyzer are flagged.",
    ),
  "aws.securityhub.not_enabled": () =>
    copy(
      "Verify that AWS Security Hub is enabled with your organization security standard.",
      "Vigil reads Security Hub enrollment status. Accounts or regions without Security Hub enabled are flagged.",
    ),
  "vpc.flow_logs.not_enabled": () =>
    copy(
      "Verify that VPC flow logs are enabled and delivering to CloudWatch Logs or S3.",
      "Vigil reads VPC flow log configuration. VPCs without flow logging enabled are flagged.",
    ),
  "ec2.ami.aged": () =>
    copy(
      "Verify that EC2 workloads launch from AMIs within your patch-age threshold.",
      "Vigil reads AMI creation dates. AMIs older than the configured patch-age threshold are flagged.",
    ),
  "ec2.ami.public": () =>
    copy(
      "Verify that custom AMIs are not shared publicly (allAccounts launch permission).",
      "Vigil reads AMI launch permissions. AMIs with allAccounts (public) launch permission are flagged.",
    ),
  "ec2.instance.imdsv2_not_required": () =>
    copy(
      "Verify that EC2 instances require IMDSv2 (HttpTokens required).",
      "Vigil reads instance metadata options. Instances without HttpTokens set to required are flagged.",
    ),
  "ec2.ebs.encryption_not_default": () =>
    copy(
      "Verify that EBS encryption-by-default is enabled in each region.",
      "Vigil reads EBS encryption-by-default settings per region. Regions where default encryption is disabled are flagged.",
    ),
  "ec2.ebs.volume_unencrypted": () =>
    copy(
      "Verify that attached EBS volumes are encrypted at rest.",
      "Vigil lists attached EBS volumes. Volumes with encryption disabled are flagged.",
    ),
  "ec2.ebs.snapshot_public": () =>
    copy(
      "Verify that EBS snapshots are not shared publicly.",
      "Vigil reads snapshot create-volume permissions. Snapshots shared with all AWS accounts are flagged.",
    ),
  "ec2.ebs.snapshot_unencrypted": () =>
    copy(
      "Verify that EBS snapshots are encrypted.",
      "Vigil lists EBS snapshots. Snapshots without encryption are flagged.",
    ),
  "rds.instance.publicly_accessible": () =>
    copy(
      "Verify that RDS instances are not publicly accessible.",
      "Vigil reads RDS instance PubliclyAccessible attribute. Instances set to publicly accessible are flagged.",
    ),
  "rds.instance.no_encryption": () =>
    copy(
      "Verify that RDS instances have storage encryption at rest enabled.",
      "Vigil reads RDS storage encryption settings. Instances without storage encryption are flagged.",
    ),
  "rds.instance.no_automated_backup": () =>
    copy(
      "Verify that RDS automated backups are enabled with retention meeting your policy minimum.",
      "Vigil reads automated backup and retention settings. Instances with backups disabled or zero retention are flagged.",
    ),
  "rds.instance.no_deletion_protection": () =>
    copy(
      "Verify that production RDS instances have deletion protection enabled.",
      "Vigil reads RDS deletion protection. Instances without deletion protection enabled are flagged.",
    ),
  "rds.instance.no_multi_az": () =>
    copy(
      "Verify that production RDS instances use Multi-AZ for high availability.",
      "Vigil reads RDS Multi-AZ configuration. Single-AZ instances are flagged when this check is in scope.",
    ),
  "dynamodb.table.no_encryption": () =>
    copy(
      "Verify that DynamoDB tables have encryption at rest enabled.",
      "Vigil reads table SSE configuration. Tables without server-side encryption at rest are flagged.",
    ),
  "dynamodb.table.no_pitr": () =>
    copy(
      "Verify that DynamoDB tables have point-in-time recovery enabled.",
      "Vigil reads continuous backup (PITR) settings. Tables without PITR enabled are flagged.",
    ),
  "acm.certificate.expiring": () =>
    copy(
      "Verify that ACM certificates are renewed before expiry within the warning window.",
      "Vigil reads ACM certificate NotAfter dates. Certificates expiring within the configured warning window are flagged.",
    ),
  "lambda.function.deprecated_runtime": () =>
    copy(
      "Verify that Lambda functions run on supported runtimes.",
      "Vigil reads function runtime identifiers. Functions on deprecated or unsupported runtimes are flagged.",
    ),
  "lambda.function.no_dlq": () =>
    copy(
      "Verify that asynchronously invoked Lambda functions have a dead-letter queue configured.",
      "Vigil reads async-invoke DLQ configuration. Asynchronous functions without a configured dead-letter target are flagged.",
    ),
  "secretsmanager.secret.no_rotation": () =>
    copy(
      "Verify that Secrets Manager secrets have automatic rotation enabled.",
      "Vigil reads Secrets Manager rotation configuration. Secrets without automatic rotation enabled are flagged.",
    ),
  "ssm.parameter.plaintext_secret": () =>
    copy(
      "Verify that sensitive values are stored as SSM SecureString parameters or in Secrets Manager, not plaintext String parameters.",
      "Vigil lists SSM String parameters and flags names matching likely-secret patterns stored as plaintext String type.",
    ),
  "elb.load_balancer.no_access_logs": () =>
    copy(
      "Verify that load balancers have access logging enabled to S3.",
      "Vigil reads load balancer access log configuration. Load balancers without access logging enabled are flagged.",
    ),
  "elb.load_balancer.weak_tls_policy": () =>
    copy(
      "Verify that load balancer listeners use TLS 1.2+ security policies with modern cipher suites.",
      "Vigil reads listener TLS security policies. Policies below the configured TLS baseline are flagged.",
    ),
  "sns.topic.no_encryption": () =>
    copy(
      "Verify that SNS topics use SSE-KMS encryption at rest.",
      "Vigil reads SNS topic encryption settings. Topics without SSE-KMS encryption are flagged.",
    ),
  "sqs.queue.no_encryption": () =>
    copy(
      "Verify that SQS queues use SSE-KMS encryption at rest.",
      "Vigil reads SQS server-side encryption settings. Queues without KMS encryption are flagged.",
    ),
};

function builderFor(checkId: string): ((s: RemediationSummary) => CheckComplianceCopy) | null {
  if (SPECIFIC[checkId]) return SPECIFIC[checkId];
  for (const [prefix, fn] of Object.entries(BUILDERS)) {
    if (checkId.startsWith(prefix)) {
      return (s) => fn(checkId, s);
    }
  }
  return null;
}

export function complianceCopyForCheck(checkId: string): CheckComplianceCopy | null {
  const s = remediationSummaries[checkId];
  if (!s) return null;
  const build = builderFor(checkId);
  return build ? build(s) : defaultCopy(checkId, s);
}

/** Short scanner description for Overview / documentation (not auditor templates). */
export function scanDescriptionForCheck(checkId: string, s: RemediationSummary): string {
  const specific: Record<string, string> = {
    "iam.access_key.unused_90d":
      "Access keys with no recorded API usage in the last 90 days.",
    "iam.access_key.no_rotation_90d":
      "Access keys older than the configured rotation-age threshold.",
    "iam.access_key.multiple_active": "IAM users with more than one Active access key.",
    "iam.policy.wildcard_resource":
      "Customer-managed or inline policies granting write actions on Resource \"*\".",
    "iam.root.no_mfa": "Root user without an assigned MFA device.",
    "iam.user.no_mfa": "Console-capable IAM users without MFA assigned.",
  };
  return specific[checkId] ?? s.impact.replace(/\.$/, "") + ".";
}
