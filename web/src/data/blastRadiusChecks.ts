/** Prefixes / IDs supported by GET /v1/accounts/{id}/blast-radius (keep in sync with accounts.py). */
const BLAST_RADIUS_PREFIXES = [
  "iam.role.",
  "iam.access_key.",
  "iam.user.",
  "iam.root.",
  "iam.policy.",
  "ec2.security_group.",
  "kms.key.",
  "s3.bucket.",
  "rds.instance.",
  "dynamodb.table.",
  "cloudtrail.trail.",
  "ec2.ebs.snapshot",
  "lambda.function.",
  "elb.load_balancer.",
  "github.",
  "gitlab.",
] as const;

const BLAST_RADIUS_EXACT = new Set([
  "iam.account.password_policy_weak",
  "iam.perm.granted_vs_used",
  "s3.account.public_access_not_blocked",
  "vpc.flow_logs.not_enabled",
  "guardduty.detector.not_enabled",
  "aws.config.not_enabled",
  "aws.securityhub.not_enabled",
  "aws.access_analyzer.not_enabled",
  "ec2.instance.imdsv2_not_required",
  "ec2.ebs.volume_unencrypted",
  "ec2.ebs.encryption_not_default",
  "ec2.ami.public",
  "acm.certificate.expiring",
  "secretsmanager.secret.no_rotation",
  "ssm.parameter.plaintext_secret",
  "sns.topic.no_encryption",
  "sqs.queue.no_encryption",
]);

/** True when the finding drawer should show the What If tab for this check. */
export function supportsBlastRadius(checkId: string): boolean {
  if (BLAST_RADIUS_EXACT.has(checkId)) return true;
  return BLAST_RADIUS_PREFIXES.some((p) => checkId.startsWith(p));
}

/**
 * @deprecated Prefer supportsBlastRadius — static set drifts when new checks ship.
 * Kept for imports that expect a Set; not exhaustive.
 */
export const BLAST_RADIUS_CHECKS = new Set<string>();
