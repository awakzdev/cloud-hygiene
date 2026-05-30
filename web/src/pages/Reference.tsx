import { useMemo, useState } from "react";

type ReferenceRow = {
  key: string;
  value: string;
  examples: string[];
  group: string;
};

const rows: ReferenceRow[] = [
  { key: "iam.root", value: "AWS account root identity findings, including MFA, root access key, and root usage checks.", examples: ["iam.root.no_mfa", "iam.root.has_access_keys", "iam.root.usage"], group: "IAM" },
  { key: "iam.user", value: "IAM users collected from the account, including direct policy attachments.", examples: ["iam.user.no_mfa", "iam.user.credentials_unused_45d", "iam.user.direct_policy_attachment"], group: "IAM" },
  { key: "iam.role", value: "IAM roles, trust policies, attached policies, and role activity.", examples: ["iam.role.unassumed_90d", "iam.role.trust_wildcard"], group: "IAM" },
  { key: "iam.policy", value: "Customer-managed IAM policies and attachment count.", examples: ["iam.policy.unattached", "iam.policy.wildcard_resource"], group: "IAM" },
  { key: "iam.perm", value: "IAM action-level permission usage — granted write actions vs. recorded usage in the last 90 days.", examples: ["iam.perm.granted_vs_used"], group: "IAM" },
  { key: "iam.access_key", value: "IAM user access keys, status, last-used service, and rotation age.", examples: ["iam.access_key.unused_45d", "iam.access_key.no_rotation_90d"], group: "IAM" },
  { key: "iam.password_policy", value: "Account password policy settings such as minimum length, reuse prevention, and age.", examples: ["iam.account.password_policy_weak"], group: "IAM" },
  { key: "iam.access_analyzer", value: "IAM Access Analyzer regional status.", examples: ["aws.access_analyzer.not_enabled"], group: "IAM" },
  { key: "s3.bucket", value: "S3 buckets and security posture flags such as encryption, logging, HTTPS-only, and public access.", examples: ["s3.bucket.no_kms", "s3.bucket.no_logging"], group: "S3" },
  { key: "s3.account_public_access_block", value: "Account-level S3 Block Public Access configuration.", examples: ["s3.account.public_access_not_blocked"], group: "S3" },
  { key: "ec2.instance", value: "EC2 instances, state, type, VPC/subnet placement, security groups, and IMDSv2 setting.", examples: ["ec2.instance.imdsv2_not_required"], group: "EC2" },
  { key: "ec2.security_group", value: "Security groups, default-group status, ingress risk flags, and attached VPC.", examples: ["ec2.security_group.unrestricted_ssh", "ec2.security_group.unrestricted_rdp"], group: "EC2" },
  { key: "ec2.vpc", value: "VPC records and flow-log coverage.", examples: ["vpc.flow_logs.not_enabled"], group: "EC2" },
  { key: "ec2.ebs_encryption_default", value: "Per-region EBS encryption-by-default status.", examples: ["ec2.ebs.encryption_not_default"], group: "EC2" },
  { key: "ec2.ebs_volume", value: "EBS volumes, encryption state, size, type, and attached instance ids.", examples: ["ec2.ebs.volume_unencrypted", "vol-0123456789abcdef0"], group: "EC2" },
  { key: "rds.instance", value: "RDS database instances, encryption, public exposure, backup retention, Multi-AZ, and deletion protection.", examples: ["rds.instance.no_encryption", "rds.instance.no_automated_backup", "rds.instance.no_multi_az", "rds.instance.no_deletion_protection"], group: "RDS" },
  { key: "lambda.function", value: "Lambda functions, runtime version, and dead-letter queue configuration.", examples: ["lambda.function.deprecated_runtime", "lambda.function.no_dlq"], group: "Lambda" },
  { key: "dynamodb.table", value: "DynamoDB tables, point-in-time recovery, and encryption status.", examples: ["dynamodb.table.no_pitr", "dynamodb.table.no_encryption"], group: "DynamoDB" },
  { key: "acm.certificate", value: "ACM TLS certificates and expiry dates.", examples: ["acm.certificate.expiring"], group: "ACM" },
  { key: "elb.load_balancer", value: "Application and network load balancers, access logs, and TLS policy.", examples: ["elb.load_balancer.no_access_logs", "elb.load_balancer.weak_tls_policy"], group: "ELB" },
  { key: "secretsmanager.secret", value: "Secrets Manager secrets and rotation configuration.", examples: ["secretsmanager.secret.no_rotation"], group: "Secrets" },
  { key: "ssm.parameter", value: "SSM parameters flagged when sensitive names use plaintext String type.", examples: ["ssm.parameter.plaintext_secret"], group: "SSM" },
  { key: "sns.topic", value: "SNS topics and KMS encryption status.", examples: ["sns.topic.no_encryption"], group: "Messaging" },
  { key: "sqs.queue", value: "SQS queues and KMS encryption status.", examples: ["sqs.queue.no_encryption"], group: "Messaging" },
  { key: "ec2.ebs.snapshot", value: "EBS snapshots and public/unencrypted posture.", examples: ["ec2.ebs.snapshot_public", "ec2.ebs.snapshot_unencrypted"], group: "EC2" },
  { key: "ec2.ami", value: "EC2 AMIs and public visibility.", examples: ["ec2.ami.public"], group: "EC2" },
  { key: "kms.key", value: "KMS keys, aliases, rotation status, and key state.", examples: ["kms.key.no_rotation"], group: "KMS" },
  { key: "cloudtrail.trail", value: "CloudTrail trails, logging state, validation, multi-region status, and KMS key usage.", examples: ["cloudtrail.trail.not_enabled", "cloudtrail.trail.no_kms"], group: "Logging" },
  { key: "config.recorder", value: "AWS Config recorder and delivery channel status.", examples: ["aws.config.not_enabled"], group: "Logging" },
  { key: "guardduty.detector", value: "GuardDuty detector status by region.", examples: ["guardduty.detector.not_enabled"], group: "Detection" },
  { key: "securityhub.hub", value: "Security Hub enablement by region.", examples: ["aws.securityhub.not_enabled"], group: "Detection" },
  { key: "arn:aws:...", value: "Full AWS ARNs are searchable when findings or collected resources have them.", examples: ["arn:aws:s3:::bucket-name", "arn:aws:iam::123456789012:role/RoleName"], group: "Identifiers" },
  { key: "region", value: "AWS region strings narrow results to regional findings and resources.", examples: ["us-east-1", "eu-west-1"], group: "Identifiers" },
  { key: "github.org", value: "GitHub organization-level identity findings — MFA enforcement, dormant members, and outside collaborators.", examples: ["github.org.mfa_not_enforced", "github.org.dormant_members", "github.org.outside_collaborators"], group: "GitHub" },
  { key: "github.repo", value: "GitHub repository change-management findings — branch protection, environment protection, self-merge, and review coverage.", examples: ["github.repo.no_branch_protection", "github.repo.no_env_protection", "github.repo.self_merge_allowed"], group: "GitHub" },
  { key: "gitlab.org", value: "GitLab group-level identity findings — MFA enforcement and dormant members.", examples: ["gitlab.org.mfa_not_enforced", "gitlab.org.dormant_members"], group: "GitLab" },
  { key: "gitlab.repo", value: "GitLab project change-management findings — protected branches, self-merge, and MR review coverage.", examples: ["gitlab.repo.no_branch_protection", "gitlab.repo.self_merge_allowed", "gitlab.repo.insufficient_reviews"], group: "GitLab" },
  { key: "github://", value: "GitHub resource URIs in the format github://<org>/<repo>. Searchable by org name or repo name.", examples: ["github://awakzdev", "github://awakzdev/my-repo"], group: "GitHub" },
  { key: "gitlab://", value: "GitLab resource URIs in the format gitlab://<group>/<project>. Searchable by group or project name.", examples: ["gitlab://my-group", "gitlab://my-group/my-project"], group: "GitLab" },
];

export default function Reference() {
  const [query, setQuery] = useState("");

  const filteredRows = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return rows;
    return rows.filter((row) =>
      [row.group, row.key, row.value, ...row.examples]
        .join(" ")
        .toLowerCase()
        .includes(q)
    );
  }, [query]);

  const byService = useMemo(() => {
    const counts = new Map<string, number>();
    for (const row of rows) counts.set(row.group, (counts.get(row.group) ?? 0) + 1);
    return [...counts.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, []);

  return (
    <div className="w-full">
      <div className="mb-7 flex items-start justify-between gap-6 pt-1">
        <div className="min-w-0">
          <h1 className="text-2xl font-bold tracking-tight text-zinc-950">Reference</h1>
          <p className="mt-1 text-sm text-zinc-500">Search keys, AWS identifiers, and finding terms supported by Vigil.</p>
        </div>
        <div className="flex h-10 w-80 items-center rounded-xl border border-zinc-200 bg-white px-3 shadow-sm focus-within:border-zinc-400 focus-within:ring-2 focus-within:ring-zinc-950/[0.06]">
          <svg className="mr-2 h-4 w-4 shrink-0 text-zinc-400" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35m1.35-5.65a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search reference..."
            className="min-w-0 flex-1 bg-transparent text-sm text-zinc-800 outline-none placeholder:text-zinc-400"
          />
        </div>
      </div>

      <div className="mb-5 flex flex-wrap gap-2">
        <span className="rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm font-semibold text-zinc-700 shadow-sm">
          {rows.length} keys
        </span>
        {byService.map(([service, count]) => (
          <span key={service} className="rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-500 shadow-sm">
            <span className="font-semibold text-zinc-700">{service}</span> {count}
          </span>
        ))}
      </div>

      {filteredRows.length === 0 && (
        <div className="rounded-xl border border-zinc-200 bg-white px-4 py-16 text-center">
          <p className="text-sm font-semibold text-zinc-700">No matching reference entry</p>
          <p className="mt-1 text-sm text-zinc-400">Try a service, resource key, check id, ARN prefix, or region.</p>
        </div>
      )}

      {filteredRows.length > 0 && (
        <div className="overflow-hidden rounded-xl border border-zinc-200 bg-white shadow-sm shadow-zinc-950/[0.04]">
          <div className="grid grid-cols-[190px_minmax(0,1fr)_minmax(260px,0.9fr)] gap-4 border-b border-zinc-100 bg-zinc-50 px-5 py-3 text-[11px] font-semibold uppercase tracking-[0.14em] text-zinc-400">
            <div>Key</div>
            <div>Value</div>
            <div>Examples</div>
          </div>
          <div className="divide-y divide-zinc-100">
            {filteredRows.map((row) => (
              <div key={row.key} className="grid grid-cols-[190px_minmax(0,1fr)_minmax(260px,0.9fr)] gap-4 px-5 py-4 hover:bg-zinc-50/70">
                <div className="min-w-0">
                  <div className="truncate font-mono text-sm font-semibold text-zinc-900">{row.key}</div>
                  <div className="mt-1 text-[11px] font-semibold uppercase tracking-[0.14em] text-zinc-400">{row.group}</div>
                </div>
                <div className="text-sm leading-6 text-zinc-600">{row.value}</div>
                <div className="flex min-w-0 flex-wrap gap-1.5">
                  {row.examples.map((example) => (
                    <span key={example} className="rounded-md border border-zinc-200 bg-zinc-50 px-2 py-1 font-mono text-xs text-zinc-600">
                      {example}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
