import { useMemo, useState, useEffect } from "react";

const rows = [
  { key: "iam.root", value: "AWS account root identity findings, including MFA, root access key, and root usage checks.", examples: ["iam.root.no_mfa", "iam.root.has_access_keys", "iam.root.usage"], group: "IAM" },
  { key: "iam.user", value: "IAM users collected from the account.", examples: ["iam.user.no_mfa", "iam.user.credentials_unused_45d"], group: "IAM" },
  { key: "iam.role", value: "IAM roles, trust policies, attached policies, and role activity.", examples: ["iam.role.unassumed_90d", "iam.role.trust_wildcard"], group: "IAM" },
  { key: "iam.policy", value: "Customer-managed IAM policies and attachment count.", examples: ["iam.policy", "PolicyName"], group: "IAM" },
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
  { key: "rds.instance", value: "RDS database instances, encryption, public exposure, backup retention, and engine.", examples: ["rds.instance.no_encryption", "rds.instance.no_automated_backup"], group: "RDS" },
  { key: "kms.key", value: "KMS keys, aliases, rotation status, and key state.", examples: ["kms.key.no_rotation"], group: "KMS" },
  { key: "cloudtrail.trail", value: "CloudTrail trails, logging state, validation, multi-region status, and KMS key usage.", examples: ["cloudtrail.trail.not_enabled", "cloudtrail.trail.no_kms"], group: "Logging" },
  { key: "config.recorder", value: "AWS Config recorder and delivery channel status.", examples: ["aws.config.not_enabled"], group: "Logging" },
  { key: "guardduty.detector", value: "GuardDuty detector status by region.", examples: ["guardduty.detector.not_enabled"], group: "Detection" },
  { key: "securityhub.hub", value: "Security Hub enablement by region.", examples: ["aws.securityhub.not_enabled"], group: "Detection" },
  { key: "arn:aws:...", value: "Full AWS ARNs are searchable when findings or collected resources have them.", examples: ["arn:aws:s3:::bucket-name", "arn:aws:iam::123456789012:role/RoleName"], group: "Identifiers" },
  { key: "region", value: "AWS region strings narrow results to regional findings and resources.", examples: ["us-east-1", "eu-west-1"], group: "Identifiers" },
];

export function SearchReferenceModal({ onClose }: { onClose: () => void }) {
  const [query, setQuery] = useState("");

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return rows;
    return rows.filter((r) =>
      [r.group, r.key, r.value, ...r.examples].join(" ").toLowerCase().includes(q)
    );
  }, [query]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/75 backdrop-blur-sm pt-16 px-4"
      onClick={onClose}
    >
      <div
        className="w-full max-w-3xl max-h-[72vh] rounded-2xl border border-zinc-700/60 bg-zinc-900 shadow-2xl shadow-black/50 flex flex-col overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center gap-3 border-b border-zinc-700/60 px-5 py-3.5">
          <span className="font-mono text-xs font-semibold text-emerald-500">GET</span>
          <span className="font-mono text-sm text-zinc-500 flex-1">/v1/reference</span>
          <input
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="filter..."
            className="w-48 rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 font-mono text-xs text-zinc-300 placeholder:text-zinc-600 outline-none focus:border-zinc-500"
          />
          <button onClick={onClose} className="ml-1 text-zinc-600 hover:text-zinc-400 transition-colors">
            <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Column headers */}
        <div className="grid grid-cols-[180px_1fr_240px] gap-4 border-b border-zinc-700/60 bg-zinc-800/50 px-5 py-2 text-[10px] font-semibold uppercase tracking-widest text-zinc-500">
          <div>Key</div>
          <div>Description</div>
          <div>Examples</div>
        </div>

        {/* Rows */}
        <div className="overflow-y-auto divide-y divide-zinc-700/40">
          {filtered.length === 0 && (
            <div className="px-5 py-12 text-center font-mono text-sm text-zinc-600">no results</div>
          )}
          {filtered.map((row) => (
            <div key={row.key} className="grid grid-cols-[180px_1fr_240px] gap-4 px-5 py-3 hover:bg-zinc-800/50 transition-colors duration-100">
              <div className="min-w-0">
                <div className="font-mono text-sm font-semibold text-zinc-100 truncate">{row.key}</div>
                <div className="mt-0.5 text-[10px] font-semibold uppercase tracking-wide text-zinc-500">{row.group}</div>
              </div>
              <div className="text-xs leading-relaxed text-zinc-400 min-w-0">{row.value}</div>
              <div className="space-y-0.5 min-w-0 overflow-hidden">
                {row.examples.map((ex) => (
                  <div key={ex} className="font-mono text-[11px] text-zinc-500 truncate">{ex}</div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
