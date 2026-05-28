/** AWS service id helpers for explorer / blast-radius UI */

const SENSITIVE = new Set([
  "iam",
  "sts",
  "kms",
  "secretsmanager",
  "organizations",
  "account",
  "sso",
  "identitystore",
  "ds",
  "cognito-identity",
  "cognito-idp",
  "guardduty",
  "securityhub",
  "cloudtrail",
  "config",
  "access-analyzer",
  "ram",
  "backup",
  "s3",
  "ec2",
  "lambda",
  "eks",
  "ecs",
  "rds",
]);

const CATEGORY_RULES: { id: string; label: string; match: (s: string) => boolean }[] = [
  { id: "identity", label: "Identity & access", match: (s) => /^(iam|sts|sso|identitystore|cognito|organizations|account|ds)$/.test(s) },
  { id: "compute", label: "Compute", match: (s) => /^(ec2|lambda|ecs|eks|batch|elasticbeanstalk|lightsail|autoscaling)$/.test(s) },
  { id: "storage", label: "Storage & data", match: (s) => /^(s3|dynamodb|rds|redshift|elasticache|efs|fsx|glacier|backup|storagegateway)$/.test(s) },
  { id: "network", label: "Networking", match: (s) => /^(vpc|ec2|elasticloadbalancing|route53|cloudfront|apigateway|directconnect|globalaccelerator)$/.test(s) },
  { id: "security", label: "Security & compliance", match: (s) => /^(kms|secretsmanager|guardduty|securityhub|cloudtrail|config|waf|shield|macie|access-analyzer|inspector)$/.test(s) },
  { id: "mgmt", label: "Management", match: (s) => /^(cloudwatch|logs|events|sns|sqs|ssm|cloudformation|servicecatalog|support|health|trustedadvisor)$/.test(s) },
];

export function isSensitiveService(serviceId: string): boolean {
  const base = serviceId.split(":")[0]?.toLowerCase() ?? serviceId.toLowerCase();
  return SENSITIVE.has(base);
}

export function serviceCategory(serviceId: string): { id: string; label: string } {
  const base = serviceId.split(":")[0]?.toLowerCase() ?? serviceId.toLowerCase();
  for (const rule of CATEGORY_RULES) {
    if (rule.match(base)) return { id: rule.id, label: rule.label };
  }
  return { id: "other", label: "Other" };
}

export function allCategories(): { id: string; label: string }[] {
  return [...CATEGORY_RULES.map((r) => ({ id: r.id, label: r.label })), { id: "other", label: "Other" }];
}
