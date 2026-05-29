"""Pre-written audit response narratives per control.

Copy-paste starting points for SOC2/CIS/ISO questionnaires.
Each narrative describes what the control covers and what evidence Vigil collects.
"""

NARRATIVES: dict[str, str] = {
    # ── SOC2 CC6 ────────────────────────────────────────────────────────────
    "CC6.1": (
        "Logical access to production systems is restricted and continuously monitored. "
        "Vigil collects evidence of IAM user activity, role usage, and access key last-used dates from AWS IAM. "
        "Dormant identities (no activity in 90+ days) are flagged as findings. "
        "GitHub and GitLab member activity is monitored where integrated. "
        "Evidence is collected at each scan and retained for the selected audit period."
    ),
    "CC6.2": (
        "System credentials are issued only to registered, authorized users. "
        "Vigil verifies that no root access keys exist, that each IAM user holds at most one active access key, "
        "that the account IAM password policy meets minimum complexity (length, reuse, and related fields), "
        "and that MFA is enforced at the organization level in GitHub and GitLab where integrated. "
        "Outside collaborators with direct repository access are enumerated and flagged for review."
    ),
    "CC6.3": (
        "Access to protected resources is restricted based on least-privilege principles. "
        "Vigil collects evidence of IAM roles and policies, flagging wildcard Resource scopes "
        "on customer-managed policies, external-account role trust, unused granted services, "
        "and roles granted write permissions to services they have never called. "
        "Evidence includes inline policy documents, attached managed policy names, service last-accessed data, "
        "and IAM Identity Center user roster snapshots where enabled. "
        "User deprovisioning workflow attestation remains outside automated scope."
    ),
    "CC6.6": (
        "Logical access controls prevent unauthorized access from outside the organization. "
        "Vigil monitors IAM permission usage (granted vs. actually used) using AWS access advisor data, "
        "flags roles and users with excessive unused permissions, and checks that EC2 security groups "
        "do not expose sensitive ports (SSH/RDP) to 0.0.0.0/0. "
        "GitHub and GitLab branch protection enforcement is included where integrated."
    ),
    "CC6.7": (
        "Transmission and storage of data is protected using encryption controls. "
        "Vigil verifies S3 bucket default encryption (SSE-S3 or SSE-KMS), KMS key rotation status, "
        "HTTPS-only bucket policies, EBS volume encryption, RDS instance storage encryption, "
        "and account-level S3 public access block settings."
    ),
    "CC6.8": (
        "Controls protect against unauthorized or malicious software. "
        "Vigil verifies GuardDuty detector status across regions and Security Hub enablement. "
        "IMDSv2 enforcement on EC2 instances is checked to mitigate SSRF-based metadata exfiltration. "
        "VPC flow log enablement is verified for network traffic visibility."
    ),
    "CC7.1": (
        "Configuration changes that can introduce vulnerabilities are detected and monitored. "
        "Vigil verifies CloudTrail is enabled with log file validation and KMS encryption, "
        "AWS Config recorder status and rule compliance, ACM certificate expiry, and "
        "deprecated Lambda runtimes that may lack security patches."
    ),
    "CC7.2": (
        "Security events and anomalies are detected and monitored. "
        "Vigil verifies that AWS CloudTrail is enabled, covers all regions, and has log file validation active. "
        "AWS Config (including non-compliant managed rules), GuardDuty detector enablement, "
        "active GuardDuty findings, and Security Hub enablement are checked. "
        "CloudTrail write events (IAM changes, security group modifications, S3 policy changes) "
        "are collected and retained to support audit sampling. "
        "Evidence packs include a coverage indicator when the selected audit window predates Vigil monitoring."
    ),
    "CC8.1": (
        "Changes to infrastructure and application code are authorized before production use. "
        "Vigil collects GitHub and GitLab evidence for branch protection on default branches, "
        "required pull request reviews, absence of self-merged PRs, and protected deployment environments. "
        "CloudTrail write events for infrastructure changes are included in evidence packs for correlation."
    ),

    # ── CIS AWS L1 ──────────────────────────────────────────────────────────
    "CIS 1.4": (
        "Vigil verifies that the AWS root account does not have active access keys. "
        "Evidence is collected from the IAM credential report at each scan."
    ),
    "CIS 1.5": (
        "Vigil verifies that MFA is enabled on the AWS root account. "
        "Evidence is collected from the IAM account summary at each scan."
    ),
    "CIS 1.10": (
        "Vigil enumerates all IAM users with console access and verifies MFA device enrollment. "
        "Users with no MFA device are reported as findings. Evidence is collected from IAM at each scan."
    ),
    "CIS 1.14": (
        "Vigil verifies that IAM users do not have access keys older than 90 days without rotation. "
        "Key creation date and last-used date are collected from IAM at each scan."
    ),
    "CIS 1.16": (
        "Vigil verifies that IAM policies are not attached directly to users. "
        "Attached managed policy names and inline policy names are collected via "
        "iam:ListAttachedUserPolicies and iam:ListUserPolicies at each scan."
    ),
    "CIS 1.7": (
        "Vigil checks CloudTrail for root account API activity in the last 90 days. "
        "Any root usage is reported as a finding — routine operations should use IAM roles or users."
    ),
    "CIS 1.8": (
        "Vigil reads the account IAM password policy and flags weak minimum length or missing "
        "complexity requirements per CIS guidance. Policy fields are collected at each scan."
    ),
    "CIS 1.9": (
        "Vigil verifies password reuse prevention is enabled on the IAM account password policy "
        "(password reuse prevention / history). Evidence is collected from IAM at each scan."
    ),
    "CIS 1.12": (
        "Vigil flags IAM users inactive for 90+ days and access keys with no recorded usage "
        "in the same window, supporting credential disablement per CIS guidance."
    ),
    "CIS 1.22": (
        "Vigil scans customer-managed role policies for the CIS full-admin pattern: "
        "Allow with Action: '*' and Resource: '*' on the same statement."
    ),
    "CIS 1.20": (
        "Vigil verifies that a support role exists in the account for incident management. "
        "IAM roles with AWSSupportAccess policy attachment are checked."
    ),
    "CIS 2.1": (
        "Vigil verifies that AWS CloudTrail is enabled and covers all regions. "
        "Trail configuration is collected via cloudtrail:DescribeTrails at each scan."
    ),
    "CIS 2.2": (
        "Vigil verifies that CloudTrail log file validation is enabled on all trails. "
        "This ensures log integrity for audit sampling across the evidence period."
    ),
    "CIS 2.4": (
        "Vigil verifies that CloudTrail trails are integrated with CloudWatch Logs. "
        "Trail configuration is collected at each scan."
    ),
    "CIS 2.6": (
        "Vigil verifies that S3 bucket access logging is enabled on the CloudTrail delivery bucket. "
        "S3 bucket logging configuration is collected at each scan."
    ),
    "CIS 3.1": (
        "Vigil collects CloudTrail events for root account activity. "
        "Any use of root credentials triggers a finding flagged to CC6 and this control."
    ),
    "CIS 2.1.1": (
        "Vigil verifies that S3 bucket policies deny HTTP requests using an aws:SecureTransport condition."
    ),
    "CIS 2.1.2": (
        "Vigil verifies that S3 buckets have default encryption (SSE-S3 or SSE-KMS) enabled."
    ),
    "CIS 2.1.3": (
        "Vigil checks whether S3 buckets have MFA Delete enabled on versioning configuration."
    ),
    "CIS 2.1.5": (
        "Vigil verifies account-level and per-bucket S3 Block Public Access settings."
    ),
    "CIS 2.2.1": (
        "Vigil enumerates EBS volumes and flags any that are not encrypted at rest."
    ),
    "CIS 2.3.1": (
        "Vigil verifies RDS instance storage encryption is enabled."
    ),
    "CIS 2.3.2": (
        "Vigil flags RDS instances that are publicly accessible."
    ),
    "CIS 2.3.3": (
        "Vigil verifies RDS automated backup retention is greater than zero."
    ),
    "CIS 3.3": (
        "Vigil verifies CloudTrail log delivery S3 buckets are not publicly accessible."
    ),
    "CIS 3.4": (
        "Vigil verifies CloudTrail trails send logs to CloudWatch Logs."
    ),
    "CIS 3.6": (
        "Vigil verifies server access logging is enabled on CloudTrail delivery buckets."
    ),
    "CIS 3.8": (
        "Vigil verifies customer-managed KMS keys have automatic annual rotation enabled."
    ),
    "CIS 4.1": (
        "Vigil flags security groups allowing SSH (port 22) from 0.0.0.0/0 or ::/0."
    ),
    "CIS 4.2": (
        "Vigil flags security groups allowing RDP (port 3389) from 0.0.0.0/0 or ::/0."
    ),

    # ── ISO 27001 ────────────────────────────────────────────────────────────
    "A.9.2.1": (
        "Vigil provides evidence of user registration and de-registration through IAM user inventory, "
        "dormancy checks, and access key lifecycle tracking. "
        "GitHub and GitLab member rosters are collected where integrated."
    ),
    "A.9.2.2": (
        "Vigil verifies that access provisioning follows least-privilege by checking role permission usage "
        "against actual service calls (via AWS access advisor) and flagging excessive grants."
    ),
    "A.9.2.3": (
        "Vigil collects evidence of privileged account controls: root MFA, no root access keys, "
        "wildcard IAM action grants, and admin-scope roles not assumed in 90+ days."
    ),
    "A.9.2.4": (
        "Vigil verifies that secret authentication information (access keys) is rotated within 90 days "
        "and that MFA is enforced for console users."
    ),
    "A.9.2.5": (
        "Vigil supports periodic access reviews by collecting IAM user/role/key inventory with "
        "last-activity timestamps and generating CSV exports of the access state at each scan."
    ),
    "A.9.2.6": (
        "Vigil flags access keys and role assumptions inactive for 90+ days, supporting "
        "timely revocation of access rights for leavers and role cleanup."
    ),
    "A.9.4.2": (
        "Vigil verifies MFA enrollment for all console-access IAM users and GitHub/GitLab organization members."
    ),
    "A.10.1.1": (
        "Vigil verifies encryption key management: KMS key rotation status, "
        "key state (enabled/disabled/pending deletion), and CloudTrail trail KMS encryption."
    ),
    "A.10.1.2": (
        "Vigil verifies that key management policies are in place: KMS key rotation enabled, "
        "CloudTrail delivery encrypted, S3 buckets using SSE-KMS where required."
    ),
    "A.12.4.1": (
        "Vigil verifies that event logging is active: CloudTrail enabled with all-regions coverage, "
        "log file validation enabled, VPC flow logs enabled, S3 server access logging enabled."
    ),
    "A.12.6.1": (
        "Vigil verifies that technical vulnerability controls are operating: "
        "GuardDuty enabled across regions, Security Hub enabled, IMDSv2 required on EC2 instances, "
        "EBS volumes encrypted, security groups not exposing sensitive ports."
    ),
    "A.13.1.1": (
        "Vigil collects evidence of network security controls: "
        "security groups are checked for unrestricted SSH/RDP/all-traffic ingress, "
        "default VPC security groups are verified not to allow traffic, "
        "and VPC flow logs are verified to be enabled."
    ),
    "A.13.1.3": (
        "Vigil verifies network segregation controls through VPC flow log collection, "
        "security group rule inventory, and RDS public accessibility checks."
    ),
    "A.12.4.2": (
        "Vigil verifies log integrity and protection: CloudTrail log file validation, "
        "KMS encryption on trails, and that delivery buckets are not public."
    ),
    "A.13.2.3": (
        "Vigil verifies data-in-transit controls: S3 HTTPS-only bucket policies and "
        "Block Public Access at account and bucket level."
    ),
    "A.12.3.1": (
        "Vigil verifies backup-related controls: RDS deletion protection enabled and "
        "DynamoDB Point-in-Time Recovery enabled on tables."
    ),
    "A.17.2.1": (
        "Vigil verifies RDS Multi-AZ deployment for production databases requiring "
        "high availability and automatic failover."
    ),
}


SHORT_ANSWERS: dict[str, str] = {
    "CC6.1": "Logical access is restricted; Vigil continuously monitors IAM and integrated identity providers for MFA and dormant accounts.",
    "CC6.2": "Credentials are issued only to authorized users; root keys, access key limits, and org MFA are verified each scan.",
    "CC6.3": "Least-privilege access is enforced; wildcard actions/resources, external trust, and unused permissions are flagged with policy evidence.",
    "CC6.6": "External access paths are controlled via permission-usage analysis, security group checks, and branch protection evidence.",
    "CC6.7": "Encryption at rest is verified for S3, KMS, EBS, and RDS using collected configuration snapshots.",
    "CC6.8": "Malware and threat detection controls include GuardDuty, Security Hub, IMDSv2, and VPC flow log checks.",
    "CC7.1": "Configuration change detection via CloudTrail, AWS Config, certificate and runtime hygiene signals.",
    "CC7.2": "Security monitoring is active; CloudTrail, Config rules, GuardDuty findings, and Security Hub status are verified each scan.",
    "CC8.1": "SCM branch protection and review evidence from GitHub/GitLab; CloudTrail write events support authorized infrastructure changes.",
    "CIS 1.5": "Root account MFA is verified from the IAM account summary at each scan.",
    "CIS 1.8": "IAM password policy minimum length and complexity are verified each scan.",
    "CIS 1.9": "IAM password policy reuse prevention is verified each scan.",
    "CIS 1.10": "Console IAM users without MFA devices are enumerated and reported as findings.",
    "CIS 2.1": "Multi-region CloudTrail enablement is verified from trail configuration snapshots.",
    "CIS 2.2": "CloudTrail log file validation status is collected for every trail.",
    "A.9.2.1": "User registration and de-registration evidence comes from IAM inventory and integrated identity rosters.",
    "A.12.4.1": "Event logging controls include CloudTrail, VPC flow logs, and S3 access logging verification.",
}


KNOWN_GAPS: dict[str, list[str]] = {
    "CC6.1": ["Physical access to data centers is out of scope — attest separately for colo/on-prem."],
    "CC6.2": ["HR/offboarding attestations for non-AWS identities are outside Vigil scope."],
    "CC6.3": ["Formal user deprovisioning approval workflow is not automated — attest separately."],
    "CC7.2": ["GuardDuty finding triage and incident response runbooks require manual attestation."],
    "CC7.1": ["Emergency break-glass deploys outside SCM are not captured unless logged in CloudTrail."],
    "CC8.1": [
        "Changes made directly in the AWS Console appear in CloudTrail only — process attestation may be required.",
        "CODEOWNERS file coverage is optional hygiene (Settings → Detection coverage); branch protection and required reviews are the mapped SCM evidence.",
    ],
    "CIS 1.20": ["AWS Support role existence is checked; support plan enrollment is manual attestation."],
    "CIS 1.16": ["Vigil automates policy attachment checks; manual attestation still needed for business justification."],
}


def _narrative_key(framework: str, control_id: str) -> str:
    if framework == "cis_aws_l1":
        return f"CIS {control_id}"
    return control_id


def _short_answer(framework: str, control_id: str, long_text: str | None) -> str | None:
    key = _narrative_key(framework, control_id)
    if key in SHORT_ANSWERS:
        return SHORT_ANSWERS[key]
    if control_id in SHORT_ANSWERS:
        return SHORT_ANSWERS[control_id]
    if not long_text:
        return None
    sentence = long_text.split(". ")[0].strip()
    return sentence + "." if sentence and not sentence.endswith(".") else sentence


def evidence_refs_from_checks(check_ids: list[str]) -> list[str]:
    if not check_ids:
        return ["No automated Vigil checks mapped — manual attestation required."]
    refs: list[str] = []
    seen_groups: set[str] = set()
    for cid in sorted(check_ids):
        prefix = cid.split(".")[0]
        group_hint = {
            "iam": "IAM inventory snapshots (users, roles, keys, policies)",
            "s3": "S3 bucket configuration snapshots",
            "kms": "KMS key configuration snapshots",
            "cloudtrail": "CloudTrail trail configuration snapshots",
            "github": "GitHub org/repo/PR evidence from integration sync",
            "gitlab": "GitLab project/merge request evidence from integration sync",
            "ec2": "EC2 instance and security group snapshots",
            "rds": "RDS instance configuration snapshots",
            "guardduty": "GuardDuty detector status snapshots",
            "aws": "AWS account-level service status snapshots",
            "vpc": "VPC and flow log snapshots",
        }.get(prefix, f"Resource snapshots for `{prefix}` checks")
        if group_hint not in seen_groups:
            refs.append(group_hint)
            seen_groups.add(group_hint)
        refs.append(f"Finding/check: `{cid}` — evaluated each scan")
    if len(refs) > 8:
        return refs[:7] + [f"+ {len(check_ids) - 7} additional mapped checks"]
    return refs


def narrative_for(framework: str, control_id: str) -> str | None:
    """Resolve questionnaire narrative; CIS controls use ``CIS {id}`` keys in NARRATIVES."""
    key = _narrative_key(framework, control_id)
    return NARRATIVES.get(key) or NARRATIVES.get(control_id)


def narrative_detail_for(
    framework: str,
    control_id: str,
    check_ids: list[str] | None = None,
) -> dict[str, object]:
    """Structured narrative for Compliance UI and questionnaire export."""
    key = _narrative_key(framework, control_id)
    long_answer = narrative_for(framework, control_id)
    gaps = list(KNOWN_GAPS.get(key, KNOWN_GAPS.get(control_id, [])))
    if not check_ids:
        gaps.insert(0, "No automated checks mapped — this control requires manual attestation in Vigil.")
    return {
        "short_answer": _short_answer(framework, control_id, long_answer),
        "long_answer": long_answer,
        "evidence_refs": evidence_refs_from_checks(check_ids or []),
        "known_gaps": gaps,
    }
