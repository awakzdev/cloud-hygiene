from app.checks import (
    access_analyzer_not_enabled,
    access_key_multiple_active,
    access_key_no_rotation,
    cloudtrail_not_enabled,
    cloudtrail_no_log_validation,
    config_not_enabled,
    ec2_ebs_encryption_default,
    ec2_imdsv2_not_required,
    guardduty_not_enabled,
    iam_access_key_unused,
    iam_password_policy_weak,
    iam_root_access_keys,
    iam_root_no_mfa,
    iam_user_inactive,
    iam_user_no_mfa,
    kms_no_rotation,
    rds_no_encryption,
    rds_publicly_accessible,
    role_trust_wildcard,
    role_unassumed_90d,
    role_unused_services,
    role_wildcard_action,
    s3_no_https_policy,
    s3_no_kms,
    s3_no_logging,
    s3_public_access,
    sg_default_allows_traffic,
    sg_unrestricted_rdp,
    sg_unrestricted_ssh,
    securityhub_not_enabled,
    vpc_no_flow_logs,
)

ALL_CHECKS = [
    # root (critical — run first)
    iam_root_access_keys,
    iam_root_no_mfa,
    # IAM account
    iam_password_policy_weak,
    # IAM users
    iam_user_inactive,
    iam_access_key_unused,
    access_key_no_rotation,
    access_key_multiple_active,
    iam_user_no_mfa,
    # IAM roles
    role_unassumed_90d,
    role_wildcard_action,
    role_unused_services,
    role_trust_wildcard,
    # S3
    s3_public_access,
    s3_no_https_policy,
    s3_no_kms,
    s3_no_logging,
    # KMS
    kms_no_rotation,
    # CloudTrail
    cloudtrail_not_enabled,
    cloudtrail_no_log_validation,
    # GuardDuty
    guardduty_not_enabled,
    # Access Analyzer
    access_analyzer_not_enabled,
    # AWS Config
    config_not_enabled,
    # Security Hub
    securityhub_not_enabled,
    # VPC
    vpc_no_flow_logs,
    # EC2 Security Groups
    sg_unrestricted_ssh,
    sg_unrestricted_rdp,
    sg_default_allows_traffic,
    # EC2 Instances
    ec2_imdsv2_not_required,
    ec2_ebs_encryption_default,
    # RDS
    rds_publicly_accessible,
    rds_no_encryption,
]
