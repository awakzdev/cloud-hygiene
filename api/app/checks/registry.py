from app.checks import (
    access_key_multiple_active,
    access_key_no_rotation,
    iam_access_key_unused,
    iam_root_access_keys,
    iam_root_no_mfa,
    iam_user_inactive,
    iam_user_no_mfa,
    kms_no_rotation,
    role_trust_wildcard,
    role_unassumed_90d,
    role_unused_services,
    role_wildcard_action,
    s3_no_https_policy,
    s3_no_kms,
    s3_no_logging,
    s3_public_access,
)

ALL_CHECKS = [
    # root (critical — run first)
    iam_root_access_keys,
    iam_root_no_mfa,
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
]
