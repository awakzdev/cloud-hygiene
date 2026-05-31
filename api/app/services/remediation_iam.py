"""IAM policy fragments for customer remediation automation (per check family)."""
from __future__ import annotations

from typing import Any


def inline_policy_for_check(check_id: str) -> list[dict[str, Any]]:
    """Least-privilege statements for the given finding check (customer role inline policy)."""
    if check_id.startswith("s3."):
        return [
            {
                "Sid": "S3PublicAccessBlock",
                "Effect": "Allow",
                "Action": ["s3:PutPublicAccessBlock", "s3:GetPublicAccessBlock", "s3:GetBucketLocation"],
                "Resource": "*",
            },
        ]
    if check_id.startswith("ec2.security_group"):
        return [
            {
                "Sid": "Ec2SecurityGroupIngress",
                "Effect": "Allow",
                "Action": [
                    "ec2:RevokeSecurityGroupIngress",
                    "ec2:DescribeSecurityGroups",
                    "ec2:DescribeSecurityGroupRules",
                ],
                "Resource": "*",
            },
        ]
    if check_id.startswith("kms."):
        return [
            {
                "Sid": "KmsKeyPolicy",
                "Effect": "Allow",
                "Action": ["kms:GetKeyPolicy", "kms:PutKeyPolicy", "kms:EnableKeyRotation"],
                "Resource": "*",
            },
        ]
    if check_id.startswith("ssm."):
        return [
            {
                "Sid": "SsmParameterSecureStringMigration",
                "Effect": "Allow",
                "Action": ["ssm:GetParameter", "ssm:PutParameter"],
                "Resource": "*",
            }
        ]
    if check_id.startswith("iam."):
        return [
            {
                "Sid": "IamRead",
                "Effect": "Allow",
                "Action": ["iam:GetRole", "iam:GetPolicy", "iam:ListAttachedRolePolicies"],
                "Resource": "*",
            },
        ]
    return [
        {
            "Sid": "ReadOnlyStub",
            "Effect": "Allow",
            "Action": ["iam:GetRole"],
            "Resource": "*",
        },
    ]


def inline_policy_document(check_id: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": inline_policy_for_check(check_id),
    }
