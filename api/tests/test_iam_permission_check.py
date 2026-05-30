"""IAM policy document action matching."""

from app.services.iam_permission_check import iam_action_matches, statements_allow_action


def test_iam_action_matches_wildcard():
    assert iam_action_matches("ec2:*", "ec2:DescribeSecurityGroups")
    assert iam_action_matches("*", "s3:GetObject")
    assert not iam_action_matches("ec2:Describe*", "ec2:AuthorizeSecurityGroupIngress")


def test_statements_allow_action():
    statements = [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:RevokeSecurityGroupIngress",
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:DescribeSecurityGroups",
            ],
            "Resource": "*",
        }
    ]
    assert statements_allow_action(statements, "ec2:DescribeSecurityGroups")
    assert not statements_allow_action(statements, "s3:PutBucketPolicy")
