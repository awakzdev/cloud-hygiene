from app.routes.accounts import _clean_policy_doc


def test_wildcard_narrowed_to_used_services():
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    unused = {"s3", "ec2", "lambda"}
    used = {"iam", "sts"}

    cleaned, removed, modified = _clean_policy_doc(doc, unused, used, [])

    assert removed == 0
    assert modified == 1
    assert cleaned["Statement"][0]["Action"] == ["iam:*", "sts:*"]


def test_wildcard_narrowed_to_used_actions():
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    used_actions = ["ec2:DescribeInstances", "iam:ListRoles", "s3:GetObject"]

    cleaned, removed, modified = _clean_policy_doc(doc, set(), set(), used_actions)

    assert removed == 0
    assert modified == 1
    assert cleaned["Statement"][0]["Action"] == used_actions


def test_service_wildcard_narrowed_to_used_actions():
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}],
    }
    used_actions = ["ec2:DescribeInstances", "ec2:RunInstances", "iam:ListRoles"]

    cleaned, removed, modified = _clean_policy_doc(doc, set(), {"ec2"}, used_actions)

    assert removed == 0
    assert modified == 1
    assert cleaned["Statement"][0]["Action"] == ["ec2:DescribeInstances", "ec2:RunInstances"]


def test_unused_service_actions_removed():
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "iam:ListUsers"], "Resource": "*"}],
    }
    unused = {"s3"}
    used = {"iam"}
    used_actions = ["iam:ListUsers"]

    cleaned, removed, modified = _clean_policy_doc(doc, unused, used, used_actions)

    assert removed == 0
    assert modified == 1
    assert cleaned["Statement"][0]["Action"] == "iam:ListUsers"


def test_fully_unused_statement_removed():
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
    }
    unused = {"s3"}
    used = {"iam"}

    cleaned, removed, modified = _clean_policy_doc(doc, unused, used, [])

    assert removed == 1
    assert modified == 0
    assert cleaned["Statement"] == []


def test_wildcard_removed_when_no_used_services():
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }

    cleaned, removed, modified = _clean_policy_doc(doc, {"s3", "ec2"}, set(), [])

    assert removed == 1
    assert modified == 0
    assert cleaned["Statement"] == []
