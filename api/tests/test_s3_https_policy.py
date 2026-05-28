from app.services.s3_https_policy import (
    deny_insecure_transport_statement,
    merge_deny_insecure_transport,
    policy_has_https_deny,
)


def test_deny_statement_shape():
    stmt = deny_insecure_transport_statement("my-bucket")
    assert stmt["Sid"] == "DenyInsecureTransport"
    assert stmt["Condition"]["Bool"]["aws:SecureTransport"] == "false"
    assert "arn:aws:s3:::my-bucket" in stmt["Resource"]


def test_merge_empty_policy():
    merged, added = merge_deny_insecure_transport(None, "b")
    assert added is True
    assert len(merged["Statement"]) == 1
    assert merged["Statement"][0]["Sid"] == "DenyInsecureTransport"


def test_merge_appends_to_existing():
    original = {
        "Version": "2012-10-17",
        "Statement": [{"Sid": "AllowRead", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }
    merged, added = merge_deny_insecure_transport(original, "b")
    assert added is True
    assert len(merged["Statement"]) == 2
    assert merged["Statement"][1]["Sid"] == "DenyInsecureTransport"


def test_merge_skips_when_https_deny_present():
    original = {
        "Version": "2012-10-17",
        "Statement": [deny_insecure_transport_statement("b")],
    }
    merged, added = merge_deny_insecure_transport(original, "b")
    assert added is False
    assert policy_has_https_deny(merged)
    assert len(merged["Statement"]) == 1


def test_merge_skips_equivalent_condition_without_sid():
    original = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": "*",
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            }
        ],
    }
    _, added = merge_deny_insecure_transport(original, "b")
    assert added is False
