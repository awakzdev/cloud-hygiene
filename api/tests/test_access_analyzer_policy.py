"""Tests for IAM Access Analyzer generated-policy integration (advanced least-privilege)."""
from __future__ import annotations

import json

import boto3
from botocore.stub import Stubber

import app.core.aws  # noqa: F401 — side effect: clears empty AWS_* env so boto3 clients build
from app.services.access_analyzer_policy import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    apply_aa_resources_to_policy_doc,
    confidence_for,
    derive_advanced_role_arn,
    fetch_latest_generated_policy,
    merge_access_analyzer,
    parse_generated_policy,
    security_findings_only,
    validate_policy,
)


def test_derive_advanced_role_arn_unified_connector_uses_same_role():
    arn = "arn:aws:iam::123456789012:role/VigilScannerRole"
    assert derive_advanced_role_arn(arn) == arn


def test_derive_advanced_role_arn_maps_legacy_split_stack_scanner():
    assert (
        derive_advanced_role_arn("arn:aws:iam::123456789012:role/VigilReadOnlyScannerRole")
        == "arn:aws:iam::123456789012:role/VigilPolicyGenerationRole"
    )


def test_derive_advanced_role_arn_idempotent_and_guards_bad_input():
    legacy = "arn:aws:iam::123456789012:role/VigilReadonlyAdvancedPolicyGen"
    assert derive_advanced_role_arn(legacy) == legacy
    current = "arn:aws:iam::123456789012:role/VigilPolicyGenerationRole"
    assert derive_advanced_role_arn(current) == current
    assert derive_advanced_role_arn(None) is None
    assert derive_advanced_role_arn("not-an-arn") is None
    assert derive_advanced_role_arn("arn:aws:iam::123456789012:user/bob") is None


def test_parse_generated_policy_extracts_actions_and_resources():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["dynamodb:GetItem", "dynamodb:PutItem"],
                "Resource": ["arn:aws:dynamodb:us-east-1:123456789012:table/orders"],
            },
            {"Effect": "Deny", "Action": "s3:*", "Resource": "*"},  # skipped
        ],
    }
    resp = {"generatedPolicyResult": {"generatedPolicies": [{"policy": json.dumps(policy)}]}}

    statements = parse_generated_policy(resp)

    assert len(statements) == 1
    assert statements[0]["actions"] == ["dynamodb:GetItem", "dynamodb:PutItem"]
    assert statements[0]["resources"] == ["arn:aws:dynamodb:us-east-1:123456789012:table/orders"]


def test_parse_generated_policy_tolerates_garbage():
    assert parse_generated_policy({}) == []
    assert parse_generated_policy({"generatedPolicyResult": {"generatedPolicies": [{"policy": "{bad"}]}}) == []


def test_merge_never_drops_used_service_and_warns_on_uncovered():
    # last-accessed says ec2 + dynamodb used; AA only has CloudTrail history for dynamodb.
    last_accessed = ["ec2:DescribeInstances"]
    aa_statements = [
        {"actions": ["dynamodb:GetItem"], "resources": ["arn:aws:dynamodb:::table/x"]},
    ]
    used_services = {"ec2", "dynamodb"}

    actions, warnings = merge_access_analyzer(last_accessed, aa_statements, used_services)

    # union: ec2 (last-accessed) preserved, dynamodb (AA) added — nothing dropped
    assert "ec2:DescribeInstances" in actions
    assert "dynamodb:GetItem" in actions
    # ec2 had no AA coverage -> warned it stays action-level; dynamodb covered -> no warning
    assert any(w.startswith("ec2:") for w in warnings)
    assert not any(w.startswith("dynamodb:") for w in warnings)


def test_confidence_tiers():
    assert confidence_for(aa_resource_data=True, has_action_data=True) == CONFIDENCE_HIGH
    assert confidence_for(aa_resource_data=False, has_action_data=True) == CONFIDENCE_MEDIUM
    assert confidence_for(aa_resource_data=False, has_action_data=False) == CONFIDENCE_LOW


def test_apply_aa_resources_replaces_wildcard_resource():
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": "*"}],
    }
    aa_statements = [
        {"actions": ["dynamodb:GetItem"], "resources": ["arn:aws:dynamodb:us-east-1:123:table/orders"]},
    ]

    cleaned = apply_aa_resources_to_policy_doc(doc, aa_statements)

    assert cleaned["Statement"][0]["Resource"] == "arn:aws:dynamodb:us-east-1:123:table/orders"


def test_apply_aa_resources_dedupes_and_preserves_specific_resources():
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::already-scoped/*",
            },
        ],
    }
    aa_statements = [
        {"actions": ["dynamodb:GetItem"], "resources": ["arn:aws:dynamodb:us-east-1:123:table/a"]},
        {"actions": ["dynamodb:PutItem"], "resources": ["arn:aws:dynamodb:us-east-1:123:table/a", "*"]},
        {"actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::bucket/key"]},
    ]

    cleaned = apply_aa_resources_to_policy_doc(doc, aa_statements)

    assert cleaned["Statement"][0]["Resource"] == [
        "arn:aws:dynamodb:us-east-1:123:table/a",
        "arn:aws:s3:::bucket/key",
    ]
    assert cleaned["Statement"][1]["Resource"] == "arn:aws:s3:::already-scoped/*"


def test_apply_aa_resources_handles_list_wildcard_resource():
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "cloudfront:*", "Resource": ["*"]}],
    }
    aa_statements = [
        {"actions": ["cloudfront:CreateInvalidation"], "resources": ["arn:aws:cloudfront::123:distribution/E123"]},
    ]

    cleaned = apply_aa_resources_to_policy_doc(doc, aa_statements)

    assert cleaned["Statement"][0]["Resource"] == "arn:aws:cloudfront::123:distribution/E123"


def test_fetch_latest_generated_policy_picks_newest_succeeded():
    principal = "arn:aws:iam::123456789012:role/app"
    client = boto3.client("accessanalyzer", region_name="us-east-1")
    stub = Stubber(client)

    stub.add_response(
        "list_policy_generations",
        {
            "policyGenerations": [
                {"jobId": "old", "principalArn": principal, "status": "SUCCEEDED", "startedOn": "2026-01-01T00:00:00Z", "completedOn": "2026-01-01T00:05:00Z"},
                {"jobId": "new", "principalArn": principal, "status": "SUCCEEDED", "startedOn": "2026-03-01T00:00:00Z", "completedOn": "2026-03-01T00:05:00Z"},
                {"jobId": "wip", "principalArn": principal, "status": "IN_PROGRESS", "startedOn": "2026-03-02T00:00:00Z"},
            ]
        },
        {"principalArn": principal},
    )
    policy = {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::b/*"]}]}
    stub.add_response(
        "get_generated_policy",
        {
            "jobDetails": {"jobId": "new", "status": "SUCCEEDED", "startedOn": "2026-03-01T00:00:00Z"},
            "generatedPolicyResult": {
                "properties": {"principalArn": principal},
                "generatedPolicies": [{"policy": json.dumps(policy)}],
            },
        },
        {"jobId": "new", "includeResourcePlaceholders": True},
    )

    with stub:
        result = fetch_latest_generated_policy(client, principal)

    assert result is not None
    assert result["job_id"] == "new"
    assert result["statements"][0]["actions"] == ["s3:GetObject"]


def test_fetch_latest_generated_policy_returns_none_without_success():
    principal = "arn:aws:iam::123456789012:role/app"
    client = boto3.client("accessanalyzer", region_name="us-east-1")
    stub = Stubber(client)
    stub.add_response(
        "list_policy_generations",
        {"policyGenerations": [{"jobId": "wip", "principalArn": principal, "status": "IN_PROGRESS", "startedOn": "2026-03-02T00:00:00Z"}]},
        {"principalArn": principal},
    )
    with stub:
        assert fetch_latest_generated_policy(client, principal) is None


def test_validate_policy_normalizes_and_security_filter():
    policy_doc = json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    )
    client = boto3.client("accessanalyzer", region_name="us-east-1")
    stub = Stubber(client)
    stub.add_response(
        "validate_policy",
        {
            "findings": [
                {
                    "findingType": "SECURITY_WARNING",
                    "issueCode": "PASS_ROLE_WITH_STAR_IN_RESOURCE",
                    "findingDetails": "Using a wildcard in the resource is overly permissive.",
                    "learnMoreLink": "https://docs.aws.amazon.com/x",
                    "locations": [],
                },
                {
                    "findingType": "SUGGESTION",
                    "issueCode": "EMPTY_ARRAY_ACTION",
                    "findingDetails": "Consider tightening.",
                    "learnMoreLink": "https://docs.aws.amazon.com/y",
                    "locations": [],
                },
            ]
        },
        {"policyDocument": policy_doc, "policyType": "IDENTITY_POLICY"},
    )

    with stub:
        findings = validate_policy(client, policy_doc)

    assert len(findings) == 2
    assert findings[0]["finding_type"] == "SECURITY_WARNING"
    assert findings[0]["issue_code"] == "PASS_ROLE_WITH_STAR_IN_RESOURCE"

    security = security_findings_only(findings)
    assert len(security) == 1
    assert security[0]["finding_type"] == "SECURITY_WARNING"
