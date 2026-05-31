"""Tests for IAM Access Analyzer generated-policy integration (advanced least-privilege)."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import boto3
from botocore.stub import Stubber

import app.core.aws  # noqa: F401 — side effect: clears empty AWS_* env so boto3 clients build
from app.core.iam_usage import remove_service_wildcards_when_specific_actions_exist
from app.services.access_analyzer_policy import (
    latest_policy_generation_status,
    start_policy_generation,
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    apply_aa_resources_to_policy_doc,
    confidence_for,
    derive_advanced_role_arn,
    derive_cloudtrail_access_role_arn,
    fetch_latest_generated_policy,
    is_placeholder_resource,
    merge_access_analyzer,
    normalize_aa_statements,
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


def test_parse_generated_policy_skips_malformed_actions():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["dynamodb:GetItem", "${account}:${region}", "not-an-action"],
                "Resource": ["arn:aws:dynamodb:us-east-1:123456789012:table/orders"],
            },
        ],
    }
    resp = {"generatedPolicyResult": {"generatedPolicies": [{"policy": json.dumps(policy)}]}}

    statements = parse_generated_policy(resp)

    assert statements[0]["actions"] == ["dynamodb:GetItem"]


def test_merge_never_drops_used_service_and_warns_on_uncovered():
    last_accessed = ["ec2:DescribeInstances"]
    aa_statements = [
        {"actions": ["dynamodb:GetItem"], "resources": ["arn:aws:dynamodb:::table/x"], "placeholder_resources": []},
    ]
    used_services = {"ec2", "dynamodb"}

    actions, warnings = merge_access_analyzer(
        last_accessed, aa_statements, used_services, policy_gen_job_completed=True
    )

    assert "ec2:DescribeInstances" in actions
    assert "dynamodb:GetItem" in actions
    assert warnings == []


def test_merge_then_cleanup_drops_service_wildcard_when_cloudtrail_has_actions():
    last_accessed = ["cloudfront:*", "ec2:DescribeInstances"]
    aa_statements = [
        {
            "actions": ["cloudfront:GetDistribution", "cloudfront:TagResource"],
            "resources": ["arn:aws:cloudfront::123:distribution/E123"],
            "placeholder_resources": [],
        },
    ]
    merged, _ = merge_access_analyzer(
        last_accessed, aa_statements, {"cloudfront", "ec2"}, policy_gen_job_completed=True
    )
    cleaned = remove_service_wildcards_when_specific_actions_exist(merged)
    assert "cloudfront:*" not in cleaned
    assert "cloudfront:GetDistribution" in cleaned
    assert "ec2:DescribeInstances" in cleaned


def test_parse_generated_policy_strips_placeholders():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["cloudfront:CreateInvalidation"],
                "Resource": [
                    "arn:aws:cloudfront::123:distribution/E123",
                    "arn:aws:cloudfront::${Account}:distribution/${DistributionId}",
                ],
            }
        ]
    }
    resp = {"generatedPolicyResult": {"generatedPolicies": [{"policy": json.dumps(policy)}]}}
    statements = parse_generated_policy(resp)
    assert statements[0]["resources"] == ["arn:aws:cloudfront::123:distribution/E123"]
    assert len(statements[0]["placeholder_resources"]) == 1
    assert is_placeholder_resource(statements[0]["placeholder_resources"][0])


def test_confidence_tiers():
    assert confidence_for(aa_resource_data=True, has_action_data=True) == CONFIDENCE_HIGH
    assert confidence_for(aa_resource_data=False, has_action_data=True) == CONFIDENCE_MEDIUM
    assert confidence_for(aa_resource_data=False, has_action_data=False) == CONFIDENCE_LOW


def test_apply_aa_resources_replaces_wildcard_resource():
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": "*"}],
    }
    aa_statements = normalize_aa_statements(
        [{"actions": ["dynamodb:GetItem"], "resources": ["arn:aws:dynamodb:us-east-1:123:table/orders"]}]
    )

    cleaned = apply_aa_resources_to_policy_doc(doc, aa_statements)

    assert cleaned["Statement"][0]["Resource"] == "arn:aws:dynamodb:us-east-1:123:table/orders"


def test_apply_aa_resources_maps_by_service_only():
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": "*"},
            {"Effect": "Allow", "Action": "cloudfront:CreateInvalidation", "Resource": "*"},
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::already-scoped/*",
            },
        ],
    }
    aa_statements = normalize_aa_statements(
        [
            {"actions": ["dynamodb:GetItem"], "resources": ["arn:aws:dynamodb:us-east-1:123:table/a"]},
            {
                "actions": ["cloudfront:CreateInvalidation"],
                "resources": ["arn:aws:cloudfront::123:distribution/E123"],
            },
            {"actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::bucket/key"]},
        ]
    )

    cleaned = apply_aa_resources_to_policy_doc(doc, aa_statements)

    assert cleaned["Statement"][0]["Resource"] == "arn:aws:dynamodb:us-east-1:123:table/a"
    assert cleaned["Statement"][1]["Resource"] == "arn:aws:cloudfront::123:distribution/E123"
    assert cleaned["Statement"][2]["Resource"] == "arn:aws:s3:::already-scoped/*"


def test_apply_aa_resources_handles_list_wildcard_resource():
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "cloudfront:*", "Resource": ["*"]}],
    }
    aa_statements = normalize_aa_statements(
        [
            {
                "actions": ["cloudfront:CreateInvalidation"],
                "resources": ["arn:aws:cloudfront::123:distribution/E123"],
            }
        ]
    )

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
        {"jobId": "new", "includeResourcePlaceholders": False},
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


def test_derive_cloudtrail_access_role_arn_from_scanner():
    base = "arn:aws:iam::946796614687:role/VigilScannerRole"
    assert (
        derive_cloudtrail_access_role_arn(base)
        == "arn:aws:iam::946796614687:role/VigilScannerRoleAccessAnalyzerMonitor"
    )


def test_start_policy_generation_calls_api():
    principal = "arn:aws:iam::123456789012:role/app"
    access_role = "arn:aws:iam::123456789012:role/VigilPolicyGenerationRole"
    trail = "arn:aws:cloudtrail:us-east-1:123:trail/t1"
    start = datetime(2026, 3, 1, tzinfo=timezone.utc)
    client = boto3.client("accessanalyzer", region_name="us-east-1")
    stub = Stubber(client)
    stub.add_response(
        "start_policy_generation",
        {"jobId": "job-1"},
        {
            "policyGenerationDetails": {"principalArn": principal},
            "cloudTrailDetails": {
                "trails": [{"cloudTrailArn": trail}],
                "accessRole": access_role,
                "startTime": start,
            },
        },
    )
    with stub:
        out = start_policy_generation(
            client,
            principal_arn=principal,
            trail_arns=[trail],
            access_role_arn=access_role,
            start_time=start,
        )
    assert out["job_id"] == "job-1"
    assert out["status"] == "IN_PROGRESS"


def test_latest_policy_generation_status_returns_newest():
    principal = "arn:aws:iam::123456789012:role/app"
    client = boto3.client("accessanalyzer", region_name="us-east-1")
    stub = Stubber(client)
    stub.add_response(
        "list_policy_generations",
        {
            "policyGenerations": [
                {"jobId": "old", "principalArn": principal, "status": "SUCCEEDED", "startedOn": "2026-01-01T00:00:00Z"},
                {"jobId": "new", "principalArn": principal, "status": "IN_PROGRESS", "startedOn": "2026-03-02T00:00:00Z"},
            ]
        },
        {"principalArn": principal},
    )
    with stub:
        row = latest_policy_generation_status(client, principal)
    assert row["job_id"] == "new"
    assert row["status"] == "IN_PROGRESS"
