"""Session 21: stale CFN detection + identity blast-radius helpers."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

from app.services.blast_radius_identity import _parse_identity_arn, blast_radius_identity
from app.worker.tasks import _cfn_permissions_likely_stale


def test_cfn_permissions_likely_stale_when_gap_collectors_empty():
    stats = {
        "s3_buckets": 3,
        "ec2_instances": 1,
        "acm_certificates": 0,
        "lambda_functions": 0,
        "secrets_manager_secrets": 0,
        "ssm_parameters": 0,
        "elb_load_balancers": 0,
        "dynamodb_tables": 0,
        "sns_topics": 0,
        "sqs_queues": 0,
        "ebs_snapshots": 0,
        "ec2_amis": 0,
    }
    assert _cfn_permissions_likely_stale(stats) is True


def test_cfn_permissions_not_stale_when_gap_collectors_have_data():
    stats = {
        "s3_buckets": 2,
        "lambda_functions": 5,
        "acm_certificates": 0,
        "secrets_manager_secrets": 0,
        "ssm_parameters": 0,
        "elb_load_balancers": 0,
        "dynamodb_tables": 0,
        "sns_topics": 0,
        "sqs_queues": 0,
        "ebs_snapshots": 0,
        "ec2_amis": 0,
    }
    assert _cfn_permissions_likely_stale(stats) is False


def test_cfn_permissions_not_stale_without_baseline():
    stats = {k: 0 for k in (
        "s3_buckets", "ec2_instances", "acm_certificates", "lambda_functions",
        "secrets_manager_secrets", "ssm_parameters", "elb_load_balancers",
        "dynamodb_tables", "sns_topics", "sqs_queues", "ebs_snapshots", "ec2_amis",
    )}
    assert _cfn_permissions_likely_stale(stats) is False


def test_parse_identity_arn_github_user():
    ptype, first, second = _parse_identity_arn("github://acme-corp/alice")
    assert ptype == "github"
    assert first == "acme-corp"
    assert second == "alice"


def test_parse_identity_arn_github_org():
    ptype, first, second = _parse_identity_arn("github://org/acme-corp")
    assert ptype == "github"
    assert first == "org"
    assert second == "acme-corp"


def test_blast_radius_identity_no_provider():
    acc = MagicMock()
    acc.org_id = uuid.uuid4()
    db = MagicMock()
    db.scalars.return_value.all.return_value = []

    out = blast_radius_identity(
        db,
        acc,
        "github.org.mfa_not_enforced",
        "github://org/acme",
        now=datetime.now(timezone.utc),
    )
    assert out["resource_type"] == "identity_provider"
    assert "No identity provider" in out["warnings"][0]
