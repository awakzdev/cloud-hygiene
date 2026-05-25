"""Collector tests using botocore Stubber to avoid real AWS calls."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import boto3
import pytest
from botocore.stub import Stubber

from tests.conftest import make_account


def _make_stubbed_session(stubbers: dict) -> MagicMock:
    """Return a boto3.Session mock where client(service) returns a pre-stubbed client."""
    clients = {}
    for svc, stub in stubbers.items():
        clients[svc] = stub.client
    sess = MagicMock(spec=boto3.Session)
    sess.client.side_effect = lambda svc, **kw: clients[svc]
    return sess


class TestCollectIam:
    def test_collects_users_and_keys(self):
        """collect_iam calls ListUsers, ListMFADevices, GetLoginProfile, ListAccessKeys,
        GetAccessKeyLastUsed, ListRoles for a minimal account."""
        from app.collectors.iam import collect_iam

        iam_client = boto3.client("iam", region_name="us-east-1")
        stub = Stubber(iam_client)

        user_arn = "arn:aws:iam::123456789012:user/alice"
        key_id = "AKIAIOSFODNN7EXAMPLE"

        # list_users (paginator calls the underlying API without PaginationConfig)
        stub.add_response(
            "list_users",
            {
                "Users": [
                    {
                        "UserName": "alice",
                        "Arn": user_arn,
                        "UserId": "AIDIOSFODNN7EXAMPLE",
                        "Path": "/",
                        "CreateDate": datetime(2023, 1, 1, tzinfo=timezone.utc),
                    }
                ],
                "IsTruncated": False,
            },
        )
        # list_mfa_devices
        stub.add_response(
            "list_mfa_devices",
            {"MFADevices": [], "IsTruncated": False},
            {"UserName": "alice"},
        )
        # get_login_profile → NoSuchEntity means no console password
        stub.add_client_error(
            "get_login_profile",
            service_error_code="NoSuchEntity",
            expected_params={"UserName": "alice"},
        )
        # list_access_keys
        stub.add_response(
            "list_access_keys",
            {
                "AccessKeyMetadata": [
                    {
                        "UserName": "alice",
                        "AccessKeyId": key_id,
                        "Status": "Active",
                        "CreateDate": datetime(2023, 1, 1, tzinfo=timezone.utc),
                    }
                ],
                "IsTruncated": False,
            },
            {"UserName": "alice"},
        )
        # get_access_key_last_used
        stub.add_response(
            "get_access_key_last_used",
            {
                "AccessKeyLastUsed": {
                    "LastUsedDate": datetime(2023, 6, 1, tzinfo=timezone.utc),
                    "ServiceName": "s3",
                    "Region": "us-east-1",
                },
                "UserName": "alice",
            },
            {"AccessKeyId": key_id},
        )
        # list_roles (paginator)
        stub.add_response(
            "list_roles",
            {"Roles": [], "IsTruncated": False},
        )
        # get_account_password_policy -> NoSuchEntity means default/no explicit policy
        stub.add_client_error(
            "get_account_password_policy",
            service_error_code="NoSuchEntity",
        )

        stub.activate()

        acc = make_account()
        db = MagicMock()
        db.execute = MagicMock()
        db.commit = MagicMock()

        sess = _make_stubbed_session({"iam": stub})
        with patch("app.collectors.iam.assume_role", return_value=sess):
            result = collect_iam(db, acc)

        stub.assert_no_pending_responses()
        assert result["iam_users"] == 1
        assert result["iam_access_keys"] == 1
        assert result["iam_roles"] == 0

    def test_empty_account(self):
        """Empty account: no users, no roles."""
        from app.collectors.iam import collect_iam

        iam_client = boto3.client("iam", region_name="us-east-1")
        stub = Stubber(iam_client)

        stub.add_response(
            "list_users",
            {"Users": [], "IsTruncated": False},
        )
        stub.add_response(
            "list_roles",
            {"Roles": [], "IsTruncated": False},
        )
        stub.add_client_error(
            "get_account_password_policy",
            service_error_code="NoSuchEntity",
        )
        stub.activate()

        acc = make_account()
        db = MagicMock()
        db.execute = MagicMock()
        db.commit = MagicMock()

        sess = _make_stubbed_session({"iam": stub})
        with patch("app.collectors.iam.assume_role", return_value=sess):
            result = collect_iam(db, acc)

        stub.assert_no_pending_responses()
        assert result == {"iam_users": 0, "iam_access_keys": 0, "iam_roles": 0}


class TestCollectS3:
    def test_collects_bucket_properties(self):
        from app.collectors.account import collect_s3
        from botocore.exceptions import ClientError

        s3_client = boto3.client("s3", region_name="us-east-1")
        stub = Stubber(s3_client)

        stub.add_response(
            "list_buckets",
            {"Buckets": [{"Name": "prod-data", "CreationDate": datetime(2023, 1, 1, tzinfo=timezone.utc)}]},
        )
        stub.add_response(
            "get_bucket_logging",
            {"LoggingEnabled": {"TargetBucket": "log-bucket", "TargetPrefix": "s3/"}},
            {"Bucket": "prod-data"},
        )
        stub.add_response(
            "get_bucket_encryption",
            {
                "ServerSideEncryptionConfiguration": {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "aws:kms",
                                "KMSMasterKeyID": "arn:aws:kms:us-east-1:123:key/abc",
                            }
                        }
                    ]
                }
            },
            {"Bucket": "prod-data"},
        )
        stub.add_response(
            "get_bucket_versioning",
            {"Status": "Enabled"},
            {"Bucket": "prod-data"},
        )
        stub.add_response(
            "get_public_access_block",
            {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            },
            {"Bucket": "prod-data"},
        )
        stub.add_response(
            "get_bucket_policy",
            {"Policy": '{"Statement":[{"Effect":"Deny","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}'},
            {"Bucket": "prod-data"},
        )
        stub.activate()

        acc = make_account()
        db = MagicMock()
        db.execute = MagicMock()
        db.commit = MagicMock()

        sess = _make_stubbed_session({"s3": stub})
        with patch("app.collectors.account.assume_role", return_value=sess):
            count = collect_s3(db, acc)

        stub.assert_no_pending_responses()
        assert count == 1

    def test_empty_account_returns_zero(self):
        from app.collectors.account import collect_s3

        s3_client = boto3.client("s3", region_name="us-east-1")
        stub = Stubber(s3_client)
        stub.add_response("list_buckets", {"Buckets": []})
        stub.activate()

        acc = make_account()
        db = MagicMock()
        db.execute = MagicMock()
        db.commit = MagicMock()

        sess = _make_stubbed_session({"s3": stub})
        with patch("app.collectors.account.assume_role", return_value=sess):
            count = collect_s3(db, acc)

        assert count == 0
