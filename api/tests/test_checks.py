"""Unit tests for check modules. DB is mocked — checks are pure logic."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from tests.conftest import make_account, now


def _user(*, arn=None, name="alice", has_console_password=True, mfa_enabled=False, account_id=None):
    u = MagicMock()
    u.account_id = account_id or uuid.uuid4()
    u.arn = arn or f"arn:aws:iam::123456789012:user/{name}"
    u.name = name
    u.has_console_password = has_console_password
    u.mfa_enabled = mfa_enabled
    u.last_used_at = None
    u.created_at = datetime.now(timezone.utc) - timedelta(days=200)
    return u


def _key(*, key_id="AKIAIOSFODNN7EXAMPLE", user_arn="arn:aws:iam::123456789012:user/alice",
         status="Active", created=None, last_used=None, account_id=None):
    k = MagicMock()
    k.account_id = account_id or uuid.uuid4()
    k.key_id = key_id
    k.user_arn = user_arn
    k.status = status
    k.created = created or (datetime.now(timezone.utc) - timedelta(days=120))
    k.last_used = last_used
    return k


def _role(*, arn=None, name="DeployRole", inline_policies=None, account_id=None):
    r = MagicMock()
    r.account_id = account_id or uuid.uuid4()
    r.arn = arn or f"arn:aws:iam::123456789012:role/{name}"
    r.name = name
    r.inline_policies = inline_policies or {}
    r.last_used_at = None
    r.created_at = datetime.now(timezone.utc) - timedelta(days=100)
    return r


# --- iam.user.no_mfa ---

class TestNoMfa:
    def test_flags_console_user_without_mfa(self, mock_db):
        from app.checks import iam_user_no_mfa
        acc_id = uuid.uuid4()
        mock_db.scalars.return_value.all.return_value = [_user(account_id=acc_id)]
        drafts = iam_user_no_mfa.run(mock_db, acc_id)
        assert len(drafts) == 1
        assert drafts[0].check_id == "iam.user.no_mfa"
        assert drafts[0].severity == "high"

    def test_skips_user_with_mfa(self, mock_db):
        from app.checks import iam_user_no_mfa
        acc_id = uuid.uuid4()
        mock_db.scalars.return_value.all.return_value = [_user(mfa_enabled=True)]
        # check filters in SQL — mock returns empty (as if WHERE filtered it out)
        mock_db.scalars.return_value.all.return_value = []
        drafts = iam_user_no_mfa.run(mock_db, acc_id)
        assert drafts == []

    def test_skips_user_without_console_access(self, mock_db):
        from app.checks import iam_user_no_mfa
        mock_db.scalars.return_value.all.return_value = []
        drafts = iam_user_no_mfa.run(mock_db, uuid.uuid4())
        assert drafts == []


# --- iam.access_key.unused_90d ---

class TestAccessKeyUnused:
    def test_flags_key_never_used(self, mock_db):
        from app.checks import iam_access_key_unused
        acc_id = uuid.uuid4()
        old_key = _key(account_id=acc_id, last_used=None,
                       created=datetime.now(timezone.utc) - timedelta(days=120))
        mock_db.scalars.return_value.all.return_value = [old_key]
        drafts = iam_access_key_unused.run(mock_db, acc_id)
        assert len(drafts) == 1
        assert "unused" in drafts[0].title.lower()

    def test_flags_key_last_used_over_90d(self, mock_db):
        from app.checks import iam_access_key_unused
        acc_id = uuid.uuid4()
        stale_key = _key(
            account_id=acc_id,
            last_used=datetime.now(timezone.utc) - timedelta(days=95),
        )
        mock_db.scalars.return_value.all.return_value = [stale_key]
        drafts = iam_access_key_unused.run(mock_db, acc_id)
        assert len(drafts) == 1

    def test_skips_recently_used_key(self, mock_db):
        from app.checks import iam_access_key_unused
        acc_id = uuid.uuid4()
        fresh_key = _key(
            account_id=acc_id,
            last_used=datetime.now(timezone.utc) - timedelta(days=10),
        )
        mock_db.scalars.return_value.all.return_value = [fresh_key]
        drafts = iam_access_key_unused.run(mock_db, acc_id)
        assert drafts == []

    def test_skips_inactive_key(self, mock_db):
        from app.checks import iam_access_key_unused
        # inactive keys filtered by SQL WHERE status='Active', so mock returns []
        mock_db.scalars.return_value.all.return_value = []
        drafts = iam_access_key_unused.run(mock_db, uuid.uuid4())
        assert drafts == []


# --- iam.user.credentials_unused_45d ---


class TestCredentialsUnused45d:
    def test_flags_console_user_inactive_50d(self, mock_db):
        from app.checks import iam_user_credentials_unused_45d

        acc_id = uuid.uuid4()
        u = _user(account_id=acc_id)
        u.password_last_used = datetime.now(timezone.utc) - timedelta(days=50)
        mock_db.scalars.return_value.all.return_value = [u]
        drafts = iam_user_credentials_unused_45d.run(mock_db, acc_id)
        assert len(drafts) == 1
        assert drafts[0].check_id == "iam.user.credentials_unused_45d"

    def test_skips_recent_sign_in(self, mock_db):
        from app.checks import iam_user_credentials_unused_45d

        acc_id = uuid.uuid4()
        u = _user(account_id=acc_id)
        u.password_last_used = datetime.now(timezone.utc) - timedelta(days=30)
        mock_db.scalars.return_value.all.return_value = [u]
        drafts = iam_user_credentials_unused_45d.run(mock_db, acc_id)
        assert drafts == []


# --- iam.access_key.unused_45d ---


class TestAccessKeyUnused45d:
    def test_flags_key_last_used_over_45d(self, mock_db):
        from app.checks import iam_access_key_unused_45d

        acc_id = uuid.uuid4()
        stale_key = _key(
            account_id=acc_id,
            last_used=datetime.now(timezone.utc) - timedelta(days=50),
        )
        mock_db.scalars.return_value.all.return_value = [stale_key]
        drafts = iam_access_key_unused_45d.run(mock_db, acc_id)
        assert len(drafts) == 1
        assert drafts[0].check_id == "iam.access_key.unused_45d"

    def test_skips_key_last_used_within_45d(self, mock_db):
        from app.checks import iam_access_key_unused_45d

        acc_id = uuid.uuid4()
        fresh_key = _key(
            account_id=acc_id,
            last_used=datetime.now(timezone.utc) - timedelta(days=30),
        )
        mock_db.scalars.return_value.all.return_value = [fresh_key]
        drafts = iam_access_key_unused_45d.run(mock_db, acc_id)
        assert drafts == []


# --- iam.role.unassumed_90d ---

class TestRoleUnassumed:
    def test_flags_stale_custom_role(self, mock_db):
        from app.checks import role_unassumed_90d
        acc_id = uuid.uuid4()
        r = MagicMock()
        r.account_id = acc_id
        r.arn = "arn:aws:iam::123456789012:role/DeployRole"
        r.name = "DeployRole"
        r.last_assumed = None
        r.created = datetime.now(timezone.utc) - timedelta(days=200)
        mock_db.scalars.return_value.all.return_value = [r]
        drafts = role_unassumed_90d.run(mock_db, acc_id)
        assert len(drafts) == 1
        assert drafts[0].check_id == "iam.role.unassumed_90d"

    def test_skips_sso_reserved_role_by_name(self, mock_db):
        from app.checks import role_unassumed_90d
        acc_id = uuid.uuid4()
        r = MagicMock()
        r.account_id = acc_id
        r.name = "AWSReservedSSO_AdministratorAccess_33bebb4004caf898"
        r.arn = (
            "arn:aws:iam::946796614687:role/aws-reserved/sso.amazonaws.com/"
            "AWSReservedSSO_AdministratorAccess_33bebb4004caf898"
        )
        r.last_assumed = None
        r.created = datetime.now(timezone.utc) - timedelta(days=1314)
        mock_db.scalars.return_value.all.return_value = [r]
        drafts = role_unassumed_90d.run(mock_db, acc_id)
        assert drafts == []

    def test_skips_service_linked_role(self, mock_db):
        from app.checks import role_unassumed_90d
        acc_id = uuid.uuid4()
        r = MagicMock()
        r.account_id = acc_id
        r.name = "AWSServiceRoleForEC2"
        r.arn = "arn:aws:iam::123456789012:role/aws-service-role/ec2.amazonaws.com/AWSServiceRoleForEC2"
        r.last_assumed = None
        r.created = datetime.now(timezone.utc) - timedelta(days=400)
        mock_db.scalars.return_value.all.return_value = [r]
        drafts = role_unassumed_90d.run(mock_db, acc_id)
        assert drafts == []


# --- iam.role.wildcard_action ---

class TestWildcardAction:
    def test_flags_role_with_star_action(self, mock_db):
        from app.checks import role_wildcard_action
        acc_id = uuid.uuid4()
        policy = {
            "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"}
            ]
        }
        r = _role(account_id=acc_id, inline_policies={"AdminPolicy": policy})
        mock_db.scalars.return_value.all.return_value = [r]
        drafts = role_wildcard_action.run(mock_db, acc_id)
        assert len(drafts) == 1
        assert drafts[0].check_id == "iam.role.wildcard_action"
        assert drafts[0].severity == "high"

    def test_skips_role_without_wildcard(self, mock_db):
        from app.checks import role_wildcard_action
        acc_id = uuid.uuid4()
        policy = {
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "*"}
            ]
        }
        r = _role(account_id=acc_id, inline_policies={"S3Policy": policy})
        mock_db.scalars.return_value.all.return_value = [r]
        drafts = role_wildcard_action.run(mock_db, acc_id)
        assert drafts == []

    def test_skips_deny_statement_with_star(self, mock_db):
        from app.checks import role_wildcard_action
        acc_id = uuid.uuid4()
        policy = {
            "Statement": [
                {"Effect": "Deny", "Action": "*", "Resource": "*"}
            ]
        }
        r = _role(account_id=acc_id, inline_policies={"DenyAll": policy})
        mock_db.scalars.return_value.all.return_value = [r]
        drafts = role_wildcard_action.run(mock_db, acc_id)
        assert drafts == []

    def test_skips_service_linked_role(self, mock_db):
        from app.checks import role_wildcard_action
        acc_id = uuid.uuid4()
        policy = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        r = _role(
            account_id=acc_id,
            arn="arn:aws:iam::123:role/aws-service-role/ec2.amazonaws.com/AWSServiceRoleForEC2",
            inline_policies={"AdminPolicy": policy},
        )
        mock_db.scalars.return_value.all.return_value = [r]
        drafts = role_wildcard_action.run(mock_db, acc_id)
        assert drafts == []

    def test_no_roles_returns_empty(self, mock_db):
        from app.checks import role_wildcard_action
        mock_db.scalars.return_value.all.return_value = []
        drafts = role_wildcard_action.run(mock_db, uuid.uuid4())
        assert drafts == []

    def test_flags_action_star_without_resource_star(self, mock_db):
        from app.checks import role_wildcard_action
        acc_id = uuid.uuid4()
        policy = {
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::bucket/*"}]
        }
        r = _role(account_id=acc_id, inline_policies={"Broad": policy})
        mock_db.scalars.return_value.all.return_value = [r]
        drafts = role_wildcard_action.run(mock_db, acc_id)
        assert len(drafts) == 1


# --- iam.role.full_admin_policy ---


class TestFullAdminPolicy:
    def test_flags_action_and_resource_star(self, mock_db):
        from app.checks import iam_role_full_admin
        acc_id = uuid.uuid4()
        policy = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        r = _role(account_id=acc_id, inline_policies={"Admin": policy})
        mock_db.scalars.return_value.all.return_value = [r]
        drafts = iam_role_full_admin.run(mock_db, acc_id)
        assert len(drafts) == 1
        assert drafts[0].check_id == "iam.role.full_admin_policy"

    def test_skips_action_star_scoped_resource(self, mock_db):
        from app.checks import iam_role_full_admin
        acc_id = uuid.uuid4()
        policy = {
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::bucket/*"}]
        }
        r = _role(account_id=acc_id, inline_policies={"S3Admin": policy})
        mock_db.scalars.return_value.all.return_value = [r]
        drafts = iam_role_full_admin.run(mock_db, acc_id)
        assert drafts == []


# helpers for new checks

def _rds(*, db_instance_id="db-1", arn="arn:aws:rds:us-east-1:123:db:db-1",
         region="us-east-1", engine="mysql", backup_retention_period=0, account_id=None):
    r = MagicMock()
    r.account_id = account_id or uuid.uuid4()
    r.db_instance_id = db_instance_id
    r.arn = arn
    r.region = region
    r.engine = engine
    r.backup_retention_period = backup_retention_period
    return r


def _trail(*, name="mgmt-trail", arn="arn:aws:cloudtrail:us-east-1:123:trail/mgmt-trail",
           home_region="us-east-1", is_logging=True, kms_key_id=None, account_id=None):
    t = MagicMock()
    t.account_id = account_id or uuid.uuid4()
    t.name = name
    t.arn = arn
    t.home_region = home_region
    t.is_logging = is_logging
    t.kms_key_id = kms_key_id
    return t


def _ebs_volume(*, volume_id="vol-0abc", arn="arn:aws:ec2:us-east-1:123:volume/vol-0abc",
                region="us-east-1", encrypted=False, state="in-use", account_id=None):
    v = MagicMock()
    v.account_id = account_id or uuid.uuid4()
    v.volume_id = volume_id
    v.arn = arn
    v.region = region
    v.encrypted = encrypted
    v.state = state
    v.size_gib = 20
    v.volume_type = "gp3"
    v.attached_instance_ids = []
    return v


def _ebs_default(*, region="us-east-1", enabled=False, account_id=None):
    d = MagicMock()
    d.account_id = account_id or uuid.uuid4()
    d.region = region
    d.enabled = enabled
    return d


def _instance(*, instance_id="i-0abc", region="us-east-1", imdsv2_required=False,
              state="running", instance_type="t3.micro", account_id=None):
    i = MagicMock()
    i.account_id = account_id or uuid.uuid4()
    i.instance_id = instance_id
    i.region = region
    i.imdsv2_required = imdsv2_required
    i.state = state
    i.instance_type = instance_type
    return i


def _hub_status(*, region="us-east-1", enabled=False, account_id=None):
    s = MagicMock()
    s.account_id = account_id or uuid.uuid4()
    s.region = region
    s.enabled = enabled
    return s


# --- rds.instance.no_automated_backup ---

class TestRdsNoAutomatedBackup:
    def test_flags_instance_with_no_backup(self, mock_db):
        from app.checks import rds_no_automated_backup
        acc_id = uuid.uuid4()
        mock_db.scalars.return_value.all.return_value = [_rds(account_id=acc_id, backup_retention_period=0)]
        drafts = rds_no_automated_backup.run(mock_db, acc_id)
        assert len(drafts) == 1
        assert drafts[0].check_id == "rds.instance.no_automated_backup"
        assert drafts[0].severity == "medium"

    def test_skips_instance_with_backup(self, mock_db):
        from app.checks import rds_no_automated_backup
        mock_db.scalars.return_value.all.return_value = []
        drafts = rds_no_automated_backup.run(mock_db, uuid.uuid4())
        assert drafts == []


# --- cloudtrail.trail.no_kms ---

class TestCloudtrailNoKms:
    def test_flags_logging_trail_without_kms(self, mock_db):
        from app.checks import cloudtrail_no_kms
        acc_id = uuid.uuid4()
        mock_db.scalars.return_value.all.return_value = [_trail(account_id=acc_id, is_logging=True, kms_key_id=None)]
        drafts = cloudtrail_no_kms.run(mock_db, acc_id)
        assert len(drafts) == 1
        assert drafts[0].check_id == "cloudtrail.trail.no_kms"

    def test_skips_trail_with_kms(self, mock_db):
        from app.checks import cloudtrail_no_kms
        mock_db.scalars.return_value.all.return_value = []
        drafts = cloudtrail_no_kms.run(mock_db, uuid.uuid4())
        assert drafts == []


# --- ec2.ebs.volume_unencrypted ---

class TestEbsVolumeUnencrypted:
    def test_flags_unencrypted_volume(self, mock_db):
        from app.checks import ec2_ebs_volume_unencrypted
        acc_id = uuid.uuid4()
        mock_db.scalars.return_value.all.return_value = [_ebs_volume(account_id=acc_id, encrypted=False)]
        drafts = ec2_ebs_volume_unencrypted.run(mock_db, acc_id)
        assert len(drafts) == 1
        assert drafts[0].check_id == "ec2.ebs.volume_unencrypted"
        assert drafts[0].severity == "high"

    def test_skips_encrypted_volume(self, mock_db):
        from app.checks import ec2_ebs_volume_unencrypted
        mock_db.scalars.return_value.all.return_value = []
        drafts = ec2_ebs_volume_unencrypted.run(mock_db, uuid.uuid4())
        assert drafts == []


# --- ec2.ebs.encryption_not_default ---

class TestEbsEncryptionNotDefault:
    def test_flags_regions_without_default_encryption(self, mock_db):
        from app.checks import ec2_ebs_encryption_default
        from tests.conftest import make_account
        acc = make_account()
        acc_id = acc.id
        mock_db.get.return_value = acc
        mock_db.scalars.return_value.all.return_value = [
            _ebs_default(region="us-east-1", enabled=False, account_id=acc_id),
            _ebs_default(region="eu-west-1", enabled=False, account_id=acc_id),
        ]
        drafts = ec2_ebs_encryption_default.run(mock_db, acc_id)
        assert len(drafts) == 1
        assert drafts[0].check_id == "ec2.ebs.encryption_not_default"
        assert "us-east-1" in drafts[0].evidence["disabled_regions"]

    def test_skips_when_all_regions_enabled(self, mock_db):
        from app.checks import ec2_ebs_encryption_default
        from tests.conftest import make_account
        acc = make_account()
        mock_db.get.return_value = acc
        mock_db.scalars.return_value.all.return_value = []
        drafts = ec2_ebs_encryption_default.run(mock_db, acc.id)
        assert drafts == []

    def test_skips_when_no_account(self, mock_db):
        from app.checks import ec2_ebs_encryption_default
        mock_db.get.return_value = None
        drafts = ec2_ebs_encryption_default.run(mock_db, uuid.uuid4())
        assert drafts == []


# --- ec2.instance.imdsv2_not_required ---

class TestImdsv2NotRequired:
    def test_flags_running_instance_without_imdsv2(self, mock_db):
        from app.checks import ec2_imdsv2_not_required
        from tests.conftest import make_account
        acc = make_account()
        mock_db.get.return_value = acc
        mock_db.scalars.return_value.all.return_value = [
            _instance(account_id=acc.id, imdsv2_required=False, state="running")
        ]
        drafts = ec2_imdsv2_not_required.run(mock_db, acc.id)
        assert len(drafts) == 1
        assert drafts[0].check_id == "ec2.instance.imdsv2_not_required"

    def test_skips_instance_with_imdsv2(self, mock_db):
        from app.checks import ec2_imdsv2_not_required
        from tests.conftest import make_account
        acc = make_account()
        mock_db.get.return_value = acc
        mock_db.scalars.return_value.all.return_value = []
        drafts = ec2_imdsv2_not_required.run(mock_db, acc.id)
        assert drafts == []


# --- aws.securityhub.not_enabled ---

class TestSecurityHubNotEnabled:
    def test_flags_disabled_regions(self, mock_db):
        from app.checks import securityhub_not_enabled
        from tests.conftest import make_account
        acc = make_account()
        mock_db.get.return_value = acc
        mock_db.scalars.return_value.all.return_value = [
            _hub_status(region="us-east-1", enabled=False),
            _hub_status(region="eu-west-1", enabled=False),
        ]
        drafts = securityhub_not_enabled.run(mock_db, acc.id)
        assert len(drafts) == 1
        assert drafts[0].check_id == "aws.securityhub.not_enabled"
        assert drafts[0].evidence["region_count"] == 2

    def test_skips_when_all_regions_enabled(self, mock_db):
        from app.checks import securityhub_not_enabled
        from tests.conftest import make_account
        acc = make_account()
        mock_db.get.return_value = acc
        mock_db.scalars.return_value.all.return_value = []
        drafts = securityhub_not_enabled.run(mock_db, acc.id)
        assert drafts == []


# --- ec2.security_group checks ---

def _sg(*, group_id="sg-0abc", group_name="default", region="us-east-1", vpc_id="vpc-0abc",
        is_default=False, unrestricted_ssh=False, unrestricted_rdp=False,
        has_any_inbound_rules=False, has_any_outbound_rules=False, account_id=None):
    sg = MagicMock()
    sg.account_id = account_id or uuid.uuid4()
    sg.group_id = group_id
    sg.group_name = group_name
    sg.region = region
    sg.vpc_id = vpc_id
    sg.is_default = is_default
    sg.unrestricted_ssh = unrestricted_ssh
    sg.unrestricted_rdp = unrestricted_rdp
    sg.has_any_inbound_rules = has_any_inbound_rules
    sg.has_any_outbound_rules = has_any_outbound_rules
    return sg


class TestSgUnrestrictedSsh:
    def test_flags_sg_with_unrestricted_ssh(self, mock_db):
        from app.checks import sg_unrestricted_ssh
        from tests.conftest import make_account
        acc = make_account()
        mock_db.get.return_value = acc
        mock_db.scalars.return_value.all.return_value = [
            _sg(account_id=acc.id, unrestricted_ssh=True)
        ]
        drafts = sg_unrestricted_ssh.run(mock_db, acc.id)
        assert len(drafts) == 1
        assert drafts[0].check_id == "ec2.security_group.unrestricted_ssh"
        assert drafts[0].severity == "high"

    def test_skips_sg_without_open_ssh(self, mock_db):
        from app.checks import sg_unrestricted_ssh
        from tests.conftest import make_account
        acc = make_account()
        mock_db.get.return_value = acc
        mock_db.scalars.return_value.all.return_value = []
        drafts = sg_unrestricted_ssh.run(mock_db, acc.id)
        assert drafts == []


class TestSgDefaultAllowsTraffic:
    def test_flags_default_sg_with_inbound_rules(self, mock_db):
        from app.checks import sg_default_allows_traffic
        from tests.conftest import make_account
        acc = make_account()
        mock_db.get.return_value = acc
        mock_db.scalars.return_value.all.return_value = [
            _sg(account_id=acc.id, is_default=True, has_any_inbound_rules=True)
        ]
        drafts = sg_default_allows_traffic.run(mock_db, acc.id)
        assert len(drafts) == 1
        assert drafts[0].check_id == "ec2.security_group.default_allows_traffic"

    def test_skips_default_sg_with_no_rules(self, mock_db):
        from app.checks import sg_default_allows_traffic
        from tests.conftest import make_account
        acc = make_account()
        mock_db.get.return_value = acc
        mock_db.scalars.return_value.all.return_value = []
        drafts = sg_default_allows_traffic.run(mock_db, acc.id)
        assert drafts == []


# --- iam.policy.wildcard_resource ---

def _role_with_inline(*, arn=None, name="TestRole", inline=None, attached=None, account_id=None):
    r = MagicMock()
    r.account_id = account_id or uuid.uuid4()
    r.arn = arn or f"arn:aws:iam::123456789012:role/{name}"
    r.name = name
    r.inline_policies = inline or {}
    r.attached_policies = attached or []
    return r


class TestWildcardResourceCheck:
    def test_flags_role_with_dangerous_inline_policy(self, mock_db):
        from app.checks import iam_policy_wildcard_resource
        acc_id = uuid.uuid4()
        role = _role_with_inline(
            account_id=acc_id,
            inline={"InlineAdmin": {"Statement": [
                {"Effect": "Allow", "Action": ["iam:CreateUser", "iam:DeleteUser"], "Resource": "*"}
            ]}}
        )
        mock_db.scalars.return_value.all.return_value = [role]
        drafts = iam_policy_wildcard_resource.run(mock_db, acc_id)
        assert len(drafts) == 1
        assert drafts[0].check_id == "iam.policy.wildcard_resource"
        assert drafts[0].severity == "low"
        assert "InlineAdmin" in drafts[0].evidence["policy_names"]

    def test_skips_read_only_actions(self, mock_db):
        from app.checks import iam_policy_wildcard_resource
        acc_id = uuid.uuid4()
        role = _role_with_inline(
            account_id=acc_id,
            inline={"ReadOnly": {"Statement": [
                {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": "*"}
            ]}}
        )
        mock_db.scalars.return_value.all.return_value = [role]
        drafts = iam_policy_wildcard_resource.run(mock_db, acc_id)
        assert drafts == []

    def test_skips_deny_statements(self, mock_db):
        from app.checks import iam_policy_wildcard_resource
        acc_id = uuid.uuid4()
        role = _role_with_inline(
            account_id=acc_id,
            inline={"DenyAll": {"Statement": [
                {"Effect": "Deny", "Action": "iam:*", "Resource": "*"}
            ]}}
        )
        mock_db.scalars.return_value.all.return_value = [role]
        drafts = iam_policy_wildcard_resource.run(mock_db, acc_id)
        assert drafts == []

    def test_skips_service_linked_role(self, mock_db):
        from app.checks import iam_policy_wildcard_resource
        acc_id = uuid.uuid4()
        role = _role_with_inline(
            arn="arn:aws:iam::123456789012:role/aws-service-role/ec2.amazonaws.com/AWSServiceRoleForEC2",
            account_id=acc_id,
            inline={"Policy": {"Statement": [
                {"Effect": "Allow", "Action": "iam:CreateUser", "Resource": "*"}
            ]}}
        )
        mock_db.scalars.return_value.all.return_value = [role]
        drafts = iam_policy_wildcard_resource.run(mock_db, acc_id)
        assert drafts == []

    def test_skips_vigil_scan_role(self, mock_db):
        from app.checks import iam_policy_wildcard_resource
        acc_id = uuid.uuid4()
        vigil_arn = "arn:aws:iam::123456789012:role/VigilReadOnly"
        acc = MagicMock()
        acc.role_arn = vigil_arn
        mock_db.get.return_value = acc
        role = _role_with_inline(
            arn=vigil_arn,
            account_id=acc_id,
            inline={"VigilMinimalReadOnly": {"Statement": [
                {"Effect": "Allow", "Action": ["iam:GenerateServiceLastAccessedDetails"], "Resource": "*"}
            ]}},
        )
        mock_db.scalars.return_value.all.return_value = [role]
        drafts = iam_policy_wildcard_resource.run(mock_db, acc_id)
        assert drafts == []

    def test_skips_iam_last_accessed_actions(self, mock_db):
        from app.checks import iam_policy_wildcard_resource
        acc_id = uuid.uuid4()
        role = _role_with_inline(
            account_id=acc_id,
            inline={"PermUsage": {"Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "iam:GenerateServiceLastAccessedDetails",
                        "iam:GetServiceLastAccessedDetails",
                    ],
                    "Resource": "*",
                }
            ]}},
        )
        mock_db.scalars.return_value.all.return_value = [role]
        drafts = iam_policy_wildcard_resource.run(mock_db, acc_id)
        assert drafts == []


# --- github.org.outside_collaborators ---

class TestOutsideCollaborators:
    def _provider(self, org="myorg", collaborators=None):
        p = MagicMock()
        import json
        cfg: dict = {"org_login": org, "org_logins": [org]}
        if collaborators is not None:
            cfg["outside_collaborators"] = collaborators
        p.config_json_encrypted = json.dumps(cfg)
        return p

    def test_flags_when_collaborators_present(self, mock_db):
        from app.checks import github_org_outside_collaborators
        acc_id = uuid.uuid4()
        org_id = uuid.uuid4()
        acc = MagicMock()
        acc.org_id = org_id
        mock_db.get.return_value = acc
        mock_db.scalars.return_value.all.return_value = [
            self._provider(collaborators=[{"login": "ext-user", "id": 99}])
        ]
        drafts = github_org_outside_collaborators.run(mock_db, acc_id)
        assert len(drafts) == 1
        assert drafts[0].check_id == "github.org.outside_collaborators"
        assert drafts[0].evidence["count"] == 1

    def test_no_finding_when_empty(self, mock_db):
        from app.checks import github_org_outside_collaborators
        acc = MagicMock()
        acc.org_id = uuid.uuid4()
        mock_db.get.return_value = acc
        mock_db.scalars.return_value.all.return_value = [self._provider(collaborators=[])]
        drafts = github_org_outside_collaborators.run(mock_db, uuid.uuid4())
        assert drafts == []

    def test_skips_when_not_yet_collected(self, mock_db):
        from app.checks import github_org_outside_collaborators
        acc = MagicMock()
        acc.org_id = uuid.uuid4()
        mock_db.get.return_value = acc
        mock_db.scalars.return_value.all.return_value = [self._provider()]
        drafts = github_org_outside_collaborators.run(mock_db, uuid.uuid4())
        assert drafts == []


# --- iam.perm.granted_vs_used ---

class TestPermGrantedVsUsed:
    def _role_with_policies(self, *, arn=None, name="TestRole", inline=None, attached=None, account_id=None):
        r = MagicMock()
        r.account_id = account_id or uuid.uuid4()
        r.arn = arn or f"arn:aws:iam::123456789012:role/{name}"
        r.name = name
        r.inline_policies = inline or {}
        r.attached_policies = attached or []
        return r

    def _usage(self, *, service="s3", last_auth=None, actions_json=None):
        u = MagicMock()
        u.service = service
        u.last_authenticated = last_auth
        u.actions_json = actions_json or []
        return u

    def test_flags_role_with_high_unused_pct(self, mock_db):
        from app.checks import iam_perm_granted_vs_used
        acc_id = uuid.uuid4()
        role = self._role_with_policies(
            account_id=acc_id,
            inline={"Policy": {"Statement": [
                {"Effect": "Allow", "Action": [
                    "s3:PutObject", "s3:DeleteObject", "ec2:TerminateInstances",
                    "iam:CreateUser", "iam:DeleteUser",
                ], "Resource": "*"}
            ]}}
        )
        # Usage exists (with actions_json) but nothing was used recently
        cutoff = datetime.now(timezone.utc) - timedelta(days=100)
        usages = [self._usage(service="s3", last_auth=cutoff, actions_json=["s3:PutObject"])]

        def scalars_side_effect(query):
            result = MagicMock()
            # First call → roles; subsequent → usages
            result.all.return_value = [role] if not hasattr(scalars_side_effect, "called") else usages
            scalars_side_effect.called = True
            return result

        mock_db.scalars.side_effect = scalars_side_effect
        drafts = iam_perm_granted_vs_used.run(mock_db, acc_id)
        # Should produce a finding since most actions unused
        assert len(drafts) == 1
        assert drafts[0].check_id == "iam.perm.granted_vs_used"

    def test_skips_when_no_action_data(self, mock_db):
        from app.checks import iam_perm_granted_vs_used
        acc_id = uuid.uuid4()
        role = self._role_with_policies(
            account_id=acc_id,
            inline={"Policy": {"Statement": [
                {"Effect": "Allow", "Action": "s3:PutObject", "Resource": "*"}
            ]}}
        )
        usage_no_actions = self._usage(service="s3", actions_json=None)

        def scalars_side_effect(query):
            result = MagicMock()
            result.all.return_value = [role] if not hasattr(scalars_side_effect, "called") else [usage_no_actions]
            scalars_side_effect.called = True
            return result

        mock_db.scalars.side_effect = scalars_side_effect
        drafts = iam_perm_granted_vs_used.run(mock_db, acc_id)
        assert drafts == []


# --- iam.user.direct_policy_attachment ---

class TestUserDirectPolicy:
    def test_flags_user_with_attached_policy(self, mock_db):
        from app.checks import iam_user_direct_policy
        u = MagicMock()
        u.arn = "arn:aws:iam::123:user/alice"
        u.name = "alice"
        u.attached_policies = [{"policy_arn": "arn:aws:iam::123:policy/ReadOnly", "policy_name": "ReadOnly"}]
        u.inline_policies = {}
        mock_db.scalars.return_value.all.return_value = [u]
        drafts = iam_user_direct_policy.run(mock_db, uuid.uuid4())
        assert len(drafts) == 1
        assert drafts[0].check_id == "iam.user.direct_policy_attachment"

    def test_passes_user_with_no_direct_policies(self, mock_db):
        from app.checks import iam_user_direct_policy
        u = MagicMock()
        u.attached_policies = []
        u.inline_policies = {}
        mock_db.scalars.return_value.all.return_value = [u]
        drafts = iam_user_direct_policy.run(mock_db, uuid.uuid4())
        assert drafts == []
