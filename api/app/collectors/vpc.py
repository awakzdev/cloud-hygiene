"""Collect VPC flow log status and security group ingress rules per region."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import structlog
from botocore.exceptions import ClientError
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.aws import assume_role
from app.models import AwsAccount
from app.models.resources import SecurityGroup, Vpc

log = structlog.get_logger()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _get_regions(sess) -> list[str]:
    ec2 = sess.client("ec2", region_name="us-east-1")
    return [
        r["RegionName"]
        for r in ec2.describe_regions(
            Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
        )["Regions"]
    ]


def _is_unrestricted(ip_ranges: list[dict], port: int) -> bool:
    for perm in ip_ranges:
        from_port = perm.get("FromPort", 0)
        to_port = perm.get("ToPort", 65535)
        if not (from_port <= port <= to_port):
            continue
        for cidr in perm.get("IpRanges", []):
            if cidr.get("CidrIp") in ("0.0.0.0/0",):
                return True
        for cidr6 in perm.get("Ipv6Ranges", []):
            if cidr6.get("CidrIpv6") in ("::/0",):
                return True
    return False


def collect_vpc(db: Session, account: AwsAccount) -> dict:
    sess = assume_role(account.role_arn, account.external_id, session_name="vigil-vpc")
    regions = _get_regions(sess)
    vpc_count = sg_count = 0

    for region in regions:
        try:
            ec2 = sess.client("ec2", region_name=region)

            # VPCs + flow logs
            vpcs = ec2.describe_vpcs().get("Vpcs", [])
            flow_log_vpc_ids: set[str] = set()
            try:
                fls = ec2.describe_flow_logs(
                    Filters=[{"Name": "resource-type", "Values": ["VPC"]}]
                ).get("FlowLogs", [])
                for fl in fls:
                    if fl.get("FlowLogStatus") == "ACTIVE":
                        flow_log_vpc_ids.add(fl.get("ResourceId", ""))
            except ClientError:
                pass

            for vpc in vpcs:
                vpc_id = vpc["VpcId"]
                flow_logs_enabled = vpc_id in flow_log_vpc_ids
                stmt = pg_insert(Vpc).values(
                    id=uuid.uuid5(uuid.NAMESPACE_URL, f"{account.id}:{region}:{vpc_id}"),
                    account_id=account.id,
                    vpc_id=vpc_id,
                    region=region,
                    flow_logs_enabled=flow_logs_enabled,
                    last_seen=_now(),
                ).on_conflict_do_update(
                    index_elements=["account_id", "vpc_id", "region"],
                    set_={"flow_logs_enabled": flow_logs_enabled, "last_seen": _now()},
                )
                db.execute(stmt)
                vpc_count += 1

            # Security groups
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    group_id = sg["GroupId"]
                    group_name = sg.get("GroupName", "")
                    ingress = sg.get("IpPermissions", [])
                    egress = sg.get("IpPermissionsEgress", [])
                    unrestricted_ssh = _is_unrestricted(ingress, 22)
                    unrestricted_rdp = _is_unrestricted(ingress, 3389)
                    is_default = group_name == "default"
                    has_any_inbound_rules = len(ingress) > 0
                    has_any_outbound_rules = len(egress) > 0
                    vpc_id = sg.get("VpcId")

                    stmt = pg_insert(SecurityGroup).values(
                        id=uuid.uuid5(uuid.NAMESPACE_URL, f"{account.id}:{region}:{group_id}"),
                        account_id=account.id,
                        group_id=group_id,
                        group_name=group_name,
                        region=region,
                        vpc_id=vpc_id,
                        is_default=is_default,
                        unrestricted_ssh=unrestricted_ssh,
                        unrestricted_rdp=unrestricted_rdp,
                        has_any_inbound_rules=has_any_inbound_rules,
                        has_any_outbound_rules=has_any_outbound_rules,
                        last_seen=_now(),
                    ).on_conflict_do_update(
                        index_elements=["account_id", "group_id", "region"],
                        set_={
                            "vpc_id": vpc_id,
                            "is_default": is_default,
                            "unrestricted_ssh": unrestricted_ssh,
                            "unrestricted_rdp": unrestricted_rdp,
                            "has_any_inbound_rules": has_any_inbound_rules,
                            "has_any_outbound_rules": has_any_outbound_rules,
                            "last_seen": _now(),
                        },
                    )
                    db.execute(stmt)
                    sg_count += 1

        except ClientError:
            continue

    db.commit()
    log.info("collect_vpc.done", account_id=str(account.id), vpcs=vpc_count, sgs=sg_count)
    return {"vpcs": vpc_count, "security_groups": sg_count}


def collect_security_groups(db: Session, account: AwsAccount) -> int:
    return collect_vpc(db, account)["security_groups"]
