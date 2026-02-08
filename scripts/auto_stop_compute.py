#!/usr/bin/env python3
"""Auto-stop AWS compute resources past AutoStopAt time.

This script automatically stops RDS instances and EC2 instances that have
exceeded their AutoStopAt timestamp. Run this manually or via cron to manage
testing costs.

Usage:
    python scripts/auto_stop_compute.py [--dry-run]
"""

import argparse
import sys
from datetime import UTC, datetime

import boto3

REGION = "us-east-1"
AUTO_STOP_TAG = "AutoStopAt"


def should_stop_instance(tags: list[dict]) -> bool:
    """Check if instance should be stopped based on AutoStopAt tag.

    Args:
        tags: List of tag dicts with 'Key' and 'Value' fields

    Returns:
        True if current time is past AutoStopAt time, False otherwise
    """
    auto_stop_tag = None
    for tag in tags:
        if tag.get("Key") == AUTO_STOP_TAG:
            auto_stop_tag = tag.get("Value")
            break

    if not auto_stop_tag:
        return False

    try:
        stop_time = datetime.fromisoformat(auto_stop_tag)
        return stop_time < datetime.now(UTC)
    except ValueError:
        return False


def stop_rds_instances(rds_client, dry_run: bool = False) -> int:
    """Stop RDS instances past AutoStopAt time.

    Args:
        rds_client: boto3 RDS client
        dry_run: If True, don't actually stop instances

    Returns:
        Number of instances stopped
    """
    count = 0
    try:
        response = rds_client.describe_db_instances()
        for db in response.get("DBInstances", []):
            tags = db.get("TagList", [])
            if should_stop_instance(tags):
                if dry_run:
                    print(f"[DRY-RUN] Would stop RDS instance: {db['DBInstanceIdentifier']}")
                else:
                    rds_client.stop_db_instance(
                        DBInstanceIdentifier=db["DBInstanceIdentifier"]
                    )
                    print(f"✅ Stopped RDS instance: {db['DBInstanceIdentifier']}")
                count += 1
    except Exception as e:  # noqa: S110
        print(f"⚠️  Error stopping RDS instances: {e}", file=sys.stderr)

    return count


def stop_ec2_instances(ec2_client, dry_run: bool = False) -> int:
    """Stop EC2 instances past AutoStopAt time.

    Args:
        ec2_client: boto3 EC2 client
        dry_run: If True, don't actually stop instances

    Returns:
        Number of instances stopped
    """
    count = 0
    try:
        response = ec2_client.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        )
        for reservation in response.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                tags = instance.get("Tags", [])
                if should_stop_instance(tags):
                    if dry_run:
                        print(f"[DRY-RUN] Would stop EC2 instance: {instance['InstanceId']}")
                    else:
                        ec2_client.stop_instances(InstanceIds=[instance["InstanceId"]])
                        print(f"✅ Stopped EC2 instance: {instance['InstanceId']}")
                    count += 1
    except Exception as e:  # noqa: S110
        print(f"⚠️  Error stopping EC2 instances: {e}", file=sys.stderr)

    return count


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Auto-stop AWS compute resources past AutoStopAt time"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview what would be stopped without making changes",
    )
    args = parser.parse_args()

    print("Auto-stopping AWS compute resources...")
    print(f"Region: {REGION}")
    print(f"Dry-run: {args.dry_run}\n")

    try:
        session = boto3.Session(region_name=REGION)
        rds = session.client("rds")
        ec2 = session.client("ec2")

        rds_count = stop_rds_instances(rds, dry_run=args.dry_run)
        ec2_count = stop_ec2_instances(ec2, dry_run=args.dry_run)

        print("\n✅ Auto-stop complete!")
        print(f"  RDS instances: {rds_count}")
        print(f"  EC2 instances: {ec2_count}")

    except Exception as e:  # noqa: S110
        print(f"\n❌ Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
