#!/usr/bin/env python3
"""Clean up AWS test resources."""

import sys

import boto3

RESOURCE_PREFIX = "cspm-test-"
REGION = "us-east-1"


def cleanup_s3_buckets(s3_client):
    """Delete all test S3 buckets."""
    count = 0
    try:
        buckets = s3_client.list_buckets()["Buckets"]
        for bucket in buckets:
            if bucket["Name"].startswith(RESOURCE_PREFIX):
                # Empty bucket first
                try:
                    objects = s3_client.list_objects_v2(Bucket=bucket["Name"])
                    if "Contents" in objects:
                        for obj in objects["Contents"]:
                            s3_client.delete_object(Bucket=bucket["Name"], Key=obj["Key"])
                except Exception:  # noqa: S110
                    pass

                s3_client.delete_bucket(Bucket=bucket["Name"])
                print(f"✅ Deleted S3 bucket: {bucket['Name']}")
                count += 1
    except Exception as e:  # noqa: S110
        print(f"⚠️  Error cleaning S3: {e}", file=sys.stderr)

    return count


def cleanup_security_groups(ec2_client):
    """Delete all test security groups."""
    count = 0
    try:
        response = ec2_client.describe_security_groups()
        for sg in response["SecurityGroups"]:
            if sg["GroupName"].startswith(RESOURCE_PREFIX):
                ec2_client.delete_security_group(GroupId=sg["GroupId"])
                print(f"✅ Deleted security group: {sg['GroupName']} ({sg['GroupId']})")
                count += 1
    except Exception as e:  # noqa: S110
        print(f"⚠️  Error cleaning security groups: {e}", file=sys.stderr)

    return count


def cleanup_rds_instances(rds_client):
    """Delete all test RDS instances."""
    count = 0
    try:
        response = rds_client.describe_db_instances()
        for db in response.get("DBInstances", []):
            if db["DBInstanceIdentifier"].startswith(RESOURCE_PREFIX):
                rds_client.delete_db_instance(
                    DBInstanceIdentifier=db["DBInstanceIdentifier"],
                    SkipFinalSnapshot=True,
                )
                print(f"✅ Deleted RDS instance: {db['DBInstanceIdentifier']}")
                count += 1
    except Exception as e:  # noqa: S110
        print(f"⚠️  Error cleaning RDS instances: {e}", file=sys.stderr)

    return count


def cleanup_ec2_instances(ec2_client):
    """Delete all test EC2 instances and release EIPs."""
    count = 0
    try:
        # Terminate EC2 instances
        response = ec2_client.describe_instances(
            Filters=[{"Name": "tag:ManagedBy", "Values": ["cspm-integration-tests"]}]
        )
        for reservation in response.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                if instance["State"]["Name"] != "terminated":
                    ec2_client.terminate_instances(InstanceIds=[instance["InstanceId"]])
                    print(f"✅ Terminated EC2 instance: {instance['InstanceId']}")
                    count += 1

        # Release Elastic IPs
        eip_response = ec2_client.describe_addresses(
            Filters=[{"Name": "tag:ManagedBy", "Values": ["cspm-integration-tests"]}]
        )
        for eip in eip_response.get("Addresses", []):
            if eip.get("AllocationId"):
                ec2_client.release_address(AllocationId=eip["AllocationId"])
                print(f"✅ Released Elastic IP: {eip['AllocationId']}")

    except Exception as e:  # noqa: S110
        print(f"⚠️  Error cleaning EC2 instances: {e}", file=sys.stderr)

    return count


def main():
    print("Cleaning up AWS test resources...\n")

    session = boto3.Session(region_name=REGION)
    s3 = session.client("s3")
    ec2 = session.client("ec2")
    rds = session.client("rds")

    s3_count = cleanup_s3_buckets(s3)
    sg_count = cleanup_security_groups(ec2)
    rds_count = cleanup_rds_instances(rds)
    ec2_count = cleanup_ec2_instances(ec2)

    print("\n✅ Cleanup complete!")
    print(f"  S3 buckets deleted: {s3_count}")
    print(f"  Security groups deleted: {sg_count}")
    print(f"  RDS instances deleted: {rds_count}")
    print(f"  EC2 instances terminated: {ec2_count}")


if __name__ == "__main__":
    main()
