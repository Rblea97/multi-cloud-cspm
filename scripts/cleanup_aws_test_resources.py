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
                except Exception as e:  # noqa: S110
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


def main():
    print("Cleaning up AWS test resources...\n")

    session = boto3.Session(region_name=REGION)
    s3 = session.client("s3")
    ec2 = session.client("ec2")

    s3_count = cleanup_s3_buckets(s3)
    sg_count = cleanup_security_groups(ec2)

    print(f"\n✅ Cleanup complete!")
    print(f"  S3 buckets deleted: {s3_count}")
    print(f"  Security groups deleted: {sg_count}")


if __name__ == "__main__":
    main()
