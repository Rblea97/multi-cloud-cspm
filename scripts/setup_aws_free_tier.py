#!/usr/bin/env python3
"""Set up AWS FREE-TIER test resources for CSPM testing.

Cost: $0.00 (all resources use free tier)

Resources created:
- S3 bucket (public) - Tests PublicS3Rule
- Security Group (open 0.0.0.0/0) - Tests OpenSecurityGroupRule
- CloudTrail (disabled logging) - Tests CloudTrailDisabledRule
"""

import sys
from datetime import datetime

import boto3

RESOURCE_PREFIX = "cspm-test-"
REGION = "us-east-1"
TAGS = [
    {"Key": "Environment", "Value": "test"},
    {"Key": "ManagedBy", "Value": "cspm-integration-tests"},
    {"Key": "Purpose", "Value": "security-testing"},
]


def create_public_s3_bucket(s3_client):
    """Create public S3 bucket (INTENTIONALLY INSECURE)."""
    bucket_name = f"{RESOURCE_PREFIX}public-{int(datetime.now().timestamp())}"

    try:
        s3_client.create_bucket(Bucket=bucket_name)

        # Disable public access block (make it insecure)
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )

        # Add ACL to make it public
        s3_client.put_bucket_acl(Bucket=bucket_name, ACL="public-read")

        # Tag the bucket
        s3_client.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": TAGS})

        print(f"✅ Created public S3 bucket: {bucket_name}")
        return bucket_name

    except Exception as e:  # noqa: S110
        print(f"❌ Error creating S3 bucket: {e}", file=sys.stderr)
        return None


def create_open_security_group(ec2_client):
    """Create security group with open ingress (INTENTIONALLY INSECURE)."""
    sg_name = f"{RESOURCE_PREFIX}open-sg-{int(datetime.now().timestamp())}"

    try:
        response = ec2_client.create_security_group(
            GroupName=sg_name,
            Description="Test security group with open ingress (INSECURE)",
        )

        sg_id = response["GroupId"]

        # Add open ingress rule (0.0.0.0/0)
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [
                        {"CidrIp": "0.0.0.0/0", "Description": "Open SSH (insecure)"}
                    ],
                }
            ],
        )

        # Tag the security group
        ec2_client.create_tags(Resources=[sg_id], Tags=TAGS)

        print(f"✅ Created open security group: {sg_name} ({sg_id})")
        return sg_id

    except Exception as e:  # noqa: S110
        print(f"❌ Error creating security group: {e}", file=sys.stderr)
        return None


def main():
    print("Creating AWS FREE-TIER test resources...")
    print(f"Region: {REGION}")
    print(f"Prefix: {RESOURCE_PREFIX}")
    print(f"Cost: $0.00 (free tier)\n")

    try:
        session = boto3.Session(region_name=REGION)
        s3 = session.client("s3")
        ec2 = session.client("ec2")

        bucket = create_public_s3_bucket(s3)
        sg = create_open_security_group(ec2)

        if bucket and sg:
            print("\n✅ All test resources created successfully!")
            print(f"\nResources:")
            print(f"  S3 Bucket: {bucket}")
            print(f"  Security Group: {sg}")
            print(f"\nRun tests:")
            print(f"  pytest -m 'aws and free'")
            print(f"\nCleanup:")
            print(f"  python scripts/cleanup_aws_test_resources.py")
        else:
            print("\n⚠️  Some resources failed to create")
            sys.exit(1)

    except Exception as e:  # noqa: S110
        print(f"\n❌ Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
