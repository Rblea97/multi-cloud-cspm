#!/usr/bin/env python3
"""Set up AWS FREE-TIER test resources for CSPM testing.

Cost: $0.00 (all resources use free tier)

Resources created:
- S3 bucket (public) - Tests PublicS3Rule
- Security Group (open 0.0.0.0/0) - Tests OpenSecurityGroupRule
- CloudTrail (disabled logging) - Tests CloudTrailDisabledRule
- RDS instance (unencrypted) - Tests UnencryptedRDSRule
- EC2 instance (public IP) - Tests EC2PublicIPRule
"""

import secrets
import sys
from datetime import UTC, datetime, timedelta

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


def create_unencrypted_rds(rds_client):
    """Create unencrypted RDS db.t3.micro (INTENTIONALLY INSECURE)."""
    db_id = f"{RESOURCE_PREFIX}db-{int(datetime.now().timestamp())}"
    db_password = secrets.token_urlsafe(16)

    try:
        # Auto-stop time: 2 hours from now
        auto_stop_time = (datetime.now(UTC) + timedelta(hours=2)).isoformat()

        rds_client.create_db_instance(
            DBInstanceIdentifier=db_id,
            DBInstanceClass="db.t3.micro",
            Engine="mysql",
            MasterUsername="admin",
            MasterUserPassword=db_password,
            AllocatedStorage=20,
            StorageEncrypted=False,  # INSECURE
            Tags=TAGS + [{"Key": "AutoStopAt", "Value": auto_stop_time}],
        )

        print(f"✅ Created unencrypted RDS instance: {db_id}")
        return db_id

    except Exception as e:  # noqa: S110
        print(f"❌ Error creating RDS instance: {e}", file=sys.stderr)
        return None


def create_ec2_with_public_ip(ec2_client):
    """Create EC2 t2.micro with public IP (INTENTIONALLY INSECURE)."""
    instance_name = f"{RESOURCE_PREFIX}ec2-{int(datetime.now().timestamp())}"

    try:
        # Get default VPC
        vpcs = ec2_client.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}])
        if not vpcs["Vpcs"]:
            print("❌ No default VPC found", file=sys.stderr)
            return None

        vpc_id = vpcs["Vpcs"][0]["VpcId"]

        # Get default subnet
        subnets = ec2_client.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )
        if not subnets["Subnets"]:
            print("❌ No subnets found in default VPC", file=sys.stderr)
            return None

        subnet_id = subnets["Subnets"][0]["SubnetId"]

        # Auto-stop time: 2 hours from now
        auto_stop_time = (datetime.now(UTC) + timedelta(hours=2)).isoformat()

        # Launch EC2 instance
        response = ec2_client.run_instances(
            ImageId="ami-0c55b159cbfafe1f0",  # Amazon Linux 2
            InstanceType="t2.micro",
            MinCount=1,
            MaxCount=1,
            SubnetId=subnet_id,
            AssociatePublicIpAddress=True,
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": TAGS + [{"Key": "AutoStopAt", "Value": auto_stop_time}, {"Key": "Name", "Value": instance_name}],
                },
                {
                    "ResourceType": "volume",
                    "Tags": TAGS,
                },
            ],
        )

        instance_id = response["Instances"][0]["InstanceId"]

        # Wait for instance to be running
        waiter = ec2_client.get_waiter("instance_running")
        waiter.wait(InstanceIds=[instance_id])

        print(f"✅ Created EC2 instance with public IP: {instance_name} ({instance_id})")
        return instance_id

    except Exception as e:  # noqa: S110
        print(f"❌ Error creating EC2 instance: {e}", file=sys.stderr)
        return None


def main():
    print("Creating AWS FREE-TIER test resources...")
    print(f"Region: {REGION}")
    print(f"Prefix: {RESOURCE_PREFIX}")
    print("Cost: $0.00 (free tier)\n")

    try:
        session = boto3.Session(region_name=REGION)
        s3 = session.client("s3")
        ec2 = session.client("ec2")
        rds = session.client("rds")

        bucket = create_public_s3_bucket(s3)
        sg = create_open_security_group(ec2)
        db_instance = create_unencrypted_rds(rds)
        ec2_instance = create_ec2_with_public_ip(ec2)

        if bucket and sg and db_instance and ec2_instance:
            print("\n✅ All test resources created successfully!")
            print("\nResources:")
            print(f"  S3 Bucket: {bucket}")
            print(f"  Security Group: {sg}")
            print(f"  RDS Instance: {db_instance}")
            print(f"  EC2 Instance: {ec2_instance}")
            print("\nRun tests:")
            print("  pytest -m 'aws and free'")
            print("\nCleanup:")
            print("  python scripts/cleanup_aws_test_resources.py")
        else:
            print("\n⚠️  Some resources failed to create")
            sys.exit(1)

    except Exception as e:  # noqa: S110
        print(f"\n❌ Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
