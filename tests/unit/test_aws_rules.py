"""Tests for AWS security rules."""

import pytest

from cspm.cloud.base import Resource
from cspm.rules.aws_rules import PublicS3Rule
from cspm.rules.base import RuleSeverity


@pytest.fixture
def s3_resource_public():
    """Create a public S3 bucket resource."""
    return Resource(
        id="public-bucket",
        name="public-bucket",
        type="AWS::S3::Bucket",
        region="us-east-1",
        cloud_provider="aws",
        attributes={
            "CreationDate": "2024-01-01",
            "ACL": "public-read",
        },
        tags={},
    )


@pytest.fixture
def s3_resource_private():
    """Create a private S3 bucket resource."""
    return Resource(
        id="private-bucket",
        name="private-bucket",
        type="AWS::S3::Bucket",
        region="us-east-1",
        cloud_provider="aws",
        attributes={
            "CreationDate": "2024-01-01",
            "ACL": "private",
        },
        tags={},
    )


def test_public_s3_rule_is_applicable_to_s3_buckets(s3_resource_public):
    """Test that PublicS3Rule applies to S3 buckets."""
    rule = PublicS3Rule()
    assert rule.is_applicable(s3_resource_public) is True


def test_public_s3_rule_is_not_applicable_to_other_resources():
    """Test that PublicS3Rule doesn't apply to other resource types."""
    rule = PublicS3Rule()
    instance = Resource(
        id="i-12345",
        name="test-instance",
        type="AWS::EC2::Instance",
        region="us-east-1",
        cloud_provider="aws",
        attributes={},
        tags={},
    )
    assert rule.is_applicable(instance) is False


def test_public_s3_rule_detects_public_bucket(s3_resource_public):
    """Test that PublicS3Rule detects public S3 buckets."""
    rule = PublicS3Rule()
    result = rule.evaluate(s3_resource_public)

    assert result.has_finding is True
    assert result.severity == RuleSeverity.CRITICAL
    assert result.resource.id == "public-bucket"
    assert "public" in result.description.lower()


def test_public_s3_rule_does_not_flag_private_bucket(s3_resource_private):
    """Test that PublicS3Rule doesn't flag private S3 buckets."""
    rule = PublicS3Rule()
    result = rule.evaluate(s3_resource_private)

    assert result.has_finding is False


# Tests for UnencryptedRDSRule
@pytest.fixture
def rds_resource_unencrypted():
    """Create an unencrypted RDS instance resource."""
    return Resource(
        id="unencrypted-db",
        name="unencrypted-db",
        type="AWS::RDS::DBInstance",
        region="us-east-1",
        cloud_provider="aws",
        attributes={
            "Engine": "mysql",
            "StorageEncrypted": False,
        },
        tags={},
    )


@pytest.fixture
def rds_resource_encrypted():
    """Create an encrypted RDS instance resource."""
    return Resource(
        id="encrypted-db",
        name="encrypted-db",
        type="AWS::RDS::DBInstance",
        region="us-east-1",
        cloud_provider="aws",
        attributes={
            "Engine": "mysql",
            "StorageEncrypted": True,
        },
        tags={},
    )


def test_unencrypted_rds_rule_detects_unencrypted(rds_resource_unencrypted):
    """Test that UnencryptedRDSRule detects unencrypted RDS instances."""
    from cspm.rules.aws_rules import UnencryptedRDSRule

    rule = UnencryptedRDSRule()
    result = rule.evaluate(rds_resource_unencrypted)

    assert result.has_finding is True
    assert result.severity == RuleSeverity.HIGH


def test_unencrypted_rds_rule_does_not_flag_encrypted(rds_resource_encrypted):
    """Test that UnencryptedRDSRule doesn't flag encrypted RDS instances."""
    from cspm.rules.aws_rules import UnencryptedRDSRule

    rule = UnencryptedRDSRule()
    result = rule.evaluate(rds_resource_encrypted)

    assert result.has_finding is False


# Tests for EC2PublicIPRule
@pytest.fixture
def ec2_resource_with_public_ip():
    """Create an EC2 instance with public IP."""
    return Resource(
        id="i-public",
        name="public-instance",
        type="AWS::EC2::Instance",
        region="us-east-1",
        cloud_provider="aws",
        attributes={
            "State": "running",
            "PublicIpAddress": "203.0.113.0",
        },
        tags={},
    )


@pytest.fixture
def ec2_resource_without_public_ip():
    """Create an EC2 instance without public IP."""
    return Resource(
        id="i-private",
        name="private-instance",
        type="AWS::EC2::Instance",
        region="us-east-1",
        cloud_provider="aws",
        attributes={
            "State": "running",
            "PublicIpAddress": None,
        },
        tags={},
    )


def test_ec2_public_ip_rule_detects_public_ip(ec2_resource_with_public_ip):
    """Test that EC2PublicIPRule detects instances with public IP."""
    from cspm.rules.aws_rules import EC2PublicIPRule

    rule = EC2PublicIPRule()
    result = rule.evaluate(ec2_resource_with_public_ip)

    assert result.has_finding is True
    assert result.severity == RuleSeverity.MEDIUM


def test_ec2_public_ip_rule_does_not_flag_private(ec2_resource_without_public_ip):
    """Test that EC2PublicIPRule doesn't flag private instances."""
    from cspm.rules.aws_rules import EC2PublicIPRule

    rule = EC2PublicIPRule()
    result = rule.evaluate(ec2_resource_without_public_ip)

    assert result.has_finding is False


# Tests for OpenSecurityGroupRule
@pytest.fixture
def sg_resource_open():
    """Create an open security group."""
    return Resource(
        id="sg-open",
        name="open-sg",
        type="AWS::EC2::SecurityGroup",
        region="us-east-1",
        cloud_provider="aws",
        attributes={
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 80,
                    "ToPort": 80,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        },
        tags={},
    )


@pytest.fixture
def sg_resource_restricted():
    """Create a restricted security group."""
    return Resource(
        id="sg-restricted",
        name="restricted-sg",
        type="AWS::EC2::SecurityGroup",
        region="us-east-1",
        cloud_provider="aws",
        attributes={
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 80,
                    "ToPort": 80,
                    "IpRanges": [{"CidrIp": "192.168.0.0/16"}],
                }
            ],
        },
        tags={},
    )


def test_open_sg_rule_detects_open_sg(sg_resource_open):
    """Test that OpenSecurityGroupRule detects open security groups."""
    from cspm.rules.aws_rules import OpenSecurityGroupRule

    rule = OpenSecurityGroupRule()
    result = rule.evaluate(sg_resource_open)

    assert result.has_finding is True
    assert result.severity == RuleSeverity.HIGH


def test_open_sg_rule_does_not_flag_restricted(sg_resource_restricted):
    """Test that OpenSecurityGroupRule doesn't flag restricted security groups."""
    from cspm.rules.aws_rules import OpenSecurityGroupRule

    rule = OpenSecurityGroupRule()
    result = rule.evaluate(sg_resource_restricted)

    assert result.has_finding is False


# Tests for CloudTrailDisabledRule
@pytest.fixture
def cloudtrail_resource_enabled():
    """Create an enabled CloudTrail."""
    return Resource(
        id="trail-arn-enabled",
        name="trail-enabled",
        type="AWS::CloudTrail::Trail",
        region="us-east-1",
        cloud_provider="aws",
        attributes={
            "IsLogging": True,
            "S3BucketName": "cloudtrail-logs",
        },
        tags={},
    )


@pytest.fixture
def cloudtrail_resource_disabled():
    """Create a disabled CloudTrail."""
    return Resource(
        id="trail-arn-disabled",
        name="trail-disabled",
        type="AWS::CloudTrail::Trail",
        region="us-east-1",
        cloud_provider="aws",
        attributes={
            "IsLogging": False,
            "S3BucketName": "cloudtrail-logs",
        },
        tags={},
    )


def test_cloudtrail_disabled_rule_detects_disabled(cloudtrail_resource_disabled):
    """Test that CloudTrailDisabledRule detects disabled CloudTrail."""
    from cspm.rules.aws_rules import CloudTrailDisabledRule

    rule = CloudTrailDisabledRule()
    result = rule.evaluate(cloudtrail_resource_disabled)

    assert result.has_finding is True
    assert result.severity == RuleSeverity.CRITICAL


def test_cloudtrail_disabled_rule_does_not_flag_enabled(cloudtrail_resource_enabled):
    """Test that CloudTrailDisabledRule doesn't flag enabled CloudTrail."""
    from cspm.rules.aws_rules import CloudTrailDisabledRule

    rule = CloudTrailDisabledRule()
    result = rule.evaluate(cloudtrail_resource_enabled)

    assert result.has_finding is False
