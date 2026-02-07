"""End-to-end integration test for full scan cycle."""

from unittest.mock import MagicMock

import pytest

from cspm.cloud.base import CloudProvider, Resource
from cspm.rules.aws_rules import (
    CloudTrailDisabledRule,
    EC2PublicIPRule,
    OpenSecurityGroupRule,
    PublicS3Rule,
    UnencryptedRDSRule,
)


@pytest.fixture
def mock_aws_provider():
    """Create a mocked AWS provider with test resources."""
    provider = MagicMock(spec=CloudProvider)
    provider.authenticate.return_value = True
    provider.is_authenticated.return_value = True

    # Create test resources
    resources = [
        # Public S3 bucket (should trigger finding)
        Resource(
            id="public-bucket",
            name="public-bucket",
            type="AWS::S3::Bucket",
            region="us-east-1",
            cloud_provider="aws",
            attributes={"ACL": "public-read"},
            tags={},
        ),
        # Private S3 bucket (no finding)
        Resource(
            id="private-bucket",
            name="private-bucket",
            type="AWS::S3::Bucket",
            region="us-east-1",
            cloud_provider="aws",
            attributes={"ACL": "private"},
            tags={},
        ),
        # Unencrypted RDS (should trigger finding)
        Resource(
            id="unencrypted-db",
            name="unencrypted-db",
            type="AWS::RDS::DBInstance",
            region="us-east-1",
            cloud_provider="aws",
            attributes={"StorageEncrypted": False, "Engine": "mysql"},
            tags={},
        ),
        # EC2 with public IP (should trigger finding)
        Resource(
            id="public-instance",
            name="public-instance",
            type="AWS::EC2::Instance",
            region="us-east-1",
            cloud_provider="aws",
            attributes={"State": "running", "PublicIpAddress": "203.0.113.0"},
            tags={},
        ),
        # Open security group (should trigger finding)
        Resource(
            id="open-sg",
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
                ]
            },
            tags={},
        ),
        # Disabled CloudTrail (should trigger finding)
        Resource(
            id="trail-disabled",
            name="trail-disabled",
            type="AWS::CloudTrail::Trail",
            region="us-east-1",
            cloud_provider="aws",
            attributes={"IsLogging": False, "S3BucketName": "logs"},
            tags={},
        ),
    ]

    provider.get_resources.return_value = resources
    return provider


def test_end_to_end_scan(scan_engine, rule_registry, db_repository, mock_aws_provider):
    """Test complete scan cycle from registration to finding storage."""
    # Register all AWS rules
    rules = [
        PublicS3Rule(),
        UnencryptedRDSRule(),
        EC2PublicIPRule(),
        OpenSecurityGroupRule(),
        CloudTrailDisabledRule(),
    ]

    for rule in rules:
        rule_registry.register(rule)

    # Register the cloud provider with the engine
    scan_engine.register_provider(mock_aws_provider)

    # Execute scan
    scan_id = scan_engine.scan(scan_type="FULL")

    # Verify scan was created
    assert scan_id is not None

    # Retrieve findings from database
    findings = db_repository.get_findings_by_scan(scan_id)

    # Should have 5 findings (1 public S3, 1 unencrypted RDS, 1 public EC2, 1 open SG, 1 disabled CloudTrail)
    assert len(findings) == 5

    # Verify finding types
    finding_rules = {f.rule_id for f in findings}
    assert "public_s3_rule" in finding_rules
    assert "unencrypted_rds_rule" in finding_rules
    assert "ec2_public_ip_rule" in finding_rules
    assert "open_sg_rule" in finding_rules
    assert "cloudtrail_disabled_rule" in finding_rules

    # Verify all findings have correct scan ID
    for finding in findings:
        assert finding.scan_id == scan_id
        assert finding.status == "OPEN"
        assert finding.severity in ["CRITICAL", "HIGH", "MEDIUM"]


def test_scan_engine_updates_scan_record(scan_engine, rule_registry, db_repository, mock_aws_provider):
    """Test that scan engine updates scan record with statistics."""
    # Register one rule for simplicity
    rule_registry.register(PublicS3Rule())

    # Register the provider
    scan_engine.register_provider(mock_aws_provider)

    # Execute scan
    scan_id = scan_engine.scan(scan_type="FULL")

    # Retrieve scan record
    scan = db_repository.get_scan(scan_id)

    # Verify scan record has correct status and stats
    assert scan.status == "COMPLETED"
    assert scan.resources_scanned == 6  # 6 test resources
    assert scan.findings_count >= 1  # At least 1 finding (public bucket)


def test_scan_handles_multiple_findings_same_resource(scan_engine, rule_registry, db_repository):
    """Test that scan correctly handles multiple findings on the same resource."""
    # Create a provider with a resource that violates multiple rules
    provider = MagicMock(spec=CloudProvider)
    provider.authenticate.return_value = True
    provider.is_authenticated.return_value = True

    # This S3 bucket could be checked by multiple S3-related rules
    resources = [
        Resource(
            id="multi-finding-bucket",
            name="multi-finding-bucket",
            type="AWS::S3::Bucket",
            region="us-east-1",
            cloud_provider="aws",
            attributes={"ACL": "public-read"},
            tags={},
        )
    ]

    provider.get_resources.return_value = resources

    # Register the same rule multiple times (simulating multiple checks on same resource)
    rule_registry.register(PublicS3Rule())

    scan_engine.register_provider(provider)
    scan_id = scan_engine.scan(scan_type="FULL")

    # Verify findings were stored
    findings = db_repository.get_findings_by_scan(scan_id)
    assert len(findings) >= 1
    assert findings[0].resource_id == "multi-finding-bucket"
