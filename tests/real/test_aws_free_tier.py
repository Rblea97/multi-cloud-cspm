"""Real AWS free-tier infrastructure tests.

These tests use ONLY free-tier resources (no cost).

Prerequisites:
1. AWS credentials configured (AWS_PROFILE or access keys)
2. Run: python scripts/setup_aws_free_tier.py
3. Run: pytest -m 'aws and free'

Cost: $0.00
"""

import pytest

from cspm.rules.aws_rules import OpenSecurityGroupRule, PublicS3Rule
from cspm.scanner.engine import ScanEngine


@pytest.mark.aws
@pytest.mark.real
@pytest.mark.free
def test_aws_provider_authentication(real_aws_provider):
    """Test real AWS authentication works."""
    assert real_aws_provider.is_authenticated()
    assert real_aws_provider.s3_client is not None
    assert real_aws_provider.ec2_client is not None


@pytest.mark.aws
@pytest.mark.real
@pytest.mark.free
def test_aws_s3_resource_discovery(real_aws_provider):
    """Test real S3 bucket discovery."""
    resources = real_aws_provider.get_resources(resource_type="s3")

    # Should find at least the test bucket
    assert len(resources) > 0

    # Verify structure
    for resource in resources:
        assert resource.type == "AWS::S3::Bucket"
        assert resource.cloud_provider == "aws"
        assert resource.id
        assert isinstance(resource.attributes, dict)


@pytest.mark.aws
@pytest.mark.real
@pytest.mark.free
def test_public_s3_rule_real_finding(real_aws_provider, scan_engine, rule_registry, db_repository):
    """Test PublicS3Rule detects real public bucket."""
    # Register rule and provider
    rule = PublicS3Rule()
    rule_registry.register(rule)
    scan_engine.register_provider(real_aws_provider)

    # Execute scan
    scan_id = scan_engine.scan(scan_type="FULL")

    # Retrieve findings
    findings = db_repository.get_findings_by_scan(scan_id)

    # Should find public S3 bucket
    s3_findings = [f for f in findings if f.rule_id == "public_s3_rule"]
    assert len(s3_findings) > 0

    # Verify finding details
    finding = s3_findings[0]
    assert finding.severity == "CRITICAL"
    assert finding.status == "OPEN"
    assert "cspm-test-" in finding.resource_id


@pytest.mark.aws
@pytest.mark.real
@pytest.mark.free
def test_security_group_discovery(real_aws_provider):
    """Test security group discovery."""
    resources = real_aws_provider.get_resources(resource_type="security_group")

    assert len(resources) > 0

    # Find our test security group
    test_sgs = [r for r in resources if "cspm-test-" in r.name]
    assert len(test_sgs) > 0


@pytest.mark.aws
@pytest.mark.real
@pytest.mark.free
def test_open_security_group_rule_real_finding(real_aws_provider, scan_engine, rule_registry, db_repository):
    """Test OpenSecurityGroupRule detects real open SG."""
    rule = OpenSecurityGroupRule()
    rule_registry.register(rule)
    scan_engine.register_provider(real_aws_provider)

    scan_id = scan_engine.scan(scan_type="FULL")
    findings = db_repository.get_findings_by_scan(scan_id)

    sg_findings = [f for f in findings if f.rule_id == "open_security_group_rule"]
    assert len(sg_findings) > 0

    finding = sg_findings[0]
    assert finding.severity == "HIGH"


@pytest.mark.aws
@pytest.mark.real
@pytest.mark.free
def test_full_free_tier_scan(real_aws_provider, scan_engine, rule_registry, db_repository):
    """Test full scan with free-tier rules."""
    # Register only free-tier rules
    rule_registry.register(PublicS3Rule())
    rule_registry.register(OpenSecurityGroupRule())

    scan_engine.register_provider(real_aws_provider)
    scan_id = scan_engine.scan(scan_type="FULL")

    # Verify scan completed
    scan_record = db_repository.get_scan(scan_id)
    assert scan_record.status == "COMPLETED"
    assert scan_record.resources_scanned > 0

    # Should have findings
    findings = db_repository.get_findings_by_scan(scan_id)
    assert len(findings) >= 2  # At least S3 + SecurityGroup
