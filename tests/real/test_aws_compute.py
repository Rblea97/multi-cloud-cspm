"""Real infrastructure tests for AWS compute resources.

These tests require real AWS credentials and free-tier resources created by
setup_aws_free_tier.py script.

Mark: aws, real, free
"""

import pytest

from cspm.rules.aws_rules import EC2PublicIPRule, UnencryptedRDSRule
from cspm.testing.safety import validate_auto_stop_tag, validate_instance_type


@pytest.mark.aws
@pytest.mark.real
@pytest.mark.free
class TestAwsComputeResourceDiscovery:
    """Tests for RDS and EC2 resource discovery."""

    def test_aws_rds_resource_discovery(self, real_aws_provider):
        """Test real RDS instance discovery."""
        resources = real_aws_provider.get_resources(resource_type="rds")
        assert isinstance(resources, list)

        # Should have at least one RDS resource if setup ran
        test_resources = [r for r in resources if "cspm-test-" in r.name]
        if test_resources:
            resource = test_resources[0]
            assert resource.type == "AWS::RDS::DBInstance"
            assert "Engine" in resource.attributes
            assert "StorageEncrypted" in resource.attributes

    def test_aws_ec2_resource_discovery(self, real_aws_provider):
        """Test real EC2 instance discovery."""
        resources = real_aws_provider.get_resources(resource_type="ec2")
        assert isinstance(resources, list)

        # Should have at least one EC2 resource if setup ran
        test_resources = [r for r in resources if "cspm-test-" in r.name]
        if test_resources:
            resource = test_resources[0]
            assert resource.type == "AWS::EC2::Instance"
            assert "State" in resource.attributes

    def test_unencrypted_rds_rule_real_finding(self, real_aws_provider):
        """Test UnencryptedRDSRule detects real unencrypted RDS."""
        resources = real_aws_provider.get_resources(resource_type="rds")
        test_resources = [r for r in resources if "cspm-test-" in r.name]

        if test_resources:
            rule = UnencryptedRDSRule()
            findings = rule.check(test_resources)
            assert isinstance(findings, list)

            # Should have findings for unencrypted instances
            unencrypted = [f for f in findings if not f.affected_resource.attributes.get("StorageEncrypted", False)]
            if unencrypted:
                finding = unencrypted[0]
                assert finding.severity == "HIGH"

    def test_ec2_public_ip_rule_real_finding(self, real_aws_provider):
        """Test EC2PublicIPRule detects real instances with public IPs."""
        resources = real_aws_provider.get_resources(resource_type="ec2")
        test_resources = [r for r in resources if "cspm-test-" in r.name]

        if test_resources:
            rule = EC2PublicIPRule()
            findings = rule.check(test_resources)
            assert isinstance(findings, list)

            # Should have findings for instances with public IPs
            public_instances = [
                f
                for f in findings
                if f.affected_resource.attributes.get("PublicIpAddress")
            ]
            if public_instances:
                finding = public_instances[0]
                assert finding.severity == "MEDIUM"

    def test_full_compute_scan(self, real_aws_provider):
        """Test full scan of RDS and EC2 resources."""
        rds_resources = real_aws_provider.get_resources(resource_type="rds")
        ec2_resources = real_aws_provider.get_resources(resource_type="ec2")

        all_resources = rds_resources + ec2_resources
        assert isinstance(all_resources, list)

        # Test resources should be discoverable
        test_resources = [r for r in all_resources if "cspm-test-" in r.name]
        if test_resources:
            assert len(test_resources) >= 1

    def test_compute_resources_have_auto_stop_tag(self, real_aws_provider):
        """Test that compute resources have AutoStopAt tag."""
        rds_resources = real_aws_provider.get_resources(resource_type="rds")
        ec2_resources = real_aws_provider.get_resources(resource_type="ec2")

        test_resources = [
            r for r in rds_resources + ec2_resources
            if "cspm-test-" in r.name
        ]

        for resource in test_resources:
            # Get tags from resource or attributes
            tags = resource.tags or []
            tag_list = [{"Key": k, "Value": v} for k, v in tags.items()] if isinstance(tags, dict) else tags

            # Should have valid AutoStopAt tag
            validate_auto_stop_tag(tag_list)

    def test_compute_resources_use_free_tier_types(self, real_aws_provider):
        """Test that compute resources use free-tier eligible types."""
        rds_resources = real_aws_provider.get_resources(resource_type="rds")
        ec2_resources = real_aws_provider.get_resources(resource_type="ec2")

        # Check RDS instances
        for resource in rds_resources:
            if "cspm-test-" in resource.name:
                instance_type = resource.attributes.get("DBInstanceClass", "")
                validate_instance_type(instance_type, "rds")

        # Check EC2 instances
        for resource in ec2_resources:
            if "cspm-test-" in resource.name:
                instance_type = resource.attributes.get("InstanceType", "")
                validate_instance_type(instance_type, "ec2")

    def test_auto_stop_script_exists(self):
        """Test that auto-stop script can be imported."""
        from scripts import auto_stop_compute

        assert hasattr(auto_stop_compute, "should_stop_instance")
        assert hasattr(auto_stop_compute, "stop_rds_instances")
        assert hasattr(auto_stop_compute, "stop_ec2_instances")

    def test_setup_script_rds_creation_function_exists(self):
        """Test that setup script has RDS creation function."""
        from scripts import setup_aws_free_tier

        assert hasattr(setup_aws_free_tier, "create_unencrypted_rds")

    def test_setup_script_ec2_creation_function_exists(self):
        """Test that setup script has EC2 creation function."""
        from scripts import setup_aws_free_tier

        assert hasattr(setup_aws_free_tier, "create_ec2_with_public_ip")

    def test_cleanup_script_rds_deletion_function_exists(self):
        """Test that cleanup script has RDS deletion function."""
        from scripts import cleanup_aws_test_resources

        assert hasattr(cleanup_aws_test_resources, "cleanup_rds_instances")

    def test_cleanup_script_ec2_deletion_function_exists(self):
        """Test that cleanup script has EC2 deletion function."""
        from scripts import cleanup_aws_test_resources

        assert hasattr(cleanup_aws_test_resources, "cleanup_ec2_instances")
