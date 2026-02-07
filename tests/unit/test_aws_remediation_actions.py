"""Unit tests for AWS remediation actions."""

import pytest
from unittest.mock import MagicMock, patch

from cspm.remediation.aws_actions import (
    RemediatePublicS3Bucket,
    RemediateUnencryptedRDS,
    RemediateEC2PublicIP,
    RemediateOpenSecurityGroup,
    RemediateCloudTrailDisabled,
)
from cspm.remediation.base import RemediationMode, RemediationStatus


class TestRemediatePublicS3Bucket:
    """Test S3 bucket remediation."""

    def test_action_properties(self):
        """Verify action properties."""
        action = RemediatePublicS3Bucket()
        assert action.action_id == "RemediatePublicS3Bucket"
        assert action.name == "Block Public S3 Bucket Access"
        assert action.rule_id == "PublicS3Rule"
        assert action.cloud_provider == "aws"
        assert "AWS::S3::Bucket" in action.resource_types
        assert action.requires_approval is True

    def test_validate_s3_bucket(self):
        """Validate S3 bucket resource."""
        action = RemediatePublicS3Bucket()
        resource = {"type": "AWS::S3::Bucket", "name": "test-bucket"}
        assert action.validate(resource) is True

    def test_validate_non_s3_resource(self):
        """Reject non-S3 resources."""
        action = RemediatePublicS3Bucket()
        resource = {"type": "AWS::EC2::Instance"}
        assert action.validate(resource) is False

    def test_dry_run_execution(self):
        """Dry-run mode returns success without changes."""
        action = RemediatePublicS3Bucket()
        resource = {"type": "AWS::S3::Bucket", "name": "test-bucket"}
        finding = {}

        result = action.execute(resource, finding, RemediationMode.DRY_RUN)

        assert result.success is True
        assert result.status == RemediationStatus.SUCCESS
        assert result.dry_run is True
        assert "action" in result.changes_made

    @patch("cspm.remediation.aws_actions.boto3")
    def test_auto_fix_execution(self, mock_boto3):
        """Auto-fix mode calls boto3."""
        mock_s3_client = MagicMock()
        mock_boto3.client.return_value = mock_s3_client

        action = RemediatePublicS3Bucket()
        action._aws_provider = MagicMock()
        action._aws_provider.s3_client = mock_s3_client

        resource = {"type": "AWS::S3::Bucket", "name": "test-bucket"}
        finding = {}

        result = action.execute(resource, finding, RemediationMode.AUTO_FIX)

        assert result.success is True
        assert result.status == RemediationStatus.SUCCESS
        mock_s3_client.put_bucket_acl.assert_called_once()

    @patch("cspm.remediation.aws_actions.boto3")
    def test_auto_fix_error_handling(self, mock_boto3):
        """Error handling in auto-fix mode."""
        mock_s3_client = MagicMock()
        mock_s3_client.put_bucket_acl.side_effect = Exception("Access Denied")
        mock_boto3.client.return_value = mock_s3_client

        action = RemediatePublicS3Bucket()
        action._aws_provider = MagicMock()
        action._aws_provider.s3_client = mock_s3_client

        resource = {"type": "AWS::S3::Bucket", "name": "test-bucket"}
        finding = {}

        result = action.execute(resource, finding, RemediationMode.AUTO_FIX)

        assert result.success is False
        assert result.status == RemediationStatus.FAILED
        assert result.error_message is not None


class TestRemediateUnencryptedRDS:
    """Test RDS encryption remediation."""

    def test_action_properties(self):
        """Verify action properties."""
        action = RemediateUnencryptedRDS()
        assert action.action_id == "RemediateUnencryptedRDS"
        assert action.rule_id == "UnencryptedRDSRule"
        assert action.cloud_provider == "aws"

    def test_validate_rds_instance(self):
        """Validate RDS resource."""
        action = RemediateUnencryptedRDS()
        resource = {"type": "AWS::RDS::DBInstance", "db_instance_identifier": "test-db"}
        assert action.validate(resource) is True

    def test_dry_run_execution(self):
        """Dry-run returns recommendation."""
        action = RemediateUnencryptedRDS()
        resource = {"type": "AWS::RDS::DBInstance", "db_instance_identifier": "test-db"}
        finding = {}

        result = action.execute(resource, finding, RemediationMode.DRY_RUN)

        assert result.success is True
        assert result.dry_run is True


class TestRemediateEC2PublicIP:
    """Test EC2 public IP remediation."""

    def test_action_properties(self):
        """Verify action properties."""
        action = RemediateEC2PublicIP()
        assert action.action_id == "RemediateEC2PublicIP"
        assert action.rule_id == "EC2PublicIPRule"
        assert action.cloud_provider == "aws"

    def test_validate_ec2_instance(self):
        """Validate EC2 resource."""
        action = RemediateEC2PublicIP()
        resource = {"type": "AWS::EC2::Instance", "instance_id": "i-12345"}
        assert action.validate(resource) is True

    def test_dry_run_execution(self):
        """Dry-run returns success."""
        action = RemediateEC2PublicIP()
        resource = {"type": "AWS::EC2::Instance", "instance_id": "i-12345"}
        finding = {}

        result = action.execute(resource, finding, RemediationMode.DRY_RUN)

        assert result.success is True
        assert result.dry_run is True


class TestRemediateOpenSecurityGroup:
    """Test security group remediation."""

    def test_action_properties(self):
        """Verify action properties."""
        action = RemediateOpenSecurityGroup()
        assert action.action_id == "RemediateOpenSecurityGroup"
        assert action.rule_id == "OpenSecurityGroupRule"
        assert action.cloud_provider == "aws"

    def test_validate_security_group(self):
        """Validate security group resource."""
        action = RemediateOpenSecurityGroup()
        resource = {"type": "AWS::EC2::SecurityGroup", "group_id": "sg-12345"}
        assert action.validate(resource) is True

    def test_dry_run_identifies_open_rules(self):
        """Dry-run identifies 0.0.0.0/0 rules."""
        action = RemediateOpenSecurityGroup()
        resource = {
            "type": "AWS::EC2::SecurityGroup",
            "group_id": "sg-12345",
            "ingress_rules": [{"CidrIp": "0.0.0.0/0", "FromPort": 22}],
        }
        finding = {}

        result = action.execute(resource, finding, RemediationMode.DRY_RUN)

        assert result.success is True
        assert result.dry_run is True


class TestRemediateCloudTrailDisabled:
    """Test CloudTrail remediation."""

    def test_action_properties(self):
        """Verify action properties."""
        action = RemediateCloudTrailDisabled()
        assert action.action_id == "RemediateCloudTrailDisabled"
        assert action.rule_id == "CloudTrailDisabledRule"
        assert action.cloud_provider == "aws"
        assert action.requires_approval is True

    def test_validate_cloudtrail(self):
        """Validate CloudTrail resource."""
        action = RemediateCloudTrailDisabled()
        resource = {"type": "AWS::CloudTrail::Trail", "name": "test-trail"}
        assert action.validate(resource) is True

    def test_dry_run_execution(self):
        """Dry-run returns success."""
        action = RemediateCloudTrailDisabled()
        resource = {"type": "AWS::CloudTrail::Trail", "name": "test-trail"}
        finding = {}

        result = action.execute(resource, finding, RemediationMode.DRY_RUN)

        assert result.success is True
        assert result.dry_run is True
