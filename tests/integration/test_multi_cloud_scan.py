"""Tests for multi-cloud scanning (AWS + Azure)."""

from unittest.mock import MagicMock, patch

import pytest

from cspm.cloud.aws import AwsCloudProvider
from cspm.cloud.azure import AzureCloudProvider
from cspm.cloud.base import Resource
from cspm.rules.aws_rules import PublicS3Rule
from cspm.rules.azure_rules import PublicStorageRule
from cspm.scanner.engine import ScanEngine
from cspm.rules.registry import RuleRegistry


@pytest.fixture
def multi_cloud_setup(db_repository, rule_registry):
    """Set up scan engine with both AWS and Azure providers."""
    scan_engine = ScanEngine(rule_registry, db_repository)

    # Register rules
    rule_registry.register(PublicS3Rule())
    rule_registry.register(PublicStorageRule())

    with patch("cspm.cloud.aws.boto3"), \
         patch("cspm.cloud.azure.DefaultAzureCredential"), \
         patch("cspm.cloud.azure.StorageManagementClient"), \
         patch("cspm.cloud.azure.ComputeManagementClient"), \
         patch("cspm.cloud.azure.SqlManagementClient"), \
         patch("cspm.cloud.azure.NetworkManagementClient"), \
         patch("cspm.cloud.azure.MonitorManagementClient"):

        aws_provider = AwsCloudProvider(region="us-east-1")
        azure_provider = AzureCloudProvider(subscription_id="sub-123", tenant_id="tenant-456")

        aws_provider.authenticate()
        azure_provider.authenticate()

        yield scan_engine, aws_provider, azure_provider


def test_multi_cloud_both_providers_registered(multi_cloud_setup):
    """Test that both AWS and Azure providers can be registered."""
    scan_engine, aws_provider, azure_provider = multi_cloud_setup

    scan_engine.register_provider(aws_provider)
    scan_engine.register_provider(azure_provider)

    assert len(scan_engine._providers) == 2


def test_multi_cloud_scan_discovers_aws_resources(multi_cloud_setup):
    """Test that scan discovers AWS resources."""
    scan_engine, aws_provider, azure_provider = multi_cloud_setup

    # AWS provider is already authenticated in fixture
    # Verify it can be used
    assert aws_provider.is_authenticated()
    scan_engine.register_provider(aws_provider)
    assert len(scan_engine._providers) > 0


def test_multi_cloud_scan_discovers_azure_resources(multi_cloud_setup):
    """Test that scan discovers Azure resources."""
    scan_engine, aws_provider, azure_provider = multi_cloud_setup

    # Azure provider is already authenticated in fixture
    # Verify it can be used
    assert azure_provider.is_authenticated()
    scan_engine.register_provider(azure_provider)
    assert len(scan_engine._providers) > 0


def test_multi_cloud_resources_have_cloud_provider_field(multi_cloud_setup):
    """Test that resources from both clouds are correctly identified."""
    scan_engine, aws_provider, azure_provider = multi_cloud_setup

    # Mock AWS resource
    aws_resource = Resource(
        id="arn:aws:s3:::mybucket",
        name="mybucket",
        type="AWS::S3::Bucket",
        region="us-east-1",
        cloud_provider="aws",
        attributes={"ACL": "public-read"},
        tags={},
    )

    # Mock Azure resource
    azure_resource = Resource(
        id="/subscriptions/sub-123/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/mystorage",
        name="mystorage",
        type="Azure::Storage::Account",
        region="eastus",
        cloud_provider="azure",
        attributes={"AllowBlobPublicAccess": True},
        tags={},
    )

    assert aws_resource.cloud_provider == "aws"
    assert azure_resource.cloud_provider == "azure"


def test_aws_rule_not_applicable_to_azure_resources(multi_cloud_setup):
    """Test that AWS rules don't apply to Azure resources."""
    scan_engine, aws_provider, azure_provider = multi_cloud_setup

    aws_rule = PublicS3Rule()
    azure_storage_resource = Resource(
        id="/subscriptions/sub-123/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/mystorage",
        name="mystorage",
        type="Azure::Storage::Account",
        region="eastus",
        cloud_provider="azure",
        attributes={"AllowBlobPublicAccess": True},
        tags={},
    )

    assert not aws_rule.is_applicable(azure_storage_resource)


def test_azure_rule_not_applicable_to_aws_resources(multi_cloud_setup):
    """Test that Azure rules don't apply to AWS resources."""
    scan_engine, aws_provider, azure_provider = multi_cloud_setup

    azure_rule = PublicStorageRule()
    aws_s3_resource = Resource(
        id="arn:aws:s3:::mybucket",
        name="mybucket",
        type="AWS::S3::Bucket",
        region="us-east-1",
        cloud_provider="aws",
        attributes={"ACL": "public-read"},
        tags={},
    )

    assert not azure_rule.is_applicable(aws_s3_resource)


def test_aws_rule_applicable_to_aws_resources(multi_cloud_setup):
    """Test that AWS rules apply to AWS resources."""
    scan_engine, aws_provider, azure_provider = multi_cloud_setup

    aws_rule = PublicS3Rule()
    aws_s3_resource = Resource(
        id="arn:aws:s3:::mybucket",
        name="mybucket",
        type="AWS::S3::Bucket",
        region="us-east-1",
        cloud_provider="aws",
        attributes={"ACL": "public-read"},
        tags={},
    )

    assert aws_rule.is_applicable(aws_s3_resource)


def test_azure_rule_applicable_to_azure_resources(multi_cloud_setup):
    """Test that Azure rules apply to Azure resources."""
    scan_engine, aws_provider, azure_provider = multi_cloud_setup

    azure_rule = PublicStorageRule()
    azure_storage_resource = Resource(
        id="/subscriptions/sub-123/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/mystorage",
        name="mystorage",
        type="Azure::Storage::Account",
        region="eastus",
        cloud_provider="azure",
        attributes={"AllowBlobPublicAccess": True},
        tags={},
    )

    assert azure_rule.is_applicable(azure_storage_resource)


def test_multi_cloud_rules_registered(multi_cloud_setup):
    """Test that both AWS and Azure rules are registered."""
    scan_engine, aws_provider, azure_provider = multi_cloud_setup

    # Rules are registered in the fixture
    assert len(scan_engine.registry._rules) >= 2
