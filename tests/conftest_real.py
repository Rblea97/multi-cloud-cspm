"""Real cloud provider fixtures for integration testing."""

import os

import pytest

from cspm.cloud.aws import AwsCloudProvider
from cspm.cloud.azure import AzureCloudProvider
from cspm.core.config import Settings


@pytest.fixture
def aws_credentials_available():
    """Check if AWS credentials are configured."""
    return bool(os.getenv("AWS_PROFILE") or os.getenv("AWS_ACCESS_KEY_ID"))


@pytest.fixture
def azure_credentials_available():
    """Check if Azure credentials are configured."""
    return bool(os.getenv("AZURE_SUBSCRIPTION_ID"))


@pytest.fixture
def real_aws_provider(aws_credentials_available):
    """Provide real AWS provider - skips if no credentials."""
    if not aws_credentials_available:
        pytest.skip("AWS credentials not configured")

    settings = Settings()
    provider = AwsCloudProvider(
        region=settings.aws_region,
        profile=os.getenv("AWS_PROFILE"),
    )

    if not provider.authenticate():
        pytest.skip("AWS authentication failed")

    return provider


@pytest.fixture
def real_azure_provider(azure_credentials_available):
    """Provide real Azure provider - skips if no credentials."""
    if not azure_credentials_available:
        pytest.skip("Azure credentials not configured")

    settings = Settings()
    if not settings.azure_subscription_id:
        pytest.skip("Azure subscription ID not configured")

    provider = AzureCloudProvider(
        subscription_id=settings.azure_subscription_id,
        tenant_id=settings.azure_tenant_id,
    )

    if not provider.authenticate():
        pytest.skip("Azure authentication failed")

    return provider


@pytest.fixture
def test_resource_tags():
    """Standard tags for test resources."""
    return {
        "Environment": "test",
        "ManagedBy": "cspm-integration-tests",
        "Purpose": "security-testing",
        "DeleteAfter": "24h",
    }
