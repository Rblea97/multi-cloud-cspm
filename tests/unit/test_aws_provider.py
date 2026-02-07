"""Tests for AWS CloudProvider implementation."""

from unittest.mock import MagicMock, patch

import pytest

from cspm.cloud.aws import AwsCloudProvider
from cspm.cloud.base import CloudProvider


@pytest.fixture
def mock_boto3_session():
    """Mock boto3.Session."""
    with patch("cspm.cloud.aws.boto3") as mock_boto3:
        yield mock_boto3


@pytest.fixture
def aws_provider(mock_boto3_session):
    """Create an AWS provider with mocked boto3."""
    provider = AwsCloudProvider(region="us-east-1")
    provider.authenticate()
    return provider


def test_aws_provider_can_be_instantiated(mock_boto3_session):
    """Test that AwsCloudProvider can be created."""
    provider = AwsCloudProvider(region="us-east-1")
    assert provider is not None


def test_aws_provider_inherits_from_cloud_provider(mock_boto3_session):
    """Test that AwsCloudProvider extends CloudProvider base class."""
    provider = AwsCloudProvider(region="us-east-1")
    assert isinstance(provider, CloudProvider)


def test_aws_provider_authenticate(mock_boto3_session):
    """Test that AWS provider can authenticate."""
    provider = AwsCloudProvider(region="us-east-1")
    result = provider.authenticate()
    assert result is True


def test_aws_provider_is_authenticated(aws_provider):
    """Test that AWS provider tracks authentication status."""
    assert aws_provider.is_authenticated() is True


def test_aws_provider_get_resources_s3(aws_provider):
    """Test that AWS provider can get S3 resources."""
    # Mock the S3 client
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {
        "Buckets": [
            {"Name": "public-bucket"},
            {"Name": "private-bucket"},
        ]
    }
    aws_provider.s3_client = mock_s3

    resources = aws_provider.get_resources("s3")

    assert len(resources) == 2
    assert any(r.name == "public-bucket" for r in resources)
    assert any(r.name == "private-bucket" for r in resources)
