"""Tests for Azure CloudProvider implementation."""

from unittest.mock import MagicMock, patch, ANY

import pytest

from cspm.cloud.azure import AzureCloudProvider
from cspm.cloud.base import CloudProvider


def test_azure_provider_can_be_instantiated():
    """Test that AzureCloudProvider can be created."""
    provider = AzureCloudProvider(subscription_id="sub-123", tenant_id="tenant-456")
    assert provider is not None


def test_azure_provider_inherits_from_cloud_provider():
    """Test that AzureCloudProvider extends CloudProvider base class."""
    provider = AzureCloudProvider(subscription_id="sub-123", tenant_id="tenant-456")
    assert isinstance(provider, CloudProvider)


def test_azure_provider_stores_subscription_and_tenant():
    """Test that AzureCloudProvider stores subscription_id and tenant_id."""
    provider = AzureCloudProvider(subscription_id="sub-123", tenant_id="tenant-456")
    assert provider.subscription_id == "sub-123"
    assert provider.tenant_id == "tenant-456"


def test_azure_provider_initializes_clients_to_none():
    """Test that AzureCloudProvider initializes clients to None."""
    provider = AzureCloudProvider(subscription_id="sub-123", tenant_id="tenant-456")
    assert provider.storage_client is None
    assert provider.compute_client is None
    assert provider.sql_client is None
    assert provider.network_client is None
    assert provider.monitor_client is None


def test_azure_provider_sets_authenticated_false():
    """Test that AzureCloudProvider initializes _authenticated to False."""
    provider = AzureCloudProvider(subscription_id="sub-123", tenant_id="tenant-456")
    assert provider._authenticated is False


def test_azure_provider_authenticate():
    """Test that Azure provider can authenticate."""
    with patch("cspm.cloud.azure.DefaultAzureCredential") as mock_cred_class, \
         patch("cspm.cloud.azure.StorageManagementClient") as mock_storage, \
         patch("cspm.cloud.azure.ComputeManagementClient") as mock_compute, \
         patch("cspm.cloud.azure.SqlManagementClient") as mock_sql, \
         patch("cspm.cloud.azure.NetworkManagementClient") as mock_network, \
         patch("cspm.cloud.azure.MonitorManagementClient") as mock_monitor:

        provider = AzureCloudProvider(subscription_id="sub-123", tenant_id="tenant-456")
        result = provider.authenticate()
        assert result is True


def test_azure_provider_is_authenticated():
    """Test that Azure provider tracks authentication status."""
    with patch("cspm.cloud.azure.DefaultAzureCredential"), \
         patch("cspm.cloud.azure.StorageManagementClient"), \
         patch("cspm.cloud.azure.ComputeManagementClient"), \
         patch("cspm.cloud.azure.SqlManagementClient"), \
         patch("cspm.cloud.azure.NetworkManagementClient"), \
         patch("cspm.cloud.azure.MonitorManagementClient"):

        provider = AzureCloudProvider(subscription_id="sub-123", tenant_id="tenant-456")
        provider.authenticate()
        assert provider.is_authenticated() is True


def test_azure_provider_authenticate_initializes_clients():
    """Test that authenticate() initializes all client objects."""
    with patch("cspm.cloud.azure.DefaultAzureCredential"), \
         patch("cspm.cloud.azure.StorageManagementClient") as mock_storage, \
         patch("cspm.cloud.azure.ComputeManagementClient") as mock_compute, \
         patch("cspm.cloud.azure.SqlManagementClient") as mock_sql, \
         patch("cspm.cloud.azure.NetworkManagementClient") as mock_network, \
         patch("cspm.cloud.azure.MonitorManagementClient") as mock_monitor:

        provider = AzureCloudProvider(subscription_id="sub-123", tenant_id="tenant-456")
        provider.authenticate()
        assert provider.storage_client is not None
        assert provider.compute_client is not None
        assert provider.sql_client is not None
        assert provider.network_client is not None
        assert provider.monitor_client is not None
