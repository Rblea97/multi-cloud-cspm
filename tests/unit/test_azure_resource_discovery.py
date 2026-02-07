"""Tests for Azure resource discovery methods."""

from unittest.mock import MagicMock, patch

import pytest

from cspm.cloud.azure import AzureCloudProvider
from cspm.cloud.base import Resource


@pytest.fixture
def azure_provider_authenticated():
    """Create an authenticated Azure provider with mocked clients."""
    with patch("cspm.cloud.azure.DefaultAzureCredential"), \
         patch("cspm.cloud.azure.StorageManagementClient") as mock_storage, \
         patch("cspm.cloud.azure.ComputeManagementClient") as mock_compute, \
         patch("cspm.cloud.azure.SqlManagementClient") as mock_sql, \
         patch("cspm.cloud.azure.NetworkManagementClient") as mock_network, \
         patch("cspm.cloud.azure.MonitorManagementClient") as mock_monitor:

        provider = AzureCloudProvider(subscription_id="sub-123", tenant_id="tenant-456")
        provider.authenticate()
        provider.storage_client = mock_storage
        provider.compute_client = mock_compute
        provider.sql_client = mock_sql
        provider.network_client = mock_network
        provider.monitor_client = mock_monitor
        yield provider


# Cycle 3: Blob Storage Resource Discovery
def test_get_storage_resources_empty(azure_provider_authenticated):
    """Test get_storage_resources returns empty list when no accounts exist."""
    azure_provider_authenticated.storage_client.storage_accounts.list.return_value = []
    resources = azure_provider_authenticated._get_storage_resources()
    assert resources == []


def test_get_storage_resources_returns_storage_accounts(azure_provider_authenticated):
    """Test get_storage_resources returns storage account resources."""
    mock_account = MagicMock()
    mock_account.id = "/subscriptions/sub-123/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/myaccount"
    mock_account.name = "myaccount"
    mock_account.type = "Azure::Storage::Account"
    mock_account.location = "eastus"
    mock_account.properties = MagicMock()
    mock_account.properties.allow_blob_public_access = True
    mock_account.properties.access_tier = "Hot"
    mock_account.properties.kind = "StorageV2"

    azure_provider_authenticated.storage_client.storage_accounts.list.return_value = [mock_account]

    resources = azure_provider_authenticated._get_storage_resources()

    assert len(resources) == 1
    assert resources[0].name == "myaccount"
    assert resources[0].type == "Azure::Storage::Account"
    assert resources[0].cloud_provider == "azure"


def test_get_resources_with_storage_type(azure_provider_authenticated):
    """Test get_resources with storage type."""
    mock_account = MagicMock()
    mock_account.id = "/subscriptions/sub-123/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/myaccount"
    mock_account.name = "myaccount"
    mock_account.properties = MagicMock()
    mock_account.properties.allow_blob_public_access = False
    mock_account.properties.access_tier = "Hot"
    mock_account.properties.kind = "StorageV2"

    azure_provider_authenticated.storage_client.storage_accounts.list.return_value = [mock_account]

    resources = azure_provider_authenticated.get_resources("storage")

    assert len(resources) == 1
    assert resources[0].type == "Azure::Storage::Account"


# Cycle 4: VM and SQL Resource Discovery
def test_get_compute_resources_empty(azure_provider_authenticated):
    """Test get_compute_resources returns empty list when no VMs exist."""
    mock_group = MagicMock()
    mock_group.name = "rg1"
    azure_provider_authenticated.compute_client.resource_groups.list.return_value = [mock_group]
    azure_provider_authenticated.compute_client.virtual_machines.list_by_resource_group.return_value = []

    resources = azure_provider_authenticated._get_compute_resources()
    assert resources == []


def test_get_compute_resources_returns_vms(azure_provider_authenticated):
    """Test get_compute_resources returns VM resources."""
    mock_group = MagicMock()
    mock_group.name = "rg1"
    mock_vm = MagicMock()
    mock_vm.id = "/subscriptions/sub-123/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1"
    mock_vm.name = "vm1"
    mock_vm.location = "eastus"
    mock_vm.hardware_profile = MagicMock()
    mock_vm.hardware_profile.vm_size = "Standard_D2s_v3"
    mock_vm.os_profile = MagicMock()
    mock_vm.os_profile.os_type = "Linux"
    mock_vm.network_profile = MagicMock()

    azure_provider_authenticated.compute_client.resource_groups.list.return_value = [mock_group]
    azure_provider_authenticated.compute_client.virtual_machines.list_by_resource_group.return_value = [mock_vm]

    resources = azure_provider_authenticated._get_compute_resources()

    assert len(resources) == 1
    assert resources[0].name == "vm1"
    assert resources[0].type == "Azure::Compute::VirtualMachine"
    assert resources[0].cloud_provider == "azure"


def test_get_sql_resources_empty(azure_provider_authenticated):
    """Test get_sql_resources returns empty list when no databases exist."""
    mock_server = MagicMock()
    mock_server.name = "server1"
    azure_provider_authenticated.sql_client.servers.list.return_value = [mock_server]
    azure_provider_authenticated.sql_client.databases.list_by_server.return_value = []

    resources = azure_provider_authenticated._get_sql_resources()
    assert resources == []


def test_get_sql_resources_returns_databases(azure_provider_authenticated):
    """Test get_sql_resources returns SQL database resources."""
    mock_server = MagicMock()
    mock_server.name = "server1"
    mock_server.id = "/subscriptions/sub-123/resourceGroups/rg1/providers/Microsoft.Sql/servers/server1"
    mock_db = MagicMock()
    mock_db.id = "/subscriptions/sub-123/resourceGroups/rg1/providers/Microsoft.Sql/servers/server1/databases/db1"
    mock_db.name = "db1"
    mock_db.location = "eastus"
    mock_db.sku = MagicMock()
    mock_db.sku.name = "Basic"
    mock_db.sku.tier = "Basic"

    azure_provider_authenticated.sql_client.servers.list.return_value = [mock_server]
    azure_provider_authenticated.sql_client.databases.list_by_server.return_value = [mock_db]

    resources = azure_provider_authenticated._get_sql_resources()

    assert len(resources) == 1
    assert resources[0].name == "db1"
    assert resources[0].type == "Azure::SQL::Database"
    assert resources[0].cloud_provider == "azure"


# Cycle 5: NSG and Monitor Resource Discovery
def test_get_nsg_resources_empty(azure_provider_authenticated):
    """Test get_nsg_resources returns empty list when no NSGs exist."""
    mock_group = MagicMock()
    mock_group.name = "rg1"
    azure_provider_authenticated.network_client.resource_groups.list.return_value = [mock_group]
    azure_provider_authenticated.network_client.network_security_groups.list.return_value = []

    resources = azure_provider_authenticated._get_nsg_resources()
    assert resources == []


def test_get_nsg_resources_returns_nsgs(azure_provider_authenticated):
    """Test get_nsg_resources returns NSG resources."""
    mock_group = MagicMock()
    mock_group.name = "rg1"
    mock_nsg = MagicMock()
    mock_nsg.id = "/subscriptions/sub-123/resourceGroups/rg1/providers/Microsoft.Network/networkSecurityGroups/nsg1"
    mock_nsg.name = "nsg1"
    mock_nsg.location = "eastus"
    mock_nsg.security_rules = []

    azure_provider_authenticated.network_client.resource_groups.list.return_value = [mock_group]
    azure_provider_authenticated.network_client.network_security_groups.list.return_value = [mock_nsg]

    resources = azure_provider_authenticated._get_nsg_resources()

    assert len(resources) == 1
    assert resources[0].name == "nsg1"
    assert resources[0].type == "Azure::Network::NetworkSecurityGroup"
    assert resources[0].cloud_provider == "azure"


def test_get_monitor_resources_returns_activity_log_default(azure_provider_authenticated):
    """Test get_monitor_resources returns activity log by default."""
    resources = azure_provider_authenticated._get_monitor_resources()
    assert len(resources) == 1
    assert resources[0].type == "Azure::Monitor::ActivityLog"


def test_get_monitor_resources_returns_activity_log(azure_provider_authenticated):
    """Test get_monitor_resources returns activity log resource."""
    # Activity log is a single per subscription
    resources = azure_provider_authenticated._get_monitor_resources()

    # For now, we expect at least a basic structure
    # The implementation will need to return the activity log as a resource
    assert isinstance(resources, list)


def test_get_resources_with_all_types(azure_provider_authenticated):
    """Test get_resources without type returns all resource types."""
    # Setup mocks for all resource types
    mock_storage_acct = MagicMock()
    mock_storage_acct.name = "mystorage"
    mock_storage_acct.id = "/subscriptions/sub-123/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/mystorage"
    mock_storage_acct.location = "eastus"
    mock_storage_acct.properties = MagicMock()
    mock_storage_acct.properties.allow_blob_public_access = False

    mock_group = MagicMock()
    mock_group.name = "rg1"

    azure_provider_authenticated.storage_client.storage_accounts.list.return_value = [mock_storage_acct]
    azure_provider_authenticated.compute_client.resource_groups.list.return_value = [mock_group]
    azure_provider_authenticated.compute_client.virtual_machines.list_by_resource_group.return_value = []
    azure_provider_authenticated.sql_client.servers.list.return_value = []
    azure_provider_authenticated.network_client.resource_groups.list.return_value = [mock_group]
    azure_provider_authenticated.network_client.network_security_groups.list.return_value = []

    resources = azure_provider_authenticated.get_resources()

    # Should have at least storage account
    assert any(r.type == "Azure::Storage::Account" for r in resources)
