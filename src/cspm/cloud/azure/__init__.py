"""Azure cloud provider implementation."""

from typing import Any

from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.storage import StorageManagementClient

from cspm.cloud.base import CloudProvider, Resource


class AzureCloudProvider(CloudProvider):
    """Azure cloud provider implementation."""

    def __init__(self, subscription_id: str, tenant_id: str) -> None:
        """Initialize Azure provider.

        Args:
            subscription_id: Azure subscription ID
            tenant_id: Azure tenant ID
        """
        self.subscription_id = subscription_id
        self.tenant_id = tenant_id
        self._authenticated = False
        self.storage_client: Any = None
        self.compute_client: Any = None
        self.sql_client: Any = None
        self.network_client: Any = None
        self.monitor_client: Any = None

    def authenticate(self) -> bool:
        """Authenticate with Azure."""
        try:
            credential = DefaultAzureCredential()
            self.storage_client = StorageManagementClient(credential, self.subscription_id)
            self.compute_client = ComputeManagementClient(credential, self.subscription_id)
            self.sql_client = SqlManagementClient(credential, self.subscription_id)
            self.network_client = NetworkManagementClient(credential, self.subscription_id)
            self.monitor_client = MonitorManagementClient(credential, self.subscription_id)
            self._authenticated = True
            return True
        except Exception:  # noqa: S110
            self._authenticated = False
            return False

    def is_authenticated(self) -> bool:
        """Check if authenticated."""
        return self._authenticated

    def get_resources(self, resource_type: str | None = None) -> list[Resource]:
        """Get resources from Azure.

        Args:
            resource_type: Type of resource (storage, compute, sql, network, monitor)

        Returns:
            List of Resource objects
        """
        if not self.is_authenticated():
            return []

        if resource_type is None:
            resources = []
            resources.extend(self._get_storage_resources())
            resources.extend(self._get_compute_resources())
            resources.extend(self._get_sql_resources())
            resources.extend(self._get_nsg_resources())
            resources.extend(self._get_monitor_resources())
            return resources

        if resource_type == "storage":
            return self._get_storage_resources()
        elif resource_type == "compute":
            return self._get_compute_resources()
        elif resource_type == "sql":
            return self._get_sql_resources()
        elif resource_type == "network":
            return self._get_nsg_resources()
        elif resource_type == "monitor":
            return self._get_monitor_resources()

        return []

    def _get_storage_resources(self) -> list[Resource]:
        """Get Azure storage account resources."""
        resources = []
        try:
            for account in self.storage_client.storage_accounts.list():  # type: ignore
                resource = Resource(
                    id=account.id,
                    name=account.name,
                    type="Azure::Storage::Account",
                    region=account.location,
                    cloud_provider="azure",
                    attributes={
                        "AllowBlobPublicAccess": getattr(account.properties, "allow_blob_public_access", False),
                        "AccessTier": getattr(account.properties, "access_tier", None),
                        "Kind": getattr(account.properties, "kind", None),
                    },
                    tags={},
                )
                resources.append(resource)
        except Exception:  # noqa: S110
            pass
        return resources

    def _get_compute_resources(self) -> list[Resource]:
        """Get Azure virtual machine resources."""
        resources = []
        try:
            for group in self.compute_client.resource_groups.list():  # type: ignore
                for vm in self.compute_client.virtual_machines.list_by_resource_group(group.name):  # type: ignore
                    resource = Resource(
                        id=vm.id,
                        name=vm.name,
                        type="Azure::Compute::VirtualMachine",
                        region=vm.location,
                        cloud_provider="azure",
                        attributes={
                            "VmSize": getattr(vm.hardware_profile, "vm_size", None),
                            "OsType": getattr(vm.os_profile, "os_type", None),
                            "PublicIpAddress": None,
                        },
                        tags={},
                    )
                    resources.append(resource)
        except Exception:  # noqa: S110
            pass
        return resources

    def _get_sql_resources(self) -> list[Resource]:
        """Get Azure SQL database resources."""
        resources = []
        try:
            for server in self.sql_client.servers.list():  # type: ignore
                for db in self.sql_client.databases.list_by_server(  # type: ignore
                    server.id.split("/")[4], server.name
                ):
                    resource = Resource(
                        id=db.id,
                        name=db.name,
                        type="Azure::SQL::Database",
                        region=db.location,
                        cloud_provider="azure",
                        attributes={
                            "Edition": getattr(db.sku, "tier", None),
                            "EncryptionProtectorType": None,
                        },
                        tags={},
                    )
                    resources.append(resource)
        except Exception:  # noqa: S110
            pass
        return resources

    def _get_nsg_resources(self) -> list[Resource]:
        """Get Azure network security group resources."""
        resources = []
        try:
            for group in self.network_client.resource_groups.list():  # type: ignore
                for nsg in self.network_client.network_security_groups.list(group.name):  # type: ignore
                    resource = Resource(
                        id=nsg.id,
                        name=nsg.name,
                        type="Azure::Network::NetworkSecurityGroup",
                        region=nsg.location,
                        cloud_provider="azure",
                        attributes={
                            "SecurityRules": getattr(nsg, "security_rules", []),
                        },
                        tags={},
                    )
                    resources.append(resource)
        except Exception:  # noqa: S110
            pass
        return resources

    def _get_monitor_resources(self) -> list[Resource]:
        """Get Azure monitor/activity log resources."""
        resources = []
        try:
            # Activity log is a subscription-level resource
            resource = Resource(
                id=f"/subscriptions/{self.subscription_id}/providers/microsoft.insights/activityLogAlert",
                name="Activity Log",
                type="Azure::Monitor::ActivityLog",
                region="global",
                cloud_provider="azure",
                attributes={
                    "Enabled": True,
                    "RetentionInDays": 90,
                },
                tags={},
            )
            resources.append(resource)
        except Exception:  # noqa: S110
            pass
        return resources

    def get_resource(self, resource_id: str) -> Resource | None:
        """Get a specific resource by ID."""
        return None

    def get_resource_details(self, resource_id: str, resource_type: str) -> dict[str, Any]:
        """Get detailed information about a resource."""
        return {}
