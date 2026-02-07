"""Abstract base class for cloud providers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class Resource:
    """Represents a cloud resource."""

    id: str
    name: str
    type: str  # AWS::S3::Bucket, Azure::Storage::Account, etc.
    region: str
    cloud_provider: str  # AWS or Azure
    attributes: Dict[str, Any]  # Metadata about the resource
    tags: Dict[str, str]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type,
            "region": self.region,
            "cloud_provider": self.cloud_provider,
            "attributes": self.attributes,
            "tags": self.tags,
        }


class CloudProvider(ABC):
    """Abstract base class for cloud providers."""

    @abstractmethod
    def authenticate(self) -> bool:
        """Authenticate with cloud provider.

        Returns:
            bool: True if authentication successful

        Raises:
            CloudAPIError: If authentication fails
        """
        pass

    @abstractmethod
    def get_resources(self, resource_type: Optional[str] = None) -> List[Resource]:
        """Get all resources, optionally filtered by type.

        Args:
            resource_type: Optional resource type to filter by

        Returns:
            List of Resource objects

        Raises:
            CloudAPIError: If resource discovery fails
        """
        pass

    @abstractmethod
    def get_resource(self, resource_id: str) -> Optional[Resource]:
        """Get a specific resource by ID.

        Args:
            resource_id: The resource ID

        Returns:
            Resource object or None if not found

        Raises:
            CloudAPIError: If API call fails
        """
        pass

    @abstractmethod
    def get_resource_details(self, resource_id: str, resource_type: str) -> Dict[str, Any]:
        """Get detailed information about a resource.

        Args:
            resource_id: The resource ID
            resource_type: The resource type

        Returns:
            Dictionary with resource details

        Raises:
            CloudAPIError: If API call fails
        """
        pass

    @abstractmethod
    def is_authenticated(self) -> bool:
        """Check if currently authenticated.

        Returns:
            bool: True if authenticated
        """
        pass
