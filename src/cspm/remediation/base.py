"""Base classes for remediation actions."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RemediationMode(Enum):
    """Mode for remediation execution."""

    DRY_RUN = "dry_run"
    AUTO_FIX = "auto_fix"


class RemediationStatus(Enum):
    """Status of remediation action."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    APPROVAL_REQUIRED = "approval_required"


@dataclass
class RemediationResult:
    """Result of a remediation action."""

    success: bool
    status: RemediationStatus
    changes_made: dict[str, Any] = field(default_factory=dict)
    error_message: str | None = None
    dry_run: bool = False


class BaseRemediationAction(ABC):
    """Abstract base class for remediation actions."""

    def __init__(self) -> None:
        """Initialize base remediation action."""
        self.action_id: str = ""
        self.name: str = ""
        self.description: str = ""
        self.rule_id: str = ""
        self.cloud_provider: str = ""
        self.resource_types: list[str] = []
        self.requires_approval: bool = False

    @abstractmethod
    def validate(self, resource: dict[str, Any]) -> bool:
        """Validate that resource can be remediated.

        Args:
            resource: Resource to validate

        Returns:
            True if resource can be remediated, False otherwise
        """

    @abstractmethod
    def execute(
        self,
        resource: dict[str, Any],
        finding: dict[str, Any],
        mode: RemediationMode,
    ) -> RemediationResult:
        """Execute remediation action.

        Args:
            resource: Resource to remediate
            finding: Finding that triggered remediation
            mode: Execution mode (DRY_RUN or AUTO_FIX)

        Returns:
            Result of remediation action
        """

    def can_remediate(self, resource: dict[str, Any]) -> bool:
        """Check if resource can be remediated.

        Args:
            resource: Resource to check

        Returns:
            True if resource matches resource_types and validates
        """
        if resource.get("type") not in self.resource_types:
            return False
        return self.validate(resource)
