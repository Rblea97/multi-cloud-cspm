"""Base class for security rules."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from cspm.cloud.base import Resource


class RuleSeverity(str, Enum):
    """Severity levels for rule violations."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class RuleResult:
    """Result of rule evaluation."""

    resource: Resource
    has_finding: bool
    severity: RuleSeverity = RuleSeverity.MEDIUM
    title: str = ""
    description: str = ""
    remediation_advice: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)


class BaseRule(ABC):
    """Abstract base class for all security rules."""

    def __init__(self) -> None:
        """Initialize rule."""
        self.rule_id = self.__class__.__name__
        self.name = self.__class__.__name__
        self.description = ""
        self.severity = RuleSeverity.MEDIUM
        self.remediation_advice = ""
        self.cloud_provider = ""  # AWS or Azure
        self.resource_types: list[str] = []

    @abstractmethod
    def evaluate(self, resource: Resource) -> RuleResult:
        """Evaluate the rule against a resource.

        Args:
            resource: The resource to evaluate

        Returns:
            RuleResult indicating if a finding was detected

        Raises:
            RuleExecutionError: If evaluation fails
        """
        pass

    def is_applicable(self, resource: Resource) -> bool:
        """Check if rule applies to a resource type.

        Args:
            resource: The resource to check

        Returns:
            bool: True if rule applies to this resource type
        """
        return resource.type in self.resource_types

    def __str__(self) -> str:
        """String representation."""
        return f"{self.name} ({self.cloud_provider})"
