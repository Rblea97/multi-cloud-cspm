"""Compliance framework base classes."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class Control:
    """CIS Control definition."""

    control_id: str
    title: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    domain: str  # Domain like "Logging", "Identity and Access Management"
    rule_ids: list[str] = field(default_factory=list)
    framework_id: str = ""


class ComplianceFramework(ABC):
    """Abstract base class for compliance frameworks."""

    @abstractmethod
    def get_controls(self) -> list[Control]:
        """Get all controls in this framework.

        Returns:
            List of Control objects

        Raises:
            NotImplementedError: Must be implemented by subclass
        """
        pass
