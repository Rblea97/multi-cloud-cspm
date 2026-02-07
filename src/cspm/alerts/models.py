"""Alert data models."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum


class AlertType(StrEnum):
    """Alert types."""

    FINDING = "FINDING"
    COMPLIANCE = "COMPLIANCE"
    ANOMALY = "ANOMALY"


# Severity hierarchy for threshold comparison
_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


@dataclass
class Alert:
    """Security alert for findings, compliance failures, or anomalies."""

    id: str
    timestamp: datetime
    alert_type: AlertType
    severity: str
    source_id: str
    title: str
    description: str
    affected_resources: list[str]
    cloud_provider: str
    evidence: str | None = None
    metadata: dict | None = field(default_factory=dict)

    def severity_meets_threshold(self, threshold: str) -> bool:
        """Check if alert severity meets or exceeds threshold."""
        severity_level = _SEVERITY_ORDER.get(self.severity, -1)
        threshold_level = _SEVERITY_ORDER.get(threshold, -1)
        return severity_level >= threshold_level
