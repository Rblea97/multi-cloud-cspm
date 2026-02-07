"""Alert manager for orchestrating alert processing."""

import logging
import uuid
from datetime import datetime
from typing import Any

from cspm.alerts.channels import AlertChannel
from cspm.alerts.models import Alert, AlertType
from cspm.database.repository import Repository

logger = logging.getLogger(__name__)


class AlertManager:
    """Orchestrate alert processing and dispatch to channels."""

    def __init__(
        self,
        repository: Repository,
        channels: list[AlertChannel],
        severity_threshold: str = "HIGH",
    ):
        """Initialize alert manager."""
        self.repository = repository
        self.channels = channels
        self.severity_threshold = severity_threshold

    def send_alert(self, alert: Alert) -> list[bool]:
        """Send alert to all enabled channels."""
        if not alert.severity_meets_threshold(self.severity_threshold):
            return []

        results = []
        for channel in self.channels:
            try:
                result = channel.send_alert(alert)
                results.append(result)
            except Exception as e:
                logger.error(f"Error sending alert to channel: {e}")
                results.append(False)
        return results

    def process_scan_alerts(self, scan_id: str) -> list[Alert]:
        """Process findings from a scan and send alerts."""
        findings = self.repository.get_findings_by_scan(scan_id)
        alerts = []

        for finding in findings:
            alert = self._finding_to_alert(finding)
            if alert.severity_meets_threshold(self.severity_threshold):
                alerts.append(alert)
                self.send_alert(alert)

        return alerts

    def process_compliance_alerts(self, scan_id: str) -> list[Alert]:
        """Process compliance failures from a scan and send alerts."""
        results = self.repository.get_compliance_results(scan_id)
        alerts = []

        for result in results:
            if result.status != "FAIL":
                continue
            alert = self._compliance_to_alert(result)
            alerts.append(alert)
            self.send_alert(alert)

        return alerts

    def _finding_to_alert(self, finding: Any) -> Alert:
        """Convert Finding database model to Alert."""
        return Alert(
            id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            alert_type=AlertType.FINDING,
            severity=finding.severity,
            source_id=finding.id,
            title=finding.title,
            description=finding.description,
            affected_resources=[finding.resource_id],
            cloud_provider=finding.cloud_provider,
            evidence=finding.evidence,
            metadata={"rule_id": finding.rule_id, "rule_name": finding.rule_name},
        )

    def _compliance_to_alert(self, result: Any) -> Alert:
        """Convert ComplianceResult database model to Alert."""
        return Alert(
            id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            alert_type=AlertType.COMPLIANCE,
            severity="HIGH",  # Compliance failures are always HIGH
            source_id=result.id,
            title=f"{result.framework} Control {result.control_id} Failed",
            description=result.control_title,
            affected_resources=[],
            cloud_provider="MULTI",
            evidence=result.evidence,
            metadata={
                "framework": result.framework,
                "control_id": result.control_id,
                "finding_count": result.finding_count,
            },
        )
