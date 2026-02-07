"""Alert formatting for different output channels."""

import json

from cspm.alerts.models import Alert


class AlertFormatter:
    """Format alerts for console, file, and email output."""

    def format_console(self, alert: Alert) -> str:
        """Format alert for console output with structured text."""
        timestamp = alert.timestamp.isoformat()
        resources = "\n  - ".join(alert.affected_resources[:5])
        if len(alert.affected_resources) > 5:
            resources += f"\n  - ... and {len(alert.affected_resources) - 5} more"
        return (
            f"[{timestamp}] {alert.severity}: {alert.title}\n"
            f"  Type: {alert.alert_type.value}\n"
            f"  Description: {alert.description}\n"
            f"  Cloud Provider: {alert.cloud_provider}\n"
            f"  Resources:\n  - {resources}"
        )

    def format_file(self, alert: Alert) -> str:
        """Format alert as JSONL (single line JSON)."""
        data = {
            "id": alert.id,
            "timestamp": alert.timestamp.isoformat(),
            "alert_type": alert.alert_type.value,
            "severity": alert.severity,
            "source_id": alert.source_id,
            "title": alert.title,
            "description": alert.description,
            "affected_resources": alert.affected_resources,
            "cloud_provider": alert.cloud_provider,
            "evidence": alert.evidence,
            "metadata": alert.metadata,
        }
        return json.dumps(data)

    def format_email(self, alert: Alert) -> tuple[str, str]:
        """Format alert for email delivery."""
        subject = f"[{alert.severity}] CSPM Alert: {alert.title}"
        resources_html = "".join(
            f"<li>{r}</li>" for r in alert.affected_resources[:10]
        )
        body = (
            f"<html><body>"
            f"<h2>{alert.title}</h2>"
            f"<p><strong>Severity:</strong> {alert.severity}</p>"
            f"<p><strong>Type:</strong> {alert.alert_type.value}</p>"
            f"<p><strong>Description:</strong> {alert.description}</p>"
            f"<p><strong>Cloud Provider:</strong> {alert.cloud_provider}</p>"
            f"<p><strong>Affected Resources:</strong></p>"
            f"<ul>{resources_html}</ul>"
            f"</body></html>"
        )
        return subject, body
