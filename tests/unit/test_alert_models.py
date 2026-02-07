"""Tests for alert data models."""

from datetime import datetime

import pytest

from cspm.alerts.models import Alert, AlertType


class TestAlertType:
    """Test AlertType enum."""

    def test_alert_type_has_finding(self):
        """AlertType enum should have FINDING."""
        assert AlertType.FINDING.value == "FINDING"

    def test_alert_type_has_compliance(self):
        """AlertType enum should have COMPLIANCE."""
        assert AlertType.COMPLIANCE.value == "COMPLIANCE"

    def test_alert_type_has_anomaly(self):
        """AlertType enum should have ANOMALY."""
        assert AlertType.ANOMALY.value == "ANOMALY"


class TestAlertCreation:
    """Test Alert dataclass creation."""

    def test_alert_creation_with_required_fields(self):
        """Alert should be creatable with required fields."""
        alert = Alert(
            id="alert-1",
            timestamp=datetime.utcnow(),
            alert_type=AlertType.FINDING,
            severity="CRITICAL",
            source_id="finding-1",
            title="Public S3 Bucket",
            description="S3 bucket is publicly accessible",
            affected_resources=["arn:aws:s3:::test-bucket"],
            cloud_provider="AWS",
        )
        assert alert.id == "alert-1"
        assert alert.alert_type == AlertType.FINDING
        assert alert.severity == "CRITICAL"
        assert alert.title == "Public S3 Bucket"

    def test_alert_creation_with_all_fields(self):
        """Alert should be creatable with all fields including optional."""
        alert = Alert(
            id="alert-2",
            timestamp=datetime.utcnow(),
            alert_type=AlertType.COMPLIANCE,
            severity="HIGH",
            source_id="control-1",
            title="CIS Control Failure",
            description="Control CIS 1.1 failed",
            affected_resources=["resource-1", "resource-2"],
            cloud_provider="Azure",
            evidence='{"control_id": "1.1"}',
            metadata={"framework": "CIS_AZURE"},
        )
        assert alert.alert_type == AlertType.COMPLIANCE
        assert len(alert.affected_resources) == 2
        assert alert.evidence is not None
        assert alert.metadata is not None

    def test_alert_severity_meets_threshold_critical(self):
        """CRITICAL alert should meet CRITICAL threshold."""
        alert = Alert(
            id="alert-1",
            timestamp=datetime.utcnow(),
            alert_type=AlertType.FINDING,
            severity="CRITICAL",
            source_id="finding-1",
            title="Test",
            description="Test",
            affected_resources=[],
            cloud_provider="AWS",
        )
        assert alert.severity_meets_threshold("CRITICAL")

    def test_alert_severity_meets_threshold_high(self):
        """HIGH alert should meet HIGH threshold."""
        alert = Alert(
            id="alert-2",
            timestamp=datetime.utcnow(),
            alert_type=AlertType.FINDING,
            severity="HIGH",
            source_id="finding-2",
            title="Test",
            description="Test",
            affected_resources=[],
            cloud_provider="AWS",
        )
        assert alert.severity_meets_threshold("HIGH")
        assert alert.severity_meets_threshold("MEDIUM")
        assert alert.severity_meets_threshold("LOW")

    def test_alert_severity_below_threshold(self):
        """Alert should not meet threshold above its severity."""
        alert = Alert(
            id="alert-3",
            timestamp=datetime.utcnow(),
            alert_type=AlertType.FINDING,
            severity="LOW",
            source_id="finding-3",
            title="Test",
            description="Test",
            affected_resources=[],
            cloud_provider="AWS",
        )
        assert not alert.severity_meets_threshold("CRITICAL")
        assert not alert.severity_meets_threshold("HIGH")
        assert not alert.severity_meets_threshold("MEDIUM")
        assert alert.severity_meets_threshold("LOW")

    def test_alert_severity_info_below_all_thresholds(self):
        """INFO alert should only meet INFO threshold."""
        alert = Alert(
            id="alert-4",
            timestamp=datetime.utcnow(),
            alert_type=AlertType.FINDING,
            severity="INFO",
            source_id="finding-4",
            title="Test",
            description="Test",
            affected_resources=[],
            cloud_provider="AWS",
        )
        assert not alert.severity_meets_threshold("CRITICAL")
        assert not alert.severity_meets_threshold("HIGH")
        assert not alert.severity_meets_threshold("MEDIUM")
        assert not alert.severity_meets_threshold("LOW")
        assert alert.severity_meets_threshold("INFO")

    def test_alert_with_empty_affected_resources(self):
        """Alert should allow empty affected_resources list."""
        alert = Alert(
            id="alert-5",
            timestamp=datetime.utcnow(),
            alert_type=AlertType.COMPLIANCE,
            severity="MEDIUM",
            source_id="control-1",
            title="Test Control",
            description="Test",
            affected_resources=[],
            cloud_provider="AWS",
        )
        assert alert.affected_resources == []
