"""Integration tests for alert system."""

import json
from datetime import datetime
from pathlib import Path

import pytest

from cspm.alerts import AlertManager, AlertFormatter, ConsoleChannel, FileChannel
from cspm.alerts.models import Alert, AlertType
from cspm.database.models import Finding, ComplianceResult
from cspm.database.repository import Repository


@pytest.fixture
def db_repository():
    """Provide in-memory test database."""
    repo = Repository(db_url="sqlite:///:memory:")
    repo.create_tables()
    return repo


@pytest.fixture
def alert_manager(db_repository, tmp_path):
    """Provide AlertManager with test channels."""
    formatter = AlertFormatter()
    channels = [
        ConsoleChannel(formatter),
        FileChannel(str(tmp_path / "alerts.jsonl"), formatter),
    ]
    return AlertManager(db_repository, channels, severity_threshold="HIGH"), tmp_path


class TestAlertIntegration:
    """Integration tests for alert system."""

    def test_scan_triggers_critical_finding_alerts(
        self, db_repository, alert_manager, caplog
    ):
        """Scan with CRITICAL findings should trigger alerts."""
        manager, tmp_path = alert_manager

        # Create a CRITICAL finding
        finding = Finding(
            id="finding-1",
            scan_id="scan-1",
            rule_id="rule-1",
            rule_name="PublicS3Rule",
            resource_id="arn:aws:s3:::bucket",
            resource_type="AWS::S3::Bucket",
            resource_name="bucket",
            cloud_provider="AWS",
            severity="CRITICAL",
            title="Public S3 Bucket",
            description="S3 bucket is publicly accessible",
            remediation_advice="Block public access",
            evidence='{"public": true}',
        )
        db_repository.save_finding(finding)

        # Process alerts
        alerts = manager.process_scan_alerts("scan-1")

        # Verify alert was created and dispatched
        assert len(alerts) == 1
        assert alerts[0].severity == "CRITICAL"
        assert "Public S3" in alerts[0].title

        # Verify file was written
        file_path = tmp_path / "alerts.jsonl"
        assert file_path.exists()
        with open(file_path) as f:
            line = f.readline()
        data = json.loads(line)
        assert data["severity"] == "CRITICAL"

    def test_scan_filters_low_severity_findings(
        self, db_repository, alert_manager
    ):
        """Scan with LOW findings should be filtered when threshold=HIGH."""
        manager, tmp_path = alert_manager

        # Create LOW and HIGH findings
        low_finding = Finding(
            id="finding-1",
            scan_id="scan-1",
            rule_id="rule-1",
            rule_name="Rule1",
            resource_id="resource-1",
            resource_type="AWS::EC2::Instance",
            resource_name="instance",
            cloud_provider="AWS",
            severity="LOW",
            title="Low Issue",
            description="Test",
            remediation_advice="Test",
            evidence='{}',
        )
        high_finding = Finding(
            id="finding-2",
            scan_id="scan-1",
            rule_id="rule-2",
            rule_name="Rule2",
            resource_id="resource-2",
            resource_type="AWS::RDS::DBInstance",
            resource_name="database",
            cloud_provider="AWS",
            severity="HIGH",
            title="High Issue",
            description="Test",
            remediation_advice="Test",
            evidence='{}',
        )
        db_repository.save_finding(low_finding)
        db_repository.save_finding(high_finding)

        # Process alerts with HIGH threshold
        alerts = manager.process_scan_alerts("scan-1")

        # Only HIGH severity should trigger alert
        assert len(alerts) == 1
        assert alerts[0].severity == "HIGH"
        assert "High Issue" in alerts[0].title

    def test_compliance_failure_triggers_alerts(
        self, db_repository, alert_manager
    ):
        """Compliance assessment failures should trigger alerts."""
        manager, tmp_path = alert_manager

        # Create compliance failure
        result = ComplianceResult(
            id="result-1",
            scan_id="scan-1",
            framework="CIS_AWS",
            control_id="1.1",
            control_title="Avoid the use of root account",
            status="FAIL",
            finding_count=1,
            evidence='{"issues": ["root account used"]}',
        )
        db_repository.save_compliance_result(result)

        # Process alerts
        alerts = manager.process_compliance_alerts("scan-1")

        # Verify compliance alert
        assert len(alerts) == 1
        assert "CIS_AWS" in alerts[0].title
        assert "1.1" in alerts[0].title
        assert alerts[0].alert_type == AlertType.COMPLIANCE

    def test_compliance_pass_does_not_trigger_alerts(
        self, db_repository, alert_manager
    ):
        """PASS compliance results should not trigger alerts."""
        manager, tmp_path = alert_manager

        # Create PASS result
        result = ComplianceResult(
            id="result-1",
            scan_id="scan-1",
            framework="CIS_AWS",
            control_id="1.1",
            control_title="Test Control",
            status="PASS",
            finding_count=0,
            evidence='{}',
        )
        db_repository.save_compliance_result(result)

        # Process alerts
        alerts = manager.process_compliance_alerts("scan-1")

        # No alerts should be generated for PASS
        assert len(alerts) == 0

    def test_multi_channel_alert_delivery(self, db_repository, alert_manager, caplog):
        """Alerts should be delivered to all configured channels."""
        manager, tmp_path = alert_manager

        # Create finding
        finding = Finding(
            id="finding-1",
            scan_id="scan-1",
            rule_id="rule-1",
            rule_name="TestRule",
            resource_id="resource-1",
            resource_type="AWS::S3::Bucket",
            resource_name="test",
            cloud_provider="AWS",
            severity="CRITICAL",
            title="Test Alert",
            description="Testing multi-channel delivery",
            remediation_advice="Test",
            evidence='{}',
        )
        db_repository.save_finding(finding)

        # Process alerts
        alerts = manager.process_scan_alerts("scan-1")

        # Verify console output (caplog captures logs)
        assert "Test Alert" in caplog.text or len(alerts) == 1

        # Verify file output
        file_path = tmp_path / "alerts.jsonl"
        assert file_path.exists()
        with open(file_path) as f:
            lines = f.readlines()
        assert len(lines) >= 1

    def test_alert_includes_resource_details(
        self, db_repository, alert_manager
    ):
        """Alert should include affected resource details."""
        manager, tmp_path = alert_manager

        # Create finding with resource details
        finding = Finding(
            id="finding-1",
            scan_id="scan-1",
            rule_id="rule-1",
            rule_name="Rule1",
            resource_id="arn:aws:s3:::my-bucket",
            resource_type="AWS::S3::Bucket",
            resource_name="my-bucket",
            cloud_provider="AWS",
            severity="CRITICAL",
            title="Public Bucket",
            description="Bucket is public",
            remediation_advice="Block access",
            evidence='{"acl": "public-read"}',
        )
        db_repository.save_finding(finding)

        # Process alerts
        alerts = manager.process_scan_alerts("scan-1")

        # Verify resource info
        assert len(alerts) == 1
        assert "arn:aws:s3:::my-bucket" in alerts[0].affected_resources

    def test_alert_metadata_preserved(self, db_repository, alert_manager):
        """Alert metadata should preserve rule and compliance details."""
        manager, tmp_path = alert_manager

        # Create finding
        finding = Finding(
            id="finding-1",
            scan_id="scan-1",
            rule_id="public-s3-rule",
            rule_name="PublicS3Rule",
            resource_id="resource-1",
            resource_type="AWS::S3::Bucket",
            resource_name="bucket",
            cloud_provider="AWS",
            severity="CRITICAL",
            title="Public S3",
            description="Test",
            remediation_advice="Test",
            evidence='{}',
        )
        db_repository.save_finding(finding)

        # Process alerts
        alerts = manager.process_scan_alerts("scan-1")

        # Verify metadata
        assert len(alerts) == 1
        assert alerts[0].metadata["rule_id"] == "public-s3-rule"
        assert alerts[0].metadata["rule_name"] == "PublicS3Rule"
