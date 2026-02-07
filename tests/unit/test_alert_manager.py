"""Tests for alert manager."""

from datetime import datetime
from unittest.mock import MagicMock

import pytest

from cspm.alerts.manager import AlertManager
from cspm.alerts.models import Alert, AlertType
from cspm.database.models import Finding, SeverityLevel


@pytest.fixture
def mock_repository():
    """Provide a mock repository."""
    return MagicMock()


@pytest.fixture
def mock_channels():
    """Provide mock channels."""
    return [
        MagicMock(send_alert=MagicMock(return_value=True)),
        MagicMock(send_alert=MagicMock(return_value=True)),
    ]


@pytest.fixture
def sample_alert():
    """Provide a sample alert."""
    return Alert(
        id="alert-1",
        timestamp=datetime(2026, 2, 7, 10, 30, 0),
        alert_type=AlertType.FINDING,
        severity="CRITICAL",
        source_id="finding-1",
        title="Public S3 Bucket",
        description="Test",
        affected_resources=["resource-1"],
        cloud_provider="AWS",
    )


class TestAlertManager:
    """Test AlertManager class."""

    def test_alert_manager_initialization(self, mock_repository, mock_channels):
        """AlertManager should initialize with repository and channels."""
        manager = AlertManager(mock_repository, mock_channels, severity_threshold="HIGH")
        assert manager.repository is mock_repository
        assert manager.channels == mock_channels
        assert manager.severity_threshold == "HIGH"

    def test_send_alert_dispatches_to_all_channels(
        self, mock_repository, mock_channels, sample_alert
    ):
        """send_alert should dispatch to all enabled channels."""
        manager = AlertManager(mock_repository, mock_channels, severity_threshold="LOW")
        manager.send_alert(sample_alert)

        # Both channels should be called
        assert mock_channels[0].send_alert.called
        assert mock_channels[1].send_alert.called

    def test_send_alert_filters_by_severity_threshold(
        self, mock_repository, mock_channels
    ):
        """send_alert should filter alerts by severity threshold."""
        manager = AlertManager(mock_repository, mock_channels, severity_threshold="CRITICAL")

        # CRITICAL alert should pass
        critical_alert = Alert(
            id="alert-1",
            timestamp=datetime(2026, 2, 7, 10, 30, 0),
            alert_type=AlertType.FINDING,
            severity="CRITICAL",
            source_id="finding-1",
            title="Critical Issue",
            description="Test",
            affected_resources=[],
            cloud_provider="AWS",
        )
        manager.send_alert(critical_alert)
        assert mock_channels[0].send_alert.called

        # Reset mocks
        mock_channels[0].reset_mock()
        mock_channels[1].reset_mock()

        # HIGH alert should be filtered out
        high_alert = Alert(
            id="alert-2",
            timestamp=datetime(2026, 2, 7, 10, 30, 0),
            alert_type=AlertType.FINDING,
            severity="HIGH",
            source_id="finding-2",
            title="High Issue",
            description="Test",
            affected_resources=[],
            cloud_provider="AWS",
        )
        manager.send_alert(high_alert)
        assert not mock_channels[0].send_alert.called

    def test_send_alert_returns_channel_results(
        self, mock_repository, mock_channels, sample_alert
    ):
        """send_alert should return list of channel results."""
        manager = AlertManager(mock_repository, mock_channels, severity_threshold="LOW")
        results = manager.send_alert(sample_alert)

        assert isinstance(results, list)
        assert len(results) == 2

    def test_send_alert_continues_on_channel_failure(
        self, mock_repository, mock_channels, sample_alert
    ):
        """send_alert should continue with other channels if one fails."""
        mock_channels[0].send_alert.return_value = False
        mock_channels[1].send_alert.return_value = True

        manager = AlertManager(mock_repository, mock_channels, severity_threshold="LOW")
        results = manager.send_alert(sample_alert)

        assert mock_channels[0].send_alert.called
        assert mock_channels[1].send_alert.called
        assert results[0] is False
        assert results[1] is True

    def test_process_scan_alerts_queries_findings(
        self, mock_repository, mock_channels
    ):
        """process_scan_alerts should query findings by scan_id."""
        mock_repository.get_findings_by_scan.return_value = []
        manager = AlertManager(mock_repository, mock_channels, severity_threshold="HIGH")
        manager.process_scan_alerts("scan-1")

        mock_repository.get_findings_by_scan.assert_called_once_with("scan-1")

    def test_process_scan_alerts_converts_findings_to_alerts(
        self, mock_repository, mock_channels
    ):
        """process_scan_alerts should convert findings to alerts."""
        # Create mock findings
        finding1 = MagicMock()
        finding1.id = "finding-1"
        finding1.title = "Public S3"
        finding1.description = "Test"
        finding1.severity = "CRITICAL"
        finding1.resource_id = "arn:aws:s3:::bucket"
        finding1.resource_name = "bucket"
        finding1.cloud_provider = "AWS"
        finding1.created_at = datetime(2026, 2, 7, 10, 30, 0)
        finding1.evidence = '{}'

        mock_repository.get_findings_by_scan.return_value = [finding1]

        manager = AlertManager(mock_repository, mock_channels, severity_threshold="CRITICAL")
        alerts = manager.process_scan_alerts("scan-1")

        assert len(alerts) == 1
        assert alerts[0].title == "Public S3"
        assert alerts[0].severity == "CRITICAL"

    def test_process_scan_alerts_respects_severity_filter(
        self, mock_repository, mock_channels
    ):
        """process_scan_alerts should filter findings by severity threshold."""
        # Create mock findings with different severities
        critical_finding = MagicMock()
        critical_finding.id = "finding-1"
        critical_finding.title = "Critical"
        critical_finding.description = "Test"
        critical_finding.severity = "CRITICAL"
        critical_finding.resource_id = "resource-1"
        critical_finding.resource_name = "res-1"
        critical_finding.cloud_provider = "AWS"
        critical_finding.created_at = datetime(2026, 2, 7, 10, 30, 0)
        critical_finding.evidence = '{}'

        low_finding = MagicMock()
        low_finding.id = "finding-2"
        low_finding.title = "Low"
        low_finding.description = "Test"
        low_finding.severity = "LOW"
        low_finding.resource_id = "resource-2"
        low_finding.resource_name = "res-2"
        low_finding.cloud_provider = "AWS"
        low_finding.created_at = datetime(2026, 2, 7, 10, 30, 0)
        low_finding.evidence = '{}'

        mock_repository.get_findings_by_scan.return_value = [
            critical_finding,
            low_finding,
        ]

        # With HIGH threshold, only CRITICAL should be alerted
        manager = AlertManager(mock_repository, mock_channels, severity_threshold="HIGH")
        alerts = manager.process_scan_alerts("scan-1")

        assert len(alerts) == 1
        assert alerts[0].title == "Critical"

    def test_process_compliance_alerts_only_fails(self, mock_repository, mock_channels):
        """process_compliance_alerts should only alert on FAIL status."""
        # Create mock compliance results
        failed_result = MagicMock()
        failed_result.id = "result-1"
        failed_result.framework = "CIS_AWS"
        failed_result.control_id = "1.1"
        failed_result.control_title = "Control 1.1"
        failed_result.status = "FAIL"
        failed_result.finding_count = 5
        failed_result.created_at = datetime(2026, 2, 7, 10, 30, 0)
        failed_result.evidence = '{}'

        passed_result = MagicMock()
        passed_result.id = "result-2"
        passed_result.framework = "CIS_AWS"
        passed_result.control_id = "1.2"
        passed_result.control_title = "Control 1.2"
        passed_result.status = "PASS"
        passed_result.finding_count = 0
        passed_result.created_at = datetime(2026, 2, 7, 10, 30, 0)
        passed_result.evidence = '{}'

        mock_repository.get_compliance_results.return_value = [
            failed_result,
            passed_result,
        ]

        manager = AlertManager(mock_repository, mock_channels, severity_threshold="HIGH")
        alerts = manager.process_compliance_alerts("scan-1")

        # Only FAIL should generate alert
        assert len(alerts) == 1
        assert "Control 1.1" in alerts[0].title

    def test_process_compliance_alerts_includes_control_details(
        self, mock_repository, mock_channels
    ):
        """process_compliance_alerts should include control details in alert."""
        failed_result = MagicMock()
        failed_result.id = "result-1"
        failed_result.framework = "CIS_AWS"
        failed_result.control_id = "1.1"
        failed_result.control_title = "Root Account Usage"
        failed_result.status = "FAIL"
        failed_result.finding_count = 3
        failed_result.created_at = datetime(2026, 2, 7, 10, 30, 0)
        failed_result.evidence = '{"details": "test"}'

        mock_repository.get_compliance_results.return_value = [failed_result]

        manager = AlertManager(mock_repository, mock_channels, severity_threshold="LOW")
        alerts = manager.process_compliance_alerts("scan-1")

        assert len(alerts) == 1
        assert "CIS_AWS" in alerts[0].title
        assert "1.1" in alerts[0].title
        assert alerts[0].severity == "HIGH"
