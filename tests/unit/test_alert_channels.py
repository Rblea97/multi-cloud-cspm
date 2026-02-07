"""Tests for alert channels."""

import json
import logging
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cspm.alerts.channels import ConsoleChannel, EmailChannel, FileChannel
from cspm.alerts.formatter import AlertFormatter
from cspm.alerts.models import Alert, AlertType


@pytest.fixture
def formatter():
    """Provide an AlertFormatter instance."""
    return AlertFormatter()


@pytest.fixture
def sample_alert():
    """Provide a sample alert for testing."""
    return Alert(
        id="alert-1",
        timestamp=datetime(2026, 2, 7, 10, 30, 0),
        alert_type=AlertType.FINDING,
        severity="CRITICAL",
        source_id="finding-1",
        title="Public S3 Bucket Detected",
        description="S3 bucket is publicly accessible",
        affected_resources=["arn:aws:s3:::test-bucket"],
        cloud_provider="AWS",
    )


class TestConsoleChannel:
    """Test ConsoleChannel implementation."""

    def test_console_channel_initialization(self, formatter):
        """ConsoleChannel should initialize with formatter."""
        channel = ConsoleChannel(formatter)
        assert channel.formatter is formatter

    def test_console_channel_logs_alert(self, formatter, sample_alert, caplog):
        """ConsoleChannel should log alert using logger."""
        channel = ConsoleChannel(formatter)
        with caplog.at_level(logging.ERROR):
            result = channel.send_alert(sample_alert)
        assert result is True
        assert "Public S3 Bucket Detected" in caplog.text

    def test_console_channel_uses_error_level_for_critical(
        self, formatter, sample_alert, caplog
    ):
        """CRITICAL severity should use ERROR log level."""
        channel = ConsoleChannel(formatter)
        with caplog.at_level(logging.ERROR):
            channel.send_alert(sample_alert)
        assert any("CRITICAL" in record.message for record in caplog.records)

    def test_console_channel_uses_warning_level_for_high(self, formatter, caplog):
        """HIGH severity should use WARNING log level."""
        alert = Alert(
            id="alert-2",
            timestamp=datetime(2026, 2, 7, 10, 30, 0),
            alert_type=AlertType.FINDING,
            severity="HIGH",
            source_id="finding-2",
            title="High Severity Issue",
            description="Test",
            affected_resources=[],
            cloud_provider="AWS",
        )
        channel = ConsoleChannel(formatter)
        with caplog.at_level(logging.WARNING):
            channel.send_alert(alert)
        assert any("High Severity Issue" in record.message for record in caplog.records)

    def test_console_channel_uses_info_level_for_medium(self, formatter, caplog):
        """MEDIUM severity should use INFO log level."""
        alert = Alert(
            id="alert-3",
            timestamp=datetime(2026, 2, 7, 10, 30, 0),
            alert_type=AlertType.FINDING,
            severity="MEDIUM",
            source_id="finding-3",
            title="Medium Issue",
            description="Test",
            affected_resources=[],
            cloud_provider="AWS",
        )
        channel = ConsoleChannel(formatter)
        with caplog.at_level(logging.INFO):
            channel.send_alert(alert)
        assert any("Medium Issue" in record.message for record in caplog.records)

    def test_console_channel_send_alert_returns_true(self, formatter, sample_alert):
        """send_alert should return True on success."""
        channel = ConsoleChannel(formatter)
        result = channel.send_alert(sample_alert)
        assert result is True


class TestFileChannel:
    """Test FileChannel implementation."""

    def test_file_channel_initialization(self, formatter, tmp_path):
        """FileChannel should initialize with formatter and file path."""
        file_path = str(tmp_path / "alerts.jsonl")
        channel = FileChannel(file_path, formatter)
        assert channel.file_path == file_path
        assert channel.formatter is formatter

    def test_file_channel_creates_file_if_not_exists(self, formatter, tmp_path):
        """FileChannel should create file if it doesn't exist."""
        file_path = str(tmp_path / "alerts.jsonl")
        channel = FileChannel(file_path, formatter)
        alert = Alert(
            id="alert-1",
            timestamp=datetime(2026, 2, 7, 10, 30, 0),
            alert_type=AlertType.FINDING,
            severity="CRITICAL",
            source_id="finding-1",
            title="Test",
            description="Test",
            affected_resources=[],
            cloud_provider="AWS",
        )
        channel.send_alert(alert)
        assert Path(file_path).exists()

    def test_file_channel_appends_jsonl_lines(self, formatter, tmp_path):
        """FileChannel should append JSON lines to file."""
        file_path = str(tmp_path / "alerts.jsonl")
        channel = FileChannel(file_path, formatter)
        alert1 = Alert(
            id="alert-1",
            timestamp=datetime(2026, 2, 7, 10, 30, 0),
            alert_type=AlertType.FINDING,
            severity="CRITICAL",
            source_id="finding-1",
            title="Alert 1",
            description="Test",
            affected_resources=[],
            cloud_provider="AWS",
        )
        alert2 = Alert(
            id="alert-2",
            timestamp=datetime(2026, 2, 7, 10, 31, 0),
            alert_type=AlertType.FINDING,
            severity="HIGH",
            source_id="finding-2",
            title="Alert 2",
            description="Test",
            affected_resources=[],
            cloud_provider="AWS",
        )
        channel.send_alert(alert1)
        channel.send_alert(alert2)

        # Verify file has two JSON lines
        with open(file_path) as f:
            lines = f.readlines()
        assert len(lines) == 2
        data1 = json.loads(lines[0])
        data2 = json.loads(lines[1])
        assert data1["id"] == "alert-1"
        assert data2["id"] == "alert-2"

    def test_file_channel_returns_true_on_success(self, formatter, tmp_path):
        """FileChannel.send_alert should return True on success."""
        file_path = str(tmp_path / "alerts.jsonl")
        channel = FileChannel(file_path, formatter)
        alert = Alert(
            id="alert-1",
            timestamp=datetime(2026, 2, 7, 10, 30, 0),
            alert_type=AlertType.FINDING,
            severity="CRITICAL",
            source_id="finding-1",
            title="Test",
            description="Test",
            affected_resources=[],
            cloud_provider="AWS",
        )
        result = channel.send_alert(alert)
        assert result is True

    def test_file_channel_returns_false_on_error(self, formatter, tmp_path):
        """FileChannel.send_alert should return False and log on error."""
        file_path = str(tmp_path / "alerts.jsonl")
        channel = FileChannel(file_path, formatter)
        # Make file path unwritable by creating a directory with same name
        Path(file_path).mkdir(parents=True)
        alert = Alert(
            id="alert-1",
            timestamp=datetime(2026, 2, 7, 10, 30, 0),
            alert_type=AlertType.FINDING,
            severity="CRITICAL",
            source_id="finding-1",
            title="Test",
            description="Test",
            affected_resources=[],
            cloud_provider="AWS",
        )
        result = channel.send_alert(alert)
        assert result is False

    def test_file_channel_handles_parent_directory_creation(
        self, formatter, tmp_path
    ):
        """FileChannel should create parent directories if needed."""
        file_path = str(tmp_path / "logs" / "alerts" / "alerts.jsonl")
        channel = FileChannel(file_path, formatter)
        alert = Alert(
            id="alert-1",
            timestamp=datetime(2026, 2, 7, 10, 30, 0),
            alert_type=AlertType.FINDING,
            severity="CRITICAL",
            source_id="finding-1",
            title="Test",
            description="Test",
            affected_resources=[],
            cloud_provider="AWS",
        )
        result = channel.send_alert(alert)
        assert result is True
        assert Path(file_path).exists()


class TestEmailChannel:
    """Test EmailChannel implementation."""

    def test_email_channel_initialization(self, formatter):
        """EmailChannel should initialize with SMTP config."""
        channel = EmailChannel(
            formatter=formatter,
            smtp_host="smtp.gmail.com",
            smtp_port=587,
            smtp_username="test@example.com",
            smtp_password="password",
            from_addr="alerts@example.com",
            to_addrs=["security@example.com"],
        )
        assert channel.formatter is formatter
        assert channel.smtp_host == "smtp.gmail.com"
        assert channel.from_addr == "alerts@example.com"

    @patch("cspm.alerts.channels.smtplib.SMTP")
    def test_email_channel_sends_via_smtp(self, mock_smtp_class, formatter):
        """EmailChannel should send email via SMTP."""
        mock_smtp = MagicMock()
        mock_smtp_class.return_value.__enter__.return_value = mock_smtp
        channel = EmailChannel(
            formatter=formatter,
            smtp_host="smtp.gmail.com",
            smtp_port=587,
            smtp_username="test@example.com",
            smtp_password="password",
            from_addr="alerts@example.com",
            to_addrs=["security@example.com"],
        )
        alert = Alert(
            id="alert-1",
            timestamp=datetime(2026, 2, 7, 10, 30, 0),
            alert_type=AlertType.FINDING,
            severity="CRITICAL",
            source_id="finding-1",
            title="Test Alert",
            description="Test",
            affected_resources=[],
            cloud_provider="AWS",
        )
        result = channel.send_alert(alert)
        assert result is True
        mock_smtp.sendmail.assert_called_once()

    @patch("cspm.alerts.channels.smtplib.SMTP")
    def test_email_channel_handles_connection_error(self, mock_smtp_class, formatter):
        """EmailChannel should handle SMTP connection errors gracefully."""
        mock_smtp_class.side_effect = Exception("Connection failed")
        channel = EmailChannel(
            formatter=formatter,
            smtp_host="smtp.gmail.com",
            smtp_port=587,
            smtp_username="test@example.com",
            smtp_password="password",
            from_addr="alerts@example.com",
            to_addrs=["security@example.com"],
        )
        alert = Alert(
            id="alert-1",
            timestamp=datetime(2026, 2, 7, 10, 30, 0),
            alert_type=AlertType.FINDING,
            severity="CRITICAL",
            source_id="finding-1",
            title="Test",
            description="Test",
            affected_resources=[],
            cloud_provider="AWS",
        )
        result = channel.send_alert(alert)
        assert result is False
