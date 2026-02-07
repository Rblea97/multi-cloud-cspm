"""Tests for alert formatting."""

from datetime import datetime

import pytest

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
        description="S3 bucket is publicly accessible without restrictions",
        affected_resources=["arn:aws:s3:::test-bucket", "arn:aws:s3:::public-data"],
        cloud_provider="AWS",
        evidence='{"public_access_block": false}',
    )


class TestConsoleFormatter:
    """Test console formatting."""

    def test_format_console_includes_title(self, formatter, sample_alert):
        """Console output should include alert title."""
        output = formatter.format_console(sample_alert)
        assert "Public S3 Bucket Detected" in output

    def test_format_console_includes_severity(self, formatter, sample_alert):
        """Console output should include severity level."""
        output = formatter.format_console(sample_alert)
        assert "CRITICAL" in output

    def test_format_console_includes_affected_resources(self, formatter, sample_alert):
        """Console output should include affected resources."""
        output = formatter.format_console(sample_alert)
        assert "test-bucket" in output
        assert "public-data" in output

    def test_format_console_includes_description(self, formatter, sample_alert):
        """Console output should include description."""
        output = formatter.format_console(sample_alert)
        assert "publicly accessible" in output

    def test_format_console_multiline_format(self, formatter, sample_alert):
        """Console output should be multiline structured."""
        output = formatter.format_console(sample_alert)
        assert "\n" in output
        lines = output.split("\n")
        assert len(lines) > 1

    def test_format_console_high_severity(self, formatter):
        """HIGH severity alert format."""
        alert = Alert(
            id="alert-2",
            timestamp=datetime(2026, 2, 7, 10, 30, 0),
            alert_type=AlertType.COMPLIANCE,
            severity="HIGH",
            source_id="control-1",
            title="CIS Control Failure",
            description="Control CIS 1.1 failed",
            affected_resources=["resource-1"],
            cloud_provider="AWS",
        )
        output = formatter.format_console(alert)
        assert "HIGH" in output
        assert "CIS Control Failure" in output

    def test_format_console_with_no_resources(self, formatter):
        """Console formatting should handle empty resources."""
        alert = Alert(
            id="alert-3",
            timestamp=datetime(2026, 2, 7, 10, 30, 0),
            alert_type=AlertType.COMPLIANCE,
            severity="MEDIUM",
            source_id="control-2",
            title="Test Alert",
            description="Test description",
            affected_resources=[],
            cloud_provider="AWS",
        )
        output = formatter.format_console(alert)
        assert "Test Alert" in output
        assert "MEDIUM" in output


class TestJsonFormatter:
    """Test JSON formatting."""

    def test_format_file_returns_valid_json(self, formatter, sample_alert):
        """File format should return valid JSON string."""
        import json

        output = formatter.format_file(sample_alert)
        # Should be parseable as JSON
        data = json.loads(output)
        assert data["id"] == "alert-1"
        assert data["severity"] == "CRITICAL"

    def test_format_file_single_line(self, formatter, sample_alert):
        """File format should be single line (JSONL compatible)."""
        output = formatter.format_file(sample_alert)
        assert "\n" not in output

    def test_format_file_includes_all_fields(self, formatter, sample_alert):
        """File format should include all alert fields."""
        import json

        output = formatter.format_file(sample_alert)
        data = json.loads(output)
        assert "id" in data
        assert "timestamp" in data
        assert "alert_type" in data
        assert "severity" in data
        assert "title" in data
        assert "description" in data
        assert "affected_resources" in data
        assert "cloud_provider" in data

    def test_format_file_with_metadata(self, formatter):
        """File format should preserve metadata."""
        import json

        alert = Alert(
            id="alert-4",
            timestamp=datetime(2026, 2, 7, 10, 30, 0),
            alert_type=AlertType.FINDING,
            severity="HIGH",
            source_id="finding-2",
            title="Test",
            description="Test",
            affected_resources=[],
            cloud_provider="AWS",
            metadata={"framework": "CIS_AWS", "rule_id": "1.1"},
        )
        output = formatter.format_file(alert)
        data = json.loads(output)
        assert data["metadata"]["framework"] == "CIS_AWS"


class TestEmailFormatter:
    """Test email formatting."""

    def test_format_email_returns_tuple(self, formatter, sample_alert):
        """Email format should return (subject, body) tuple."""
        result = formatter.format_email(sample_alert)
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_format_email_includes_severity_in_subject(self, formatter, sample_alert):
        """Email subject should include severity."""
        subject, _ = formatter.format_email(sample_alert)
        assert "CRITICAL" in subject

    def test_format_email_includes_title_in_subject(self, formatter, sample_alert):
        """Email subject should include alert title."""
        subject, _ = formatter.format_email(sample_alert)
        assert "Public S3 Bucket" in subject or "alert" in subject.lower()

    def test_format_email_body_is_html(self, formatter, sample_alert):
        """Email body should be HTML formatted."""
        _, body = formatter.format_email(sample_alert)
        assert "<" in body and ">" in body
        assert "html" in body.lower() or "body" in body.lower()

    def test_format_email_body_includes_description(self, formatter, sample_alert):
        """Email body should include alert description."""
        _, body = formatter.format_email(sample_alert)
        assert "publicly accessible" in body

    def test_format_email_body_includes_resources(self, formatter, sample_alert):
        """Email body should include affected resources."""
        _, body = formatter.format_email(sample_alert)
        assert "test-bucket" in body or "resource" in body.lower()

    def test_format_email_high_severity(self, formatter):
        """HIGH severity email formatting."""
        alert = Alert(
            id="alert-5",
            timestamp=datetime(2026, 2, 7, 10, 30, 0),
            alert_type=AlertType.FINDING,
            severity="HIGH",
            source_id="finding-3",
            title="Security Issue",
            description="A high severity issue",
            affected_resources=["resource-1"],
            cloud_provider="Azure",
        )
        subject, body = formatter.format_email(alert)
        assert "HIGH" in subject
        assert len(body) > 0
