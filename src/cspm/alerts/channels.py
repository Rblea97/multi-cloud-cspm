"""Alert delivery channels."""

import logging
import smtplib
from abc import ABC, abstractmethod
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

from cspm.alerts.formatter import AlertFormatter
from cspm.alerts.models import Alert

logger = logging.getLogger(__name__)


class AlertChannel(ABC):
    """Abstract base class for alert delivery channels."""

    @abstractmethod
    def send_alert(self, alert: Alert) -> bool:
        """Send alert through this channel."""


class ConsoleChannel(AlertChannel):
    """Log alerts to console using Python logging."""

    def __init__(self, formatter: AlertFormatter):
        """Initialize console channel."""
        self.formatter = formatter
        self.logger = logging.getLogger(__name__)

    def send_alert(self, alert: Alert) -> bool:
        """Log alert to console based on severity."""
        severity_to_level = {
            "CRITICAL": logging.ERROR,
            "HIGH": logging.WARNING,
            "MEDIUM": logging.INFO,
            "LOW": logging.DEBUG,
            "INFO": logging.DEBUG,
        }
        level = severity_to_level.get(alert.severity, logging.INFO)
        formatted = self.formatter.format_console(alert)
        self.logger.log(level, formatted)
        return True


class FileChannel(AlertChannel):
    """Append alerts to JSONL file."""

    def __init__(self, file_path: str, formatter: AlertFormatter):
        """Initialize file channel."""
        self.file_path = file_path
        self.formatter = formatter

    def send_alert(self, alert: Alert) -> bool:
        """Append formatted alert to file."""
        try:
            Path(self.file_path).parent.mkdir(parents=True, exist_ok=True)
            with open(self.file_path, "a") as f:
                f.write(self.formatter.format_file(alert) + "\n")
            return True
        except Exception as e:
            logger.error(f"Failed to write alert to {self.file_path}: {e}")
            return False


class EmailChannel(AlertChannel):
    """Send alerts via email through SMTP."""

    def __init__(
        self,
        formatter: AlertFormatter,
        smtp_host: str,
        smtp_port: int,
        smtp_username: str,
        smtp_password: str,
        from_addr: str,
        to_addrs: list[str],
    ):
        """Initialize email channel."""
        self.formatter = formatter
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_username = smtp_username
        self.smtp_password = smtp_password
        self.from_addr = from_addr
        self.to_addrs = to_addrs

    def send_alert(self, alert: Alert) -> bool:
        """Send alert via email."""
        try:
            subject, html_body = self.formatter.format_email(alert)
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.from_addr
            msg["To"] = ", ".join(self.to_addrs)
            msg.attach(MIMEText(html_body, "html"))

            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.sendmail(self.from_addr, self.to_addrs, msg.as_string())
            return True
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            return False
