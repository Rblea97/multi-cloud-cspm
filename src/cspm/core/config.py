"""Configuration management."""

import logging

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=False,
    )

    # Environment
    environment: str = "development"
    debug: bool = True

    # AWS Configuration
    aws_region: str = "us-east-1"
    aws_role_arn: str | None = None

    # Azure Configuration
    azure_subscription_id: str | None = None
    azure_tenant_id: str | None = None

    # Database Configuration
    database_url: str = "postgresql://user:password@localhost:5432/cspm"
    database_echo: bool = False

    # Redis Configuration
    redis_url: str = "redis://localhost:6379/0"

    # Scan Configuration
    scan_interval_minutes: int = 15
    max_concurrent_scans: int = 5

    # Remediation Configuration
    remediation_enabled: bool = True
    remediation_require_approval: bool = True
    remediation_auto_fix_enabled: bool = False

    # ML Model Configuration
    ml_model_retrain_interval_days: int = 7
    ml_anomaly_threshold: float = 0.8

    # Alert Configuration
    alert_enabled: bool = True
    alert_severity_threshold: str = "HIGH"
    alert_console_enabled: bool = True
    alert_file_enabled: bool = True
    alert_file_path: str = "/var/log/cspm/alerts.jsonl"
    alert_email_enabled: bool = False

    # Email Configuration (for alerts)
    alert_email_smtp_host: str | None = None
    alert_email_smtp_port: int = 587
    alert_email_smtp_username: str | None = None
    alert_email_smtp_password: str | None = None
    alert_email_from: str = "cspm-alerts@example.com"
    alert_email_to: list[str] = []


settings = Settings()


def setup_logging(level: str = "INFO") -> None:
    """Configure logging."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
