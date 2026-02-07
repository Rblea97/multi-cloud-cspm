"""SQLAlchemy models for database schema."""

import enum
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class SeverityLevel(str, enum.Enum):
    """Severity levels for findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ResourceType(str, enum.Enum):
    """Supported resource types."""

    # AWS
    S3_BUCKET = "AWS::S3::Bucket"
    EC2_INSTANCE = "AWS::EC2::Instance"
    RDS_INSTANCE = "AWS::RDS::DBInstance"
    SECURITY_GROUP = "AWS::EC2::SecurityGroup"
    IAM_USER = "AWS::IAM::User"
    IAM_ROLE = "AWS::IAM::Role"

    # Azure
    STORAGE_ACCOUNT = "Azure::Storage::Account"
    VIRTUAL_MACHINE = "Azure::Compute::VirtualMachine"
    SQL_SERVER = "Azure::SQL::Server"
    NETWORK_SECURITY_GROUP = "Azure::Network::NSG"
    KEYVAULT = "Azure::KeyVault"


class Finding(Base):
    """Security finding from rule evaluation."""

    __tablename__ = "findings"

    id = Column(String(36), primary_key=True)
    scan_id = Column(String(36), index=True)
    rule_id = Column(String(100), index=True)
    rule_name = Column(String(255))
    resource_id = Column(String(255), index=True)
    resource_type = Column(String(50))
    resource_name = Column(String(255))
    cloud_provider = Column(String(50), index=True)  # AWS or Azure
    severity = Column(String(20), default=SeverityLevel.MEDIUM.value)
    title = Column(String(255))
    description = Column(Text)
    remediation_advice = Column(Text)
    status = Column(String(20), default="OPEN")  # OPEN, REMEDIATED, ACCEPTED_RISK, FALSE_POSITIVE
    evidence = Column(Text)  # JSON with detailed findings
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    remediated_at = Column(DateTime, nullable=True)


class ComplianceResult(Base):
    """Compliance assessment result."""

    __tablename__ = "compliance_results"

    id = Column(String(36), primary_key=True)
    scan_id = Column(String(36), index=True)
    framework = Column(String(100))  # CIS_AWS, CIS_AZURE
    control_id = Column(String(50))
    control_title = Column(String(255))
    status = Column(String(20))  # PASS, FAIL, NOT_APPLICABLE
    finding_count = Column(Integer, default=0)
    evidence = Column(Text)  # JSON with control details
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class AnomalyAlert(Base):
    """AI-detected behavioral anomaly alert."""

    __tablename__ = "anomaly_alerts"

    id = Column(String(36), primary_key=True)
    user_id = Column(String(255), index=True)
    user_name = Column(String(255))
    cloud_provider = Column(String(50))
    action = Column(String(255))
    resource_id = Column(String(255))
    anomaly_score = Column(Float)  # 0.0-1.0 from ML model
    severity = Column(String(20))
    description = Column(Text)
    evidence = Column(Text)  # JSON with features and model details
    status = Column(String(20), default="OPEN")  # OPEN, INVESTIGATING, RESOLVED
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class RemediationAction(Base):
    """Remediation action history."""

    __tablename__ = "remediation_actions"

    id = Column(String(36), primary_key=True)
    finding_id = Column(String(36), ForeignKey("findings.id"), index=True)
    action_type = Column(String(100))  # block_public_s3, enable_rds_encryption, etc.
    status = Column(String(20))  # PENDING, IN_PROGRESS, SUCCESS, FAILED
    mode = Column(String(20))  # DRY_RUN, AUTO_FIX
    requested_by = Column(String(255))  # User or system
    approved_by = Column(String(255), nullable=True)
    approval_required = Column(Boolean, default=True)
    result = Column(Text)  # JSON with remediation result details
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)


class Scan(Base):
    """Scan execution record."""

    __tablename__ = "scans"

    id = Column(String(36), primary_key=True)
    cloud_provider = Column(String(50), index=True)  # AWS or Azure, or MULTI
    scan_type = Column(String(50))  # FULL, INCREMENTAL
    status = Column(String(20))  # RUNNING, COMPLETED, FAILED
    resources_scanned = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    started_at = Column(DateTime, default=datetime.utcnow, index=True)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    configuration = Column(Text)  # JSON with scan configuration
