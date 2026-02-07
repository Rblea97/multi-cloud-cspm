"""Data access layer using repository pattern."""

from typing import List, Optional
from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from cspm.core.config import settings
from cspm.database.models import Base, Finding, ComplianceResult, AnomalyAlert, RemediationAction, Scan


class Repository:
    """Repository for database operations."""

    def __init__(self, db_url: Optional[str] = None):
        """Initialize repository with database connection."""
        self.db_url = db_url or settings.database_url
        self.engine = create_engine(self.db_url, echo=settings.database_echo)
        self.SessionLocal = sessionmaker(bind=self.engine)

    def create_tables(self) -> None:
        """Create all tables."""
        Base.metadata.create_all(self.engine)

    def drop_tables(self) -> None:
        """Drop all tables (for testing)."""
        Base.metadata.drop_all(self.engine)

    def get_session(self) -> Session:
        """Get database session."""
        return self.SessionLocal()

    # Finding operations
    def save_finding(self, finding: Finding) -> Finding:
        """Save a finding to database."""
        session = self.get_session()
        try:
            session.add(finding)
            session.commit()
            session.refresh(finding)
            return finding
        finally:
            session.close()

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        """Get finding by ID."""
        session = self.get_session()
        try:
            return session.query(Finding).filter(Finding.id == finding_id).first()
        finally:
            session.close()

    def get_findings_by_scan(self, scan_id: str) -> List[Finding]:
        """Get all findings for a scan."""
        session = self.get_session()
        try:
            return session.query(Finding).filter(Finding.scan_id == scan_id).all()
        finally:
            session.close()

    def get_open_findings(self, cloud_provider: Optional[str] = None) -> List[Finding]:
        """Get all open findings, optionally filtered by cloud provider."""
        session = self.get_session()
        try:
            query = session.query(Finding).filter(Finding.status == "OPEN")
            if cloud_provider:
                query = query.filter(Finding.cloud_provider == cloud_provider)
            return query.all()
        finally:
            session.close()

    def update_finding_status(self, finding_id: str, status: str) -> None:
        """Update finding status."""
        session = self.get_session()
        try:
            finding = session.query(Finding).filter(Finding.id == finding_id).first()
            if finding:
                finding.status = status
                if status == "REMEDIATED":
                    finding.remediated_at = datetime.utcnow()
                session.commit()
        finally:
            session.close()

    # Compliance operations
    def save_compliance_result(self, result: ComplianceResult) -> ComplianceResult:
        """Save compliance result."""
        session = self.get_session()
        try:
            session.add(result)
            session.commit()
            session.refresh(result)
            return result
        finally:
            session.close()

    def get_compliance_results(self, scan_id: str) -> List[ComplianceResult]:
        """Get compliance results for a scan."""
        session = self.get_session()
        try:
            return session.query(ComplianceResult).filter(
                ComplianceResult.scan_id == scan_id
            ).all()
        finally:
            session.close()

    # Anomaly operations
    def save_anomaly_alert(self, alert: AnomalyAlert) -> AnomalyAlert:
        """Save anomaly alert."""
        session = self.get_session()
        try:
            session.add(alert)
            session.commit()
            session.refresh(alert)
            return alert
        finally:
            session.close()

    def get_open_anomalies(self) -> List[AnomalyAlert]:
        """Get all open anomaly alerts."""
        session = self.get_session()
        try:
            return session.query(AnomalyAlert).filter(
                AnomalyAlert.status == "OPEN"
            ).all()
        finally:
            session.close()

    # Remediation operations
    def save_remediation_action(self, action: RemediationAction) -> RemediationAction:
        """Save remediation action."""
        session = self.get_session()
        try:
            session.add(action)
            session.commit()
            session.refresh(action)
            return action
        finally:
            session.close()

    def get_remediation_action(self, action_id: str) -> Optional[RemediationAction]:
        """Get remediation action by ID."""
        session = self.get_session()
        try:
            return session.query(RemediationAction).filter(
                RemediationAction.id == action_id
            ).first()
        finally:
            session.close()

    # Scan operations
    def save_scan(self, scan: Scan) -> Scan:
        """Save scan record."""
        session = self.get_session()
        try:
            session.add(scan)
            session.commit()
            session.refresh(scan)
            return scan
        finally:
            session.close()

    def get_scan(self, scan_id: str) -> Optional[Scan]:
        """Get scan by ID."""
        session = self.get_session()
        try:
            return session.query(Scan).filter(Scan.id == scan_id).first()
        finally:
            session.close()
