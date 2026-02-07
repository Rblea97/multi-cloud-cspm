"""Data access layer using repository pattern."""

from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from cspm.core.config import settings
from cspm.database.models import (
    AnomalyAlert,
    Base,
    ComplianceResult,
    Finding,
    RemediationAction,
    Scan,
)


class Repository:
    """Repository for database operations."""

    def __init__(self, db_url: str | None = None):
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

    def get_finding(self, finding_id: str) -> Finding | None:
        """Get finding by ID."""
        session = self.get_session()
        try:
            return session.query(Finding).filter(Finding.id == finding_id).first()
        finally:
            session.close()

    def get_findings_by_scan(self, scan_id: str) -> list[Finding]:
        """Get all findings for a scan."""
        session = self.get_session()
        try:
            return session.query(Finding).filter(Finding.scan_id == scan_id).all()
        finally:
            session.close()

    def get_open_findings(self, cloud_provider: str | None = None) -> list[Finding]:
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

    def get_compliance_results(self, scan_id: str) -> list[ComplianceResult]:
        """Get compliance results for a scan."""
        session = self.get_session()
        try:
            return session.query(ComplianceResult).filter(
                ComplianceResult.scan_id == scan_id
            ).all()
        finally:
            session.close()

    def get_compliance_history(
        self, framework_id: str, days: int = 30
    ) -> list[tuple[str, datetime]]:
        """Get compliance history for a framework.

        Args:
            framework_id: The framework ID (e.g., "CIS_AWS_1.4.0")
            days: Number of days to look back (default 30)

        Returns:
            List of (scan_id, created_at) tuples ordered by date
        """
        from datetime import timedelta

        session = self.get_session()
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            results = (
                session.query(ComplianceResult.scan_id, ComplianceResult.created_at)
                .filter(
                    ComplianceResult.framework == framework_id,
                    ComplianceResult.created_at >= cutoff_date,
                )
                .distinct()
                .order_by(ComplianceResult.created_at)
                .all()
            )
            return results
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

    def get_open_anomalies(self) -> list[AnomalyAlert]:
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

    def get_remediation_action(self, action_id: str) -> RemediationAction | None:
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

    def get_scan(self, scan_id: str) -> Scan | None:
        """Get scan by ID."""
        session = self.get_session()
        try:
            return session.query(Scan).filter(Scan.id == scan_id).first()
        finally:
            session.close()

    # Remediation operations

    def create_remediation_action(
        self,
        finding_id: str,
        action_type: str,
        mode: str,
        requested_by: str,
        approval_required: bool,
        status: str = "PENDING",
    ) -> str:
        """Create remediation action record.

        Args:
            finding_id: ID of finding
            action_type: Type of remediation action
            mode: Execution mode (dry_run or auto_fix)
            requested_by: User requesting remediation
            approval_required: Whether approval is required
            status: Initial status

        Returns:
            ID of created remediation action
        """
        session = self.get_session()
        try:
            action = RemediationAction(
                finding_id=finding_id,
                action_type=action_type,
                mode=mode,
                status=status,
                requested_by=requested_by,
                approval_required=approval_required,
            )
            session.add(action)
            session.commit()
            session.refresh(action)
            return action.id  # type: ignore[return-value]
        finally:
            session.close()

    def get_remediation_action(self, action_id: str) -> RemediationAction | None:
        """Get remediation action by ID.

        Args:
            action_id: ID of remediation action

        Returns:
            RemediationAction or None
        """
        session = self.get_session()
        try:
            return session.query(RemediationAction).filter(
                RemediationAction.id == action_id
            ).first()
        finally:
            session.close()

    def get_pending_remediations(self, status: str) -> list[RemediationAction]:
        """Get pending remediation actions.

        Args:
            status: Status to filter by (e.g., 'PENDING')

        Returns:
            List of remediation actions
        """
        session = self.get_session()
        try:
            return session.query(RemediationAction).filter(
                RemediationAction.status == status
            ).all()
        finally:
            session.close()

    def update_remediation_status(
        self, action_id: str, status: str, result: dict
    ) -> None:
        """Update remediation action status.

        Args:
            action_id: ID of remediation action
            status: New status
            result: Result data (JSON)
        """
        session = self.get_session()
        try:
            action = session.query(RemediationAction).filter(
                RemediationAction.id == action_id
            ).first()
            if action:
                action.status = status  # type: ignore[assignment]
                action.result = result  # type: ignore[assignment]
                if status == "IN_PROGRESS":
                    action.started_at = datetime.utcnow()  # type: ignore[assignment]
                elif status in ["SUCCESS", "FAILED"]:
                    action.completed_at = datetime.utcnow()  # type: ignore[assignment]
                session.commit()
        finally:
            session.close()

    def get_remediations_by_finding(self, finding_id: str) -> list[RemediationAction]:
        """Get all remediation actions for a finding.

        Args:
            finding_id: ID of finding

        Returns:
            List of remediation actions
        """
        session = self.get_session()
        try:
            return session.query(RemediationAction).filter(
                RemediationAction.finding_id == finding_id
            ).all()
        finally:
            session.close()
