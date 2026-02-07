"""Compliance scoring and trend analysis."""

from datetime import datetime

from cspm.database.repository import Repository


class ComplianceScorer:
    """Calculates compliance scores and trends."""

    def __init__(self, repository: Repository) -> None:
        """Initialize compliance scorer.

        Args:
            repository: Data access layer for querying compliance results
        """
        self.repository = repository

    def calculate_score(self, scan_id: str, framework_id: str) -> float:
        """Calculate compliance score for a framework.

        Score = (PASS / (PASS + FAIL)) × 100
        NOT_APPLICABLE controls are excluded from calculation.

        Args:
            scan_id: The scan identifier
            framework_id: The framework ID (e.g., "CIS_AWS_1.4.0")

        Returns:
            Compliance score as percentage (0.0-100.0)
        """
        # Get all compliance results for this scan and framework
        results = self.repository.get_compliance_results(scan_id)

        # Filter by framework
        framework_results = [r for r in results if r.framework == framework_id]

        if not framework_results:
            return 0.0

        # Count PASS and FAIL (NOT_APPLICABLE excluded)
        pass_count = sum(1 for r in framework_results if r.status == "PASS")
        fail_count = sum(1 for r in framework_results if r.status == "FAIL")

        total = pass_count + fail_count

        if total == 0:
            # All controls are NOT_APPLICABLE
            return 0.0

        # Calculate percentage
        score = (pass_count / total) * 100.0
        return score

    def calculate_trend(
        self, framework_id: str, days: int = 30
    ) -> list[tuple[datetime, float]]:
        """Calculate compliance score trend over time.

        Args:
            framework_id: The framework ID (e.g., "CIS_AWS_1.4.0")
            days: Number of days to look back (default 30)

        Returns:
            List of (date, score) tuples ordered by date
        """
        # Get historical scans
        history = self.repository.get_compliance_history(framework_id, days)

        trend: list[tuple[datetime, float]] = []

        for scan_id, created_at in history:
            score = self.calculate_score(scan_id, framework_id)
            trend.append((created_at, score))

        return trend
