"""Tests for compliance scoring."""

import json
import uuid
from datetime import datetime
from unittest.mock import MagicMock

import pytest

from cspm.compliance.scoring import ComplianceScorer
from cspm.database.models import ComplianceResult
from cspm.database.repository import Repository


@pytest.fixture
def mock_repository() -> MagicMock:
    """Create a mock repository."""
    return MagicMock(spec=Repository)


@pytest.fixture
def compliance_scorer(mock_repository: MagicMock) -> ComplianceScorer:
    """Create a compliance scorer."""
    return ComplianceScorer(mock_repository)


def create_compliance_result(
    scan_id: str,
    framework: str,
    control_id: str,
    status: str,
    finding_count: int = 0,
) -> ComplianceResult:
    """Helper to create compliance result."""
    return ComplianceResult(
        id=str(uuid.uuid4()),
        scan_id=scan_id,
        framework=framework,
        control_id=control_id,
        control_title=f"Control {control_id}",
        status=status,
        finding_count=finding_count,
        evidence=json.dumps({}),
        created_at=datetime.utcnow(),
    )


class TestComplianceScorerCalculation:
    """Test compliance score calculation."""

    def test_calculate_unweighted_score(
        self, compliance_scorer: ComplianceScorer, mock_repository: MagicMock
    ) -> None:
        """Test score calculation: (PASS / (PASS + FAIL)) × 100."""
        # 7 PASS, 3 FAIL → score = 70%
        results = [
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", "CIS_AWS_1", "PASS"),
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", "CIS_AWS_2", "PASS"),
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", "CIS_AWS_3", "PASS"),
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", "CIS_AWS_4", "PASS"),
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", "CIS_AWS_5", "PASS"),
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", "CIS_AWS_6", "PASS"),
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", "CIS_AWS_7", "PASS"),
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", "CIS_AWS_8", "FAIL"),
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", "CIS_AWS_9", "FAIL"),
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", "CIS_AWS_10", "FAIL"),
        ]
        mock_repository.get_compliance_results.return_value = results

        score = compliance_scorer.calculate_score("scan-1", "CIS_AWS_1.4.0")

        # 7 / (7 + 3) * 100 = 70%
        assert score == 70.0

    def test_score_excludes_not_applicable(
        self, compliance_scorer: ComplianceScorer, mock_repository: MagicMock
    ) -> None:
        """Test that NOT_APPLICABLE status is excluded from denominator."""
        # 5 PASS, 2 FAIL, 3 NOT_APPLICABLE
        # Score = 5 / (5 + 2) * 100 = 71.43% (NOT_APPLICABLE not counted)
        results = [
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", "CIS_AWS_1", "PASS"),
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", "CIS_AWS_2", "PASS"),
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", "CIS_AWS_3", "PASS"),
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", "CIS_AWS_4", "PASS"),
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", "CIS_AWS_5", "PASS"),
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", "CIS_AWS_6", "FAIL"),
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", "CIS_AWS_7", "FAIL"),
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", "CIS_AWS_8", "NOT_APPLICABLE"),
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", "CIS_AWS_9", "NOT_APPLICABLE"),
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", "CIS_AWS_10", "NOT_APPLICABLE"),
        ]
        mock_repository.get_compliance_results.return_value = results

        score = compliance_scorer.calculate_score("scan-1", "CIS_AWS_1.4.0")

        # 5 / 7 * 100 = 71.43%
        assert abs(score - 71.43) < 0.1

    def test_score_by_framework(
        self, compliance_scorer: ComplianceScorer, mock_repository: MagicMock
    ) -> None:
        """Test that scores are calculated separately per framework."""
        # AWS: 7 PASS, 3 FAIL → 70%
        # Azure: 8 PASS, 2 FAIL → 80%
        results = [
            # AWS
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", "CIS_AWS_1", "PASS"),
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", "CIS_AWS_2", "PASS"),
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", "CIS_AWS_3", "PASS"),
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", "CIS_AWS_4", "PASS"),
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", "CIS_AWS_5", "PASS"),
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", "CIS_AWS_6", "PASS"),
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", "CIS_AWS_7", "PASS"),
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", "CIS_AWS_8", "FAIL"),
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", "CIS_AWS_9", "FAIL"),
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", "CIS_AWS_10", "FAIL"),
            # Azure
            create_compliance_result("scan-1", "CIS_AZURE_1.4.0", "CIS_AZURE_1", "PASS"),
            create_compliance_result("scan-1", "CIS_AZURE_1.4.0", "CIS_AZURE_2", "PASS"),
            create_compliance_result("scan-1", "CIS_AZURE_1.4.0", "CIS_AZURE_3", "PASS"),
            create_compliance_result("scan-1", "CIS_AZURE_1.4.0", "CIS_AZURE_4", "PASS"),
            create_compliance_result("scan-1", "CIS_AZURE_1.4.0", "CIS_AZURE_5", "PASS"),
            create_compliance_result("scan-1", "CIS_AZURE_1.4.0", "CIS_AZURE_6", "PASS"),
            create_compliance_result("scan-1", "CIS_AZURE_1.4.0", "CIS_AZURE_7", "PASS"),
            create_compliance_result("scan-1", "CIS_AZURE_1.4.0", "CIS_AZURE_8", "PASS"),
            create_compliance_result("scan-1", "CIS_AZURE_1.4.0", "CIS_AZURE_9", "FAIL"),
            create_compliance_result("scan-1", "CIS_AZURE_1.4.0", "CIS_AZURE_10", "FAIL"),
        ]
        mock_repository.get_compliance_results.return_value = results

        aws_score = compliance_scorer.calculate_score("scan-1", "CIS_AWS_1.4.0")
        azure_score = compliance_scorer.calculate_score("scan-1", "CIS_AZURE_1.4.0")

        assert aws_score == 70.0
        assert azure_score == 80.0

    def test_score_with_all_pass_is_100(
        self, compliance_scorer: ComplianceScorer, mock_repository: MagicMock
    ) -> None:
        """Test that all PASS controls result in 100% score."""
        results = [
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", f"CIS_AWS_{i}", "PASS")
            for i in range(10)
        ]
        mock_repository.get_compliance_results.return_value = results

        score = compliance_scorer.calculate_score("scan-1", "CIS_AWS_1.4.0")

        assert score == 100.0

    def test_score_with_all_fail_is_0(
        self, compliance_scorer: ComplianceScorer, mock_repository: MagicMock
    ) -> None:
        """Test that all FAIL controls result in 0% score."""
        results = [
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", f"CIS_AWS_{i}", "FAIL")
            for i in range(10)
        ]
        mock_repository.get_compliance_results.return_value = results

        score = compliance_scorer.calculate_score("scan-1", "CIS_AWS_1.4.0")

        assert score == 0.0

    def test_score_with_no_applicable_controls(
        self, compliance_scorer: ComplianceScorer, mock_repository: MagicMock
    ) -> None:
        """Test score when all controls are NOT_APPLICABLE."""
        results = [
            create_compliance_result("scan-1", "CIS_AWS_1.4.0", f"CIS_AWS_{i}", "NOT_APPLICABLE")
            for i in range(10)
        ]
        mock_repository.get_compliance_results.return_value = results

        score = compliance_scorer.calculate_score("scan-1", "CIS_AWS_1.4.0")

        # No applicable controls → score is 0 or undefined
        # We return 0 for this case
        assert score == 0.0


class TestHistoricalCompliance:
    """Test historical compliance tracking."""

    def test_calculate_trend_over_30_days(
        self, compliance_scorer: ComplianceScorer, mock_repository: MagicMock
    ) -> None:
        """Test calculating compliance trend over 30 days."""
        from datetime import timedelta
        # Mock history: 5 scans with different dates
        base_date = datetime.utcnow()
        history_data = [
            ("scan-1", base_date - timedelta(days=25)),
            ("scan-2", base_date - timedelta(days=20)),
            ("scan-3", base_date - timedelta(days=15)),
            ("scan-4", base_date - timedelta(days=8)),
            ("scan-5", base_date),
        ]
        mock_repository.get_compliance_history.return_value = history_data

        # Mock scores for each scan: improving trend
        mock_repository.get_compliance_results.side_effect = [
            [create_compliance_result(f"scan-{i}", "CIS_AWS_1.4.0", f"CIS_AWS_{j}", "PASS")
             for j in range(5)] +
            [create_compliance_result(f"scan-{i}", "CIS_AWS_1.4.0", f"CIS_AWS_{j}", "FAIL")
             for j in range(5, 10)]
            for i in range(1, 6)
        ]

        trend = compliance_scorer.calculate_trend("CIS_AWS_1.4.0", days=30)

        assert len(trend) >= 1
        # Each item should be (date, score) tuple
        for date, score in trend:
            assert isinstance(date, datetime)
            assert isinstance(score, float)
            assert 0.0 <= score <= 100.0

    def test_trend_with_multiple_scans(
        self, compliance_scorer: ComplianceScorer, mock_repository: MagicMock
    ) -> None:
        """Test trend calculation with multiple scans."""
        # 3 scans with increasing scores
        from datetime import timedelta
        base_date = datetime.utcnow()
        history_data = [
            ("scan-1", base_date - timedelta(days=20)),
            ("scan-2", base_date - timedelta(days=10)),
            ("scan-3", base_date),
        ]
        mock_repository.get_compliance_history.return_value = history_data

        # Scan 1: 60% (6 PASS, 4 FAIL)
        # Scan 2: 75% (7.5 PASS, 2.5 FAIL - simulated with rounded values)
        # Scan 3: 100% (10 PASS)
        def get_results_side_effect(scan_id):
            if scan_id == "scan-1":
                return [create_compliance_result(scan_id, "CIS_AWS_1.4.0", f"CIS_AWS_{i}", "PASS")
                        for i in range(6)] + \
                       [create_compliance_result(scan_id, "CIS_AWS_1.4.0", f"CIS_AWS_{i}", "FAIL")
                        for i in range(6, 10)]
            elif scan_id == "scan-2":
                return [create_compliance_result(scan_id, "CIS_AWS_1.4.0", f"CIS_AWS_{i}", "PASS")
                        for i in range(8)] + \
                       [create_compliance_result(scan_id, "CIS_AWS_1.4.0", f"CIS_AWS_{i}", "FAIL")
                        for i in range(8, 10)]
            else:  # scan-3
                return [create_compliance_result(scan_id, "CIS_AWS_1.4.0", f"CIS_AWS_{i}", "PASS")
                        for i in range(10)]

        mock_repository.get_compliance_results.side_effect = get_results_side_effect

        trend = compliance_scorer.calculate_trend("CIS_AWS_1.4.0", days=30)

        # Should have 3 data points
        assert len(trend) == 3

        # Verify trend is improving
        scores = [score for _, score in trend]
        assert scores[0] < scores[1] < scores[2]
