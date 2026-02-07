"""Compliance report generation."""

import json
from typing import Any

from cspm.compliance.scoring import ComplianceScorer
from cspm.database.repository import Repository


class ComplianceReporter:
    """Generates compliance reports."""

    def __init__(self, repository: Repository) -> None:
        """Initialize compliance reporter.

        Args:
            repository: Data access layer for querying compliance results
        """
        self.repository = repository
        self.scorer = ComplianceScorer(repository)

    def generate_report(self, scan_id: str) -> dict[str, Any]:
        """Generate a compliance report for a scan.

        Args:
            scan_id: The scan identifier

        Returns:
            Dictionary containing compliance report with scores and control details
        """
        # Get all compliance results for this scan
        results = self.repository.get_compliance_results(scan_id)

        if not results:
            return {"scan_id": scan_id, "error": "No compliance results found"}

        # Group results by framework
        frameworks_data: dict[str, Any] = {}

        for result in results:
            if result.framework not in frameworks_data:
                frameworks_data[result.framework] = {
                    "controls": [],
                    "pass": 0,
                    "fail": 0,
                    "not_applicable": 0,
                }

            # Count by status
            if result.status == "PASS":
                frameworks_data[result.framework]["pass"] += 1
            elif result.status == "FAIL":
                frameworks_data[result.framework]["fail"] += 1
            elif result.status == "NOT_APPLICABLE":
                frameworks_data[result.framework]["not_applicable"] += 1

            # Add control details
            control_detail = {
                "control_id": result.control_id,
                "control_title": result.control_title,
                "status": result.status,
                "finding_count": result.finding_count,
            }

            # Parse evidence if available
            if result.evidence:
                try:
                    evidence_data = json.loads(result.evidence)
                    control_detail["evidence"] = evidence_data
                except json.JSONDecodeError:
                    control_detail["evidence"] = {}

            frameworks_data[result.framework]["controls"].append(control_detail)

        # Calculate scores for each framework
        report: dict[str, Any] = {
            "scan_id": scan_id,
            "frameworks": {},
        }

        for framework_id, data in frameworks_data.items():
            # Calculate score
            score = self.scorer.calculate_score(scan_id, framework_id)

            total_applicable = data["pass"] + data["fail"]
            total = total_applicable + data["not_applicable"]

            framework_report = {
                "score": round(score, 2),
                "pass": data["pass"],
                "fail": data["fail"],
                "not_applicable": data["not_applicable"],
                "total_assessed": total_applicable,
                "total_controls": total,
            }

            # Get failing controls with details
            failing_controls = [
                c for c in data["controls"] if c["status"] == "FAIL"
            ]
            if failing_controls:
                framework_report["failing_controls"] = failing_controls

            report["frameworks"][framework_id] = framework_report

        return report
