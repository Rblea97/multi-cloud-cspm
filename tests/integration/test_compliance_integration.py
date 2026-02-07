"""Integration tests for compliance assessment."""

import json
import uuid
from datetime import datetime

import pytest

from cspm.cloud.base import Resource
from cspm.compliance.engine import ComplianceEngine
from cspm.compliance.mapper import create_default_mapper
from cspm.compliance.controls.aws import CISAWSFramework
from cspm.compliance.controls.azure import CISAzureFramework
from cspm.compliance.reporting import ComplianceReporter
from cspm.compliance.scoring import ComplianceScorer
from cspm.database.models import Finding, SeverityLevel, Scan
from cspm.database.repository import Repository
from cspm.rules.aws_rules import PublicS3Rule


@pytest.fixture
def temp_db() -> Repository:
    """Create a temporary in-memory database."""
    repo = Repository("sqlite:///:memory:")
    repo.create_tables()
    return repo


class TestComplianceEngineIntegration:
    """Integration tests for compliance engine."""

    def test_scan_automatically_assesses_compliance(self, temp_db: Repository) -> None:
        """Test that scan results can be assessed for compliance."""
        # Create a scan record
        scan = Scan(
            id="scan-123",
            cloud_provider="AWS",
            scan_type="FULL",
            status="COMPLETED",
            resources_scanned=1,
            findings_count=1,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
        )
        temp_db.save_scan(scan)

        # Create a finding
        finding = Finding(
            id=str(uuid.uuid4()),
            scan_id="scan-123",
            rule_id="PublicS3Rule",
            rule_name="PublicS3Rule",
            resource_id="arn:aws:s3:::my-bucket",
            resource_type="AWS::S3::Bucket",
            resource_name="my-bucket",
            cloud_provider="AWS",
            severity=SeverityLevel.CRITICAL.value,
            title="S3 Bucket is Public",
            description="S3 bucket allows public access",
            remediation_advice="Block public access",
            status="OPEN",
            evidence=json.dumps({"acl": "public-read"}),
            created_at=datetime.utcnow(),
        )
        temp_db.save_finding(finding)

        # Run compliance assessment
        mapper = create_default_mapper()
        engine = ComplianceEngine(temp_db, mapper)
        frameworks = [CISAWSFramework()]
        results = engine.assess_compliance("scan-123", frameworks)

        # Verify compliance results were saved
        saved_results = temp_db.get_compliance_results("scan-123")
        assert len(saved_results) >= 9

        # Verify CIS_AWS_3.1 failed (mapped to PublicS3Rule)
        result_3_1 = next((r for r in saved_results if r.control_id == "CIS_AWS_3.1"), None)
        assert result_3_1 is not None
        assert result_3_1.status == "FAIL"
        assert result_3_1.finding_count == 1

    def test_compliance_results_in_database(self, temp_db: Repository) -> None:
        """Test that compliance results persist to database."""
        # Create scan and finding
        scan = Scan(
            id="scan-456",
            cloud_provider="AWS",
            scan_type="FULL",
            status="COMPLETED",
            resources_scanned=0,
            findings_count=0,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
        )
        temp_db.save_scan(scan)

        # Run assessment
        mapper = create_default_mapper()
        engine = ComplianceEngine(temp_db, mapper)
        frameworks = [CISAWSFramework()]
        engine.assess_compliance("scan-456", frameworks)

        # Query database
        results = temp_db.get_compliance_results("scan-456")
        assert len(results) >= 9

        # Verify data types and structure
        for result in results:
            assert result.scan_id == "scan-456"
            assert result.framework == "CIS_AWS_1.4.0"
            assert result.control_id
            assert result.control_title
            assert result.status in ["PASS", "FAIL", "NOT_APPLICABLE"]
            assert isinstance(result.finding_count, int)
            assert result.evidence

    def test_multi_cloud_compliance_assessment(self, temp_db: Repository) -> None:
        """Test compliance assessment for multiple clouds."""
        # Create scan
        scan = Scan(
            id="scan-multi",
            cloud_provider="MULTI",
            scan_type="FULL",
            status="COMPLETED",
            resources_scanned=0,
            findings_count=0,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
        )
        temp_db.save_scan(scan)

        # Run multi-framework assessment
        mapper = create_default_mapper()
        engine = ComplianceEngine(temp_db, mapper)
        frameworks = [CISAWSFramework(), CISAzureFramework()]
        results = engine.assess_compliance("scan-multi", frameworks)

        # Verify results include both frameworks
        aws_results = [r for r in results if r.framework == "CIS_AWS_1.4.0"]
        azure_results = [r for r in results if r.framework == "CIS_AZURE_1.4.0"]

        assert len(aws_results) >= 9
        assert len(azure_results) >= 2


class TestComplianceScoring:
    """Test compliance scoring."""

    def test_score_calculation_from_results(self, temp_db: Repository) -> None:
        """Test score calculation from compliance results."""
        scan = Scan(
            id="score-test",
            cloud_provider="AWS",
            scan_type="FULL",
            status="COMPLETED",
            resources_scanned=0,
            findings_count=0,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
        )
        temp_db.save_scan(scan)

        # Create compliance results (7 PASS, 3 FAIL)
        mapper = create_default_mapper()
        engine = ComplianceEngine(temp_db, mapper)
        frameworks = [CISAWSFramework()]
        engine.assess_compliance("score-test", frameworks)

        # Calculate score
        scorer = ComplianceScorer(temp_db)
        score = scorer.calculate_score("score-test", "CIS_AWS_1.4.0")

        # With default (no findings), all should pass → 100%
        assert score == 100.0

    def test_score_with_failures(self, temp_db: Repository) -> None:
        """Test score calculation with failing controls."""
        # Create scan and finding
        scan = Scan(
            id="score-fail",
            cloud_provider="AWS",
            scan_type="FULL",
            status="COMPLETED",
            resources_scanned=1,
            findings_count=1,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
        )
        temp_db.save_scan(scan)

        finding = Finding(
            id=str(uuid.uuid4()),
            scan_id="score-fail",
            rule_id="PublicS3Rule",
            rule_name="PublicS3Rule",
            resource_id="arn:aws:s3:::bucket",
            resource_type="AWS::S3::Bucket",
            resource_name="bucket",
            cloud_provider="AWS",
            severity=SeverityLevel.CRITICAL.value,
            title="Public Bucket",
            description="Bucket is public",
            remediation_advice="Fix",
            status="OPEN",
            evidence=json.dumps({}),
            created_at=datetime.utcnow(),
        )
        temp_db.save_finding(finding)

        # Assess compliance
        mapper = create_default_mapper()
        engine = ComplianceEngine(temp_db, mapper)
        frameworks = [CISAWSFramework()]
        engine.assess_compliance("score-fail", frameworks)

        # Calculate score
        scorer = ComplianceScorer(temp_db)
        score = scorer.calculate_score("score-fail", "CIS_AWS_1.4.0")

        # 1 control fails (CIS_AWS_3.1), others pass → ~88.9% (8/9)
        assert score < 100.0
        assert score > 80.0


class TestComplianceReporting:
    """Test compliance report generation."""

    def test_compliance_report_generation(self, temp_db: Repository) -> None:
        """Test full compliance report generation."""
        # Create scan
        scan = Scan(
            id="report-test",
            cloud_provider="AWS",
            scan_type="FULL",
            status="COMPLETED",
            resources_scanned=0,
            findings_count=0,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
        )
        temp_db.save_scan(scan)

        # Assess compliance
        mapper = create_default_mapper()
        engine = ComplianceEngine(temp_db, mapper)
        frameworks = [CISAWSFramework()]
        engine.assess_compliance("report-test", frameworks)

        # Generate report
        reporter = ComplianceReporter(temp_db)
        report = reporter.generate_report("report-test")

        # Verify report structure
        assert report["scan_id"] == "report-test"
        assert "frameworks" in report
        assert "CIS_AWS_1.4.0" in report["frameworks"]

        aws_report = report["frameworks"]["CIS_AWS_1.4.0"]
        assert "score" in aws_report
        assert "pass" in aws_report
        assert "fail" in aws_report
        assert "not_applicable" in aws_report
        assert "total_assessed" in aws_report
        assert "total_controls" in aws_report

    def test_report_includes_failing_controls(self, temp_db: Repository) -> None:
        """Test that report includes failing controls with details."""
        # Create scan with finding
        scan = Scan(
            id="report-fail",
            cloud_provider="AWS",
            scan_type="FULL",
            status="COMPLETED",
            resources_scanned=1,
            findings_count=1,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
        )
        temp_db.save_scan(scan)

        finding = Finding(
            id=str(uuid.uuid4()),
            scan_id="report-fail",
            rule_id="PublicS3Rule",
            rule_name="PublicS3Rule",
            resource_id="arn:aws:s3:::bucket",
            resource_type="AWS::S3::Bucket",
            resource_name="bucket",
            cloud_provider="AWS",
            severity=SeverityLevel.CRITICAL.value,
            title="Public Bucket",
            description="Bucket is public",
            remediation_advice="Fix",
            status="OPEN",
            evidence=json.dumps({}),
            created_at=datetime.utcnow(),
        )
        temp_db.save_finding(finding)

        # Assess compliance and generate report
        mapper = create_default_mapper()
        engine = ComplianceEngine(temp_db, mapper)
        frameworks = [CISAWSFramework()]
        engine.assess_compliance("report-fail", frameworks)

        reporter = ComplianceReporter(temp_db)
        report = reporter.generate_report("report-fail")

        # Verify failing controls are included
        aws_report = report["frameworks"]["CIS_AWS_1.4.0"]
        assert "failing_controls" in aws_report
        assert len(aws_report["failing_controls"]) >= 1

        # Verify control details
        failing = aws_report["failing_controls"][0]
        assert failing["status"] == "FAIL"
        assert failing["finding_count"] >= 1
