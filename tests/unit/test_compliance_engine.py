"""Tests for compliance engine."""

import json
import uuid
from datetime import datetime
from unittest.mock import MagicMock

import pytest

from cspm.compliance.engine import ComplianceEngine
from cspm.compliance.mapper import create_default_mapper
from cspm.compliance.controls.aws import CISAWSFramework
from cspm.compliance.controls.azure import CISAzureFramework
from cspm.database.models import Finding, ComplianceResult, SeverityLevel
from cspm.database.repository import Repository


@pytest.fixture
def mock_repository() -> MagicMock:
    """Create a mock repository."""
    return MagicMock(spec=Repository)


@pytest.fixture
def compliance_engine(mock_repository: MagicMock) -> ComplianceEngine:
    """Create a compliance engine with default mapper."""
    mapper = create_default_mapper()
    return ComplianceEngine(mock_repository, mapper)


@pytest.fixture
def sample_finding() -> Finding:
    """Create a sample finding."""
    return Finding(
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


class TestComplianceEnginePassStatus:
    """Test PASS status assessment."""

    def test_assess_compliance_no_findings_all_pass(
        self, compliance_engine: ComplianceEngine, mock_repository: MagicMock
    ) -> None:
        """Test that all controls PASS when no findings exist."""
        mock_repository.get_findings_by_scan.return_value = []

        frameworks = [CISAWSFramework()]
        results = compliance_engine.assess_compliance("scan-123", frameworks)

        # AWS has 10 controls, all should be assessed
        assert len(results) >= 9  # At least 9 because some may not have rules yet

        # Filter to only controls with rules
        results_with_rules = [r for r in results if r.status != "NOT_APPLICABLE"]
        for result in results_with_rules:
            assert result.status == "PASS", f"Control {result.control_id} should PASS"
            assert result.finding_count == 0

    def test_compliance_result_saved_to_repository(
        self, compliance_engine: ComplianceEngine, mock_repository: MagicMock
    ) -> None:
        """Test that compliance results are saved to repository."""
        mock_repository.get_findings_by_scan.return_value = []
        mock_repository.save_compliance_result.side_effect = lambda x: x

        frameworks = [CISAWSFramework()]
        results = compliance_engine.assess_compliance("scan-123", frameworks)

        # Verify save_compliance_result was called for each result
        assert mock_repository.save_compliance_result.called
        assert mock_repository.save_compliance_result.call_count >= 9

    def test_compliance_result_has_correct_fields(
        self, compliance_engine: ComplianceEngine, mock_repository: MagicMock
    ) -> None:
        """Test that compliance results have correct fields."""
        mock_repository.get_findings_by_scan.return_value = []
        mock_repository.save_compliance_result.side_effect = lambda x: x

        frameworks = [CISAWSFramework()]
        results = compliance_engine.assess_compliance("scan-123", frameworks)

        for result in results:
            assert result.scan_id == "scan-123"
            assert result.framework in ["CIS_AWS_1.4.0"]
            assert result.control_id
            assert result.control_title
            assert result.status in ["PASS", "FAIL", "NOT_APPLICABLE"]
            assert isinstance(result.finding_count, int)
            assert result.finding_count >= 0


class TestComplianceEngineFailStatus:
    """Test FAIL status assessment."""

    def test_assess_compliance_with_findings_fail(
        self, compliance_engine: ComplianceEngine, mock_repository: MagicMock, sample_finding: Finding
    ) -> None:
        """Test that controls FAIL when findings exist for mapped rules."""
        mock_repository.get_findings_by_scan.return_value = [sample_finding]

        frameworks = [CISAWSFramework()]
        results = compliance_engine.assess_compliance("scan-123", frameworks)

        # Find CIS_AWS_3.1 (mapped to PublicS3Rule)
        result_3_1 = next((r for r in results if r.control_id == "CIS_AWS_3.1"), None)
        assert result_3_1 is not None
        assert result_3_1.status == "FAIL"
        assert result_3_1.finding_count == 1

    def test_fail_status_propagates_to_multiple_controls(
        self, compliance_engine: ComplianceEngine, mock_repository: MagicMock, sample_finding: Finding
    ) -> None:
        """Test that FAIL status propagates to all mapped controls."""
        # Create a finding for CloudTrailDisabledRule which maps to 2 controls
        finding = Finding(
            id=str(uuid.uuid4()),
            scan_id="scan-123",
            rule_id="CloudTrailDisabledRule",
            rule_name="CloudTrailDisabledRule",
            resource_id="arn:aws:cloudtrail:us-east-1:123456789:trail/my-trail",
            resource_type="AWS::CloudTrail::Trail",
            resource_name="my-trail",
            cloud_provider="AWS",
            severity=SeverityLevel.CRITICAL.value,
            title="CloudTrail is not enabled",
            description="CloudTrail logging is not enabled",
            remediation_advice="Enable CloudTrail",
            status="OPEN",
            evidence=json.dumps({}),
            created_at=datetime.utcnow(),
        )
        mock_repository.get_findings_by_scan.return_value = [finding]

        frameworks = [CISAWSFramework()]
        results = compliance_engine.assess_compliance("scan-123", frameworks)

        # Both CIS_AWS_2.1 and CIS_AWS_2.5 should FAIL
        result_2_1 = next((r for r in results if r.control_id == "CIS_AWS_2.1"), None)
        result_2_5 = next((r for r in results if r.control_id == "CIS_AWS_2.5"), None)

        assert result_2_1 is not None
        assert result_2_1.status == "FAIL"
        assert result_2_5 is not None
        assert result_2_5.status == "FAIL"

    def test_finding_count_matches_actual_findings(
        self, compliance_engine: ComplianceEngine, mock_repository: MagicMock, sample_finding: Finding
    ) -> None:
        """Test that finding_count field matches actual findings."""
        # Create multiple findings for the same rule
        finding2 = Finding(
            id=str(uuid.uuid4()),
            scan_id="scan-123",
            rule_id="PublicS3Rule",
            rule_name="PublicS3Rule",
            resource_id="arn:aws:s3:::another-bucket",
            resource_type="AWS::S3::Bucket",
            resource_name="another-bucket",
            cloud_provider="AWS",
            severity=SeverityLevel.CRITICAL.value,
            title="S3 Bucket is Public",
            description="S3 bucket allows public access",
            remediation_advice="Block public access",
            status="OPEN",
            evidence=json.dumps({"acl": "public-read"}),
            created_at=datetime.utcnow(),
        )
        mock_repository.get_findings_by_scan.return_value = [sample_finding, finding2]

        frameworks = [CISAWSFramework()]
        results = compliance_engine.assess_compliance("scan-123", frameworks)

        result_3_1 = next((r for r in results if r.control_id == "CIS_AWS_3.1"), None)
        assert result_3_1 is not None
        assert result_3_1.finding_count == 2


class TestComplianceEngineNotApplicableStatus:
    """Test NOT_APPLICABLE status."""

    def test_control_without_rules_not_applicable(
        self, compliance_engine: ComplianceEngine, mock_repository: MagicMock
    ) -> None:
        """Test that controls without mapped rules are NOT_APPLICABLE."""
        mock_repository.get_findings_by_scan.return_value = []

        frameworks = [CISAWSFramework()]
        results = compliance_engine.assess_compliance("scan-123", frameworks)

        # Find controls without rules (e.g., CIS_AWS_1.2, CIS_AWS_1.4 have no rules)
        result_1_2 = next((r for r in results if r.control_id == "CIS_AWS_1.2"), None)
        result_1_4 = next((r for r in results if r.control_id == "CIS_AWS_1.4"), None)

        assert result_1_2 is not None
        assert result_1_2.status == "NOT_APPLICABLE"
        assert result_1_4 is not None
        assert result_1_4.status == "NOT_APPLICABLE"

    def test_mixed_status_assessment(
        self, compliance_engine: ComplianceEngine, mock_repository: MagicMock, sample_finding: Finding
    ) -> None:
        """Test mix of PASS, FAIL, and NOT_APPLICABLE statuses."""
        mock_repository.get_findings_by_scan.return_value = [sample_finding]

        frameworks = [CISAWSFramework()]
        results = compliance_engine.assess_compliance("scan-123", frameworks)

        statuses = {r.status for r in results}
        # Should have at least 2 different statuses
        assert len(statuses) >= 2
        assert "PASS" in statuses or "NOT_APPLICABLE" in statuses
        assert "FAIL" in statuses

    def test_evidence_field_contains_finding_ids(
        self, compliance_engine: ComplianceEngine, mock_repository: MagicMock, sample_finding: Finding
    ) -> None:
        """Test that evidence field contains finding IDs and summary."""
        mock_repository.get_findings_by_scan.return_value = [sample_finding]

        frameworks = [CISAWSFramework()]
        results = compliance_engine.assess_compliance("scan-123", frameworks)

        result_3_1 = next((r for r in results if r.control_id == "CIS_AWS_3.1"), None)
        assert result_3_1 is not None
        assert result_3_1.evidence

        # Parse evidence JSON
        evidence_data = json.loads(result_3_1.evidence)
        assert "control_description" in evidence_data
        assert "finding_ids" in evidence_data or "affected_resources" in evidence_data

    def test_evidence_for_not_applicable_control(
        self, compliance_engine: ComplianceEngine, mock_repository: MagicMock
    ) -> None:
        """Test that NOT_APPLICABLE controls have evidence."""
        mock_repository.get_findings_by_scan.return_value = []

        frameworks = [CISAWSFramework()]
        results = compliance_engine.assess_compliance("scan-123", frameworks)

        result_1_2 = next((r for r in results if r.control_id == "CIS_AWS_1.2"), None)
        assert result_1_2 is not None
        assert result_1_2.evidence

        evidence_data = json.loads(result_1_2.evidence)
        assert "control_description" in evidence_data


class TestMultiFrameworkAssessment:
    """Test multi-framework compliance assessment."""

    def test_multi_cloud_compliance_assessment(
        self, compliance_engine: ComplianceEngine, mock_repository: MagicMock
    ) -> None:
        """Test assessing AWS and Azure frameworks together."""
        mock_repository.get_findings_by_scan.return_value = []

        frameworks = [CISAWSFramework(), CISAzureFramework()]
        results = compliance_engine.assess_compliance("scan-123", frameworks)

        # Should have results for both frameworks
        aws_results = [r for r in results if r.framework == "CIS_AWS_1.4.0"]
        azure_results = [r for r in results if r.framework == "CIS_AZURE_1.4.0"]

        assert len(aws_results) >= 9
        assert len(azure_results) >= 2  # At least 2 with rules
