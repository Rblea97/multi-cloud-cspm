"""Tests for compliance framework base classes."""

import pytest

from cspm.compliance.framework import ComplianceFramework, Control
from cspm.compliance.controls.aws import CISAWSFramework
from cspm.compliance.controls.azure import CISAzureFramework


class TestControlDataclass:
    """Test Control dataclass."""

    def test_control_dataclass_creation(self) -> None:
        """Test creating a Control instance."""
        control = Control(
            control_id="CIS_AWS_2.1",
            title="Enable MFA for console access",
            description="Ensure multi-factor authentication is enabled for all IAM users",
            severity="CRITICAL",
            domain="Identity and Access Management",
            rule_ids=["CloudTrailDisabledRule"],
            framework_id="CIS_AWS_1.4.0",
        )

        assert control.control_id == "CIS_AWS_2.1"
        assert control.title == "Enable MFA for console access"
        assert control.description == "Ensure multi-factor authentication is enabled for all IAM users"
        assert control.severity == "CRITICAL"
        assert control.domain == "Identity and Access Management"
        assert control.rule_ids == ["CloudTrailDisabledRule"]
        assert control.framework_id == "CIS_AWS_1.4.0"

    def test_control_with_multiple_rule_ids(self) -> None:
        """Test Control with multiple rule IDs."""
        control = Control(
            control_id="CIS_AWS_2.5",
            title="Enable CloudTrail file validation",
            description="Enable file validation for CloudTrail",
            severity="HIGH",
            domain="Logging",
            rule_ids=["CloudTrailDisabledRule", "AnotherRule"],
            framework_id="CIS_AWS_1.4.0",
        )

        assert len(control.rule_ids) == 2
        assert "CloudTrailDisabledRule" in control.rule_ids


class TestComplianceFrameworkABC:
    """Test ComplianceFramework abstract base class."""

    def test_compliance_framework_is_abstract(self) -> None:
        """Test that ComplianceFramework cannot be instantiated directly."""
        with pytest.raises(TypeError):
            ComplianceFramework()  # type: ignore

    def test_aws_framework_instantiation(self) -> None:
        """Test CISAWSFramework instantiation."""
        framework = CISAWSFramework()
        assert framework is not None

    def test_aws_framework_returns_controls(self) -> None:
        """Test that CISAWSFramework returns controls."""
        framework = CISAWSFramework()
        controls = framework.get_controls()

        assert isinstance(controls, list)
        assert len(controls) == 10
        assert all(isinstance(c, Control) for c in controls)

    def test_aws_framework_control_ids(self) -> None:
        """Test AWS framework has expected control IDs."""
        framework = CISAWSFramework()
        controls = framework.get_controls()
        control_ids = {c.control_id for c in controls}

        expected_ids = {"CIS_AWS_2.1", "CIS_AWS_2.2", "CIS_AWS_2.5", "CIS_AWS_3.1", "CIS_AWS_4.1",
                        "CIS_AWS_4.2", "CIS_AWS_5.1", "CIS_AWS_5.2", "CIS_AWS_1.2", "CIS_AWS_1.4"}
        assert control_ids == expected_ids

    def test_aws_framework_control_has_framework_id(self) -> None:
        """Test that AWS controls have correct framework_id."""
        framework = CISAWSFramework()
        controls = framework.get_controls()

        for control in controls:
            assert control.framework_id == "CIS_AWS_1.4.0"


class TestControlValidation:
    """Test Control validation."""

    def test_control_has_required_fields(self) -> None:
        """Test that controls have all required non-empty fields."""
        framework = CISAWSFramework()
        controls = framework.get_controls()

        for control in controls:
            assert control.control_id, f"Control missing control_id"
            assert control.title, f"Control {control.control_id} missing title"
            assert control.description, f"Control {control.control_id} missing description"
            assert control.severity, f"Control {control.control_id} missing severity"
            assert control.domain, f"Control {control.control_id} missing domain"
            assert control.framework_id, f"Control {control.control_id} missing framework_id"

    def test_frameworks_have_unique_control_ids(self) -> None:
        """Test that frameworks have no duplicate control IDs."""
        framework = CISAWSFramework()
        controls = framework.get_controls()
        control_ids = [c.control_id for c in controls]

        assert len(control_ids) == len(set(control_ids)), "Duplicate control IDs found"


class TestAzureFramework:
    """Test CISAzureFramework."""

    def test_azure_framework_instantiation(self) -> None:
        """Test CISAzureFramework instantiation."""
        framework = CISAzureFramework()
        assert framework is not None

    def test_azure_framework_returns_controls(self) -> None:
        """Test that CISAzureFramework returns controls."""
        framework = CISAzureFramework()
        controls = framework.get_controls()

        assert isinstance(controls, list)
        assert len(controls) == 10
        assert all(isinstance(c, Control) for c in controls)

    def test_azure_framework_control_ids(self) -> None:
        """Test Azure framework has expected control IDs."""
        framework = CISAzureFramework()
        controls = framework.get_controls()
        control_ids = {c.control_id for c in controls}

        expected_ids = {"CIS_AZURE_5.1", "CIS_AZURE_5.2", "CIS_AZURE_5.3", "CIS_AZURE_5.6", "CIS_AZURE_5.7",
                        "CIS_AZURE_4.3", "CIS_AZURE_4.4", "CIS_AZURE_3.1", "CIS_AZURE_1.1", "CIS_AZURE_1.9"}
        assert control_ids == expected_ids

    def test_azure_framework_control_has_framework_id(self) -> None:
        """Test that Azure controls have correct framework_id."""
        framework = CISAzureFramework()
        controls = framework.get_controls()

        for control in controls:
            assert control.framework_id == "CIS_AZURE_1.4.0"

    def test_azure_controls_have_required_fields(self) -> None:
        """Test that Azure controls have all required non-empty fields."""
        framework = CISAzureFramework()
        controls = framework.get_controls()

        for control in controls:
            assert control.control_id, f"Control missing control_id"
            assert control.title, f"Control {control.control_id} missing title"
            assert control.description, f"Control {control.control_id} missing description"
            assert control.severity, f"Control {control.control_id} missing severity"
            assert control.domain, f"Control {control.control_id} missing domain"
            assert control.framework_id, f"Control {control.control_id} missing framework_id"

    def test_azure_framework_has_unique_control_ids(self) -> None:
        """Test that Azure framework has no duplicate control IDs."""
        framework = CISAzureFramework()
        controls = framework.get_controls()
        control_ids = [c.control_id for c in controls]

        assert len(control_ids) == len(set(control_ids)), "Duplicate control IDs found"
