"""Unit tests for remediation base classes."""

import pytest
from enum import Enum
from dataclasses import dataclass
from abc import ABC, abstractmethod

from cspm.remediation.base import (
    RemediationMode,
    RemediationStatus,
    RemediationResult,
    BaseRemediationAction,
)


class TestRemediationMode:
    """Test RemediationMode enum."""

    def test_remediation_mode_dry_run(self):
        """DRY_RUN mode exists."""
        assert hasattr(RemediationMode, 'DRY_RUN')

    def test_remediation_mode_auto_fix(self):
        """AUTO_FIX mode exists."""
        assert hasattr(RemediationMode, 'AUTO_FIX')


class TestRemediationStatus:
    """Test RemediationStatus enum."""

    def test_status_pending(self):
        """PENDING status exists."""
        assert hasattr(RemediationStatus, 'PENDING')

    def test_status_in_progress(self):
        """IN_PROGRESS status exists."""
        assert hasattr(RemediationStatus, 'IN_PROGRESS')

    def test_status_success(self):
        """SUCCESS status exists."""
        assert hasattr(RemediationStatus, 'SUCCESS')

    def test_status_failed(self):
        """FAILED status exists."""
        assert hasattr(RemediationStatus, 'FAILED')

    def test_status_approval_required(self):
        """APPROVAL_REQUIRED status exists."""
        assert hasattr(RemediationStatus, 'APPROVAL_REQUIRED')


class TestRemediationResult:
    """Test RemediationResult dataclass."""

    def test_create_success_result(self):
        """Create successful remediation result."""
        result = RemediationResult(
            success=True,
            status=RemediationStatus.SUCCESS,
            changes_made={"key": "value"},
            dry_run=False
        )
        assert result.success is True
        assert result.status == RemediationStatus.SUCCESS
        assert result.changes_made == {"key": "value"}
        assert result.dry_run is False

    def test_create_failed_result_with_error(self):
        """Create failed remediation result with error message."""
        result = RemediationResult(
            success=False,
            status=RemediationStatus.FAILED,
            changes_made={},
            error_message="Permission denied",
            dry_run=False
        )
        assert result.success is False
        assert result.status == RemediationStatus.FAILED
        assert result.error_message == "Permission denied"

    def test_dry_run_result(self):
        """Create dry-run remediation result."""
        result = RemediationResult(
            success=True,
            status=RemediationStatus.SUCCESS,
            changes_made={"action": "Would update resource"},
            dry_run=True
        )
        assert result.dry_run is True


class TestBaseRemediationAction:
    """Test BaseRemediationAction ABC."""

    def test_cannot_instantiate_abstract_class(self):
        """Cannot instantiate BaseRemediationAction directly."""
        with pytest.raises(TypeError):
            BaseRemediationAction()

    def test_concrete_implementation(self):
        """Concrete subclass can be instantiated."""

        class TestAction(BaseRemediationAction):
            def __init__(self):
                super().__init__()
                self.action_id = "TestAction"
                self.name = "Test Remediation"
                self.description = "A test remediation action"
                self.rule_id = "TestRule"
                self.cloud_provider = "aws"
                self.resource_types = ["TEST::Resource"]
                self.requires_approval = False

            def validate(self, resource):
                return resource.get("type") == "TEST::Resource"

            def execute(self, resource, finding, mode):
                return RemediationResult(
                    success=True,
                    status=RemediationStatus.SUCCESS,
                    changes_made={},
                    dry_run=(mode == RemediationMode.DRY_RUN)
                )

        action = TestAction()
        assert action.action_id == "TestAction"
        assert action.name == "Test Remediation"
        assert action.rule_id == "TestRule"

    def test_abstract_methods_required(self):
        """Abstract methods must be implemented."""

        class IncompleteAction(BaseRemediationAction):
            def __init__(self):
                super().__init__()
                # Missing validate and execute implementations

            def validate(self, resource):
                return True

            # Missing execute method

        with pytest.raises(TypeError):
            IncompleteAction()

    def test_action_properties(self):
        """Action has required properties."""

        class TestAction(BaseRemediationAction):
            def __init__(self):
                super().__init__()
                self.action_id = "TestAction"
                self.name = "Test"
                self.description = "Test action"
                self.rule_id = "TestRule"
                self.cloud_provider = "aws"
                self.resource_types = ["AWS::S3::Bucket"]
                self.requires_approval = True

            def validate(self, resource):
                return True

            def execute(self, resource, finding, mode):
                return RemediationResult(
                    success=True,
                    status=RemediationStatus.SUCCESS,
                    changes_made={},
                    dry_run=False
                )

        action = TestAction()
        assert action.action_id == "TestAction"
        assert action.name == "Test"
        assert action.description == "Test action"
        assert action.rule_id == "TestRule"
        assert action.cloud_provider == "aws"
        assert action.resource_types == ["AWS::S3::Bucket"]
        assert action.requires_approval is True
