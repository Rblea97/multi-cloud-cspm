"""Unit tests for remediation engine."""

import pytest
from datetime import datetime
from unittest.mock import MagicMock

from cspm.remediation.engine import RemediationEngine
from cspm.remediation.registry import RemediationRegistry
from cspm.remediation.base import (
    BaseRemediationAction,
    RemediationMode,
    RemediationResult,
    RemediationStatus,
)
from cspm.database.models import Finding, RemediationAction


class MockAction(BaseRemediationAction):
    """Mock remediation action for testing."""

    def __init__(self):
        super().__init__()
        self.action_id = "MockAction"
        self.name = "Mock Action"
        self.description = "Mock test action"
        self.rule_id = "MockRule"
        self.cloud_provider = "aws"
        self.resource_types = ["Mock::Resource"]
        self.requires_approval = False

    def validate(self, resource):
        return True

    def execute(self, resource, finding, mode):
        return RemediationResult(
            success=True, status=RemediationStatus.SUCCESS, changes_made={}
        )


class TestRemediationEngine:
    """Test RemediationEngine."""

    @pytest.fixture
    def mock_registry(self):
        """Create mock registry."""
        registry = RemediationRegistry()
        registry.register(MockAction())
        return registry

    @pytest.fixture
    def mock_repository(self):
        """Create mock repository."""
        return MagicMock()

    @pytest.fixture
    def engine(self, mock_registry, mock_repository):
        """Create remediation engine."""
        return RemediationEngine(mock_registry, mock_repository)

    def test_engine_initialization(self, engine, mock_registry, mock_repository):
        """Engine initializes with registry and repository."""
        assert engine._registry == mock_registry
        assert engine._repository == mock_repository

    def test_remediate_finding_creates_db_record(self, engine, mock_repository):
        """remediate_finding creates database record."""
        mock_repository.get_finding.return_value = MagicMock(
            id="finding-123", rule_id="MockRule", severity="MEDIUM"
        )
        mock_repository.create_remediation_action.return_value = "action-123"

        finding_id = "finding-123"
        action_id = engine.remediate_finding(
            finding_id, RemediationMode.DRY_RUN, "test-user"
        )

        assert action_id == "action-123"
        mock_repository.create_remediation_action.assert_called_once()

    def test_dry_run_mode_no_execution(self, engine, mock_repository):
        """DRY_RUN mode creates record but doesn't execute."""
        mock_repository.get_finding.return_value = MagicMock(
            id="finding-123",
            rule_id="MockRule",
            severity="MEDIUM",
            resource_data={"type": "Mock::Resource"},
        )
        mock_repository.create_remediation_action.return_value = "action-123"

        action_id = engine.remediate_finding(
            "finding-123", RemediationMode.DRY_RUN, "test-user"
        )

        assert action_id == "action-123"
        # In DRY_RUN, status should be SUCCESS (dry-run executed)
        call_args = mock_repository.create_remediation_action.call_args
        assert call_args is not None

    def test_critical_finding_requires_approval(self, engine, mock_repository):
        """CRITICAL severity findings require approval."""
        mock_repository.get_finding.return_value = MagicMock(
            id="finding-123",
            rule_id="MockRule",
            severity="CRITICAL",
            resource_data={"type": "Mock::Resource"},
        )
        mock_repository.create_remediation_action.return_value = "action-123"

        action_id = engine.remediate_finding(
            "finding-123", RemediationMode.AUTO_FIX, "test-user"
        )

        # Should create action with approval_required=True
        call_args = mock_repository.create_remediation_action.call_args
        assert call_args is not None
        call_kwargs = call_args[1]
        assert call_kwargs.get("approval_required") is True

    def test_high_finding_requires_approval(self, engine, mock_repository):
        """HIGH severity findings require approval."""
        mock_repository.get_finding.return_value = MagicMock(
            id="finding-123",
            rule_id="MockRule",
            severity="HIGH",
            resource_data={"type": "Mock::Resource"},
        )
        mock_repository.create_remediation_action.return_value = "action-123"

        action_id = engine.remediate_finding(
            "finding-123", RemediationMode.AUTO_FIX, "test-user"
        )

        call_args = mock_repository.create_remediation_action.call_args
        assert call_args is not None
        call_kwargs = call_args[1]
        assert call_kwargs.get("approval_required") is True

    def test_medium_finding_auto_executes(self, engine, mock_repository):
        """MEDIUM severity findings auto-execute without approval."""
        mock_repository.get_finding.return_value = MagicMock(
            id="finding-123",
            rule_id="MockRule",
            severity="MEDIUM",
            resource_data={"type": "Mock::Resource"},
        )
        mock_repository.create_remediation_action.return_value = "action-123"

        action_id = engine.remediate_finding(
            "finding-123", RemediationMode.AUTO_FIX, "test-user"
        )

        call_args = mock_repository.create_remediation_action.call_args
        assert call_args is not None
        call_kwargs = call_args[1]
        assert call_kwargs.get("approval_required") is False

    def test_approve_remediation(self, engine, mock_repository):
        """Approve remediation action."""
        mock_repository.get_remediation_action.return_value = MagicMock(
            id="action-123", status="APPROVAL_REQUIRED"
        )

        result = engine.approve_remediation("action-123", "approver-user")

        assert result is True
        mock_repository.update_remediation_status.assert_called_once()

    def test_reject_remediation(self, engine, mock_repository):
        """Reject remediation action."""
        mock_repository.get_remediation_action.return_value = MagicMock(
            id="action-123", status="APPROVAL_REQUIRED"
        )

        result = engine.reject_remediation("action-123", "approver-user")

        assert result is True
        mock_repository.update_remediation_status.assert_called_once()

    def test_execute_pending_remediations(self, engine, mock_repository):
        """Execute pending approved remediations."""
        mock_action_record = MagicMock(
            id="action-123",
            status="PENDING",
            approval_required=False,
            action_type="MockAction",
            finding_id="finding-123",
            mode="dry_run",
        )
        mock_repository.get_pending_remediations.return_value = [mock_action_record]
        mock_repository.get_finding.return_value = MagicMock(
            resource_data={"type": "Mock::Resource"}
        )

        action_ids = engine.execute_pending_remediations()

        assert "action-123" in action_ids
        # Should update status to SUCCESS (DRY_RUN is default)
        mock_repository.update_remediation_status.assert_called()
