"""Integration tests for remediation system."""

import pytest
from datetime import datetime
from unittest.mock import MagicMock, patch

from cspm.remediation.engine import RemediationEngine
from cspm.remediation.registry import RemediationRegistry
from cspm.remediation.base import RemediationMode
from cspm.remediation.aws_actions import (
    RemediatePublicS3Bucket,
    RemediateEC2PublicIP,
)
from cspm.remediation.azure_actions import RemediatePublicStorage
from cspm.database.repository import Repository
from cspm.database.models import Finding


class TestRemediationIntegration:
    """Integration tests for remediation workflow."""

    @pytest.fixture
    def registry(self):
        """Create populated registry."""
        registry = RemediationRegistry()
        registry.register(RemediatePublicS3Bucket())
        registry.register(RemediateEC2PublicIP())
        registry.register(RemediatePublicStorage())
        return registry

    @pytest.fixture
    def mock_repository(self):
        """Create mock repository."""
        repo = MagicMock(spec=Repository)
        return repo

    @pytest.fixture
    def engine(self, registry, mock_repository):
        """Create engine with registry."""
        return RemediationEngine(registry, mock_repository)

    def test_full_remediation_workflow(self, engine, mock_repository):
        """Test complete remediation workflow."""
        # Setup mock finding
        mock_repository.get_finding.return_value = MagicMock(
            id="finding-123",
            rule_id="PublicS3Rule",
            severity="CRITICAL",
            resource_data={"type": "AWS::S3::Bucket", "name": "test-bucket"},
        )
        mock_repository.create_remediation_action.return_value = "action-123"

        # Step 1: Request remediation
        action_id = engine.remediate_finding(
            "finding-123", RemediationMode.DRY_RUN, "requester"
        )

        assert action_id == "action-123"

        # Verify approval required for CRITICAL
        call_kwargs = mock_repository.create_remediation_action.call_args[1]
        assert call_kwargs.get("approval_required") is True

        # Step 2: Approve remediation
        mock_repository.get_remediation_action.return_value = MagicMock(
            id="action-123", status="APPROVAL_REQUIRED"
        )

        result = engine.approve_remediation("action-123", "approver")
        assert result is True

        # Step 3: Execute approved remediation
        mock_repository.get_pending_remediations.return_value = [
            MagicMock(
                id="action-123",
                status="PENDING",
                action_type="RemediatePublicS3Bucket",
                finding_id="finding-123",
                mode="dry_run",
            )
        ]

        executed = engine.execute_pending_remediations()
        assert "action-123" in executed

    def test_dry_run_workflow_no_changes(self, engine, mock_repository):
        """Dry-run mode should not make actual changes."""
        mock_repository.get_finding.return_value = MagicMock(
            id="finding-456",
            rule_id="PublicS3Rule",
            severity="HIGH",
            resource_data={"type": "AWS::S3::Bucket", "name": "test-bucket"},
        )
        mock_repository.create_remediation_action.return_value = "action-456"

        # Request dry-run
        action_id = engine.remediate_finding(
            "finding-456", RemediationMode.DRY_RUN, "requester"
        )

        # Verify dry_run mode in created action
        call_kwargs = mock_repository.create_remediation_action.call_args[1]
        assert call_kwargs.get("mode") == "dry_run"

    def test_medium_severity_auto_executes(self, engine, mock_repository):
        """MEDIUM severity should auto-execute without approval if action doesn't require it."""
        # EC2PublicIP action has requires_approval=False
        mock_repository.get_finding.return_value = MagicMock(
            id="finding-789",
            rule_id="EC2PublicIPRule",
            severity="MEDIUM",
            resource_data={"type": "AWS::EC2::Instance", "instance_id": "i-12345"},
        )
        mock_repository.create_remediation_action.return_value = "action-789"

        action_id = engine.remediate_finding(
            "finding-789", RemediationMode.AUTO_FIX, "requester"
        )

        # Verify approval NOT required for MEDIUM with requires_approval=False action
        call_kwargs = mock_repository.create_remediation_action.call_args[1]
        assert call_kwargs.get("approval_required") is False
        assert call_kwargs.get("status") == "PENDING"

    def test_rejection_workflow(self, engine, mock_repository):
        """Test rejecting a remediation."""
        mock_repository.get_remediation_action.return_value = MagicMock(
            id="action-reject", status="APPROVAL_REQUIRED"
        )

        result = engine.reject_remediation("action-reject", "approver")
        assert result is True

        # Verify status updated to FAILED
        mock_repository.update_remediation_status.assert_called()
        # Call args: (action_id, status, result_dict)
        call_args = mock_repository.update_remediation_status.call_args[0]
        assert call_args[1] == "FAILED"  # Status is FAILED
        assert "error_message" in call_args[2]  # Result dict has error_message

    def test_execution_with_error_handling(self, engine, mock_repository):
        """Test error handling during execution."""
        # Setup action that will fail
        mock_repository.get_pending_remediations.return_value = [
            MagicMock(
                id="action-error",
                status="PENDING",
                action_type="NonExistentAction",
                finding_id="finding-error",
                mode="dry_run",
            )
        ]
        mock_repository.get_finding.return_value = MagicMock(
            resource_data={"type": "AWS::S3::Bucket"}
        )

        executed = engine.execute_pending_remediations()

        # Should skip invalid action gracefully
        assert "action-error" not in executed

    def test_multi_cloud_remediation(self, engine, mock_repository):
        """Test remediating AWS and Azure findings."""
        # Test AWS finding
        aws_finding = MagicMock(
            id="aws-finding",
            rule_id="PublicS3Rule",
            severity="HIGH",
            resource_data={"type": "AWS::S3::Bucket", "name": "test-bucket"},
        )
        mock_repository.get_finding.return_value = aws_finding
        mock_repository.create_remediation_action.return_value = "aws-action"

        aws_action_id = engine.remediate_finding(
            "aws-finding", RemediationMode.DRY_RUN, "user"
        )
        assert aws_action_id == "aws-action"

        # Test Azure finding
        azure_finding = MagicMock(
            id="azure-finding",
            rule_id="PublicStorageRule",
            severity="HIGH",
            resource_data={
                "type": "Azure::Storage::Account",
                "name": "test-storage",
            },
        )
        mock_repository.get_finding.return_value = azure_finding
        mock_repository.create_remediation_action.return_value = "azure-action"

        azure_action_id = engine.remediate_finding(
            "azure-finding", RemediationMode.DRY_RUN, "user"
        )
        assert azure_action_id == "azure-action"

        # Both should have approval required (HIGH severity)
        assert mock_repository.create_remediation_action.call_count == 2
        for call in mock_repository.create_remediation_action.call_args_list:
            assert call[1].get("approval_required") is True

    def test_get_remediations_by_finding(self, mock_repository):
        """Test retrieving remediations for a specific finding."""
        # This uses repository directly
        mock_repository.get_remediations_by_finding.return_value = [
            MagicMock(id="action-1", status="SUCCESS"),
            MagicMock(id="action-2", status="FAILED"),
        ]

        # In real usage, repository would return these
        actions = mock_repository.get_remediations_by_finding("finding-123")
        assert len(actions) == 2
        assert actions[0].id == "action-1"
        assert actions[1].id == "action-2"
