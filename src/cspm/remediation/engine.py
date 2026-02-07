"""Remediation orchestration engine."""

from datetime import datetime
from typing import Any

from cspm.database.models import Finding, RemediationAction
from cspm.database.repository import Repository
from cspm.remediation.base import RemediationMode
from cspm.remediation.registry import RemediationRegistry


class RemediationEngine:
    """Orchestrates remediation workflow."""

    def __init__(self, registry: RemediationRegistry, repository: Repository) -> None:
        """Initialize remediation engine.

        Args:
            registry: RemediationRegistry with registered actions
            repository: Repository for database access
        """
        self._registry = registry
        self._repository = repository

    def remediate_finding(
        self, finding_id: str, mode: RemediationMode, requested_by: str
    ) -> str:
        """Remediate a finding.

        Args:
            finding_id: ID of finding to remediate
            mode: Execution mode (DRY_RUN or AUTO_FIX)
            requested_by: User requesting remediation

        Returns:
            ID of created remediation action
        """
        finding: Finding | None = self._repository.get_finding(finding_id)
        if not finding:
            raise ValueError(f"Finding {finding_id} not found")

        # Get remediation action for rule
        rule_id: str = finding.rule_id  # type: ignore[assignment]
        action = self._registry.get_action_by_rule_id(rule_id)
        if not action:
            raise ValueError(f"No remediation action for rule {finding.rule_id}")

        # Check if approval required based on severity
        approval_required = self._check_approval_required(finding, action)

        # Create database record
        action_id = self._repository.create_remediation_action(
            finding_id=finding_id,
            action_type=action.action_id,
            mode=mode.value,
            requested_by=requested_by,
            approval_required=approval_required,
            status="APPROVAL_REQUIRED" if approval_required else "PENDING",
        )

        return action_id

    def approve_remediation(self, action_id: str, approved_by: str) -> bool:
        """Approve remediation action.

        Args:
            action_id: ID of remediation action
            approved_by: User approving the action

        Returns:
            True if approval successful
        """
        action_record = self._repository.get_remediation_action(action_id)
        if not action_record:
            return False

        # Update status and approver
        self._repository.update_remediation_status(
            action_id,
            "PENDING",
            {
                "approved_by": approved_by,
                "approved_at": datetime.utcnow().isoformat(),
            },
        )

        return True

    def reject_remediation(self, action_id: str, rejected_by: str) -> bool:
        """Reject remediation action.

        Args:
            action_id: ID of remediation action
            rejected_by: User rejecting the action

        Returns:
            True if rejection successful
        """
        action_record = self._repository.get_remediation_action(action_id)
        if not action_record:
            return False

        # Update status to FAILED
        self._repository.update_remediation_status(
            action_id,
            "FAILED",
            {
                "rejected_by": rejected_by,
                "rejected_at": datetime.utcnow().isoformat(),
                "error_message": "Remediation rejected by approval authority",
            },
        )

        return True

    def execute_pending_remediations(self) -> list[str]:
        """Execute pending approved remediations.

        Returns:
            List of executed action IDs
        """
        pending_actions: list[RemediationAction] = self._repository.get_pending_remediations(
            "PENDING"
        )
        executed_action_ids: list[str] = []

        for action_record in pending_actions:
            try:
                # Get action implementation
                action_type: str = action_record.action_type  # type: ignore[assignment]
                action = self._registry.get_action_by_action_id(action_type)
                if not action:
                    continue

                # Get finding
                finding_id: str = action_record.finding_id  # type: ignore[assignment]
                finding: Finding | None = self._repository.get_finding(finding_id)
                if not finding:
                    continue

                # Execute remediation (DRY_RUN mode by default for safety)
                mode_str: str = action_record.mode  # type: ignore[assignment]
                mode = (
                    RemediationMode.DRY_RUN
                    if mode_str == "dry_run"
                    else RemediationMode.AUTO_FIX
                )

                result = action.execute(
                    finding.resource_data, finding.__dict__, mode  # type: ignore[arg-type]
                )

                # Update status
                status = "SUCCESS" if result.success else "FAILED"
                action_id: str = action_record.id  # type: ignore[assignment]
                self._repository.update_remediation_status(
                    action_id,
                    status,
                    {
                        "changes_made": result.changes_made,
                        "error_message": result.error_message,
                        "completed_at": datetime.utcnow().isoformat(),
                    },
                )

                executed_action_ids.append(action_id)

            except Exception as e:
                # Update to FAILED on exception
                action_id_err: str = action_record.id  # type: ignore[assignment]
                self._repository.update_remediation_status(
                    action_id_err,
                    "FAILED",
                    {
                        "error_message": str(e),
                        "completed_at": datetime.utcnow().isoformat(),
                    },
                )

        return executed_action_ids

    def _check_approval_required(self, finding: Finding, action: Any) -> bool:
        """Check if approval required for remediation.

        Args:
            finding: Finding to remediate
            action: Remediation action

        Returns:
            True if approval required
        """
        # CRITICAL and HIGH severity always require approval
        severity: str = finding.severity  # type: ignore[assignment]
        if severity in ["CRITICAL", "HIGH"]:
            return True
        # Use action's default if severity doesn't mandate approval
        return action.requires_approval
