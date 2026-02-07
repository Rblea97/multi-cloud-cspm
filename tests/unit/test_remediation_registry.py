"""Unit tests for remediation registry."""

import pytest

from cspm.remediation.base import (
    BaseRemediationAction,
    RemediationMode,
    RemediationResult,
    RemediationStatus,
)
from cspm.remediation.registry import RemediationRegistry


class MockAction1(BaseRemediationAction):
    """Mock action 1."""

    def __init__(self):
        super().__init__()
        self.action_id = "TestAction1"
        self.name = "Test Action 1"
        self.description = "First test action"
        self.rule_id = "TestRule1"
        self.cloud_provider = "aws"
        self.resource_types = ["AWS::S3::Bucket"]
        self.requires_approval = False

    def validate(self, resource):
        return True

    def execute(self, resource, finding, mode):
        return RemediationResult(
            success=True, status=RemediationStatus.SUCCESS, changes_made={}
        )


class MockAction2(BaseRemediationAction):
    """Mock action 2."""

    def __init__(self):
        super().__init__()
        self.action_id = "TestAction2"
        self.name = "Test Action 2"
        self.description = "Second test action"
        self.rule_id = "TestRule2"
        self.cloud_provider = "azure"
        self.resource_types = ["Azure::Storage::Account"]
        self.requires_approval = True

    def validate(self, resource):
        return True

    def execute(self, resource, finding, mode):
        return RemediationResult(
            success=True, status=RemediationStatus.SUCCESS, changes_made={}
        )


class TestRemediationRegistry:
    """Test RemediationRegistry."""

    def test_register_action(self):
        """Register remediation action."""
        registry = RemediationRegistry()
        action = MockAction1()
        registry.register(action)
        assert registry._actions["TestAction1"] == action

    def test_get_action_by_action_id(self):
        """Retrieve action by action_id."""
        registry = RemediationRegistry()
        action = MockAction1()
        registry.register(action)
        retrieved = registry.get_action_by_action_id("TestAction1")
        assert retrieved == action

    def test_get_action_by_rule_id(self):
        """Retrieve action by rule_id."""
        registry = RemediationRegistry()
        action = MockAction1()
        registry.register(action)
        retrieved = registry.get_action_by_rule_id("TestRule1")
        assert retrieved == action

    def test_get_actions_by_cloud_provider(self):
        """Retrieve actions by cloud provider."""
        registry = RemediationRegistry()
        action1 = MockAction1()
        action2 = MockAction2()
        registry.register(action1)
        registry.register(action2)
        aws_actions = registry.get_actions_by_cloud_provider("aws")
        assert action1 in aws_actions
        assert action2 not in aws_actions

    def test_get_action_not_found(self):
        """Return None when action not found."""
        registry = RemediationRegistry()
        assert registry.get_action_by_action_id("NonExistent") is None
        assert registry.get_action_by_rule_id("NonExistent") is None
