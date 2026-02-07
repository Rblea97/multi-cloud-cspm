"""Remediation action registry."""


from cspm.remediation.base import BaseRemediationAction


class RemediationRegistry:
    """Registry for remediation actions."""

    def __init__(self) -> None:
        """Initialize registry."""
        self._actions: dict[str, BaseRemediationAction] = {}
        self._actions_by_rule: dict[str, BaseRemediationAction] = {}
        self._actions_by_provider: dict[str, list[BaseRemediationAction]] = {}

    def register(self, action: BaseRemediationAction) -> None:
        """Register a remediation action.

        Args:
            action: Remediation action to register
        """
        self._actions[action.action_id] = action
        self._actions_by_rule[action.rule_id] = action

        if action.cloud_provider not in self._actions_by_provider:
            self._actions_by_provider[action.cloud_provider] = []
        self._actions_by_provider[action.cloud_provider].append(action)

    def get_action_by_action_id(
        self, action_id: str
    ) -> BaseRemediationAction | None:
        """Get remediation action by action ID.

        Args:
            action_id: Action ID to lookup

        Returns:
            Remediation action or None if not found
        """
        return self._actions.get(action_id)

    def get_action_by_rule_id(self, rule_id: str) -> BaseRemediationAction | None:
        """Get remediation action by rule ID.

        Args:
            rule_id: Rule ID to lookup

        Returns:
            Remediation action or None if not found
        """
        return self._actions_by_rule.get(rule_id)

    def get_actions_by_cloud_provider(self, provider: str) -> list[BaseRemediationAction]:
        """Get all remediation actions for a cloud provider.

        Args:
            provider: Cloud provider name

        Returns:
            List of remediation actions for provider
        """
        return self._actions_by_provider.get(provider, [])
