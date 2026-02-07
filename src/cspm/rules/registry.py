"""Rule registry for managing all available rules."""

from typing import Dict, List, Optional

from cspm.rules.base import BaseRule


class RuleRegistry:
    """Registry for managing security rules."""

    def __init__(self) -> None:
        """Initialize registry."""
        self._rules: Dict[str, BaseRule] = {}
        self._rules_by_provider: Dict[str, List[str]] = {}

    def register(self, rule: BaseRule) -> None:
        """Register a rule.

        Args:
            rule: The rule to register
        """
        self._rules[rule.rule_id] = rule

        # Track by cloud provider
        if rule.cloud_provider not in self._rules_by_provider:
            self._rules_by_provider[rule.cloud_provider] = []
        self._rules_by_provider[rule.cloud_provider].append(rule.rule_id)

    def get_rule(self, rule_id: str) -> Optional[BaseRule]:
        """Get a rule by ID.

        Args:
            rule_id: The rule ID

        Returns:
            The rule or None if not found
        """
        return self._rules.get(rule_id)

    def get_all_rules(self) -> List[BaseRule]:
        """Get all registered rules.

        Returns:
            List of all rules
        """
        return list(self._rules.values())

    def get_rules_by_provider(self, cloud_provider: str) -> List[BaseRule]:
        """Get rules for a specific cloud provider.

        Args:
            cloud_provider: The cloud provider (AWS or Azure)

        Returns:
            List of rules for that provider
        """
        rule_ids = self._rules_by_provider.get(cloud_provider, [])
        return [self._rules[rule_id] for rule_id in rule_ids]

    def get_rules_by_resource_type(self, resource_type: str) -> List[BaseRule]:
        """Get rules applicable to a resource type.

        Args:
            resource_type: The resource type

        Returns:
            List of applicable rules
        """
        return [r for r in self._rules.values() if resource_type in r.resource_types]
