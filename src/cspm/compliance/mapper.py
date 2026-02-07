"""Rule-to-control mapper for CIS compliance framework."""

from collections import defaultdict


class RuleToControlMapper:
    """Maps rules to CIS controls in a many-to-many relationship."""

    def __init__(self) -> None:
        """Initialize the mapper."""
        self._rule_to_controls: dict[str, list[str]] = defaultdict(list)
        self._control_to_rules: dict[str, list[str]] = defaultdict(list)

    def register_mapping(self, rule_id: str, control_ids: list[str]) -> None:
        """Register a rule to control mapping.

        Args:
            rule_id: The rule identifier
            control_ids: List of control IDs this rule satisfies
        """
        if not control_ids:
            return

        # Add to rule → controls mapping
        self._rule_to_controls[rule_id] = control_ids

        # Add to control → rules mapping
        for control_id in control_ids:
            if control_id not in self._control_to_rules[control_id]:
                self._control_to_rules[control_id].append(rule_id)

    def get_controls_for_rule(self, rule_id: str) -> list[str]:
        """Get all controls satisfied by a rule.

        Args:
            rule_id: The rule identifier

        Returns:
            List of control IDs satisfied by this rule
        """
        return self._rule_to_controls.get(rule_id, [])

    def get_rules_for_control(self, control_id: str) -> list[str]:
        """Get all rules that satisfy a control.

        Args:
            control_id: The control identifier

        Returns:
            List of rule IDs that satisfy this control
        """
        return self._control_to_rules.get(control_id, [])


def create_default_mapper() -> RuleToControlMapper:
    """Create a default mapper with existing rules pre-populated.

    Returns:
        RuleToControlMapper with Phase 1 & 2 rules mapped to controls
    """
    mapper = RuleToControlMapper()

    # AWS rules (Phase 1)
    mapper.register_mapping("PublicS3Rule", ["CIS_AWS_3.1"])
    mapper.register_mapping("UnencryptedRDSRule", ["CIS_AWS_4.2"])
    mapper.register_mapping("EC2PublicIPRule", ["CIS_AWS_5.1"])
    mapper.register_mapping("OpenSecurityGroupRule", ["CIS_AWS_4.1"])
    mapper.register_mapping("CloudTrailDisabledRule", ["CIS_AWS_2.1", "CIS_AWS_2.5"])

    # Azure rules (Phase 2)
    mapper.register_mapping("PublicStorageRule", ["CIS_AZURE_5.1"])
    mapper.register_mapping("UnencryptedSQLRule", ["CIS_AZURE_5.6"])

    return mapper
