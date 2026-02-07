"""Tests for rule-to-control mapper."""

import pytest

from cspm.compliance.mapper import RuleToControlMapper, create_default_mapper


class TestRuleToControlMapper:
    """Test RuleToControlMapper."""

    def test_register_single_rule_to_control(self) -> None:
        """Test registering a rule to a control."""
        mapper = RuleToControlMapper()
        mapper.register_mapping("PublicS3Rule", ["CIS_AWS_3.1"])

        assert mapper.get_rules_for_control("CIS_AWS_3.1") == ["PublicS3Rule"]
        assert mapper.get_controls_for_rule("PublicS3Rule") == ["CIS_AWS_3.1"]

    def test_get_controls_for_rule(self) -> None:
        """Test retrieving controls for a rule."""
        mapper = RuleToControlMapper()
        mapper.register_mapping("CloudTrailDisabledRule", ["CIS_AWS_2.1", "CIS_AWS_2.5"])

        controls = mapper.get_controls_for_rule("CloudTrailDisabledRule")
        assert set(controls) == {"CIS_AWS_2.1", "CIS_AWS_2.5"}

    def test_get_rules_for_control(self) -> None:
        """Test retrieving rules for a control."""
        mapper = RuleToControlMapper()
        mapper.register_mapping("PublicS3Rule", ["CIS_AWS_3.1"])
        mapper.register_mapping("AnotherRule", ["CIS_AWS_3.1"])

        rules = mapper.get_rules_for_control("CIS_AWS_3.1")
        assert set(rules) == {"PublicS3Rule", "AnotherRule"}

    def test_many_to_many_mapping(self) -> None:
        """Test many-to-many rule-control relationships."""
        mapper = RuleToControlMapper()

        # One rule → multiple controls
        mapper.register_mapping("CloudTrailDisabledRule", ["CIS_AWS_2.1", "CIS_AWS_2.5"])

        # Multiple rules → same control
        mapper.register_mapping("PublicS3Rule", ["CIS_AWS_3.1"])
        mapper.register_mapping("AnotherRule", ["CIS_AWS_3.1"])

        # Verify one rule → multiple controls
        assert set(mapper.get_controls_for_rule("CloudTrailDisabledRule")) == {"CIS_AWS_2.1", "CIS_AWS_2.5"}

        # Verify multiple rules → same control
        assert set(mapper.get_rules_for_control("CIS_AWS_3.1")) == {"PublicS3Rule", "AnotherRule"}

    def test_register_mapping_multiple_calls(self) -> None:
        """Test registering multiple mappings."""
        mapper = RuleToControlMapper()
        mapper.register_mapping("Rule1", ["Control1", "Control2"])
        mapper.register_mapping("Rule2", ["Control3"])
        mapper.register_mapping("Rule3", ["Control1"])

        assert set(mapper.get_controls_for_rule("Rule1")) == {"Control1", "Control2"}
        assert mapper.get_controls_for_rule("Rule2") == ["Control3"]
        assert set(mapper.get_rules_for_control("Control1")) == {"Rule1", "Rule3"}

    def test_empty_mapper_returns_empty_lists(self) -> None:
        """Test empty mapper returns empty lists."""
        mapper = RuleToControlMapper()

        assert mapper.get_controls_for_rule("NonexistentRule") == []
        assert mapper.get_rules_for_control("NonexistentControl") == []

    def test_register_mapping_with_empty_control_list(self) -> None:
        """Test registering a rule with empty control list does nothing."""
        mapper = RuleToControlMapper()
        mapper.register_mapping("Rule1", [])

        assert mapper.get_controls_for_rule("Rule1") == []

    def test_mapper_preserves_order_within_mapping(self) -> None:
        """Test that mapper preserves the controls/rules order."""
        mapper = RuleToControlMapper()
        mapper.register_mapping("Rule1", ["Control_A", "Control_B", "Control_C"])

        controls = mapper.get_controls_for_rule("Rule1")
        assert controls == ["Control_A", "Control_B", "Control_C"]


class TestDefaultMapper:
    """Test default mapper factory function."""

    def test_create_default_mapper_returns_mapper(self) -> None:
        """Test that create_default_mapper returns a RuleToControlMapper."""
        mapper = create_default_mapper()
        assert isinstance(mapper, RuleToControlMapper)

    def test_mapper_has_aws_rules_preloaded(self) -> None:
        """Test that default mapper has AWS rules preloaded."""
        mapper = create_default_mapper()

        # Verify 5 AWS rules are mapped
        assert mapper.get_controls_for_rule("PublicS3Rule") != []
        assert mapper.get_controls_for_rule("UnencryptedRDSRule") != []
        assert mapper.get_controls_for_rule("EC2PublicIPRule") != []
        assert mapper.get_controls_for_rule("OpenSecurityGroupRule") != []
        assert mapper.get_controls_for_rule("CloudTrailDisabledRule") != []

    def test_mapper_has_azure_rules_preloaded(self) -> None:
        """Test that default mapper has Azure rules preloaded."""
        mapper = create_default_mapper()

        # Verify 2 Azure rules are mapped
        assert mapper.get_controls_for_rule("PublicStorageRule") != []
        assert mapper.get_controls_for_rule("UnencryptedSQLRule") != []

    def test_cloudtrail_rule_maps_to_multiple_controls(self) -> None:
        """Test that CloudTrailDisabledRule maps to multiple CIS controls."""
        mapper = create_default_mapper()
        controls = mapper.get_controls_for_rule("CloudTrailDisabledRule")

        # CloudTrailDisabledRule should map to CIS_AWS_2.1 and CIS_AWS_2.5
        assert "CIS_AWS_2.1" in controls
        assert "CIS_AWS_2.5" in controls

    def test_public_s3_rule_maps_to_aws_control(self) -> None:
        """Test that PublicS3Rule maps to CIS_AWS_3.1."""
        mapper = create_default_mapper()
        controls = mapper.get_controls_for_rule("PublicS3Rule")

        assert "CIS_AWS_3.1" in controls

    def test_public_storage_rule_maps_to_azure_control(self) -> None:
        """Test that PublicStorageRule maps to CIS_AZURE_5.1."""
        mapper = create_default_mapper()
        controls = mapper.get_controls_for_rule("PublicStorageRule")

        assert "CIS_AZURE_5.1" in controls

    def test_unencrypted_sql_rule_maps_to_azure_control(self) -> None:
        """Test that UnencryptedSQLRule maps to CIS_AZURE_5.6."""
        mapper = create_default_mapper()
        controls = mapper.get_controls_for_rule("UnencryptedSQLRule")

        assert "CIS_AZURE_5.6" in controls
