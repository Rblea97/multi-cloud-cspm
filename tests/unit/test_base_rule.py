"""Tests for base rule class."""

import pytest

from cspm.cloud.base import Resource
from cspm.rules.base import BaseRule, RuleResult, RuleSeverity


class SimpleRule(BaseRule):
    """Simple test implementation of BaseRule."""

    def __init__(self):
        """Initialize test rule."""
        super().__init__()
        self.rule_id = "simple_rule"
        self.name = "Simple Test Rule"
        self.cloud_provider = "AWS"
        self.resource_types = ["AWS::S3::Bucket"]

    def evaluate(self, resource: Resource) -> RuleResult:
        """Simple evaluation that checks public access."""
        has_finding = not resource.attributes.get("public_access_block_enabled", False)
        return RuleResult(
            resource=resource,
            has_finding=has_finding,
            severity=RuleSeverity.HIGH if has_finding else RuleSeverity.INFO,
            title="Public Access Detected" if has_finding else "No Finding",
            description="S3 bucket is publicly accessible" if has_finding else "",
        )


def test_rule_can_be_instantiated():
    """Test that a rule can be instantiated."""
    rule = SimpleRule()
    assert rule.rule_id == "simple_rule"
    assert rule.name == "Simple Test Rule"
    assert rule.cloud_provider == "AWS"


def test_rule_is_applicable_to_matching_resource_type():
    """Test that rule identifies applicable resources."""
    rule = SimpleRule()
    bucket = Resource(
        id="test-bucket",
        name="test-bucket",
        type="AWS::S3::Bucket",
        region="us-east-1",
        cloud_provider="AWS",
        attributes={},
        tags={},
    )
    assert rule.is_applicable(bucket) is True


def test_rule_is_not_applicable_to_non_matching_resource_type():
    """Test that rule is not applicable to wrong resource type."""
    rule = SimpleRule()
    instance = Resource(
        id="i-12345",
        name="test-instance",
        type="AWS::EC2::Instance",
        region="us-east-1",
        cloud_provider="AWS",
        attributes={},
        tags={},
    )
    assert rule.is_applicable(instance) is False


def test_rule_detects_public_s3_bucket(sample_s3_bucket):
    """Test that rule detects public S3 bucket."""
    rule = SimpleRule()
    result = rule.evaluate(sample_s3_bucket)
    assert result.has_finding is True
    assert result.severity == RuleSeverity.HIGH


def test_rule_does_not_flag_private_s3_bucket(sample_private_s3_bucket):
    """Test that rule does not flag private S3 bucket."""
    rule = SimpleRule()
    result = rule.evaluate(sample_private_s3_bucket)
    assert result.has_finding is False
    assert result.severity == RuleSeverity.INFO


def test_rule_result_contains_resource_reference(sample_s3_bucket):
    """Test that rule result includes resource reference."""
    rule = SimpleRule()
    result = rule.evaluate(sample_s3_bucket)
    assert result.resource == sample_s3_bucket
    assert result.resource.name == "test-bucket"


def test_rule_result_has_required_fields(sample_s3_bucket):
    """Test that rule result has all required fields."""
    rule = SimpleRule()
    result = rule.evaluate(sample_s3_bucket)
    assert hasattr(result, "has_finding")
    assert hasattr(result, "severity")
    assert hasattr(result, "title")
    assert hasattr(result, "description")
    assert hasattr(result, "resource")


def test_rule_string_representation():
    """Test rule string representation."""
    rule = SimpleRule()
    assert "Simple Test Rule" in str(rule)
    assert "AWS" in str(rule)
