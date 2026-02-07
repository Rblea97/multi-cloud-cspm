"""Unit tests for safety validators."""

from unittest.mock import patch

import pytest

from cspm.testing.safety import (
    SafetyError,
    is_test_resource,
    validate_aws_account,
    validate_azure_subscription,
    validate_resource_name,
)


class TestAwsAccountValidation:
    """Tests for AWS account validation."""

    def test_validate_aws_account_success(self):
        """Test successful AWS account validation."""
        with patch("cspm.testing.safety.settings") as mock_settings:
            mock_settings.test_mode = True
            mock_settings.test_aws_account_id = "123456789012"

            validate_aws_account("123456789012")

    def test_validate_aws_account_fails_when_not_whitelisted(self):
        """Test validation fails for non-whitelisted account."""
        with patch("cspm.testing.safety.settings") as mock_settings:
            mock_settings.test_mode = True
            mock_settings.test_aws_account_id = "111111111111"

            with pytest.raises(SafetyError):
                validate_aws_account("222222222222")

    def test_validate_aws_account_fails_without_test_mode(self):
        """Test validation fails if test mode not enabled."""
        with patch("cspm.testing.safety.settings") as mock_settings:
            mock_settings.test_mode = False

            with pytest.raises(SafetyError):
                validate_aws_account("123456789012")

    def test_validate_aws_account_skips_when_no_whitelist(self):
        """Test validation skips if no whitelist configured."""
        with patch("cspm.testing.safety.settings") as mock_settings:
            mock_settings.test_mode = True
            mock_settings.test_aws_account_id = None

            validate_aws_account("any-account-id")


class TestAzureSubscriptionValidation:
    """Tests for Azure subscription validation."""

    def test_validate_azure_subscription_success(self):
        """Test successful Azure subscription validation."""
        with patch("cspm.testing.safety.settings") as mock_settings:
            mock_settings.test_mode = True
            mock_settings.test_azure_subscription_id = "12345678-1234-1234-1234-123456789012"

            validate_azure_subscription("12345678-1234-1234-1234-123456789012")

    def test_validate_azure_subscription_fails_when_not_whitelisted(self):
        """Test validation fails for non-whitelisted subscription."""
        with patch("cspm.testing.safety.settings") as mock_settings:
            mock_settings.test_mode = True
            mock_settings.test_azure_subscription_id = "11111111-1111-1111-1111-111111111111"

            with pytest.raises(SafetyError):
                validate_azure_subscription("22222222-2222-2222-2222-222222222222")

    def test_validate_azure_subscription_fails_without_test_mode(self):
        """Test validation fails if test mode not enabled."""
        with patch("cspm.testing.safety.settings") as mock_settings:
            mock_settings.test_mode = False

            with pytest.raises(SafetyError):
                validate_azure_subscription("any-subscription-id")


class TestResourceNameValidation:
    """Tests for resource name validation."""

    def test_validate_resource_name_with_valid_prefix(self):
        """Test validation passes for resource with correct prefix."""
        with patch("cspm.testing.safety.settings") as mock_settings:
            mock_settings.test_resource_prefix = "cspm-test-"

            validate_resource_name("cspm-test-bucket-123")

    def test_validate_resource_name_fails_without_prefix(self):
        """Test validation fails for resource without prefix."""
        with patch("cspm.testing.safety.settings") as mock_settings:
            mock_settings.test_resource_prefix = "cspm-test-"

            with pytest.raises(SafetyError):
                validate_resource_name("my-bucket-123")

    def test_validate_resource_name_custom_prefix(self):
        """Test validation with custom prefix."""
        with patch("cspm.testing.safety.settings") as mock_settings:
            mock_settings.test_resource_prefix = "test-"

            validate_resource_name("test-resource-123")


class TestIsTestResource:
    """Tests for test resource detection."""

    def test_is_test_resource_by_environment_tag(self):
        """Test detection by Environment tag."""
        resource = {
            "name": "my-bucket",
            "tags": {"Environment": "test"},
        }
        assert is_test_resource(resource) is True

    def test_is_test_resource_by_managed_by_tag(self):
        """Test detection by ManagedBy tag."""
        resource = {
            "name": "my-resource",
            "tags": {"ManagedBy": "cspm-integration-tests"},
        }
        assert is_test_resource(resource) is True

    def test_is_test_resource_by_prefix(self, monkeypatch):
        """Test detection by name prefix."""
        monkeypatch.setenv("TEST_RESOURCE_PREFIX", "cspm-test-")
        resource = {
            "name": "cspm-test-bucket",
            "tags": {},
        }
        assert is_test_resource(resource) is True

    def test_is_not_test_resource(self):
        """Test non-test resource returns False."""
        resource = {
            "name": "my-bucket",
            "tags": {"Environment": "prod"},
        }
        assert is_test_resource(resource) is False

    def test_is_test_resource_empty_tags(self):
        """Test with missing tags dict."""
        resource = {"name": "my-resource"}
        assert is_test_resource(resource) is False
