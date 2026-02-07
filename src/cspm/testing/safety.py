"""Safety checks for real infrastructure testing."""

import logging

from cspm.core.config import settings

logger = logging.getLogger(__name__)


class SafetyError(Exception):
    """Raised when safety check fails."""

    pass


def validate_aws_account(account_id: str) -> None:
    """Verify AWS account is whitelisted for testing."""
    if not settings.test_mode:
        raise SafetyError("test_mode must be enabled for real infrastructure tests")

    if settings.test_aws_account_id is None:
        logger.warning("test_aws_account_id not configured - skipping validation")
        return

    if account_id != settings.test_aws_account_id:
        raise SafetyError(
            f"AWS account {account_id} is not whitelisted. "
            f"Expected: {settings.test_aws_account_id}"
        )

    logger.info(f"AWS account {account_id} validated for testing")


def validate_azure_subscription(subscription_id: str) -> None:
    """Verify Azure subscription is whitelisted for testing."""
    if not settings.test_mode:
        raise SafetyError("test_mode must be enabled for real infrastructure tests")

    if settings.test_azure_subscription_id is None:
        logger.warning("test_azure_subscription_id not configured - skipping validation")
        return

    if subscription_id != settings.test_azure_subscription_id:
        raise SafetyError(
            f"Azure subscription {subscription_id} is not whitelisted. "
            f"Expected: {settings.test_azure_subscription_id}"
        )

    logger.info(f"Azure subscription {subscription_id} validated for testing")


def validate_resource_name(resource_name: str) -> None:
    """Ensure resource name has test prefix."""
    if not resource_name.startswith(settings.test_resource_prefix):
        raise SafetyError(
            f"Resource '{resource_name}' does not have test prefix "
            f"'{settings.test_resource_prefix}'"
        )


def is_test_resource(resource: dict) -> bool:
    """Check if resource is tagged as a test resource."""
    tags = resource.get("tags", {})
    return (
        tags.get("Environment") == "test"
        or tags.get("ManagedBy") == "cspm-integration-tests"
        or resource.get("name", "").startswith(settings.test_resource_prefix)
    )
