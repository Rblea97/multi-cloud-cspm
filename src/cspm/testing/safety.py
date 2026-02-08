"""Safety checks for real infrastructure testing."""

import logging
from datetime import UTC, datetime

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
    return bool(
        tags.get("Environment") == "test"
        or tags.get("ManagedBy") == "cspm-integration-tests"
        or resource.get("name", "").startswith(settings.test_resource_prefix)
    )


FREE_TIER_EC2_TYPES = ["t2.micro", "t3.micro"]
FREE_TIER_RDS_TYPES = ["db.t2.micro", "db.t3.micro"]


def validate_instance_type(instance_type: str, service: str) -> None:
    """Ensure instance type is free-tier eligible.

    Args:
        instance_type: EC2 instance type (e.g., t2.micro) or RDS type (e.g., db.t3.micro)
        service: Cloud service type ('ec2' or 'rds')

    Raises:
        SafetyError: If instance type is not free-tier eligible
    """
    allowed_types = FREE_TIER_EC2_TYPES if service == "ec2" else FREE_TIER_RDS_TYPES

    if instance_type not in allowed_types:
        raise SafetyError(
            f"Instance type '{instance_type}' is not free-tier eligible for {service}. "
            f"Allowed types: {', '.join(allowed_types)}"
        )


def validate_auto_stop_tag(tags: list[dict]) -> None:
    """Ensure compute resource has AutoStopAt tag in future.

    Args:
        tags: List of tag dicts with 'Key' and 'Value' fields

    Raises:
        SafetyError: If AutoStopAt tag is missing or set to past time
    """
    auto_stop_tag = None
    for tag in tags:
        if tag.get("Key") == "AutoStopAt":
            auto_stop_tag = tag.get("Value")
            break

    if not auto_stop_tag:
        raise SafetyError("AutoStopAt tag is required for compute resources")

    try:
        stop_time = datetime.fromisoformat(auto_stop_tag)
        if stop_time < datetime.now(UTC):
            raise SafetyError(
                f"AutoStopAt time {auto_stop_tag} is in the past"
            )
    except ValueError as e:
        raise SafetyError(f"Invalid AutoStopAt timestamp: {auto_stop_tag}") from e
