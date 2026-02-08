"""Unit tests for auto-stop functionality."""

from datetime import datetime, timedelta, timezone

import pytest


def test_should_stop_instance_past_auto_stop_time():
    """Test that instance with past AutoStopAt time should be stopped."""
    from scripts.auto_stop_compute import should_stop_instance

    past_time = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    tags = [{"Key": "AutoStopAt", "Value": past_time}]

    assert should_stop_instance(tags) is True


def test_should_stop_instance_future_auto_stop_time():
    """Test that instance with future AutoStopAt time should not be stopped."""
    from scripts.auto_stop_compute import should_stop_instance

    future_time = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    tags = [{"Key": "AutoStopAt", "Value": future_time}]

    assert should_stop_instance(tags) is False
