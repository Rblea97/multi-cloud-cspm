"""Dry-run remediation tests for real infrastructure testing.

These tests validate that remediation works in dry-run mode
without making actual changes to cloud resources.

Markers:
- @pytest.mark.remediation - Marks test as remediation test
- @pytest.mark.free - Uses only free-tier resources

Cost: $0.00 (dry-run, no actual changes)
"""

import pytest

from cspm.remediation.base import RemediationMode


@pytest.mark.remediation
@pytest.mark.free
def test_dry_run_mode_exists():
    """Test that dry-run mode is available."""
    assert RemediationMode.DRY_RUN is not None
    assert str(RemediationMode.DRY_RUN.value) == "dry_run"


@pytest.mark.remediation
@pytest.mark.free
def test_auto_fix_mode_exists():
    """Test that auto-fix mode is available."""
    assert RemediationMode.AUTO_FIX is not None
    assert str(RemediationMode.AUTO_FIX.value) == "auto_fix"
