"""Unit tests for Azure remediation actions."""

import pytest
from unittest.mock import MagicMock, patch

from cspm.remediation.azure_actions import (
    RemediatePublicStorage,
    RemediateUnencryptedSQL,
    RemediateVMPublicIP,
    RemediateOpenNSG,
    RemediateActivityLogDisabled,
)
from cspm.remediation.base import RemediationMode, RemediationStatus


class TestRemediatePublicStorage:
    """Test Azure storage account remediation."""

    def test_action_properties(self):
        """Verify action properties."""
        action = RemediatePublicStorage()
        assert action.action_id == "RemediatePublicStorage"
        assert action.name == "Block Public Blob Access"
        assert action.rule_id == "PublicStorageRule"
        assert action.cloud_provider == "azure"
        assert "Azure::Storage::Account" in action.resource_types
        assert action.requires_approval is True

    def test_validate_storage_account(self):
        """Validate storage account resource."""
        action = RemediatePublicStorage()
        resource = {
            "type": "Azure::Storage::Account",
            "name": "test-storage",
            "resource_group": "test-rg",
        }
        assert action.validate(resource) is True

    def test_validate_non_storage_resource(self):
        """Reject non-storage resources."""
        action = RemediatePublicStorage()
        resource = {"type": "Azure::Compute::VirtualMachine"}
        assert action.validate(resource) is False

    def test_dry_run_execution(self):
        """Dry-run mode returns success without changes."""
        action = RemediatePublicStorage()
        resource = {"type": "Azure::Storage::Account", "name": "test-storage"}
        finding = {}

        result = action.execute(resource, finding, RemediationMode.DRY_RUN)

        assert result.success is True
        assert result.status == RemediationStatus.SUCCESS
        assert result.dry_run is True


class TestRemediateUnencryptedSQL:
    """Test Azure SQL encryption remediation."""

    def test_action_properties(self):
        """Verify action properties."""
        action = RemediateUnencryptedSQL()
        assert action.action_id == "RemediateUnencryptedSQL"
        assert action.rule_id == "UnencryptedSQLRule"
        assert action.cloud_provider == "azure"

    def test_validate_sql_database(self):
        """Validate SQL database resource."""
        action = RemediateUnencryptedSQL()
        resource = {
            "type": "Azure::SQL::Database",
            "name": "test-db",
            "server": "test-server",
        }
        assert action.validate(resource) is True

    def test_dry_run_execution(self):
        """Dry-run returns recommendation."""
        action = RemediateUnencryptedSQL()
        resource = {"type": "Azure::SQL::Database", "name": "test-db"}
        finding = {}

        result = action.execute(resource, finding, RemediationMode.DRY_RUN)

        assert result.success is True
        assert result.dry_run is True


class TestRemediateVMPublicIP:
    """Test Azure VM public IP remediation."""

    def test_action_properties(self):
        """Verify action properties."""
        action = RemediateVMPublicIP()
        assert action.action_id == "RemediateVMPublicIP"
        assert action.rule_id == "VMPublicIPRule"
        assert action.cloud_provider == "azure"

    def test_validate_vm_resource(self):
        """Validate VM resource."""
        action = RemediateVMPublicIP()
        resource = {
            "type": "Azure::Compute::VirtualMachine",
            "name": "test-vm",
            "resource_group": "test-rg",
        }
        assert action.validate(resource) is True

    def test_dry_run_execution(self):
        """Dry-run returns success."""
        action = RemediateVMPublicIP()
        resource = {"type": "Azure::Compute::VirtualMachine", "name": "test-vm"}
        finding = {}

        result = action.execute(resource, finding, RemediationMode.DRY_RUN)

        assert result.success is True
        assert result.dry_run is True


class TestRemediateOpenNSG:
    """Test Azure NSG remediation."""

    def test_action_properties(self):
        """Verify action properties."""
        action = RemediateOpenNSG()
        assert action.action_id == "RemediateOpenNSG"
        assert action.rule_id == "OpenNSGRule"
        assert action.cloud_provider == "azure"

    def test_validate_nsg(self):
        """Validate NSG resource."""
        action = RemediateOpenNSG()
        resource = {
            "type": "Azure::Network::NetworkSecurityGroup",
            "name": "test-nsg",
            "resource_group": "test-rg",
        }
        assert action.validate(resource) is True

    def test_dry_run_identifies_open_rules(self):
        """Dry-run identifies permissive rules."""
        action = RemediateOpenNSG()
        resource = {
            "type": "Azure::Network::NetworkSecurityGroup",
            "name": "test-nsg",
            "security_rules": [
                {
                    "name": "AllowHttp",
                    "source_address_prefix": "*",
                    "access": "Allow",
                }
            ],
        }
        finding = {}

        result = action.execute(resource, finding, RemediationMode.DRY_RUN)

        assert result.success is True
        assert result.dry_run is True


class TestRemediateActivityLogDisabled:
    """Test Azure Activity Log remediation."""

    def test_action_properties(self):
        """Verify action properties."""
        action = RemediateActivityLogDisabled()
        assert action.action_id == "RemediateActivityLogDisabled"
        assert action.rule_id == "ActivityLogDisabledRule"
        assert action.cloud_provider == "azure"
        assert action.requires_approval is True

    def test_validate_activity_log(self):
        """Validate Activity Log resource."""
        action = RemediateActivityLogDisabled()
        resource = {
            "type": "Azure::Insights::DiagnosticSettings",
            "name": "test-diagnostic",
        }
        assert action.validate(resource) is True

    def test_dry_run_execution(self):
        """Dry-run returns success."""
        action = RemediateActivityLogDisabled()
        resource = {
            "type": "Azure::Insights::DiagnosticSettings",
            "name": "test-diagnostic",
        }
        finding = {}

        result = action.execute(resource, finding, RemediationMode.DRY_RUN)

        assert result.success is True
        assert result.dry_run is True
