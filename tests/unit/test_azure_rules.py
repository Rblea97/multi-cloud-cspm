"""Tests for Azure security rules."""

import pytest

from cspm.cloud.base import Resource
from cspm.rules.azure_rules import (
    PublicStorageRule,
    UnencryptedSQLRule,
    VMPublicIPRule,
    OpenNSGRule,
    ActivityLogDisabledRule,
)
from cspm.rules.base import RuleSeverity


# Cycle 6: Public Storage Account Rule
def test_public_storage_rule_is_applicable():
    """Test PublicStorageRule applies to storage accounts."""
    rule = PublicStorageRule()
    resource = Resource(
        id="storage-1",
        name="public-bucket",
        type="Azure::Storage::Account",
        region="eastus",
        cloud_provider="azure",
        attributes={"AllowBlobPublicAccess": True},
        tags={},
    )
    assert rule.is_applicable(resource)


def test_public_storage_rule_not_applicable_to_other_resources():
    """Test PublicStorageRule doesn't apply to non-storage resources."""
    rule = PublicStorageRule()
    resource = Resource(
        id="vm-1",
        name="my-vm",
        type="Azure::Compute::VirtualMachine",
        region="eastus",
        cloud_provider="azure",
        attributes={},
        tags={},
    )
    assert not rule.is_applicable(resource)


def test_public_storage_rule_detects_public_access():
    """Test PublicStorageRule detects public blob access."""
    rule = PublicStorageRule()
    resource = Resource(
        id="storage-1",
        name="public-bucket",
        type="Azure::Storage::Account",
        region="eastus",
        cloud_provider="azure",
        attributes={"AllowBlobPublicAccess": True},
        tags={},
    )
    result = rule.evaluate(resource)
    assert result.has_finding is True


def test_public_storage_rule_allows_private_access():
    """Test PublicStorageRule allows private storage accounts."""
    rule = PublicStorageRule()
    resource = Resource(
        id="storage-1",
        name="private-bucket",
        type="Azure::Storage::Account",
        region="eastus",
        cloud_provider="azure",
        attributes={"AllowBlobPublicAccess": False},
        tags={},
    )
    result = rule.evaluate(resource)
    assert result.has_finding is False


def test_public_storage_rule_has_critical_severity():
    """Test PublicStorageRule has CRITICAL severity."""
    rule = PublicStorageRule()
    assert rule.severity == RuleSeverity.CRITICAL


# Cycle 7: Unencrypted SQL Rule
def test_unencrypted_sql_rule_is_applicable():
    """Test UnencryptedSQLRule applies to SQL databases."""
    rule = UnencryptedSQLRule()
    resource = Resource(
        id="db-1",
        name="mydb",
        type="Azure::SQL::Database",
        region="eastus",
        cloud_provider="azure",
        attributes={"EncryptionProtectorType": "ServiceManaged"},
        tags={},
    )
    assert rule.is_applicable(resource)


def test_unencrypted_sql_rule_not_applicable_to_other_resources():
    """Test UnencryptedSQLRule doesn't apply to non-SQL resources."""
    rule = UnencryptedSQLRule()
    resource = Resource(
        id="storage-1",
        name="mystorage",
        type="Azure::Storage::Account",
        region="eastus",
        cloud_provider="azure",
        attributes={},
        tags={},
    )
    assert not rule.is_applicable(resource)


def test_unencrypted_sql_rule_detects_service_managed_encryption():
    """Test UnencryptedSQLRule detects service-managed encryption."""
    rule = UnencryptedSQLRule()
    resource = Resource(
        id="db-1",
        name="mydb",
        type="Azure::SQL::Database",
        region="eastus",
        cloud_provider="azure",
        attributes={"EncryptionProtectorType": "ServiceManaged"},
        tags={},
    )
    result = rule.evaluate(resource)
    assert result.has_finding is True


def test_unencrypted_sql_rule_allows_keyvault_encryption():
    """Test UnencryptedSQLRule allows Azure Key Vault encryption."""
    rule = UnencryptedSQLRule()
    resource = Resource(
        id="db-1",
        name="mydb",
        type="Azure::SQL::Database",
        region="eastus",
        cloud_provider="azure",
        attributes={"EncryptionProtectorType": "AzureKeyVault"},
        tags={},
    )
    result = rule.evaluate(resource)
    assert result.has_finding is False


def test_unencrypted_sql_rule_has_high_severity():
    """Test UnencryptedSQLRule has HIGH severity."""
    rule = UnencryptedSQLRule()
    assert rule.severity == RuleSeverity.HIGH


# Cycle 7: VM Public IP Rule
def test_vm_public_ip_rule_is_applicable():
    """Test VMPublicIPRule applies to VMs."""
    rule = VMPublicIPRule()
    resource = Resource(
        id="vm-1",
        name="my-vm",
        type="Azure::Compute::VirtualMachine",
        region="eastus",
        cloud_provider="azure",
        attributes={"PublicIpAddress": "203.0.113.1"},
        tags={},
    )
    assert rule.is_applicable(resource)


def test_vm_public_ip_rule_not_applicable_to_other_resources():
    """Test VMPublicIPRule doesn't apply to non-VM resources."""
    rule = VMPublicIPRule()
    resource = Resource(
        id="db-1",
        name="mydb",
        type="Azure::SQL::Database",
        region="eastus",
        cloud_provider="azure",
        attributes={},
        tags={},
    )
    assert not rule.is_applicable(resource)


def test_vm_public_ip_rule_detects_public_ip():
    """Test VMPublicIPRule detects VMs with public IPs."""
    rule = VMPublicIPRule()
    resource = Resource(
        id="vm-1",
        name="my-vm",
        type="Azure::Compute::VirtualMachine",
        region="eastus",
        cloud_provider="azure",
        attributes={"PublicIpAddress": "203.0.113.1"},
        tags={},
    )
    result = rule.evaluate(resource)
    assert result.has_finding is True


def test_vm_public_ip_rule_allows_private_vms():
    """Test VMPublicIPRule allows VMs without public IPs."""
    rule = VMPublicIPRule()
    resource = Resource(
        id="vm-1",
        name="my-vm",
        type="Azure::Compute::VirtualMachine",
        region="eastus",
        cloud_provider="azure",
        attributes={"PublicIpAddress": None},
        tags={},
    )
    result = rule.evaluate(resource)
    assert result.has_finding is False


def test_vm_public_ip_rule_has_medium_severity():
    """Test VMPublicIPRule has MEDIUM severity."""
    rule = VMPublicIPRule()
    assert rule.severity == RuleSeverity.MEDIUM


# Cycle 8: Open NSG Rule
def test_open_nsg_rule_is_applicable():
    """Test OpenNSGRule applies to NSGs."""
    rule = OpenNSGRule()
    resource = Resource(
        id="nsg-1",
        name="my-nsg",
        type="Azure::Network::NetworkSecurityGroup",
        region="eastus",
        cloud_provider="azure",
        attributes={"SecurityRules": []},
        tags={},
    )
    assert rule.is_applicable(resource)


def test_open_nsg_rule_not_applicable_to_other_resources():
    """Test OpenNSGRule doesn't apply to non-NSG resources."""
    rule = OpenNSGRule()
    resource = Resource(
        id="vm-1",
        name="my-vm",
        type="Azure::Compute::VirtualMachine",
        region="eastus",
        cloud_provider="azure",
        attributes={},
        tags={},
    )
    assert not rule.is_applicable(resource)


def test_open_nsg_rule_detects_open_rules():
    """Test OpenNSGRule detects NSGs with open rules."""
    rule = OpenNSGRule()
    open_rule = type("Rule", (), {
        "properties": type("Props", (), {
            "source_address_prefix": "*",
            "access": "Allow",
            "direction": "Inbound"
        })()
    })()
    resource = Resource(
        id="nsg-1",
        name="my-nsg",
        type="Azure::Network::NetworkSecurityGroup",
        region="eastus",
        cloud_provider="azure",
        attributes={"SecurityRules": [open_rule]},
        tags={},
    )
    result = rule.evaluate(resource)
    assert result.has_finding is True


def test_open_nsg_rule_allows_restricted_rules():
    """Test OpenNSGRule allows NSGs without open rules."""
    rule = OpenNSGRule()
    restricted_rule = type("Rule", (), {
        "properties": type("Props", (), {
            "source_address_prefix": "10.0.0.0/8",
            "access": "Allow",
            "direction": "Inbound"
        })()
    })()
    resource = Resource(
        id="nsg-1",
        name="my-nsg",
        type="Azure::Network::NetworkSecurityGroup",
        region="eastus",
        cloud_provider="azure",
        attributes={"SecurityRules": [restricted_rule]},
        tags={},
    )
    result = rule.evaluate(resource)
    assert result.has_finding is False


def test_open_nsg_rule_has_high_severity():
    """Test OpenNSGRule has HIGH severity."""
    rule = OpenNSGRule()
    assert rule.severity == RuleSeverity.HIGH


# Cycle 8: Activity Log Disabled Rule
def test_activity_log_disabled_rule_is_applicable():
    """Test ActivityLogDisabledRule applies to activity logs."""
    rule = ActivityLogDisabledRule()
    resource = Resource(
        id="log-1",
        name="Activity Log",
        type="Azure::Monitor::ActivityLog",
        region="global",
        cloud_provider="azure",
        attributes={"Enabled": True},
        tags={},
    )
    assert rule.is_applicable(resource)


def test_activity_log_disabled_rule_not_applicable_to_other_resources():
    """Test ActivityLogDisabledRule doesn't apply to non-activity-log resources."""
    rule = ActivityLogDisabledRule()
    resource = Resource(
        id="nsg-1",
        name="my-nsg",
        type="Azure::Network::NetworkSecurityGroup",
        region="eastus",
        cloud_provider="azure",
        attributes={},
        tags={},
    )
    assert not rule.is_applicable(resource)


def test_activity_log_disabled_rule_detects_disabled_logging():
    """Test ActivityLogDisabledRule detects disabled activity logs."""
    rule = ActivityLogDisabledRule()
    resource = Resource(
        id="log-1",
        name="Activity Log",
        type="Azure::Monitor::ActivityLog",
        region="global",
        cloud_provider="azure",
        attributes={"Enabled": False},
        tags={},
    )
    result = rule.evaluate(resource)
    assert result.has_finding is True


def test_activity_log_disabled_rule_allows_enabled_logging():
    """Test ActivityLogDisabledRule allows enabled activity logs."""
    rule = ActivityLogDisabledRule()
    resource = Resource(
        id="log-1",
        name="Activity Log",
        type="Azure::Monitor::ActivityLog",
        region="global",
        cloud_provider="azure",
        attributes={"Enabled": True},
        tags={},
    )
    result = rule.evaluate(resource)
    assert result.has_finding is False


def test_activity_log_disabled_rule_has_critical_severity():
    """Test ActivityLogDisabledRule has CRITICAL severity."""
    rule = ActivityLogDisabledRule()
    assert rule.severity == RuleSeverity.CRITICAL
