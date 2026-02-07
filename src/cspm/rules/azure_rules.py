"""Azure security rules implementation."""

from cspm.cloud.base import Resource
from cspm.rules.base import BaseRule, RuleResult, RuleSeverity


class PublicStorageRule(BaseRule):
    """Rule to detect publicly accessible Azure Storage accounts."""

    def __init__(self) -> None:
        """Initialize PublicStorageRule."""
        super().__init__()
        self.rule_id = "public_storage_rule"
        self.name = "Public Storage Account"
        self.description = "Detects Azure Storage accounts with public blob access"
        self.severity = RuleSeverity.CRITICAL
        self.cloud_provider = "azure"
        self.resource_types = ["Azure::Storage::Account"]
        self.remediation_advice = "Disable public blob access on storage account"

    def evaluate(self, resource: Resource) -> RuleResult:
        """Evaluate if storage account allows public blob access.

        Args:
            resource: The storage account resource to evaluate

        Returns:
            RuleResult indicating if public access is enabled
        """
        is_public = resource.attributes.get("AllowBlobPublicAccess", False)

        return RuleResult(
            resource=resource,
            has_finding=is_public,
            severity=RuleSeverity.CRITICAL if is_public else RuleSeverity.INFO,
            title="Public Storage Account Detected" if is_public else "Storage Account is Private",
            description=f"Storage account '{resource.name}' allows public blob access"
            if is_public
            else f"Storage account '{resource.name}' does not allow public blob access",
        )


class UnencryptedSQLRule(BaseRule):
    """Rule to detect SQL databases without Azure Key Vault encryption."""

    def __init__(self) -> None:
        """Initialize UnencryptedSQLRule."""
        super().__init__()
        self.rule_id = "unencrypted_sql_rule"
        self.name = "Unencrypted SQL Database"
        self.description = "Detects SQL databases without Azure Key Vault encryption"
        self.severity = RuleSeverity.HIGH
        self.cloud_provider = "azure"
        self.resource_types = ["Azure::SQL::Database"]
        self.remediation_advice = "Enable Azure Key Vault encryption for SQL databases"

    def evaluate(self, resource: Resource) -> RuleResult:
        """Evaluate if SQL database uses non-Key Vault encryption.

        Args:
            resource: The SQL database resource to evaluate

        Returns:
            RuleResult indicating if non-Key Vault encryption is used
        """
        encryption_type = resource.attributes.get("EncryptionProtectorType")
        is_unencrypted = encryption_type != "AzureKeyVault"

        return RuleResult(
            resource=resource,
            has_finding=is_unencrypted,
            severity=RuleSeverity.HIGH if is_unencrypted else RuleSeverity.INFO,
            title="Unencrypted SQL Database" if is_unencrypted else "SQL Database is Encrypted",
            description=f"SQL database '{resource.name}' does not use Azure Key Vault encryption"
            if is_unencrypted
            else f"SQL database '{resource.name}' uses Azure Key Vault encryption",
        )


class VMPublicIPRule(BaseRule):
    """Rule to detect Azure VMs with public IP addresses."""

    def __init__(self) -> None:
        """Initialize VMPublicIPRule."""
        super().__init__()
        self.rule_id = "vm_public_ip_rule"
        self.name = "VM with Public IP"
        self.description = "Detects Azure VMs with public IP addresses"
        self.severity = RuleSeverity.MEDIUM
        self.cloud_provider = "azure"
        self.resource_types = ["Azure::Compute::VirtualMachine"]
        self.remediation_advice = "Remove public IP from VM or restrict access with NSG rules"

    def evaluate(self, resource: Resource) -> RuleResult:
        """Evaluate if VM has a public IP address.

        Args:
            resource: The VM resource to evaluate

        Returns:
            RuleResult indicating if a public IP is assigned
        """
        has_public_ip = resource.attributes.get("PublicIpAddress") is not None

        return RuleResult(
            resource=resource,
            has_finding=has_public_ip,
            severity=RuleSeverity.MEDIUM if has_public_ip else RuleSeverity.INFO,
            title="VM with Public IP" if has_public_ip else "VM has no Public IP",
            description=f"VM '{resource.name}' has public IP address {resource.attributes.get('PublicIpAddress')}"
            if has_public_ip
            else f"VM '{resource.name}' does not have a public IP address",
        )


class OpenNSGRule(BaseRule):
    """Rule to detect Network Security Groups with overly permissive rules."""

    def __init__(self) -> None:
        """Initialize OpenNSGRule."""
        super().__init__()
        self.rule_id = "open_nsg_rule"
        self.name = "Open Network Security Group"
        self.description = "Detects NSGs with overly permissive ingress rules"
        self.severity = RuleSeverity.HIGH
        self.cloud_provider = "azure"
        self.resource_types = ["Azure::Network::NetworkSecurityGroup"]
        self.remediation_advice = "Restrict NSG ingress rules to specific source addresses"

    def evaluate(self, resource: Resource) -> RuleResult:
        """Evaluate if NSG has open ingress rules.

        Args:
            resource: The NSG resource to evaluate

        Returns:
            RuleResult indicating if open rules exist
        """
        rules = resource.attributes.get("SecurityRules", [])
        has_open_rule = False

        for rule in rules:
            if hasattr(rule, "properties"):
                props = rule.properties
                source = getattr(props, "source_address_prefix", "")
                access = getattr(props, "access", "")
                direction = getattr(props, "direction", "")
                if direction == "Inbound" and access == "Allow" and source in ("*", "0.0.0.0/0"):
                    has_open_rule = True
                    break

        return RuleResult(
            resource=resource,
            has_finding=has_open_rule,
            severity=RuleSeverity.HIGH if has_open_rule else RuleSeverity.INFO,
            title="Open Network Security Group" if has_open_rule else "NSG is Restricted",
            description=f"NSG '{resource.name}' has overly permissive ingress rules"
            if has_open_rule
            else f"NSG '{resource.name}' has properly restricted rules",
        )


class ActivityLogDisabledRule(BaseRule):
    """Rule to detect disabled Azure Activity Log monitoring."""

    def __init__(self) -> None:
        """Initialize ActivityLogDisabledRule."""
        super().__init__()
        self.rule_id = "activity_log_disabled_rule"
        self.name = "Activity Log Disabled"
        self.description = "Detects disabled Azure Activity Log monitoring"
        self.severity = RuleSeverity.CRITICAL
        self.cloud_provider = "azure"
        self.resource_types = ["Azure::Monitor::ActivityLog"]
        self.remediation_advice = "Enable Activity Log monitoring for the subscription"

    def evaluate(self, resource: Resource) -> RuleResult:
        """Evaluate if activity log monitoring is disabled.

        Args:
            resource: The activity log resource to evaluate

        Returns:
            RuleResult indicating if monitoring is disabled
        """
        is_disabled = not resource.attributes.get("Enabled", True)

        return RuleResult(
            resource=resource,
            has_finding=is_disabled,
            severity=RuleSeverity.CRITICAL if is_disabled else RuleSeverity.INFO,
            title="Activity Log Disabled" if is_disabled else "Activity Log Enabled",
            description="Activity Log monitoring is disabled"
            if is_disabled
            else "Activity Log monitoring is enabled",
        )
