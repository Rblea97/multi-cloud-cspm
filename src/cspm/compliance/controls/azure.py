"""Azure CIS Foundations Benchmark controls."""

from cspm.compliance.framework import ComplianceFramework, Control


class CISAzureFramework(ComplianceFramework):
    """Azure CIS Foundations Benchmark v1.4.0 framework."""

    def get_controls(self) -> list[Control]:
        """Get all 10 Azure CIS controls.

        Returns:
            List of Control objects for Azure CIS v1.4.0
        """
        return [
            Control(
                control_id="CIS_AZURE_1.1",
                title="Ensure that multi-factor authentication is enabled for all users",
                description="Multi-factor authentication adds a second layer of authentication to verify the identity of a user.",
                severity="CRITICAL",
                domain="Identity and Access Management",
                rule_ids=[],
                framework_id="CIS_AZURE_1.4.0",
            ),
            Control(
                control_id="CIS_AZURE_1.9",
                title="Ensure that 'Notify all admins when other admins reset their password?' is Enabled",
                description="When an admin resets their password, all admins should be notified to detect unauthorized account access.",
                severity="MEDIUM",
                domain="Identity and Access Management",
                rule_ids=[],
                framework_id="CIS_AZURE_1.4.0",
            ),
            Control(
                control_id="CIS_AZURE_3.1",
                title="Ensure that Activity Log Alert exists for Create Policy Assignment",
                description="Activity Log Alerts are available in the Azure portal for policies.",
                severity="MEDIUM",
                domain="Logging",
                rule_ids=[],
                framework_id="CIS_AZURE_1.4.0",
            ),
            Control(
                control_id="CIS_AZURE_4.3",
                title="Ensure that 'Enforce SSL connection' is set to 'ENABLED' for MySQL Database Server'",
                description="SSL enforces connections to MySQL Database over SSL/TLS, protecting data in transit.",
                severity="MEDIUM",
                domain="Database",
                rule_ids=[],
                framework_id="CIS_AZURE_1.4.0",
            ),
            Control(
                control_id="CIS_AZURE_4.4",
                title="Ensure 'log_checkpoints' server parameter is set to 'ON' for PostgreSQL Database Server",
                description="Checkpoint log events allow PostgreSQL servers to log when database checkpoints occur.",
                severity="MEDIUM",
                domain="Database",
                rule_ids=[],
                framework_id="CIS_AZURE_1.4.0",
            ),
            Control(
                control_id="CIS_AZURE_5.1",
                title="Ensure that 'Secure transfer required' is set to 'True'",
                description="Secure transfer requires the use of HTTPS for storage account operations.",
                severity="CRITICAL",
                domain="Storage",
                rule_ids=["PublicStorageRule"],
                framework_id="CIS_AZURE_1.4.0",
            ),
            Control(
                control_id="CIS_AZURE_5.2",
                title="Ensure that storage accounts are configured with 'Shared access signature' expiration set",
                description="Shared access signatures should have expiration times set to prevent indefinite access.",
                severity="HIGH",
                domain="Storage",
                rule_ids=[],
                framework_id="CIS_AZURE_1.4.0",
            ),
            Control(
                control_id="CIS_AZURE_5.3",
                title="Ensure that 'default' network access rule for Storage Blobs is set to deny",
                description="Network access rules should restrict access to storage blobs to authorized networks only.",
                severity="HIGH",
                domain="Storage",
                rule_ids=[],
                framework_id="CIS_AZURE_1.4.0",
            ),
            Control(
                control_id="CIS_AZURE_5.6",
                title="Ensure that 'Transparent Data Encryption' is 'On' for SQL databases",
                description="Transparent Data Encryption encrypts the database at rest.",
                severity="HIGH",
                domain="Database",
                rule_ids=["UnencryptedSQLRule"],
                framework_id="CIS_AZURE_1.4.0",
            ),
            Control(
                control_id="CIS_AZURE_5.7",
                title="Ensure that 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database Server",
                description="SSL enforces connections to PostgreSQL Database over SSL/TLS.",
                severity="HIGH",
                domain="Database",
                rule_ids=[],
                framework_id="CIS_AZURE_1.4.0",
            ),
        ]
