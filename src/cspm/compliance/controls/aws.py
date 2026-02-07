"""AWS CIS Foundations Benchmark controls."""

from cspm.compliance.framework import ComplianceFramework, Control


class CISAWSFramework(ComplianceFramework):
    """AWS CIS Foundations Benchmark v1.4.0 framework."""

    def get_controls(self) -> list[Control]:
        """Get all 10 AWS CIS controls.

        Returns:
            List of Control objects for AWS CIS v1.4.0
        """
        return [
            Control(
                control_id="CIS_AWS_1.2",
                title="Ensure IAM policy is attached only to groups or roles to reduce access management complexity as users are granted access through group or role membership",
                description="Access to computing resources should be granted to identity groups rather than individual users to reduce access management complexity.",
                severity="MEDIUM",
                domain="Identity and Access Management",
                rule_ids=[],
                framework_id="CIS_AWS_1.4.0",
            ),
            Control(
                control_id="CIS_AWS_1.4",
                title="Ensure access keys are rotated every 90 days or less",
                description="Access keys consist of an access key ID and secret access key that can be used to sign programmatic requests to AWS.",
                severity="MEDIUM",
                domain="Identity and Access Management",
                rule_ids=[],
                framework_id="CIS_AWS_1.4.0",
            ),
            Control(
                control_id="CIS_AWS_2.1",
                title="Ensure CloudTrail is enabled in all regions",
                description="CloudTrail is a web service that records AWS API calls for your account and delivers log files to you.",
                severity="CRITICAL",
                domain="Logging",
                rule_ids=["CloudTrailDisabledRule"],
                framework_id="CIS_AWS_1.4.0",
            ),
            Control(
                control_id="CIS_AWS_2.2",
                title="Ensure CloudTrail log file validation is enabled",
                description="CloudTrail log file validation creates a digitally signed digest file that can be used to detect tampering.",
                severity="HIGH",
                domain="Logging",
                rule_ids=[],
                framework_id="CIS_AWS_1.4.0",
            ),
            Control(
                control_id="CIS_AWS_2.5",
                title="Ensure CloudTrail logs are encrypted at rest using KMS",
                description="CloudTrail logs should be encrypted with KMS to protect sensitive information.",
                severity="CRITICAL",
                domain="Logging",
                rule_ids=["CloudTrailDisabledRule"],
                framework_id="CIS_AWS_1.4.0",
            ),
            Control(
                control_id="CIS_AWS_3.1",
                title="Ensure S3 bucket does not allow an unencrypted object upload",
                description="By default, S3 buckets and objects are private. The S3 bucket policy or access control list (ACL) only grants access to the resource creators.",
                severity="CRITICAL",
                domain="Storage",
                rule_ids=["PublicS3Rule"],
                framework_id="CIS_AWS_1.4.0",
            ),
            Control(
                control_id="CIS_AWS_4.1",
                title="Ensure a security group and network ACL allow only the ports and protocols that are required",
                description="Security groups and network ACLs provide stateful and stateless filtering of ingress and egress network traffic to AWS resources.",
                severity="HIGH",
                domain="Networking",
                rule_ids=["OpenSecurityGroupRule"],
                framework_id="CIS_AWS_1.4.0",
            ),
            Control(
                control_id="CIS_AWS_4.2",
                title="Ensure encryption is enabled for RDS instances",
                description="Amazon RDS encrypts your databases using keys you manage through AWS KMS.",
                severity="HIGH",
                domain="Database",
                rule_ids=["UnencryptedRDSRule"],
                framework_id="CIS_AWS_1.4.0",
            ),
            Control(
                control_id="CIS_AWS_5.1",
                title="Ensure EC2 instances do not have a public IP address",
                description="EC2 instances should not have publicly routable IP addresses assigned to them unless required.",
                severity="MEDIUM",
                domain="Compute",
                rule_ids=["EC2PublicIPRule"],
                framework_id="CIS_AWS_1.4.0",
            ),
            Control(
                control_id="CIS_AWS_5.2",
                title="Ensure EC2 security groups and network ACLs are optimized",
                description="Security groups and network ACLs provide stateless and stateful filtering of ingress and egress network traffic.",
                severity="MEDIUM",
                domain="Compute",
                rule_ids=[],
                framework_id="CIS_AWS_1.4.0",
            ),
        ]
