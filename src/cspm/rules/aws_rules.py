"""AWS security rules implementation."""

from cspm.cloud.base import Resource
from cspm.rules.base import BaseRule, RuleResult, RuleSeverity


class PublicS3Rule(BaseRule):
    """Rule to detect publicly accessible S3 buckets."""

    def __init__(self) -> None:
        """Initialize PublicS3Rule."""
        super().__init__()
        self.rule_id = "public_s3_rule"
        self.name = "Public S3 Bucket"
        self.description = "Detects S3 buckets with public access"
        self.severity = RuleSeverity.CRITICAL
        self.cloud_provider = "aws"
        self.resource_types = ["AWS::S3::Bucket"]
        self.remediation_advice = "Set bucket ACL to private and enable block public access"

    def evaluate(self, resource: Resource) -> RuleResult:
        """Evaluate if S3 bucket is publicly accessible.

        Args:
            resource: The S3 bucket resource to evaluate

        Returns:
            RuleResult indicating if the bucket is public
        """
        acl = resource.attributes.get("ACL", "").lower()

        # Check if ACL indicates public access
        is_public = acl in ["public-read", "public-read-write", "authenticated-read"]

        return RuleResult(
            resource=resource,
            has_finding=is_public,
            severity=RuleSeverity.CRITICAL if is_public else RuleSeverity.INFO,
            title="Public S3 Bucket Detected" if is_public else "S3 Bucket is Private",
            description=f"S3 bucket '{resource.name}' has public ACL: {acl}"
            if is_public
            else f"S3 bucket '{resource.name}' is private",
        )


class UnencryptedRDSRule(BaseRule):
    """Rule to detect unencrypted RDS instances."""

    def __init__(self) -> None:
        """Initialize UnencryptedRDSRule."""
        super().__init__()
        self.rule_id = "unencrypted_rds_rule"
        self.name = "Unencrypted RDS Instance"
        self.description = "Detects RDS instances without encryption"
        self.severity = RuleSeverity.HIGH
        self.cloud_provider = "aws"
        self.resource_types = ["AWS::RDS::DBInstance"]
        self.remediation_advice = "Enable encryption at rest for RDS instances"

    def evaluate(self, resource: Resource) -> RuleResult:
        """Evaluate if RDS instance is unencrypted.

        Args:
            resource: The RDS instance resource to evaluate

        Returns:
            RuleResult indicating if encryption is disabled
        """
        is_encrypted = resource.attributes.get("StorageEncrypted", False)

        return RuleResult(
            resource=resource,
            has_finding=not is_encrypted,
            severity=RuleSeverity.HIGH if not is_encrypted else RuleSeverity.INFO,
            title="Unencrypted RDS Instance" if not is_encrypted else "RDS Instance is Encrypted",
            description=f"RDS instance '{resource.name}' has encryption disabled"
            if not is_encrypted
            else f"RDS instance '{resource.name}' has encryption enabled",
        )


class EC2PublicIPRule(BaseRule):
    """Rule to detect EC2 instances with public IPs."""

    def __init__(self) -> None:
        """Initialize EC2PublicIPRule."""
        super().__init__()
        self.rule_id = "ec2_public_ip_rule"
        self.name = "EC2 Instance with Public IP"
        self.description = "Detects EC2 instances with public IP addresses"
        self.severity = RuleSeverity.MEDIUM
        self.cloud_provider = "aws"
        self.resource_types = ["AWS::EC2::Instance"]
        self.remediation_advice = "Use private IPs or place instances in private subnets"

    def evaluate(self, resource: Resource) -> RuleResult:
        """Evaluate if EC2 instance has public IP.

        Args:
            resource: The EC2 instance resource to evaluate

        Returns:
            RuleResult indicating if the instance has a public IP
        """
        public_ip = resource.attributes.get("PublicIpAddress")
        has_public_ip = public_ip is not None

        return RuleResult(
            resource=resource,
            has_finding=has_public_ip,
            severity=RuleSeverity.MEDIUM if has_public_ip else RuleSeverity.INFO,
            title="EC2 Instance with Public IP" if has_public_ip else "EC2 Instance is Private",
            description=f"EC2 instance '{resource.name}' has public IP: {public_ip}"
            if has_public_ip
            else f"EC2 instance '{resource.name}' is private",
        )


class OpenSecurityGroupRule(BaseRule):
    """Rule to detect overly permissive security groups."""

    def __init__(self) -> None:
        """Initialize OpenSecurityGroupRule."""
        super().__init__()
        self.rule_id = "open_sg_rule"
        self.name = "Open Security Group"
        self.description = "Detects security groups with 0.0.0.0/0 ingress"
        self.severity = RuleSeverity.HIGH
        self.cloud_provider = "aws"
        self.resource_types = ["AWS::EC2::SecurityGroup"]
        self.remediation_advice = "Restrict ingress rules to specific IP ranges"

    def evaluate(self, resource: Resource) -> RuleResult:
        """Evaluate if security group is overly permissive.

        Args:
            resource: The security group resource to evaluate

        Returns:
            RuleResult indicating if the group allows 0.0.0.0/0 ingress
        """
        ip_permissions = resource.attributes.get("IpPermissions", [])
        has_open_rule = False

        for permission in ip_permissions:
            ip_ranges = permission.get("IpRanges", [])
            for ip_range in ip_ranges:
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    has_open_rule = True
                    break

        return RuleResult(
            resource=resource,
            has_finding=has_open_rule,
            severity=RuleSeverity.HIGH if has_open_rule else RuleSeverity.INFO,
            title="Open Security Group Detected" if has_open_rule else "Security Group is Restricted",
            description=f"Security group '{resource.name}' allows 0.0.0.0/0 ingress"
            if has_open_rule
            else f"Security group '{resource.name}' is restricted",
        )


class CloudTrailDisabledRule(BaseRule):
    """Rule to detect disabled CloudTrail logging."""

    def __init__(self) -> None:
        """Initialize CloudTrailDisabledRule."""
        super().__init__()
        self.rule_id = "cloudtrail_disabled_rule"
        self.name = "CloudTrail Disabled"
        self.description = "Detects CloudTrail trails that are not actively logging"
        self.severity = RuleSeverity.CRITICAL
        self.cloud_provider = "aws"
        self.resource_types = ["AWS::CloudTrail::Trail"]
        self.remediation_advice = "Enable CloudTrail logging to track API calls"

    def evaluate(self, resource: Resource) -> RuleResult:
        """Evaluate if CloudTrail is logging.

        Args:
            resource: The CloudTrail resource to evaluate

        Returns:
            RuleResult indicating if logging is disabled
        """
        is_logging = resource.attributes.get("IsLogging", False)

        return RuleResult(
            resource=resource,
            has_finding=not is_logging,
            severity=RuleSeverity.CRITICAL if not is_logging else RuleSeverity.INFO,
            title="CloudTrail Disabled" if not is_logging else "CloudTrail is Enabled",
            description=f"CloudTrail '{resource.name}' is not logging"
            if not is_logging
            else f"CloudTrail '{resource.name}' is actively logging",
        )
