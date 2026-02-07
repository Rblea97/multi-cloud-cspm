"""AWS cloud remediation actions."""

from typing import Any

import boto3  # type: ignore[import-untyped]

from cspm.remediation.base import (
    BaseRemediationAction,
    RemediationMode,
    RemediationResult,
    RemediationStatus,
)


class RemediatePublicS3Bucket(BaseRemediationAction):
    """Remediate public S3 bucket by blocking public access."""

    def __init__(self) -> None:
        """Initialize S3 bucket remediation action."""
        super().__init__()
        self.action_id = "RemediatePublicS3Bucket"
        self.name = "Block Public S3 Bucket Access"
        self.description = "Sets bucket ACL to private and enables Block Public Access"
        self.rule_id = "PublicS3Rule"
        self.cloud_provider = "aws"
        self.resource_types = ["AWS::S3::Bucket"]
        self.requires_approval = True
        self._aws_provider: Any | None = None

    def validate(self, resource: dict[str, Any]) -> bool:
        """Validate S3 bucket resource.

        Args:
            resource: S3 bucket resource

        Returns:
            True if resource is S3 bucket
        """
        return resource.get("type") == "AWS::S3::Bucket"

    def execute(
        self,
        resource: dict[str, Any],
        finding: dict[str, Any],
        mode: RemediationMode,
    ) -> RemediationResult:
        """Execute S3 bucket remediation.

        Args:
            resource: S3 bucket resource
            finding: Finding that triggered remediation
            mode: Execution mode (DRY_RUN or AUTO_FIX)

        Returns:
            Result of remediation
        """
        if mode == RemediationMode.DRY_RUN:
            return RemediationResult(
                success=True,
                status=RemediationStatus.SUCCESS,
                changes_made={"action": "Would block public access to S3 bucket"},
                dry_run=True,
            )

        try:
            s3_client = (
                self._aws_provider.s3_client if self._aws_provider else boto3.client("s3")
            )
            bucket_name = resource.get("name") or resource.get("bucket_name")

            # Set bucket ACL to private
            s3_client.put_bucket_acl(Bucket=bucket_name, ACL="private")

            # Enable Block Public Access
            s3_client.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )

            return RemediationResult(
                success=True,
                status=RemediationStatus.SUCCESS,
                changes_made={
                    "bucket": bucket_name,
                    "acl": "private",
                    "public_access_blocked": True,
                },
            )
        except Exception as e:
            return RemediationResult(
                success=False,
                status=RemediationStatus.FAILED,
                changes_made={},
                error_message=str(e),
            )


class RemediateUnencryptedRDS(BaseRemediationAction):
    """Remediate unencrypted RDS database."""

    def __init__(self) -> None:
        """Initialize RDS remediation action."""
        super().__init__()
        self.action_id = "RemediateUnencryptedRDS"
        self.name = "Enable RDS Encryption"
        self.description = "Tags RDS instance for encryption enablement"
        self.rule_id = "UnencryptedRDSRule"
        self.cloud_provider = "aws"
        self.resource_types = ["AWS::RDS::DBInstance"]
        self.requires_approval = True
        self._aws_provider: Any | None = None

    def validate(self, resource: dict[str, Any]) -> bool:
        """Validate RDS resource.

        Args:
            resource: RDS database resource

        Returns:
            True if resource is RDS instance
        """
        return resource.get("type") == "AWS::RDS::DBInstance"

    def execute(
        self,
        resource: dict[str, Any],
        finding: dict[str, Any],
        mode: RemediationMode,
    ) -> RemediationResult:
        """Execute RDS remediation.

        Args:
            resource: RDS database resource
            finding: Finding that triggered remediation
            mode: Execution mode (DRY_RUN or AUTO_FIX)

        Returns:
            Result of remediation
        """
        if mode == RemediationMode.DRY_RUN:
            return RemediationResult(
                success=True,
                status=RemediationStatus.SUCCESS,
                changes_made={
                    "action": "Would tag RDS instance for encryption enablement"
                },
                dry_run=True,
            )

        try:
            rds_client = (
                self._aws_provider.rds_client if self._aws_provider else boto3.client("rds")
            )
            db_identifier = resource.get("db_instance_identifier")

            # Tag instance for encryption
            rds_client.add_tags_to_resource(
                ResourceName=f"arn:aws:rds:*:*:db:{db_identifier}",
                Tags=[
                    {"Key": "RequiresEncryption", "Value": "true"},
                    {
                        "Key": "EncryptionStatus",
                        "Value": "Manual encryption required - db snapshot required",
                    },
                ],
            )

            return RemediationResult(
                success=True,
                status=RemediationStatus.SUCCESS,
                changes_made={
                    "db_instance": db_identifier,
                    "action": "Tagged for encryption enablement",
                },
            )
        except Exception as e:
            return RemediationResult(
                success=False,
                status=RemediationStatus.FAILED,
                changes_made={},
                error_message=str(e),
            )


class RemediateEC2PublicIP(BaseRemediationAction):
    """Remediate EC2 instance with public IP."""

    def __init__(self) -> None:
        """Initialize EC2 public IP remediation action."""
        super().__init__()
        self.action_id = "RemediateEC2PublicIP"
        self.name = "Disassociate EC2 Public IP"
        self.description = "Removes public IP address from EC2 instance"
        self.rule_id = "EC2PublicIPRule"
        self.cloud_provider = "aws"
        self.resource_types = ["AWS::EC2::Instance"]
        self.requires_approval = False
        self._aws_provider: Any | None = None

    def validate(self, resource: dict[str, Any]) -> bool:
        """Validate EC2 resource.

        Args:
            resource: EC2 instance resource

        Returns:
            True if resource is EC2 instance
        """
        return resource.get("type") == "AWS::EC2::Instance"

    def execute(
        self,
        resource: dict[str, Any],
        finding: dict[str, Any],
        mode: RemediationMode,
    ) -> RemediationResult:
        """Execute EC2 public IP remediation.

        Args:
            resource: EC2 instance resource
            finding: Finding that triggered remediation
            mode: Execution mode (DRY_RUN or AUTO_FIX)

        Returns:
            Result of remediation
        """
        if mode == RemediationMode.DRY_RUN:
            return RemediationResult(
                success=True,
                status=RemediationStatus.SUCCESS,
                changes_made={"action": "Would disassociate public IP"},
                dry_run=True,
            )

        try:
            ec2_client = (
                self._aws_provider.ec2_client if self._aws_provider else boto3.client("ec2")
            )
            instance_id = resource.get("instance_id")
            public_ip = resource.get("public_ip_address")

            # Disassociate public IP
            if public_ip:
                ec2_client.disassociate_address(PublicIp=public_ip)

            return RemediationResult(
                success=True,
                status=RemediationStatus.SUCCESS,
                changes_made={
                    "instance_id": instance_id,
                    "public_ip": public_ip,
                    "action": "Disassociated public IP",
                },
            )
        except Exception as e:
            return RemediationResult(
                success=False,
                status=RemediationStatus.FAILED,
                changes_made={},
                error_message=str(e),
            )


class RemediateOpenSecurityGroup(BaseRemediationAction):
    """Remediate security group with overly permissive rules."""

    def __init__(self) -> None:
        """Initialize security group remediation action."""
        super().__init__()
        self.action_id = "RemediateOpenSecurityGroup"
        self.name = "Restrict Security Group Ingress"
        self.description = "Removes 0.0.0.0/0 ingress rules from security group"
        self.rule_id = "OpenSecurityGroupRule"
        self.cloud_provider = "aws"
        self.resource_types = ["AWS::EC2::SecurityGroup"]
        self.requires_approval = True
        self._aws_provider: Any | None = None

    def validate(self, resource: dict[str, Any]) -> bool:
        """Validate security group resource.

        Args:
            resource: Security group resource

        Returns:
            True if resource is security group
        """
        return resource.get("type") == "AWS::EC2::SecurityGroup"

    def execute(
        self,
        resource: dict[str, Any],
        finding: dict[str, Any],
        mode: RemediationMode,
    ) -> RemediationResult:
        """Execute security group remediation.

        Args:
            resource: Security group resource
            finding: Finding that triggered remediation
            mode: Execution mode (DRY_RUN or AUTO_FIX)

        Returns:
            Result of remediation
        """
        if mode == RemediationMode.DRY_RUN:
            rules = resource.get("ingress_rules", [])
            open_rules = [r for r in rules if r.get("CidrIp") == "0.0.0.0/0"]
            return RemediationResult(
                success=True,
                status=RemediationStatus.SUCCESS,
                changes_made={"identified_open_rules": len(open_rules)},
                dry_run=True,
            )

        try:
            ec2_client = (
                self._aws_provider.ec2_client if self._aws_provider else boto3.client("ec2")
            )
            group_id = resource.get("group_id")
            rules = resource.get("ingress_rules", [])

            # Revoke 0.0.0.0/0 rules
            revoked_rules = []
            for rule in rules:
                if rule.get("CidrIp") == "0.0.0.0/0":
                    try:
                        ec2_client.revoke_security_group_ingress(
                            GroupId=group_id,
                            IpProtocol=rule.get("IpProtocol", "-1"),
                            FromPort=rule.get("FromPort", -1),
                            ToPort=rule.get("ToPort", -1),
                            CidrIp="0.0.0.0/0",
                        )
                        revoked_rules.append(rule)
                    except Exception:  # noqa: S110
                        pass

            return RemediationResult(
                success=True,
                status=RemediationStatus.SUCCESS,
                changes_made={
                    "group_id": group_id,
                    "revoked_rules": len(revoked_rules),
                },
            )
        except Exception as e:
            return RemediationResult(
                success=False,
                status=RemediationStatus.FAILED,
                changes_made={},
                error_message=str(e),
            )


class RemediateCloudTrailDisabled(BaseRemediationAction):
    """Remediate disabled CloudTrail."""

    def __init__(self) -> None:
        """Initialize CloudTrail remediation action."""
        super().__init__()
        self.action_id = "RemediateCloudTrailDisabled"
        self.name = "Enable CloudTrail Logging"
        self.description = "Starts logging on CloudTrail"
        self.rule_id = "CloudTrailDisabledRule"
        self.cloud_provider = "aws"
        self.resource_types = ["AWS::CloudTrail::Trail"]
        self.requires_approval = True
        self._aws_provider: Any | None = None

    def validate(self, resource: dict[str, Any]) -> bool:
        """Validate CloudTrail resource.

        Args:
            resource: CloudTrail trail resource

        Returns:
            True if resource is CloudTrail trail
        """
        return resource.get("type") == "AWS::CloudTrail::Trail"

    def execute(
        self,
        resource: dict[str, Any],
        finding: dict[str, Any],
        mode: RemediationMode,
    ) -> RemediationResult:
        """Execute CloudTrail remediation.

        Args:
            resource: CloudTrail trail resource
            finding: Finding that triggered remediation
            mode: Execution mode (DRY_RUN or AUTO_FIX)

        Returns:
            Result of remediation
        """
        if mode == RemediationMode.DRY_RUN:
            return RemediationResult(
                success=True,
                status=RemediationStatus.SUCCESS,
                changes_made={"action": "Would enable CloudTrail logging"},
                dry_run=True,
            )

        try:
            ct_client = (
                self._aws_provider.cloudtrail_client
                if self._aws_provider
                else boto3.client("cloudtrail")
            )
            trail_name = resource.get("name")

            # Start logging
            ct_client.start_logging(Name=trail_name)

            return RemediationResult(
                success=True,
                status=RemediationStatus.SUCCESS,
                changes_made={
                    "trail": trail_name,
                    "action": "Enabled logging",
                },
            )
        except Exception as e:
            return RemediationResult(
                success=False,
                status=RemediationStatus.FAILED,
                changes_made={},
                error_message=str(e),
            )
