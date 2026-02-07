#!/usr/bin/env python3
"""Execute a security scan against cloud resources.

Usage:
    python scripts/run_scan.py --cloud aws
    python scripts/run_scan.py --cloud azure
    python scripts/run_scan.py --cloud all
"""

import argparse
import json
import sys
from datetime import datetime

from sqlalchemy import create_engine

from cspm.cloud.aws import AwsCloudProvider
from cspm.cloud.azure import AzureCloudProvider
from cspm.core.config import settings
from cspm.database.models import Base
from cspm.database.repository import Repository
from cspm.rules.aws_rules import (
    CloudTrailDisabledRule,
    EC2PublicIPRule,
    OpenSecurityGroupRule,
    PublicS3Rule,
    UnencryptedRDSRule,
)
from cspm.rules.azure_rules import (
    ActivityLogDisabledRule,
    OpenNSGRule,
    PublicStorageRule,
    UnencryptedSQLRule,
    VMPublicIPRule,
)
from cspm.rules.registry import RuleRegistry
from cspm.scanner.engine import ScanEngine


def setup_database():
    """Set up database and repository."""
    engine = create_engine(settings.database_url)
    Base.metadata.create_all(engine)
    return Repository(db_url=settings.database_url)


def register_aws_rules(registry):
    """Register all AWS rules."""
    registry.register(PublicS3Rule())
    registry.register(UnencryptedRDSRule())
    registry.register(EC2PublicIPRule())
    registry.register(OpenSecurityGroupRule())
    registry.register(CloudTrailDisabledRule())


def register_azure_rules(registry):
    """Register all Azure rules."""
    registry.register(PublicStorageRule())
    registry.register(UnencryptedSQLRule())
    registry.register(VMPublicIPRule())
    registry.register(OpenNSGRule())
    registry.register(ActivityLogDisabledRule())


def run_aws_scan(scan_engine, repository):
    """Run AWS scan."""
    print("\n" + "=" * 60)
    print("AWS Security Scan")
    print("=" * 60)

    provider = AwsCloudProvider(region=settings.aws_region)
    if not provider.authenticate():
        print("❌ AWS authentication failed")
        return None

    print("✅ AWS authenticated")

    scan_engine.register_provider(provider)
    scan_id = scan_engine.scan(scan_type="FULL")

    scan = repository.get_scan(scan_id)
    print(f"\n📊 Scan Results:")
    print(f"  Scan ID: {scan_id}")
    print(f"  Status: {scan.status}")
    print(f"  Resources Scanned: {scan.resources_scanned}")

    findings = repository.get_findings_by_scan(scan_id)
    print(f"  Findings: {len(findings)}")

    if findings:
        print(f"\n🚨 Findings by Severity:")
        severity_counts = {}
        for finding in findings:
            severity = finding.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                print(f"  {severity}: {count}")

    return scan_id


def run_azure_scan(scan_engine, repository):
    """Run Azure scan."""
    print("\n" + "=" * 60)
    print("Azure Security Scan")
    print("=" * 60)

    if not settings.azure_subscription_id:
        print("⚠️  Azure subscription ID not configured")
        return None

    provider = AzureCloudProvider(
        subscription_id=settings.azure_subscription_id,
        tenant_id=settings.azure_tenant_id,
    )

    if not provider.authenticate():
        print("❌ Azure authentication failed")
        return None

    print("✅ Azure authenticated")

    scan_engine.register_provider(provider)
    scan_id = scan_engine.scan(scan_type="FULL")

    scan = repository.get_scan(scan_id)
    print(f"\n📊 Scan Results:")
    print(f"  Scan ID: {scan_id}")
    print(f"  Status: {scan.status}")
    print(f"  Resources Scanned: {scan.resources_scanned}")

    findings = repository.get_findings_by_scan(scan_id)
    print(f"  Findings: {len(findings)}")

    if findings:
        print(f"\n🚨 Findings by Severity:")
        severity_counts = {}
        for finding in findings:
            severity = finding.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                print(f"  {severity}: {count}")

    return scan_id


def main():
    parser = argparse.ArgumentParser(description="Run CSPM security scan")
    parser.add_argument(
        "--cloud",
        choices=["aws", "azure", "all"],
        default="all",
        help="Cloud provider to scan",
    )
    parser.add_argument(
        "--output",
        help="Output file for scan results (JSON format)",
    )

    args = parser.parse_args()

    # Set up database and rules
    repository = setup_database()
    rule_registry = RuleRegistry()
    scan_engine = ScanEngine(rule_registry, repository)

    # Register rules
    if args.cloud in ["aws", "all"]:
        register_aws_rules(rule_registry)

    if args.cloud in ["azure", "all"]:
        register_azure_rules(rule_registry)

    # Run scans
    scan_ids = []

    if args.cloud in ["aws", "all"]:
        aws_scan_id = run_aws_scan(scan_engine, repository)
        if aws_scan_id:
            scan_ids.append(aws_scan_id)

    if args.cloud in ["azure", "all"]:
        azure_scan_id = run_azure_scan(scan_engine, repository)
        if azure_scan_id:
            scan_ids.append(azure_scan_id)

    # Output results
    if args.output:
        results = {
            "timestamp": datetime.now().isoformat(),
            "scan_ids": scan_ids,
            "scans": [],
        }

        for scan_id in scan_ids:
            scan = repository.get_scan(scan_id)
            findings = repository.get_findings_by_scan(scan_id)

            results["scans"].append(
                {
                    "id": scan_id,
                    "status": scan.status,
                    "resources_scanned": scan.resources_scanned,
                    "findings_count": len(findings),
                    "findings": [
                        {
                            "id": f.id,
                            "rule_id": f.rule_id,
                            "resource_id": f.resource_id,
                            "severity": f.severity,
                            "status": f.status,
                        }
                        for f in findings
                    ],
                }
            )

        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n✅ Results saved to {args.output}")

    print("\n✅ Scan complete!")


if __name__ == "__main__":
    main()
