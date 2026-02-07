#!/usr/bin/env python3
"""Test remediation actions in dry-run mode.

This script tests remediation without making actual changes to cloud resources.

Usage:
    python scripts/test_remediation.py --finding-id <id> --dry-run
    python scripts/test_remediation.py --rule public_s3_rule --dry-run
"""

import argparse
import json

from cspm.core.config import settings
from cspm.database.repository import Repository
from cspm.remediation.aws_actions import (
    RemediateCloudTrailDisabled,
    RemediateEC2PublicIP,
    RemediateOpenSecurityGroup,
    RemediatePublicS3Bucket,
    RemediateUnencryptedRDS,
)
from cspm.remediation.azure_actions import (
    RemediateActivityLogDisabled,
    RemediateOpenNSG,
    RemediatePublicStorage,
    RemediateUnencryptedSQL,
    RemediateVMPublicIP,
)
from cspm.remediation.base import RemediationMode
from cspm.remediation.engine import RemediationEngine
from cspm.remediation.registry import RemediationRegistry


def setup_remediation_engine():
    """Set up remediation engine with all actions."""
    registry = RemediationRegistry()

    # Register AWS remediation actions
    registry.register(RemediatePublicS3Bucket())
    registry.register(RemediateUnencryptedRDS())
    registry.register(RemediateEC2PublicIP())
    registry.register(RemediateOpenSecurityGroup())
    registry.register(RemediateCloudTrailDisabled())

    # Register Azure remediation actions
    registry.register(RemediatePublicStorage())
    registry.register(RemediateUnencryptedSQL())
    registry.register(RemediateVMPublicIP())
    registry.register(RemediateOpenNSG())
    registry.register(RemediateActivityLogDisabled())

    repository = Repository(db_url=settings.database_url)
    return RemediationEngine(registry, repository), repository


def main():
    parser = argparse.ArgumentParser(description="Test remediation actions")
    parser.add_argument("--finding-id", help="Test remediation for specific finding")
    parser.add_argument("--rule", help="Test remediation for all findings from a rule")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run in dry-run mode (no actual changes)",
    )
    parser.add_argument(
        "--auto-approve",
        action="store_true",
        help="Auto-approve remediations (requires confirmation)",
    )

    args = parser.parse_args()

    if not args.finding_id and not args.rule:
        print("Error: Specify either --finding-id or --rule")
        return

    engine, repository = setup_remediation_engine()

    # Get findings to remediate
    if args.finding_id:
        finding = repository.get_finding(args.finding_id)
        if not finding:
            print(f"Finding {args.finding_id} not found")
            return
        findings = [finding]
    else:
        all_findings = repository.get_findings()
        findings = [f for f in all_findings if f.rule_id == args.rule]

    if not findings:
        print("No findings found")
        return

    print(f"\n🔧 Testing remediation for {len(findings)} finding(s)\n")

    mode = RemediationMode.DRY_RUN if args.dry_run else RemediationMode.EXECUTE
    print(f"Mode: {mode.value}")

    # Test remediation for each finding
    remediation_ids = []
    for finding in findings:
        print(f"\n{'=' * 60}")
        print(f"Finding: {finding.resource_id}")
        print(f"Rule: {finding.rule_id}")
        print(f"Severity: {finding.severity}")
        print(f"{'=' * 60}")

        try:
            # Create remediation request
            remediation_id = engine.remediate_finding(
                finding_id=finding.id,
                mode=mode,
            )

            remediation = repository.get_remediation(remediation_id)
            print(f"✅ Remediation created: {remediation_id}")
            print(f"   Status: {remediation.status}")
            print(f"   Mode: {remediation.mode}")

            remediation_ids.append(remediation_id)

            # Auto-approve if requested
            if args.auto_approve:
                engine.approve_remediation(remediation_id)
                print(f"   ✅ Auto-approved")

                # Execute if not dry-run
                if not args.dry_run:
                    engine.execute_pending_remediations()
                    remediation = repository.get_remediation(remediation_id)
                    print(f"   ✅ Executed (status: {remediation.status})")

        except Exception as e:  # noqa: S110
            print(f"❌ Error: {e}")

    # Summary
    print(f"\n{'=' * 60}")
    print(f"Remediation Summary")
    print(f"{'=' * 60}")
    print(f"Total remediations: {len(remediation_ids)}")
    print(f"Mode: {mode.value}")

    if args.dry_run:
        print("\n💡 Tip: Run with --auto-approve to approve and execute remediations")

    print("\n✅ Test complete!")


if __name__ == "__main__":
    main()
