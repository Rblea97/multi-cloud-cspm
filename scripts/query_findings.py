#!/usr/bin/env python3
"""Query findings from the CSPM database.

Usage:
    python scripts/query_findings.py --severity CRITICAL,HIGH
    python scripts/query_findings.py --status OPEN
    python scripts/query_findings.py --rule public_s3_rule
"""

import argparse
import json

from cspm.core.config import settings
from cspm.database.repository import Repository

try:
    from tabulate import tabulate
except ImportError:
    tabulate = None


def format_findings(findings, output_format="table"):
    """Format findings for output."""
    if output_format == "json":
        return json.dumps(
            [
                {
                    "id": f.id,
                    "rule_id": f.rule_id,
                    "resource_id": f.resource_id,
                    "resource_type": f.resource_type,
                    "severity": f.severity,
                    "status": f.status,
                    "cloud_provider": f.cloud_provider,
                    "description": f.description,
                }
                for f in findings
            ],
            indent=2,
        )

    # Table format (fallback to simple text if tabulate not available)
    if not tabulate:
        output = "Rule ID | Resource ID | Severity | Status | Provider\n"
        output += "-" * 80 + "\n"
        for f in findings:
            res_id = f.resource_id[:40] + "..." if len(f.resource_id) > 40 else f.resource_id
            output += f"{f.rule_id} | {res_id} | {f.severity} | {f.status} | {f.cloud_provider}\n"
        return output

    headers = ["Rule", "Resource", "Severity", "Status", "Provider"]
    rows = [
        [
            f.rule_id,
            f.resource_id[:40] + "..." if len(f.resource_id) > 40 else f.resource_id,
            f.severity,
            f.status,
            f.cloud_provider,
        ]
        for f in findings
    ]

    return tabulate(rows, headers=headers, tablefmt="grid")


def main():
    parser = argparse.ArgumentParser(description="Query CSPM findings")
    parser.add_argument(
        "--severity",
        help="Filter by severity (comma-separated: CRITICAL,HIGH,MEDIUM,LOW)",
    )
    parser.add_argument("--status", help="Filter by status (OPEN,CLOSED,REMEDIATED)")
    parser.add_argument("--rule", help="Filter by rule ID")
    parser.add_argument("--cloud", help="Filter by cloud provider (aws,azure)")
    parser.add_argument(
        "--output",
        choices=["table", "json"],
        default="table",
        help="Output format",
    )
    parser.add_argument("--limit", type=int, default=100, help="Limit number of results")

    args = parser.parse_args()

    # Get findings
    repository = Repository(db_url=settings.database_url)
    findings = repository.get_findings()

    # Filter by severity
    if args.severity:
        severities = [s.strip().upper() for s in args.severity.split(",")]
        findings = [f for f in findings if f.severity in severities]

    # Filter by status
    if args.status:
        findings = [f for f in findings if f.status == args.status]

    # Filter by rule
    if args.rule:
        findings = [f for f in findings if f.rule_id == args.rule]

    # Filter by cloud provider
    if args.cloud:
        findings = [f for f in findings if f.cloud_provider.lower() == args.cloud.lower()]

    # Limit results
    findings = findings[: args.limit]

    # Output
    print(f"\n📊 Found {len(findings)} findings\n")

    if findings:
        print(format_findings(findings, output_format=args.output))
    else:
        print("No findings found")

    # Summary by severity
    if findings and args.output == "table":
        print("\n📈 Summary by Severity:")
        severity_counts = {}
        for finding in findings:
            severity = finding.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                print(f"  {severity}: {count}")


if __name__ == "__main__":
    main()
