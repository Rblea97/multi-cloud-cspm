"""Compliance assessment engine."""

import json
import uuid
from collections import defaultdict
from datetime import datetime

from cspm.compliance.framework import ComplianceFramework
from cspm.compliance.mapper import RuleToControlMapper
from cspm.database.models import ComplianceResult
from cspm.database.repository import Repository


class ComplianceEngine:
    """Orchestrates compliance assessment against frameworks."""

    def __init__(self, repository: Repository, mapper: RuleToControlMapper) -> None:
        """Initialize compliance engine.

        Args:
            repository: Data access layer for persistence
            mapper: Rule-to-control mapper with control definitions
        """
        self.repository = repository
        self.mapper = mapper

    def assess_compliance(
        self, scan_id: str, frameworks: list[ComplianceFramework]
    ) -> list[ComplianceResult]:
        """Assess compliance for a scan against multiple frameworks.

        Args:
            scan_id: The scan identifier to assess
            frameworks: List of compliance frameworks to assess against

        Returns:
            List of ComplianceResult objects
        """
        # Get findings for this scan
        findings = self.repository.get_findings_by_scan(scan_id)

        # Group findings by rule_id for efficient lookup
        findings_by_rule: dict[str, list] = defaultdict(list)
        for finding in findings:
            findings_by_rule[finding.rule_id].append(finding)

        results: list[ComplianceResult] = []

        # Assess each framework
        for framework in frameworks:
            controls = framework.get_controls()

            for control in controls:
                # Get rules mapped to this control
                rule_ids = self.mapper.get_rules_for_control(control.control_id)

                # Determine control status
                if not rule_ids:
                    # No rules mapped → NOT_APPLICABLE
                    status = "NOT_APPLICABLE"
                    finding_count = 0
                else:
                    # Check if any mapped rule has findings
                    has_findings = any(rule_id in findings_by_rule for rule_id in rule_ids)

                    if has_findings:
                        status = "FAIL"
                        # Count total findings for this control
                        finding_count = sum(
                            len(findings_by_rule[rule_id]) for rule_id in rule_ids
                            if rule_id in findings_by_rule
                        )
                    else:
                        status = "PASS"
                        finding_count = 0

                # Build evidence
                evidence = self._build_evidence(control, rule_ids, findings_by_rule, status)

                # Create compliance result
                result = ComplianceResult(
                    id=str(uuid.uuid4()),
                    scan_id=scan_id,
                    framework=framework.get_controls()[0].framework_id if framework.get_controls() else "",
                    control_id=control.control_id,
                    control_title=control.title,
                    status=status,
                    finding_count=finding_count,
                    evidence=evidence,
                    created_at=datetime.utcnow(),
                )

                # Save to repository
                self.repository.save_compliance_result(result)
                results.append(result)

        return results

    def _build_evidence(
        self, control, rule_ids: list[str], findings_by_rule: dict, status: str
    ) -> str:
        """Build evidence JSON for a compliance result.

        Args:
            control: Control object
            rule_ids: List of rule IDs mapped to this control
            findings_by_rule: Dictionary of rule_id → findings
            status: Control status (PASS, FAIL, NOT_APPLICABLE)

        Returns:
            JSON string with evidence details
        """
        evidence_dict = {
            "control_description": control.description,
            "control_domain": control.domain,
            "control_severity": control.severity,
            "status": status,
            "mapped_rules": rule_ids,
        }

        if status == "FAIL":
            # Add finding details for FAIL status
            finding_ids = []
            affected_resources = []
            for rule_id in rule_ids:
                if rule_id in findings_by_rule:
                    for finding in findings_by_rule[rule_id]:
                        finding_ids.append(finding.id)
                        affected_resources.append(finding.resource_id)

            evidence_dict["finding_ids"] = finding_ids
            evidence_dict["affected_resources"] = list(set(affected_resources))

        elif status == "NOT_APPLICABLE":
            # Note that control is not yet implemented
            evidence_dict["reason"] = "No rules mapped to this control"

        elif status == "PASS":
            # Note that all mapped rules passed
            evidence_dict["reason"] = "All mapped rules passed"

        return json.dumps(evidence_dict)
