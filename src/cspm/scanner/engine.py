"""Main scan orchestration engine."""

import logging
import uuid
from typing import List, Optional

from cspm.cloud.base import CloudProvider
from cspm.database.models import Finding, Scan as ScanModel
from cspm.database.repository import Repository
from cspm.rules.base import BaseRule
from cspm.rules.registry import RuleRegistry

logger = logging.getLogger(__name__)


class ScanEngine:
    """Orchestrates security scanning."""

    def __init__(
        self,
        registry: RuleRegistry,
        repository: Repository,
    ):
        """Initialize scan engine.

        Args:
            registry: Rule registry with all available rules
            repository: Database repository for storing findings
        """
        self.registry = registry
        self.repository = repository
        self._providers: List[CloudProvider] = []

    def register_provider(self, provider: CloudProvider) -> None:
        """Register a cloud provider.

        Args:
            provider: The cloud provider instance
        """
        if provider.authenticate():
            self._providers.append(provider)
            logger.info(f"Registered cloud provider")
        else:
            logger.error(f"Failed to authenticate cloud provider")

    def scan(
        self,
        scan_type: str = "FULL",
        cloud_providers: Optional[List[str]] = None,
        resource_types: Optional[List[str]] = None,
    ) -> str:
        """Execute a security scan.

        Args:
            scan_type: Type of scan (FULL or INCREMENTAL)
            cloud_providers: Optional list of cloud providers to scan
            resource_types: Optional list of resource types to scan

        Returns:
            Scan ID

        Raises:
            ScanEngineError: If scan fails
        """
        scan_id = str(uuid.uuid4())
        logger.info(f"Starting scan {scan_id} (type={scan_type})")

        # Create scan record
        scan_record = ScanModel(
            id=scan_id,
            cloud_provider="MULTI" if len(self._providers) > 1 else self._providers[0].__class__.__name__,
            scan_type=scan_type,
            status="RUNNING",
        )
        self.repository.save_scan(scan_record)

        findings_count = 0
        resources_scanned = 0

        try:
            # Scan each provider
            for provider in self._providers:
                resources = provider.get_resources(resource_type=None)

                # Evaluate each resource against rules
                for resource in resources:
                    resources_scanned += 1

                    # Get applicable rules
                    applicable_rules = self.registry.get_rules_by_resource_type(resource.type)

                    # Evaluate each rule
                    for rule in applicable_rules:
                        try:
                            result = rule.evaluate(resource)

                            # Store finding if one was detected
                            if result.has_finding:
                                finding = Finding(
                                    id=str(uuid.uuid4()),
                                    scan_id=scan_id,
                                    rule_id=rule.rule_id,
                                    rule_name=rule.name,
                                    resource_id=resource.id,
                                    resource_type=resource.type,
                                    resource_name=resource.name,
                                    cloud_provider=resource.cloud_provider,
                                    severity=result.severity.value,
                                    title=result.title,
                                    description=result.description,
                                    remediation_advice=result.remediation_advice,
                                    evidence=str(result.evidence),
                                    status="OPEN",
                                )
                                self.repository.save_finding(finding)
                                findings_count += 1
                                logger.info(f"Finding: {rule.name} on {resource.name}")

                        except Exception as e:
                            logger.error(f"Error evaluating rule {rule.rule_id}: {e}")

            # Update scan record
            scan_record.status = "COMPLETED"
            scan_record.resources_scanned = resources_scanned
            scan_record.findings_count = findings_count
            self.repository.save_scan(scan_record)

            logger.info(
                f"Scan {scan_id} completed: {resources_scanned} resources, {findings_count} findings"
            )
            return scan_id

        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            scan_record.status = "FAILED"
            scan_record.error_message = str(e)
            self.repository.save_scan(scan_record)
            raise
