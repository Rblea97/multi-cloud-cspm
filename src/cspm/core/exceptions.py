"""Custom exceptions."""


class CSPMException(Exception):
    """Base exception for CSPM."""

    pass


class CloudAPIError(CSPMException):
    """Exception for cloud provider API errors."""

    pass


class RuleExecutionError(CSPMException):
    """Exception for rule execution errors."""

    pass


class RemediationError(CSPMException):
    """Exception for remediation errors."""

    pass


class ComplianceError(CSPMException):
    """Exception for compliance errors."""

    pass


class DatabaseError(CSPMException):
    """Exception for database errors."""

    pass
