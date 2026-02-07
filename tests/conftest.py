"""Shared test fixtures."""

from unittest.mock import MagicMock

import pytest

from cspm.cloud.base import CloudProvider, Resource
from cspm.database.repository import Repository
from cspm.rules.registry import RuleRegistry
from cspm.scanner.engine import ScanEngine

# Always load real cloud fixtures (they skip gracefully if no credentials)
pytest_plugins = ["tests.conftest_real"]


@pytest.fixture
def db_repository():
    """Provide an in-memory test database."""
    repo = Repository(db_url="sqlite:///:memory:")
    repo.create_tables()
    return repo


@pytest.fixture
def rule_registry():
    """Provide a rule registry."""
    return RuleRegistry()


@pytest.fixture
def scan_engine(rule_registry, db_repository):
    """Provide a scan engine."""
    return ScanEngine(rule_registry, db_repository)


@pytest.fixture
def mock_cloud_provider():
    """Provide a mock cloud provider."""
    provider = MagicMock(spec=CloudProvider)
    provider.authenticate.return_value = True
    provider.is_authenticated.return_value = True
    return provider


@pytest.fixture
def sample_s3_bucket():
    """Provide a sample S3 bucket resource."""
    return Resource(
        id="arn:aws:s3:::test-bucket",
        name="test-bucket",
        type="AWS::S3::Bucket",
        region="us-east-1",
        cloud_provider="AWS",
        attributes={
            "public_access_block_enabled": False,
            "versioning_enabled": False,
            "encryption_enabled": False,
        },
        tags={"Environment": "test"},
    )


@pytest.fixture
def sample_private_s3_bucket():
    """Provide a sample private S3 bucket resource."""
    return Resource(
        id="arn:aws:s3:::private-bucket",
        name="private-bucket",
        type="AWS::S3::Bucket",
        region="us-east-1",
        cloud_provider="AWS",
        attributes={
            "public_access_block_enabled": True,
            "versioning_enabled": True,
            "encryption_enabled": True,
        },
        tags={"Environment": "prod"},
    )


@pytest.fixture
def sample_ec2_instance():
    """Provide a sample EC2 instance resource."""
    return Resource(
        id="i-0123456789abcdef0",
        name="test-instance",
        type="AWS::EC2::Instance",
        region="us-east-1",
        cloud_provider="AWS",
        attributes={
            "public_ip": "203.0.113.1",
            "security_groups": ["sg-12345"],
        },
        tags={"Name": "test-instance"},
    )


@pytest.fixture
def sample_rds_instance():
    """Provide a sample RDS instance resource."""
    return Resource(
        id="arn:aws:rds:us-east-1:123456789012:db:testdb",
        name="testdb",
        type="AWS::RDS::DBInstance",
        region="us-east-1",
        cloud_provider="AWS",
        attributes={
            "storage_encrypted": False,
            "engine": "mysql",
            "multi_az": False,
        },
        tags={"Environment": "dev"},
    )
