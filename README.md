# Multi-Cloud CSPM with AI-Enhanced Threat Detection

A production-grade Cloud Security Posture Management (CSPM) system that automates security audits, compliance tracking, and threat detection across AWS and Azure clouds using AI-powered anomaly detection.

## Why This Project Matters

In 2026, entry-level cybersecurity roles demand practical cloud security experience. This project addresses top hiring priorities:

- **Multi-cloud expertise** (AWS + Azure) - Most enterprises use 2+ clouds
- **CSPM/CNAPP trends** - Emerging security standards for cloud-native applications
- **AI-driven security** - Machine learning for behavioral anomaly detection
- **DevSecOps automation** - Infrastructure as Code, CI/CD security scanning
- **Compliance frameworks** - CIS benchmark automation and tracking

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  CSPM Control Plane                     │
│  ┌──────────┐  ┌──────────┐  ┌────────────┐           │
│  │ Scanner  │  │Compliance│  │ AI Anomaly │           │
│  │ Engine   │  │ Engine   │  │  Detector  │           │
│  └────┬─────┘  └────┬─────┘  └──────┬─────┘           │
│       └─────────────┴────────────────┘                 │
│                     │                                   │
│            ┌────────▼─────────┐                        │
│            │ Remediation      │                        │
│            │ Engine           │                        │
│            └────────┬─────────┘                        │
│                     │                                   │
│         ┌───────────┴────────────┐                     │
│         │                        │                     │
│    ┌────▼─────┐          ┌──────▼──────┐             │
│    │PostgreSQL│          │   Reports   │             │
│    │ Database │          │   Storage   │             │
│    └──────────┘          └─────────────┘             │
└─────────────────────────────────────────────────────────┘
           │                         │
  ┌────────┴──────────┐   ┌─────────┴──────────┐
  │                   │   │                    │
┌─▼────────────┐  ┌───▼────────────┐
│  AWS Cloud   │  │  Azure Cloud   │
│  • Config    │  │  • Policy      │
│  • Security  │  │  • Defender    │
│    Hub       │  │  • Sentinel    │
│  • GuardDuty │  │  • Activity    │
│  • CloudTrail│  │    Logs        │
│  • Lambda    │  │  • Functions   │
└──────────────┘  └────────────────┘
```

## Key Features

### Phase 1: Core Infrastructure ✅
- Multi-cloud resource discovery (AWS + Azure)
- 10 security rules for common misconfigurations
- PostgreSQL-backed finding storage
- JSON compliance reporting

### Phase 2-3: Multi-Cloud & Compliance 🔄
- Azure integration with unified API
- CIS benchmark compliance scoring
- Historical compliance tracking
- Per-framework control mapping

### Phase 4-5: Automation & AI 📋
- Automatic remediation with approval workflows
- ML-based behavioral anomaly detection
- CloudTrail/Activity log analysis
- Real-time alert generation

### Phase 6: Production Ready 🚀
- FastAPI REST endpoints
- GitHub Actions CI/CD pipeline
- IaC security scanning (Checkov/tfsec)
- 80%+ test coverage with TDD

## Technology Stack

**Backend:**
- Python 3.11+
- FastAPI, Uvicorn
- SQLAlchemy (ORM), PostgreSQL
- boto3 (AWS SDK), azure-sdk (Azure SDK)
- scikit-learn (ML anomaly detection)

**Infrastructure:**
- Terraform (multi-cloud IaC)
- AWS Lambda/Azure Functions (remediation)
- Redis + Celery (async tasks)

**Testing & Quality:**
- pytest (80%+ coverage requirement)
- pytest-cov, pytest-mock, pytest-asyncio
- moto (AWS mocking), bandit (SAST), mypy (type checking)

**CI/CD:**
- GitHub Actions (test, lint, security scan, deploy)

## Quick Start

### Prerequisites
- Python 3.11+
- AWS CLI (configured with credentials)
- Azure CLI (configured with credentials)
- PostgreSQL 13+
- Redis 6+ (optional, for Celery)

### Installation

```bash
# Clone repository
git clone https://github.com/Rblea97/multi-cloud-cspm.git
cd multi-cloud-cspm

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements-dev.txt

# Create .env file
cp .env.example .env
# Edit .env with your AWS/Azure credentials and database URL

# Set up database
alembic upgrade head

# Run tests
pytest tests/ -v
```

### Run Your First Scan

```bash
# Trigger a security scan
python -m cspm.scanner.cli --cloud-provider aws --resource-types s3,ec2,rds

# View findings
python -m cspm.reporter.cli --scan-id <scan-id> --output json
```

## Project Structure

```
multi-cloud-cspm/
├── src/cspm/
│   ├── core/              # Config, logging, exceptions
│   ├── cloud/
│   │   ├── base.py        # Abstract cloud provider interface
│   │   ├── aws/           # AWS implementation
│   │   └── azure/         # Azure implementation
│   ├── scanner/
│   │   └── engine.py      # Main scan orchestration
│   ├── rules/
│   │   ├── base.py        # Abstract rule class
│   │   ├── registry.py    # Rule management
│   │   ├── aws/           # AWS rules (S3, EC2, RDS, SG, IAM)
│   │   └── azure/         # Azure rules (Storage, VM, SQL, NSG)
│   ├── compliance/
│   │   ├── framework.py   # Base framework
│   │   ├── cis_aws.py     # CIS AWS benchmarks
│   │   └── cis_azure.py   # CIS Azure benchmarks
│   ├── remediation/
│   │   ├── engine.py      # Remediation orchestration
│   │   └── actions/       # AWS/Azure actions
│   ├── ml/
│   │   ├── detector.py    # Anomaly detection
│   │   └── model.py       # Isolation Forest
│   ├── database/
│   │   ├── models.py      # SQLAlchemy models
│   │   └── repository.py  # Data access layer
│   └── api/
│       └── app.py         # FastAPI application
├── tests/
│   ├── unit/              # Unit tests (70% coverage)
│   ├── integration/       # Integration tests (20% coverage)
│   └── conftest.py        # Shared fixtures
├── terraform/
│   ├── aws/               # AWS infrastructure
│   ├── azure/             # Azure infrastructure
│   └── shared/            # PostgreSQL, Redis
├── docs/
│   ├── architecture.md    # Component diagrams
│   ├── security-decisions.md
│   ├── compliance-coverage.md
│   └── setup.md           # Deployment guide
├── .github/workflows/
│   ├── test.yml           # Test pipeline
│   ├── security.yml       # Bandit + Checkov
│   └── deploy.yml         # Deployment
└── pyproject.toml         # Project configuration
```

## Implementation Phases

### ✅ Phase 1: Core Infrastructure (Week 1-2)
- AWS resource discovery for S3, EC2, RDS, Security Groups
- 5 core security rules
- PostgreSQL database
- JSON reporting

### 🔄 Phase 2: Azure Integration (Week 3)
- Azure resource discovery
- Unified multi-cloud data model
- Combined reporting

### 📋 Phase 3: Compliance Engine (Week 4)
- CIS AWS Foundations (20 controls)
- CIS Azure Foundations (20 controls)
- Compliance scoring

### 🔧 Phase 4: Automated Remediation (Week 5)
- Lambda/Azure Functions
- 5 auto-remediation workflows
- Dry-run and approval modes

### 🤖 Phase 5: AI Anomaly Detection (Weeks 6-7)
- CloudTrail/Activity log collection
- Isolation Forest anomaly detection
- Real-time alert system

### 🚀 Phase 6: Production Hardening (Week 8)
- FastAPI REST API
- GitHub Actions CI/CD
- Security documentation
- Demo video

## Security Rules Implemented

### AWS Rules
1. **PublicS3Rule** - Detects public S3 buckets
2. **UnencryptedRDSRule** - Detects unencrypted RDS instances
3. **EC2PublicIPRule** - Detects EC2 instances with public IPs
4. **OpenSecurityGroupRule** - Detects overly permissive security groups
5. **CloudTrailDisabledRule** - Detects disabled CloudTrail logging
*(More rules in Phase 2+)*

### Azure Rules
1. **PublicBlobStorageRule** - Detects public blob storage
2. **UnencryptedSQLRule** - Detects unencrypted SQL databases
3. **VMPublicIPRule** - Detects VMs with public IPs
4. **OpenNSGRule** - Detects overly permissive NSGs
5. **ActivityLoggingDisabledRule** - Detects disabled Activity logging
*(More rules in Phase 2+)*

## Testing & Quality

### Test Coverage
- **Minimum 80% line coverage** (enforced by pytest)
- Unit tests: 70% of coverage
- Integration tests: 20% of coverage
- Security tests: 10% of coverage

### Quality Checks
- **Ruff**: Zero errors/warnings (linting)
- **Black**: Automatic formatting
- **MyPy**: Type checking on all public APIs
- **Bandit**: SAST for security issues
- **Checkov/tfsec**: IaC security scanning

### Running Tests
```bash
# Run all tests with coverage
pytest tests/ -v

# Run specific test file
pytest tests/unit/test_base_rule.py -v

# Run with coverage report
pytest tests/ --cov=src/cspm --cov-report=html
```

## Deployment

### Local Development
```bash
# Start PostgreSQL
docker run -e POSTGRES_PASSWORD=password -p 5432:5432 postgres:15

# Run migrations
alembic upgrade head

# Start API server
python -m uvicorn cspm.api.app:app --reload
```

### Production with Terraform
```bash
cd terraform/aws
terraform init -backend-config=backend-prod.hcl
terraform apply -var-file=prod.tfvars

cd ../azure
terraform init -backend-config=backend-prod.hcl
terraform apply -var-file=prod.tfvars
```

## Documentation

- **[Architecture](docs/architecture.md)** - Component diagrams and data flow
- **[Security Decisions](docs/security-decisions.md)** - IAM, secrets, encryption rationale
- **[Compliance Coverage](docs/compliance-coverage.md)** - CIS control mapping
- **[Setup Guide](docs/setup.md)** - Step-by-step deployment

## Performance Metrics

| Metric | Target | Status |
|--------|--------|--------|
| Scan latency | <5 min | - |
| Finding accuracy | >95% | - |
| API response time | <100ms | - |
| Remediation MTTR | <1 min | - |
| Code coverage | ≥80% | - |

## Contributing

This project follows strict TDD (Test-Driven Development):

1. Write a failing test first (RED)
2. Implement minimum code to pass (GREEN)
3. Refactor and test again (REFACTOR)
4. All tests must pass before committing

## License

MIT License - See LICENSE file for details

## Author

Richard Blea ([@Rblea97](https://github.com/Rblea97))

## Resources

- [AWS Security Best Practices](https://docs.aws.amazon.com/security/)
- [Azure Security Best Practices](https://learn.microsoft.com/en-us/azure/security/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [OWASP Cloud Security](https://owasp.org/www-project-cloud-security/)
