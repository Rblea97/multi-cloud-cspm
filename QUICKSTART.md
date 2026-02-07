# Quick Start Guide

Get the Multi-Cloud CSPM system running in minutes.

## Local Development (5 minutes)

### Prerequisites
- Docker and Docker Compose
- Python 3.11+
- Git

### Option 1: Using Docker (Recommended for quick demo)

```bash
# Clone repository
git clone https://github.com/Rblea97/multi-cloud-cspm.git
cd multi-cloud-cspm

# Start services (PostgreSQL, Redis, API)
docker-compose up -d

# Initialize database
docker-compose exec api python -c "from src.cspm.database.repository import Repository; Repository().create_tables()"

# API available at http://localhost:8000
# Swagger UI: http://localhost:8000/docs
```

### Option 2: Local Python (for development)

```bash
# Clone repository
git clone https://github.com/Rblea97/multi-cloud-cspm.git
cd multi-cloud-cspm

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements-dev.txt

# Copy environment template
cp .env.example .env

# Start PostgreSQL (Docker)
docker run --name cspm-postgres -e POSTGRES_PASSWORD=dev_password -p 5432:5432 -d postgres:15

# Start Redis (Docker, optional)
docker run --name cspm-redis -p 6379:6379 -d redis:7

# Initialize database
python -c "from src.cspm.database.repository import Repository; Repository().create_tables()"

# Start API server
python -m uvicorn src.cspm.api.app:app --reload

# API available at http://localhost:8000
```

## Running Tests

```bash
# All tests with coverage
make test

# Specific test file
pytest tests/unit/test_base_rule.py -v

# With coverage report
make coverage
open htmlcov/index.html
```

## Code Quality Checks

```bash
# Run all checks (lint → type → security → test)
make all

# Individual checks
make lint          # ruff check
make format        # black format check
make type-check    # mypy
make security      # bandit SAST
```

## Project Structure

```
multi-cloud-cspm/
├── src/cspm/              # Source code
│   ├── cloud/             # Cloud provider implementations
│   ├── scanner/           # Scanning orchestration
│   ├── rules/             # Security rules
│   ├── database/          # Data layer
│   └── ...
├── tests/                 # Test suite (70% of coverage)
│   ├── unit/
│   └── integration/
├── docs/                  # Documentation
│   ├── architecture.md
│   ├── security-decisions.md
│   └── compliance-coverage.md
├── terraform/             # Infrastructure as Code
├── .github/workflows/     # CI/CD pipelines
├── docker-compose.yml     # Local development
├── Makefile              # Common tasks
└── README.md             # Full documentation
```

## Next Steps

### For Contribution/Development

1. **Create a new feature branch**
   ```bash
   git checkout -b feature/my-rule
   ```

2. **Follow TDD workflow**
   ```bash
   # 1. Write failing test
   vim tests/unit/test_my_rule.py
   pytest tests/unit/test_my_rule.py -v  # Should FAIL

   # 2. Write minimal implementation
   vim src/cspm/rules/aws/my_rule.py
   pytest tests/unit/test_my_rule.py -v  # Should PASS

   # 3. Refactor and verify coverage
   make all
   ```

3. **Push and create pull request**
   ```bash
   git add .
   git commit -m "Add MyRule for detecting security issues"
   git push origin feature/my-rule
   ```

### Phase 1 Roadmap

- [ ] AWS CloudProvider implementation
- [ ] 5 AWS rules (S3, RDS, EC2, Security Groups, CloudTrail)
- [ ] End-to-end scan test
- [ ] JSON report generation
- [ ] 80% test coverage

### For Cloud Credential Setup

#### AWS
```bash
# Configure AWS CLI
aws configure --profile cspm

# In .env, set:
AWS_REGION=us-east-1
AWS_PROFILE=cspm
```

#### Azure
```bash
# Create service principal
az ad sp create-for-rbac --name cspm-dev --role Reader

# In .env, set:
AZURE_SUBSCRIPTION_ID=<subscription-id>
AZURE_TENANT_ID=<tenant-id>
# Store secret in .env (development only)
```

## Troubleshooting

### "ModuleNotFoundError: No module named 'cspm'"
```bash
# Ensure pytest.ini has pythonpath
# OR set PYTHONPATH
export PYTHONPATH=src
pytest tests/
```

### "Database connection refused"
```bash
# Check PostgreSQL is running
docker ps | grep postgres

# Or start it
docker run --name cspm-postgres -e POSTGRES_PASSWORD=dev_password -p 5432:5432 -d postgres:15
```

### "Coverage too low (62% < 80%)"
- This is expected for initial setup
- As you add rules and implementations, coverage will increase
- Target: 80% by end of Phase 1

## Architecture Overview

```
┌────────────────────────────────────┐
│     REST API (FastAPI)             │
│   /scan, /findings, /compliance    │
└──────────────┬─────────────────────┘
               │
┌──────────────▼─────────────────────┐
│    ScanEngine Orchestration        │
│  • Resource discovery              │
│  • Rule evaluation                 │
│  • Finding storage                 │
└──────────────┬─────────────────────┘
               │
    ┌──────────┴──────────┐
    │                     │
┌───▼────────┐   ┌───────▼──┐
│ AWS Cloud  │   │ Azure    │
│ (boto3)    │   │ (SDK)    │
└────────────┘   └──────────┘
    │                     │
    └──────────┬──────────┘
               │
    ┌──────────▼──────────┐
    │  Rules Engine       │
    │ • PublicS3Rule      │
    │ • UnencryptedRDS    │
    │ • ...40+ more       │
    └─────────────────────┘
               │
    ┌──────────▼──────────┐
    │  PostgreSQL DB      │
    │ • Findings          │
    │ • Compliance        │
    │ • Anomalies         │
    └─────────────────────┘
```

## Resources

- **Full Setup**: [docs/setup.md](docs/setup.md)
- **Architecture**: [docs/architecture.md](docs/architecture.md)
- **Security**: [docs/security-decisions.md](docs/security-decisions.md)
- **Compliance**: [docs/compliance-coverage.md](docs/compliance-coverage.md)
- **README**: [README.md](README.md)

## Getting Help

1. Check existing documentation in `docs/`
2. Look at test files for usage examples
3. Review architecture diagrams
4. Check GitHub Issues (coming soon)

## Contributing

1. Fork repository
2. Create feature branch
3. Follow TDD (test first)
4. Ensure 80%+ coverage
5. Submit pull request

Happy scanning! 🔒
