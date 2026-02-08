# Multi-Cloud CSPM: Cloud Security Posture Management

![Tests](https://img.shields.io/badge/tests-300%20passing-brightgreen) ![Coverage](https://img.shields.io/badge/coverage-83.45%25-brightgreen) ![Python](https://img.shields.io/badge/python-3.11+-blue) ![License](https://img.shields.io/badge/license-MIT-blue)

Automated security auditing, compliance tracking, and remediation for AWS and Azure. Built with test-driven development - 300 tests, 83% coverage.

## Demo (30 seconds, no credentials needed)

```bash
$ python scripts/demo.py

AWS Security Scan:
  CRITICAL: public-data-bucket (S3 bucket has public ACL)
  CRITICAL: public-data-bucket (Public access block not enabled)
  HIGH: prod-database (RDS unencrypted)
  HIGH: sg-12345678 (Security group open to 0.0.0.0/0)
  MEDIUM: prod-database (RDS publicly accessible)
  Summary: 5 findings detected

Azure Security Scan:
  CRITICAL: publicstorageacct (Public blob access enabled)
  HIGH: production-db (SQL database not encrypted)
  Summary: 2 findings detected

Compliance Check (CIS Benchmarks):
  FAIL: S3 Bucket Encryption
  FAIL: RDS Encryption
  FAIL: Storage Account Public Access
  PASS: CloudTrail Enabled
  PASS: Virtual Machine Encryption
  Compliance Score: 40% (2/5 controls passing)
```

## Features

| Feature | Details |
|---------|---------|
| Multi-Cloud Scanning | AWS + Azure resource discovery |
| Security Rules | 10 rules (5 AWS + 5 Azure) |
| Compliance Framework | CIS AWS & Azure benchmarks with scoring |
| Automated Remediation | Approval workflow for critical changes |
| Anomaly Detection | ML-powered (Isolation Forest) |
| Multi-Channel Alerts | Console, file, and email notifications |
| Testing | 300 tests, 83.45% coverage, TDD methodology |

## Tech Stack

```
Language:      Python 3.11+
Cloud SDKs:    boto3 (AWS), azure-sdk (Azure)
Testing:       pytest, pytest-cov, moto (AWS mocking)
ML:            scikit-learn (Isolation Forest)
Database:      SQLAlchemy
Quality:       ruff, black, mypy, bandit
```

## Quick Start

```bash
git clone https://github.com/Rblea97/multi-cloud-cspm.git
cd multi-cloud-cspm
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt

# Run the demo
python scripts/demo.py

# Run tests
make test   # 300 tests, 83.45% coverage
make lint   # Code quality checks
```

## Architecture

```
src/cspm/
├── cloud/          # AWS + Azure provider implementations
│   ├── aws/        # S3, EC2, RDS, CloudTrail scanning
│   └── azure/      # Storage, SQL, VMs, NSGs scanning
├── scanner/        # Orchestration engine
├── rules/          # 10 security rules (5 AWS + 5 Azure)
├── compliance/     # CIS framework compliance tracking & scoring
├── remediation/    # Auto-remediation with approval workflows
├── alerts/         # Multi-channel notifications
├── ml/             # Anomaly detection (Isolation Forest)
└── database/       # Data persistence layer
```

## Security Rules

**AWS:** Public S3 buckets, unencrypted RDS, public EC2 instances, open security groups, disabled CloudTrail

**Azure:** Public storage accounts, unencrypted SQL, public VM IPs, open NSG rules, disabled activity logs

## Development

Built with strict TDD (RED -> GREEN -> REFACTOR). Every feature started with a failing test.

### Phase Breakdown
- Phase 1: AWS Core (28 tests)
- Phase 2: Azure Integration (82 tests)
- Phase 3: Compliance Engine (138 tests)
- Phase 4: Alert System (198 tests)
- Phase 5: Remediation Engine (267 tests)
- Phase 6: Infrastructure Testing (300 tests)

## Future Improvements

- Real AWS/Azure infrastructure testing (scripts exist, not yet validated in CI)
- FastAPI REST API for scan management
- Dashboard UI for compliance visualization
- GCP provider support
- Scheduled scanning with cron integration

## Contact

**Richard Blea**
- GitHub: [@Rblea97](https://github.com/Rblea97)
- LinkedIn: [linkedin.com/in/richard-blea-748914159](http://www.linkedin.com/in/richard-blea-748914159)
- Email: [rblea97@gmail.com](mailto:rblea97@gmail.com)

Seeking entry-level Cloud Security / DevSecOps roles (AWS/Azure focus).

---

MIT Licensed | 300 tests passing | 83.45% coverage

Built with test-driven development using Claude Code AI assistance.
