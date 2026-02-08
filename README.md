# Multi-Cloud CSPM with AI-Enhanced Threat Detection

![Tests](https://img.shields.io/badge/tests-300%20passing-brightgreen) ![Coverage](https://img.shields.io/badge/coverage-82.95%25-brightgreen) ![Python](https://img.shields.io/badge/python-3.11+-blue) ![License](https://img.shields.io/badge/license-MIT-blue)

## What This Is

A production-grade Cloud Security Posture Management (CSPM) system that automates security audits, compliance tracking, and threat remediation across AWS and Azure clouds. Built with **strict TDD methodology using Claude Code** - all 300 tests written before implementation code.

## Key Features

- ✅ **Multi-cloud support** (AWS + Azure) - Real resource discovery and scanning
- ✅ **10 security rules** - Detects common misconfigurations (S3, EC2, RDS, Storage, SQL, NSGs)
- ✅ **CIS benchmark compliance** - Automated control assessment and scoring
- ✅ **Automated remediation** - Self-healing workflows with approval system
- ✅ **ML anomaly detection** - Isolation Forest for behavioral threats
- ✅ **Real infrastructure testing** - With safety controls and auto-stop functionality
- ✅ **Multi-channel alerts** - Console, file, and email notifications
- ✅ **300 tests, 82.95% coverage** - Comprehensive test suite with TDD discipline

## Tech Stack

**Backend:** Python 3.11+, FastAPI, SQLAlchemy, PostgreSQL
**Cloud SDKs:** boto3 (AWS), azure-sdk (Azure)
**ML:** scikit-learn (Isolation Forest)
**Testing:** pytest, moto, 82.95% coverage (300 tests)
**Quality:** ruff, black, mypy, bandit

## Quick Start

### 1. Installation
```bash
git clone https://github.com/Rblea97/multi-cloud-cspm.git
cd multi-cloud-cspm
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env  # Edit with your cloud credentials (optional)
```

### 2. Run Tests (Proves It Works)
```bash
make test         # 300 tests, 82.95% coverage
make lint         # Ruff + Black + type checking
make all          # Full quality suite
```

### 3. Try the Demo (30 seconds, No Credentials Needed)
```bash
python scripts/demo.py
```
Shows security findings on mocked resources - validates that scanning works without cloud access.

## Project Structure

```
src/cspm/
├── cloud/         # AWS + Azure provider implementations
├── scanner/       # Scan orchestration engine
├── rules/         # 10 security rules (5 AWS + 5 Azure)
├── compliance/    # CIS framework compliance tracking
├── remediation/   # Auto-remediation with approval workflows
├── alerts/        # Multi-channel alerting system
├── ml/            # ML anomaly detection (Isolation Forest)
└── database/      # PostgreSQL data layer (SQLAlchemy)
```

## Documentation

- **[AI Workflow](AI_WORKFLOW.md)** - How this was built with Claude Code + TDD (unique differentiator)
- **[Architecture](docs/architecture.md)** - System design and components
- **[Security Decisions](docs/security-decisions.md)** - IAM, encryption, security rationale
- **[Setup Guide](docs/setup.md)** - Detailed deployment instructions
- **[Contributing](CONTRIBUTING.md)** - Development guidelines and TDD workflow

## Development with AI

This project was built using **strict TDD with Claude Code** - an AI-assisted development approach. See [AI_WORKFLOW.md](AI_WORKFLOW.md) for the complete development process and how it differs from traditional development.

**TDD Cycle (for every feature):**
1. Write failing test (RED) - defines behavior before implementation
2. Minimal implementation (GREEN) - just enough to pass the test
3. Refactor and verify coverage (REFACTOR)
4. Repeat

All 300 tests were written BEFORE implementation code.

## Implementation Phases

- ✅ **Phase 1:** AWS Core (28 tests) - S3, EC2, RDS scanning
- ✅ **Phase 2:** Azure Integration (82 tests) - Multi-cloud unification
- ✅ **Phase 3:** Compliance Engine (138 tests) - CIS benchmarks
- ✅ **Phase 4:** Alert System (198 tests) - Multi-channel notifications
- ✅ **Phase 5:** Remediation Engine (267 tests) - Auto-remediation workflows
- 🔄 **Phase 6:** Real Infrastructure Testing (300 tests) - Free-tier testing

## Real Infrastructure Testing

For testing against real AWS/Azure resources:

```bash
cp .env.test.example .env.test
# Edit .env.test with AWS_PROFILE or credentials

python scripts/setup_aws_free_tier.py    # Create test resources ($0)
pytest -m 'aws and free' -v              # Run real infrastructure tests
python scripts/auto_stop_compute.py      # Stop instances
python scripts/cleanup_aws_test_resources.py  # Cleanup
```

Uses only AWS free-tier resources (S3, Security Groups, RDS micro, EC2 micro).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines. This project emphasizes:
- Strict TDD (test before implementation)
- Minimum 80% coverage requirement
- Clean code (ruff, black, mypy, bandit)
- Professional documentation

## License

MIT License - See [LICENSE](LICENSE)

## Contact

Richard Blea - [GitHub @Rblea97](https://github.com/Rblea97)

---

**Status:** Production-ready with 300 tests, 82.95% coverage, and real cloud support.
