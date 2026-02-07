.PHONY: help install dev test coverage lint format security docker-up docker-down

help:
	@echo "Multi-Cloud CSPM - Available Commands"
	@echo "====================================="
	@echo "make install        - Install dev dependencies"
	@echo "make dev            - Start development environment"
	@echo "make test           - Run tests with coverage"
	@echo "make coverage       - Generate coverage report"
	@echo "make lint           - Run linting (ruff)"
	@echo "make format         - Format code (black)"
	@echo "make format-check   - Check formatting"
	@echo "make type-check     - Run mypy type checking"
	@echo "make security       - Run security scans (bandit)"
	@echo "make docker-up      - Start Docker Compose services"
	@echo "make docker-down    - Stop Docker Compose services"
	@echo "make docker-build   - Build Docker image"
	@echo "make clean          - Clean build artifacts"

install:
	python3 -m venv .venv
	. .venv/bin/activate && pip install -r requirements-dev.txt

dev:
	docker-compose up -d
	@echo "Services started. API available at http://localhost:8000"
	@echo "Run: make test"

test:
	pytest tests/ -v

coverage:
	pytest tests/ -v --cov=src/cspm --cov-report=html --cov-report=term-missing
	@echo "Coverage report: htmlcov/index.html"

lint:
	ruff check src/ tests/

format:
	black src/ tests/

format-check:
	black --check src/ tests/

type-check:
	mypy src/cspm/ --ignore-missing-imports

security:
	bandit -r src/cspm/ -ll --skip B101,B601

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

docker-build:
	docker build -t cspm:latest .

docker-logs:
	docker-compose logs -f api

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage

init-db:
	@echo "Creating database tables..."
	python -c "from src.cspm.database.repository import Repository; r = Repository(); r.create_tables(); print('Database initialized')"

all: format lint type-check security test
