# Architecture

## System Overview

The Multi-Cloud CSPM system follows a modular, layered architecture designed for extensibility and cloud-agnostic security scanning.

```
┌─────────────────────────────────────────────────────────────┐
│                      REST API Layer                         │
│  ┌────────────┐ ┌────────────┐ ┌──────────┐               │
│  │ /scan      │ │ /findings  │ │/compliance│              │
│  └─────┬──────┘ └────────────┘ └──────────┘               │
│        │                                                    │
│  ┌─────▼─────────────────────────────────────┐            │
│  │      Orchestration Layer                  │            │
│  ├─────────────────────────────────────────┤            │
│  │ ┌─────────────┐  ┌─────────────────┐   │            │
│  │ │ ScanEngine  │  │RemediationEngine│   │            │
│  │ └─────────────┘  └─────────────────┘   │            │
│  │ ┌─────────────┐  ┌──────────────┐      │            │
│  │ │Compliance   │  │ ML Detector  │      │            │
│  │ │Framework    │  │              │      │            │
│  │ └─────────────┘  └──────────────┘      │            │
│  └─────┬─────────────────────────────────┘            │
│        │                                                │
│  ┌─────▼────────────────────────────────┐             │
│  │    Provider Abstraction Layer        │             │
│  │ (CloudProvider base class)           │             │
│  │ ┌────────────┐      ┌──────────┐     │             │
│  │ │ AWS Client │      │AzureClient│     │             │
│  │ └────────────┘      └──────────┘     │             │
│  └─────┬───────────────────────────┬───┘             │
│        │                           │                  │
│  ┌─────▼──┐               ┌────────▼───┐            │
│  │ Rules  │               │ CloudAPIs  │            │
│  │        │               │            │            │
│  │ • AWS  │     ◄────────►│ • EC2      │            │
│  │ • Azure│               │ • S3       │            │
│  │        │               │ • RDS      │            │
│  └────────┘               │ • VMs      │            │
│                           │ • Storage  │            │
│                           └────────────┘            │
│                                                      │
│  ┌─────────────────────────────────────┐           │
│  │      Persistence Layer              │           │
│  │                                     │           │
│  │ ┌─────────┐  ┌──────────────┐      │           │
│  │ │PostgreSQL│ │ Repository   │      │           │
│  │ │Database │ │ Layer        │      │           │
│  │ └─────────┘ └──────────────┘      │           │
│  └─────────────────────────────────┘           │
└─────────────────────────────────────────────────────────────┘
```

## Component Layers

### 1. REST API Layer (FastAPI)
- HTTP endpoints for triggering scans, querying findings, viewing compliance
- Request/response handling
- Authentication and authorization
- Location: `src/cspm/api/`

### 2. Orchestration Layer
Coordinates scanning, compliance, remediation, and ML detection:

**ScanEngine** (`src/cspm/scanner/engine.py`)
- Manages scan lifecycle
- Discovers resources from cloud providers
- Applies security rules to resources
- Stores findings in database

**ComplianceFramework** (`src/cspm/compliance/`)
- Maps findings to compliance controls (CIS benchmarks)
- Calculates compliance scores
- Tracks historical compliance data

**RemediationEngine** (`src/cspm/remediation/`)
- Orchestrates automatic remediation actions
- Implements approval workflows
- Supports dry-run mode for testing
- Logs all remediation activities

**AnomalyDetector** (`src/cspm/ml/`)
- Collects CloudTrail/Activity logs
- Extracts behavioral features
- Runs Isolation Forest ML model
- Generates alerts for anomalies

### 3. Provider Abstraction Layer
Abstract interface for cloud providers to ensure consistency:

**CloudProvider** (`src/cspm/cloud/base.py`)
- Abstract base class defining the provider interface
- Methods: `authenticate()`, `get_resources()`, `get_resource()`, `get_resource_details()`

**AWS Provider** (`src/cspm/cloud/aws/`)
- boto3-based AWS API client
- Resource discovery for EC2, S3, RDS, IAM, Security Groups
- Support for credential assumption via STS

**Azure Provider** (`src/cspm/cloud/azure/`)
- Azure SDK-based client
- Resource discovery for VMs, Storage, SQL, NSGs
- Service principal authentication

### 4. Rules Engine
Extensible rule evaluation system:

**BaseRule** (`src/cspm/rules/base.py`)
- Abstract base class for all security rules
- Methods: `evaluate(resource)`, `is_applicable(resource)`
- Returns `RuleResult` with finding details

**RuleRegistry** (`src/cspm/rules/registry.py`)
- Central registry for all rules
- Methods: `register()`, `get_rule()`, `get_rules_by_provider()`, `get_rules_by_resource_type()`

**AWS Rules** (`src/cspm/rules/aws/`)
- Rules specific to AWS resources
- Examples: PublicS3Rule, UnencryptedRDSRule, EC2PublicIPRule

**Azure Rules** (`src/cspm/rules/azure/`)
- Rules specific to Azure resources
- Examples: PublicBlobStorageRule, UnencryptedSQLRule, VMPublicIPRule

### 5. Persistence Layer
Data storage and access:

**SQLAlchemy Models** (`src/cspm/database/models.py`)
- `Finding` - Security findings with severity and status
- `ComplianceResult` - Compliance control assessments
- `AnomalyAlert` - ML-detected behavioral anomalies
- `RemediationAction` - History of remediation actions
- `Scan` - Execution records

**Repository** (`src/cspm/database/repository.py`)
- Data access layer (DAO pattern)
- Methods for CRUD operations on all models
- Abstracts database implementation details

## Data Flow

### Scanning Flow
```
1. API Request → /scan
2. ScanEngine.scan()
3. For each CloudProvider:
   a. Get all resources via CloudProvider.get_resources()
   b. For each resource:
      - Get applicable rules from RuleRegistry
      - For each rule: rule.evaluate(resource)
      - If finding: store in database via Repository
4. Return scan_id and summary
```

### Compliance Flow
```
1. API Request → /compliance/cis-aws
2. ComplianceFramework.assess()
3. Get findings for this scan
4. For each CIS control:
   - Map findings to control
   - Calculate pass/fail status
   - Store ComplianceResult
5. Return compliance report
```

### Remediation Flow
```
1. API Request → /remediation/finding-123
2. RemediationEngine.remediate()
3. Get finding and remediation rules
4. If mode == DRY_RUN:
   - Simulate remediation
5. Else if requires_approval:
   - Create approval task
   - Wait for approval
6. Execute remediation action (AWS Lambda or Azure Function)
7. Log result in RemediationAction
8. Update Finding.status
```

### ML Anomaly Flow
```
1. Scheduled job every 1 hour
2. LogCollector.collect_logs()
   - Fetch CloudTrail events (AWS)
   - Fetch Activity logs (Azure)
3. FeatureEngineering.extract_features()
   - User identity features
   - Temporal features
   - Action type encoding
4. AnomalyDetector.detect()
   - Run Isolation Forest model
   - Get anomaly scores
5. For each anomaly > threshold:
   - Create AnomalyAlert
   - Set severity based on score
6. Notify users / send alerts
```

## Technology Stack Mapping

| Component | Technology |
|-----------|-----------|
| REST API | FastAPI + Uvicorn |
| Cloud SDKs | boto3 (AWS), azure-sdk (Azure) |
| Database | PostgreSQL + SQLAlchemy |
| Rules Engine | Custom (Python) |
| Async Tasks | Celery + Redis |
| ML Model | scikit-learn (Isolation Forest) |
| Infrastructure | Terraform |
| Testing | pytest + moto (AWS mocking) |

## Extensibility Points

### Adding a New Cloud Provider
1. Create new class inheriting from `CloudProvider`
2. Implement abstract methods: `authenticate()`, `get_resources()`, `get_resource_details()`
3. Register with `ScanEngine` via `register_provider()`

### Adding a New Rule
1. Create class inheriting from `BaseRule`
2. Implement `evaluate(resource)` method
3. Register with `RuleRegistry` via `register()`
4. Rule automatically applies to all scans based on resource type

### Adding a New Remediation Action
1. Create function in `src/cspm/remediation/actions/`
2. Register with `RemediationEngine`
3. Test with dry-run mode before enabling auto-fix

## Error Handling & Resilience

- **CloudAPIError**: Caught during resource discovery, scan continues with other resources
- **RuleExecutionError**: Specific rule failure doesn't stop entire scan
- **RemediationError**: Failed remediation is logged with detailed error message
- **DatabaseError**: Retry logic with exponential backoff
- **ML Model Failures**: Falls back to static rules if model unavailable

## Security Considerations

- **Least Privilege IAM**: Scanner uses minimal permissions
- **Secrets Management**: Credentials in AWS Secrets Manager / Azure Key Vault
- **Audit Logging**: All actions logged to database
- **Encrypted Transport**: TLS for all API communications
- **Data Privacy**: Sensitive findings encrypted at rest
