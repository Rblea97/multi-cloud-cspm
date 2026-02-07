# Setup & Deployment Guide

This guide covers setting up the Multi-Cloud CSPM system for development and production.

## Prerequisites

### System Requirements
- Python 3.11+
- PostgreSQL 13+
- Redis 6+ (optional, for async tasks)
- Git
- AWS CLI v2 or Azure CLI v2 (depending on cloud provider)

### AWS Account Setup
1. Create AWS account or use existing one
2. Create IAM user for development:
   ```bash
   aws iam create-user --user-name cspm-dev
   ```
3. Attach policy:
   ```bash
   aws iam attach-user-policy --user-name cspm-dev \
     --policy-arn arn:aws:iam::aws:policy/SecurityAudit
   ```
4. Create access keys:
   ```bash
   aws iam create-access-key --user-name cspm-dev
   ```
5. Configure AWS CLI:
   ```bash
   aws configure --profile cspm
   # Enter Access Key ID
   # Enter Secret Access Key
   # Region: us-east-1
   # Output format: json
   ```

### Azure Subscription Setup
1. Create Azure account or use existing one
2. Create service principal:
   ```bash
   az ad sp create-for-rbac --name "cspm-dev" \
     --role "Reader" \
     --scopes /subscriptions/<subscription-id>
   ```
3. Save output (needed for .env):
   ```bash
   {
     "appId": "...",
     "displayName": "cspm-dev",
     "password": "...",
     "tenant": "..."
   }
   ```

## Local Development Setup

### 1. Clone Repository
```bash
git clone https://github.com/Rblea97/multi-cloud-cspm.git
cd multi-cloud-cspm
```

### 2. Create Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements-dev.txt
```

### 4. Set Up PostgreSQL (Local)

**Option A: Using Docker**
```bash
docker run --name cspm-postgres \
  -e POSTGRES_USER=cspm \
  -e POSTGRES_PASSWORD=dev_password \
  -e POSTGRES_DB=cspm_db \
  -p 5432:5432 \
  -d postgres:15
```

**Option B: Using system package**
```bash
# macOS
brew install postgresql@15
brew services start postgresql@15
createdb cspm_db

# Ubuntu/Debian
sudo apt-get install postgresql
sudo -u postgres createdb cspm_db
```

### 5. Set Up Redis (Optional, for Celery)

**Using Docker**
```bash
docker run --name cspm-redis \
  -p 6379:6379 \
  -d redis:7
```

**Using system package**
```bash
# macOS
brew install redis
brew services start redis

# Ubuntu/Debian
sudo apt-get install redis-server
sudo systemctl start redis-server
```

### 6. Create Environment File
```bash
cp .env.example .env
```

Edit `.env` with your local settings:
```bash
ENVIRONMENT=development
DEBUG=true

# AWS
AWS_REGION=us-east-1
AWS_PROFILE=cspm  # From aws configure

# Azure
AZURE_SUBSCRIPTION_ID=<your-subscription-id>
AZURE_TENANT_ID=<your-tenant-id>

# Database (local PostgreSQL)
DATABASE_URL=postgresql://cspm:dev_password@localhost:5432/cspm_db
DATABASE_ECHO=true

# Redis
REDIS_URL=redis://localhost:6379/0

# Scanning
SCAN_INTERVAL_MINUTES=15
MAX_CONCURRENT_SCANS=5

# Remediation
REMEDIATION_ENABLED=true
REMEDIATION_REQUIRE_APPROVAL=true
REMEDIATION_AUTO_FIX_ENABLED=false

# ML
ML_MODEL_RETRAIN_INTERVAL_DAYS=7
ML_ANOMALY_THRESHOLD=0.8

LOG_LEVEL=DEBUG
```

### 7. Initialize Database
```bash
# Run Alembic migrations (when available)
# alembic upgrade head

# OR create tables directly from models
python -c "from src.cspm.database.repository import Repository; r = Repository(); r.create_tables()"
```

### 8. Run Tests
```bash
pytest tests/ -v
```

Expected output:
```
====== 8 passed, coverage: 62% ======
```

### 9. Start Development Server

**Option A: Run FastAPI directly**
```bash
python -m uvicorn src.cspm.api.app:app --reload --port 8000
```

**Option B: Using Python script**
```bash
python -m src.cspm.api.main
```

Check: http://localhost:8000/docs (Swagger UI)

## Production Deployment

### Using Terraform

#### AWS Deployment

1. **Set Up Backend**
   ```bash
   cd terraform/shared
   # Create S3 bucket and DynamoDB table for state
   terraform init
   terraform apply
   ```

2. **Deploy AWS Infrastructure**
   ```bash
   cd ../aws

   # Create variables file
   cp aws.tfvars.example aws.tfvars
   # Edit aws.tfvars with production values

   # Initialize Terraform
   terraform init -backend-config="bucket=cspm-terraform-state" \
                 -backend-config="key=aws/prod/terraform.tfstate" \
                 -backend-config="dynamodb_table=cspm-terraform-locks"

   # Plan deployment
   terraform plan -var-file=aws.tfvars

   # Apply changes
   terraform apply -var-file=aws.tfvars
   ```

   **Outputs**: RDS endpoint, ALB DNS, Lambda IAM role ARN, etc.

#### Azure Deployment

1. **Set Up Storage Account for State**
   ```bash
   RESOURCE_GROUP="cspm-terraform"
   STORAGE_ACCOUNT="cspptfstate"

   az group create --name $RESOURCE_GROUP --location eastus
   az storage account create --name $STORAGE_ACCOUNT \
     --resource-group $RESOURCE_GROUP \
     --sku Standard_LRS
   ```

2. **Deploy Azure Infrastructure**
   ```bash
   cd ../azure

   cp azure.tfvars.example azure.tfvars
   # Edit azure.tfvars

   terraform init \
     -backend-config="resource_group=$RESOURCE_GROUP" \
     -backend-config="storage_account_name=$STORAGE_ACCOUNT" \
     -backend-config="container_name=terraform" \
     -backend-config="key=azure/prod/terraform.tfstate"

   terraform plan -var-file=azure.tfvars
   terraform apply -var-file=azure.tfvars
   ```

### Secrets Management

**AWS**
```bash
# Store database password
aws secretsmanager create-secret --name cspm/db-password \
  --secret-string "$(jq -n --arg pwd "$DB_PASSWORD" '{password: $pwd}')"

# Store API key
aws secretsmanager create-secret --name cspm/api-key \
  --secret-string "$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
```

**Azure**
```bash
# Create Key Vault
az keyvault create --name cspm-kv \
  --resource-group cspm-prod

# Store secrets
az keyvault secret set --vault-name cspm-kv \
  --name db-password \
  --value "$DB_PASSWORD"

az keyvault secret set --vault-name cspm-kv \
  --name api-key \
  --value "$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
```

### Database Migration (Production)

```bash
# Connect to production database
psql -h <rds-endpoint> -U cspm -d cspm_db

# Run Alembic migrations
alembic upgrade head
```

### Deploy Application

**Option A: AWS Lambda (Recommended)**
```bash
# Package application
zip -r lambda.zip src/ requirements.txt

# Update Lambda function
aws lambda update-function-code --function-name cspm-scanner \
  --zip-file fileb://lambda.zip
```

**Option B: Docker on ECS/ACS**
```bash
# Build Docker image
docker build -t cspm:latest .

# Tag for ECR
docker tag cspm:latest <account>.dkr.ecr.us-east-1.amazonaws.com/cspm:latest

# Push to ECR
docker push <account>.dkr.ecr.us-east-1.amazonaws.com/cspm:latest

# Update ECS task definition (Terraform handles this)
terraform apply
```

**Option C: App Service on Azure**
```bash
# Build and push to ACR
az acr build --registry cspm-acr --image cspm:latest .

# Update App Service
az webapp config container set --name cspm-app \
  --resource-group cspm-prod \
  --docker-custom-image-name cspm-acr.azurecr.io/cspm:latest
```

## Verification

### Health Check

```bash
# API is responsive
curl -s http://localhost:8000/health | jq .

# Database connection works
python -c "from src.cspm.database.repository import Repository; r = Repository(); print('DB OK')"

# AWS credentials work
aws sts get-caller-identity

# Azure credentials work
az account show
```

### Run Full Integration Test

```bash
# Create test resources in AWS
cd terraform/aws
terraform apply -var-file=test.tfvars

# Run scan
python -c "from src.cspm.scanner.cli import scan; scan(cloud='aws')"

# Check findings
psql -c "SELECT * FROM findings LIMIT 5"

# Tear down test resources
terraform destroy -var-file=test.tfvars
```

## Monitoring & Logging

### CloudWatch (AWS)

```bash
# View scanner logs
aws logs tail /aws/lambda/cspm-scanner --follow

# View API logs
aws logs tail /aws/ecs/cspm-api --follow
```

### Azure Monitor

```bash
# View Application Insights
az monitor app-insights metrics show --app cspm-app \
  --resource-group cspm-prod

# View logs
az monitor log-analytics query --workspace cspm-logs \
  --query "Scans | where TimeGenerated > ago(1d)"
```

### Alerts

**AWS SNS Alert for High-Severity Findings**
```bash
aws sns subscribe --topic-arn arn:aws:sns:us-east-1:...:cspm-findings \
  --protocol email \
  --notification-endpoint security-team@company.com
```

**Azure Action Group**
```bash
az monitor action-group create --name cspm-alerts \
  --resource-group cspm-prod
```

## Troubleshooting

### Connection to PostgreSQL fails
```bash
# Check PostgreSQL is running
psql -U cspm -d cspm_db -c "SELECT 1"

# Check DATABASE_URL format
echo $DATABASE_URL

# Test from Python
python -c "from sqlalchemy import create_engine; create_engine('$DATABASE_URL').connect()"
```

### AWS credentials not working
```bash
# Verify profile exists
aws configure list --profile cspm

# Check credentials are valid
aws sts get-caller-identity --profile cspm

# Update .env
AWS_PROFILE=cspm
```

### Tests fail with "No module named cspm"
```bash
# Verify pytest.ini has pythonpath
cat pytest.ini

# OR set PYTHONPATH
export PYTHONPATH=src:$PYTHONPATH
pytest tests/
```

### Database migrations fail
```bash
# Check Alembic status
alembic current

# View migration history
alembic history

# Downgrade to previous version
alembic downgrade -1
```

## Backup & Recovery

### Database Backup

**AWS RDS**
```bash
# Automated backups (Terraform enables 30-day retention)
# Manual snapshot
aws rds create-db-snapshot --db-instance-identifier cspm-db \
  --db-snapshot-identifier cspm-db-backup-$(date +%Y%m%d)
```

**Azure SQL**
```bash
# Automated backups (7-day retention)
# Export database
az sql db export --admin-user adminuser --admin-password <password> \
  --database cspm-db --resource-group cspm-prod \
  --server cspm-sql --storage-key <key> \
  --storage-uri https://csppstorage.blob.core.windows.net/backups/
```

### Restore from Backup

**AWS RDS**
```bash
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier cspm-db-restored \
  --db-snapshot-identifier cspm-db-backup-20250206
```

## CI/CD Pipeline

The GitHub Actions workflow automatically:
1. Runs tests on pull requests
2. Checks code quality (ruff, black, mypy)
3. Scans for security issues (bandit)
4. Scans infrastructure code (Checkov)
5. Deploys on merge to main

See `.github/workflows/` for pipeline configuration.
