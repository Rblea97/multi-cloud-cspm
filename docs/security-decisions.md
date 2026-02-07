# Security Decisions

This document explains the security design decisions made in the Multi-Cloud CSPM system.

## Identity & Access Management (IAM)

### Principle: Least Privilege

**Decision**: The scanner runs with minimal required permissions to discover and assess resources.

**Rationale**:
- If the scanner is compromised, attackers gain only limited access
- Reduces blast radius of potential security incidents
- Follows AWS and Azure security best practices

**Implementation**:

**AWS Scanner Role**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketVersioning",
        "s3:GetBucketEncryption",
        "s3:GetPublicAccessBlock",
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "rds:DescribeDBInstances",
        "rds:DescribeDBEncryption",
        "cloudtrail:LookupEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

**Azure Scanner Role**:
- `Reader` role on subscription (read-only)
- Scoped to specific resource groups where testing

**Key Principle**: No create/delete/modify permissions for scanner

### Remediation Service Permissions

**Decision**: Separate IAM role for remediation with auto-fix capabilities.

**Rationale**:
- Can be disabled/restricted if auto-remediation is high-risk
- Approval workflow can gate high-severity auto-fixes
- Clear audit trail for who triggered remediation

**AWS Remediation Role** (restricted set):
```json
{
  "Effect": "Allow",
  "Action": [
    "s3:PutPublicAccessBlock",
    "ec2:RevokeSecurityGroupIngress",
    "rds:ModifyDBInstance"
  ],
  "Resource": "arn:aws:*:*:*:*"
}
```

## Credential Management

### AWS Credentials

**Decision**: Use IAM role assumption with STS for temporary credentials.

**Rationale**:
- No long-lived access keys stored on disk
- Credentials rotate automatically
- Clear audit trail via CloudTrail

**Implementation**:
- Scanner assumes role from EC2/Lambda instance profile
- Optional: Cross-account role assumption for multi-account scanning
- Credentials cached in memory, never persisted

### Azure Credentials

**Decision**: Use Azure Managed Identity when running on Azure resources; Service Principal in dev.

**Rationale**:
- Managed Identity: no credential storage needed
- Service Principal: fallback for on-prem/hybrid deployments
- Client ID and secret in Azure Key Vault

**Implementation**:
- Production: Use Azure Managed Identity
- Development: Service principal JSON in `.env` (gitignored)
- Client secret stored in Key Vault, never in source code

## Data Encryption

### At-Rest Encryption

**PostgreSQL Database**:
- AWS RDS: Enable encryption with AWS KMS
- Command: `terraform/aws/rds.tf` sets `storage_encrypted = true`
- Encryption key: AWS-managed KMS key

**Sensitive Findings**:
- Remediation results: encrypted if contain credentials
- API keys/tokens in evidence: never logged plaintext

### In-Transit Encryption

**API Communications**:
- All REST endpoints use HTTPS/TLS 1.2+
- Certificate management: AWS ACM or Let's Encrypt
- Client authentication: API keys or OAuth tokens

**CloudTrail & Activity Logs**:
- Downloaded via HTTPS only
- Cached in encrypted PostgreSQL

**Cloud SDK Calls**:
- boto3 and azure-sdk use HTTPS by default
- All credentials passed securely

## Secrets Management

### AWS Secrets Manager

**Decision**: Store database credentials in AWS Secrets Manager, not in .env.

**Rationale**:
- Automatic rotation support
- Audit logging via CloudTrail
- Encryption with KMS
- Can restrict access by IAM policy

**Implementation**:
```python
# src/cspm/core/secrets.py
client = boto3.client('secretsmanager')
secret = client.get_secret_value(SecretId='cspm/db')
db_password = json.loads(secret['SecretString'])['password']
```

### Azure Key Vault

**Decision**: Store service principal secret, Key Vault connection strings in Key Vault.

**Rationale**:
- Azure-native credential storage
- Integrates with Managed Identity
- Access logging and rotation

**Implementation**:
```python
# src/cspm/core/secrets.py
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

credential = DefaultAzureCredential()
client = SecretClient(vault_url="https://cspm-kv.vault.azure.net/", credential=credential)
secret = client.get_secret("db-password")
```

### Local Development

**Decision**: Allow .env file for dev, never commit it.

**Implementation**:
- `.env.example` with template values
- `.gitignore` blocks `.env*`
- Pre-commit hook warns if secrets are committed
- Only local dev DB credentials (can change for tests)

## Audit & Logging

### Finding Changes

**All findings logged with**:
- Creation timestamp
- User/system who created it
- Status changes (OPEN → REMEDIATED)
- Remediation timestamp and result
- Query capability: "Who changed this finding?"

**Implementation**:
- PostgreSQL `updated_at` timestamp
- All updates go through Repository layer
- Never UPDATE findings without logging

### Remediation Actions

**All remediation actions logged**:
- Who triggered it (user/system)
- What action (block_public_s3, etc.)
- Mode (DRY_RUN vs AUTO_FIX)
- Start/end time and result
- Error messages if failed

**Implementation**:
- `RemediationAction` model with full audit trail
- Query: "What auto-fixes ran today?"
- Query: "Who approved this remediation?"

### API Access Logging

**All API requests logged**:
- Timestamp
- User/client
- Endpoint and method
- Request parameters
- Response status
- Latency

**Implementation**:
- FastAPI middleware captures requests
- Log to PostgreSQL and CloudWatch/Monitor

## Network Security

### API Server

**Decision**: Run behind VPC/virtual network with private subnet.

**Implementation**:
- AWS: ALB in public subnet → API in private subnet
- Azure: Application Gateway → API in private subnet
- No direct internet access to API servers

### Database

**Decision**: PostgreSQL in private subnet, not internet-accessible.

**Implementation**:
- AWS: RDS in private subnet with security group
- Azure: SQL Database with firewall rules (private endpoint)
- Only API servers can connect
- Prevent direct internet connections to DB

### CloudTrail / Activity Log Collection

**Decision**: Encrypted S3/Storage Bucket, restricted access.

**Implementation**:
- CloudTrail → S3 (versioning + encryption)
- Activity logs → Storage Account (encryption + managed identity)
- Scanner reads from these buckets only

## Approval Workflows

### High-Risk Remediation

**Decision**: Require human approval for:
- Deleting resources
- Modifying security groups
- Disabling encryption
- Modifying IAM permissions

**Implementation**:
```python
# src/cspm/remediation/engine.py
if action.risk_level == "HIGH" and settings.remediation_require_approval:
    create_approval_ticket(action)
    wait_for_approval()
```

**Process**:
1. Remediation requested
2. Create approval task (Jira ticket, email, Slack)
3. Assign to security team
4. After approval: execute remediation
5. Log approval in database

## Threat Model

### Threats Considered

**T1: Attacker gains scanner credentials**
- Mitigation: Least privilege IAM (can't modify resources)
- Mitigation: Temporary credentials via STS role assumption
- Mitigation: Audit logging of all API calls

**T2: Attacker reads findings database**
- Mitigation: Database encryption at rest (KMS)
- Mitigation: Database in private subnet (network-level)
- Mitigation: Sensitive data (creds) not stored in findings

**T3: Attacker triggers unauthorized remediation**
- Mitigation: Approval workflows for high-risk actions
- Mitigation: Detailed audit logging
- Mitigation: Separate remediation IAM role (can disable)

**T4: Attacker exfiltrates API credentials**
- Mitigation: API key rotation
- Mitigation: TLS for all API traffic
- Mitigation: Rate limiting and DDoS protection

## Future Security Enhancements

1. **Encryption at rest for findings** - AES-256 for sensitive fields
2. **Role-based access control** - Different users see different findings
3. **Zero-knowledge architecture** - Scanner doesn't know remediation logic
4. **Hardware security modules** - KMS for key storage
5. **Red team exercises** - Annual penetration testing
