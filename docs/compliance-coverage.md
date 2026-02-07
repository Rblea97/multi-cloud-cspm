# Compliance Framework Coverage

This document maps security rules to CIS Benchmarks and tracks implementation progress.

## AWS CIS Foundations Benchmark (AWS v1.4.0)

### Identity and Access Management (10 controls)

| Control | Description | Rule | Status | Implementation Notes |
|---------|-------------|------|--------|---------------------|
| 1.1 | Maintain current contact details | Manual review | ✅ MANUAL | Track AWS account contact information |
| 1.2 | Ensure MFA is enabled for all console users | IAMUserMFARule | 🔄 PHASE-4 | Check `MFAEnabled` attribute |
| 1.3 | Ensure security questions are registered | Manual review | ✅ MANUAL | AWS console setting |
| 1.4 | Ensure IAM policies are attached only to groups or roles | IAMPolicyAttachmentRule | 🔄 PHASE-4 | Detect policies on users |
| 1.5 | Ensure IAM policies that allow full "*:*" administration without MFA | AdminAccessMFARule | 🔄 PHASE-4 | Detect `AdministratorAccess` without MFA |
| 1.6 | Ensure IAM MFA is enabled for the root account | RootMFARule | 🔄 PHASE-4 | Check Account Settings |
| 1.7 | Eliminate use of root account | RootAccountAccessRule | 🔄 PHASE-4 | Monitor CloudTrail for root usage |
| 1.8 | Ensure credentials unused for 45 days are disabled | UnusedCredsRule | 🔄 PHASE-5 | Check `AccessKeyLastUsed` |
| 1.9 | Ensure access keys are rotated every 90 days | AccessKeyRotationRule | 🔄 PHASE-5 | Check `CreateDate` vs current date |
| 1.10 | Ensure multi-factor authentication (MFA) delete is enabled on S3 buckets | S3MFADeleteRule | 🔄 PHASE-2 | Check bucket versioning with MFA delete |

### Logging (9 controls)

| Control | Description | Rule | Status | Notes |
|---------|-------------|------|--------|-------|
| 2.1 | Ensure CloudTrail is enabled in all regions | CloudTrailEnabledRule | ✅ PHASE-1 | Detects disabled CloudTrail |
| 2.2 | Ensure CloudTrail log file validation is enabled | CloudTrailValidationRule | 🔄 PHASE-2 | Check `LogFileValidationEnabled` |
| 2.3 | Ensure CloudTrail log files are encrypted at rest using KMS | CloudTrailKMSRule | 🔄 PHASE-2 | Check `KmsKeyId` attribute |
| 2.4 | Ensure CloudTrail log files are integrated with CloudWatch Logs | CloudTrailCloudWatchRule | 🔄 PHASE-2 | Check `CloudWatchLogsLogGroupArn` |
| 2.5 | Ensure S3 bucket used for CloudTrail logs is not publicly accessible | S3CloudTrailBucketRule | ✅ PHASE-1 | Reuses PublicS3Rule |
| 2.6 | Ensure S3 bucket used for CloudTrail logs is encrypted | S3CloudTrailEncryptionRule | 🔄 PHASE-2 | Check S3 encryption |
| 2.7 | Ensure S3 bucket used for CloudTrail logs has MFA delete enabled | S3CloudTrailMFARule | 🔄 PHASE-2 | Check versioning + MFA |
| 2.8 | Ensure VPC Flow Logs is enabled for all VPCs | VPCFlowLogsRule | 🔄 PHASE-3 | Check VPC Flow Logs status |
| 2.9 | Ensure API logging for CloudFront distribution is enabled | CloudFrontLoggingRule | 🔄 PHASE-3 | Check CloudFront logging |

### Storage (4 controls)

| Control | Description | Rule | Status | Notes |
|---------|-------------|------|--------|-------|
| 3.1 | Ensure S3 bucket has a public access block (Deprecated: 4.1) | PublicS3Rule | ✅ PHASE-1 | Main control |
| 3.2 | Ensure S3 buckets do not allow an open ACL | S3BucketACLRule | 🔄 PHASE-2 | Check ACL configuration |
| 3.3 | Ensure S3 bucket encryption is enabled | S3EncryptionRule | 🔄 PHASE-2 | Check SSE configuration |
| 3.4 | Ensure S3 bucket has a lifecycle policy | S3LifecycleRule | 🔄 PHASE-3 | Check lifecycle rules |

### Database (5 controls)

| Control | Description | Rule | Status | Notes |
|---------|-------------|------|--------|-------|
| 4.1 | Ensure RDS database instance backup is enabled | RDSBackupRule | 🔄 PHASE-2 | Check `BackupRetentionPeriod` |
| 4.2 | Ensure RDS database instances are encrypted | UnencryptedRDSRule | ✅ PHASE-1 | Main control |
| 4.3 | Ensure RDS database instances have deletion protection enabled | RDSDeleteProtectionRule | 🔄 PHASE-2 | Check `DeletionProtection` |
| 4.4 | Ensure RDS database instances are not publicly accessible | RDSPubliclyAccessibleRule | 🔄 PHASE-2 | Check `PubliclyAccessible` |
| 4.5 | Ensure RDS database instance has enhanced monitoring enabled | RDSMonitoringRule | 🔄 PHASE-3 | Check `MonitoringInterval` |

### Compute (6 controls)

| Control | Description | Rule | Status | Notes |
|---------|-------------|------|--------|-------|
| 5.1 | Ensure Security Groups are configured with inbound rule restrictions | OpenSecurityGroupRule | ✅ PHASE-1 | Detects 0.0.0.0/0 |
| 5.2 | Ensure no security groups allow ingress from 0.0.0.0/0 to port 3306 | RestrictedMySQLRule | 🔄 PHASE-2 | Specific for MySQL |
| 5.3 | Ensure no security groups allow ingress from 0.0.0.0/0 to port 1433 | RestrictedMSSQLRule | 🔄 PHASE-2 | Specific for MSSQL |
| 5.4 | Ensure no security groups allow ingress from 0.0.0.0/0 to port 5432 | RestrictedPostgreSQLRule | 🔄 PHASE-2 | Specific for PostgreSQL |
| 5.5 | Ensure no security groups allow ingress from 0.0.0.0/0 to port 5984 | RestrictedCouchDBRule | 🔄 PHASE-3 | Specific for CouchDB |
| 5.6 | Ensure VPC endpoints are used for AWS API calls | VPCEndpointsRule | 🔄 PHASE-3 | Check for VPC endpoints |

### Networking (3 controls)

| Control | Description | Rule | Status | Notes |
|---------|-------------|------|--------|-------|
| 6.1 | Ensure Network ACLs allow list contains 0.0.0.0/0 only to necessary ports | NACLRule | 🔄 PHASE-3 | Check NACL rules |
| 6.2 | Ensure security group and NACLs inbound rule is restricted to known CIDR | InboundCIDRRule | 🔄 PHASE-3 | Check CIDR blocks |
| 6.3 | Ensure security group egress rules restrict to known ports/protocols | EgressRule | 🔄 PHASE-3 | Check outbound rules |

### Overall Progress: 5/37 Controls Implemented (14%)

**Implemented (✅)**:
- CloudTrail disabled detection
- Public S3 bucket detection
- Unencrypted RDS detection
- Overly permissive security groups
- S3 public access from CloudTrail bucket

**Phase 2-3 (🔄)**: 32 controls queued for implementation

---

## Azure CIS Foundations Benchmark (Azure v1.4.0)

### Identity and Access Management (11 controls)

| Control | Description | Rule | Status | Notes |
|---------|-------------|------|--------|-------|
| 1.1 | Ensure MFA is required for all Azure users | AzureMFARule | 🔄 PHASE-4 | Check conditional access policies |
| 1.2 | Ensure that 'All' users have MFA enabled | AzureMFAEnforcementRule | 🔄 PHASE-4 | Check per-user MFA status |
| 1.3 | Ensure that multi-factor authentication (MFA) is enforced on service accounts | ServiceAccountMFARule | 🔄 PHASE-5 | Check service principals |
| 1.4 | Ensure that guest users are reviewed on a monthly basis | GuestUserReviewRule | 🔄 PHASE-3 | Check guest account aging |
| 1.5 | Ensure that a list of allowed user-defined Azure CLI commands is configured | CLICommandRestrictionsRule | 🔄 PHASE-4 | Requires manual configuration |
| 1.6 | Ensure that 'Restrict access to Azure services' is enabled | AzureServiceAccessRule | 🔄 PHASE-3 | Check Portal settings |
| 1.7 | Ensure that 'Create Azure service principals' is restricted | ServicePrincipalCreationRule | 🔄 PHASE-4 | Check AD app registrations |
| 1.8 | Ensure role assignments include owners with MFA | OwnerMFARule | 🔄 PHASE-4 | Check role assignments |
| 1.9 | Ensure that subscriptions have an owner assigned | OwnerAssignmentRule | 🔄 PHASE-3 | Check Owner role |
| 1.10 | Ensure that service account has no owner assignments | ServiceAccountOwnerRule | 🔄 PHASE-4 | Check service principals |
| 1.11 | Ensure multi-tenant organization is configured | MultiTenantOrgRule | 🔄 PHASE-5 | B2B collaboration settings |

### Asset Management (4 controls)

| Control | Description | Rule | Status | Notes |
|---------|-------------|------|--------|-------|
| 2.1 | Ensure that subscription enables MFA for admin sign-in | AdminMFARule | 🔄 PHASE-4 | Check admin sign-in |
| 2.2 | Ensure that Activity Log Alert exists for Create Policy Assignment | CreatePolicyAlertRule | 🔄 PHASE-3 | Check alert rules |
| 2.3 | Ensure that Activity Log Alert exists for Create or Update Security Policy | SecurityPolicyAlertRule | 🔄 PHASE-3 | Check alert rules |
| 2.4 | Ensure that Activity Log Alert exists for Delete Security Policy | DeleteSecurityAlertRule | 🔄 PHASE-3 | Check alert rules |

### Logging and Monitoring (9 controls)

| Control | Description | Rule | Status | Notes |
|---------|-------------|------|--------|-------|
| 3.1 | Ensure that Activity Log Alert exists for Create Policy Assignment | ActivityLogAlertRule | 🔄 PHASE-2 | Check Azure Monitor |
| 3.2 | Ensure that Activity Log Alert exists for Create or Update Network Security Group | NSGAlertRule | 🔄 PHASE-2 | Check alerts |
| 3.3 | Ensure that Activity Log Alert exists for Delete Network Security Group | NSGDeleteAlertRule | 🔄 PHASE-2 | Check alerts |
| 3.4 | Ensure that Activity Log Alert exists for Create or Update Network Security Group Rule | NSGRuleAlertRule | 🔄 PHASE-2 | Check alerts |
| 3.5 | Ensure that Activity Log Alert exists for Delete Network Security Group Rule | NSGRuleDeleteAlertRule | 🔄 PHASE-2 | Check alerts |
| 3.6 | Ensure Defender for Cloud has the ability to auto-remediate remediation tasks | DefenderAutoRemediateRule | 🔄 PHASE-3 | Check Defender settings |
| 3.7 | Ensure that Activity Log Alert exists for Delete Storage Account | StorageDeleteAlertRule | 🔄 PHASE-2 | Check alerts |
| 3.8 | Ensure that Activity Log Alert exists for Create or Update SQL Server Firewall Rule | SQLFirewallAlertRule | 🔄 PHASE-2 | Check alerts |
| 3.9 | Ensure that Activity Log Alert exists for Delete SQL Server Firewall Rule | SQLFirewallDeleteAlertRule | 🔄 PHASE-2 | Check alerts |

### Networking (5 controls)

| Control | Description | Rule | Status | Notes |
|---------|-------------|------|--------|-------|
| 4.1 | Ensure that private endpoints are used for Azure Platform as a service | PrivateEndpointRule | 🔄 PHASE-3 | Check for private endpoints |
| 4.2 | Ensure that VNet service endpoints are used for Azure Platform as a service | VNetEndpointRule | 🔄 PHASE-3 | Check service endpoints |
| 4.3 | Ensure Network Security Groups are only used with Azure Virtual Machines | NSGUsageRule | 🔄 PHASE-2 | Verify NSG scope |
| 4.4 | Ensure Network Watcher is enabled | NetworkWatcherRule | 🔄 PHASE-3 | Check Network Watcher status |
| 4.5 | Ensure that Network Watcher flow log is enabled for every subnet | FlowLogsRule | 🔄 PHASE-3 | Check flow logs |

### Data Protection (7 controls)

| Control | Description | Rule | Status | Notes |
|---------|-------------|------|--------|-------|
| 5.1 | Ensure that Storage Account public access level is set to None | PublicBlobStorageRule | ✅ PHASE-1 | Main control |
| 5.2 | Ensure that Azure Blob Storage is encrypted at rest | StorageEncryptionRule | 🔄 PHASE-2 | Check CMK/SSE |
| 5.3 | Ensure that Azure Storage is set to enable HTTPS | HTTPSOnlyRule | 🔄 PHASE-2 | Check secure transfer |
| 5.4 | Ensure that Azure Synapse workspaces do not allow public access | SynapsePublicAccessRule | 🔄 PHASE-3 | Check public access |
| 5.5 | Ensure Azure Data Lake Storage is encrypted at rest | DataLakeEncryptionRule | 🔄 PHASE-3 | Check encryption |
| 5.6 | Ensure that Azure SQL database is encrypted | UnencryptedSQLRule | ✅ PHASE-1 | Main control |
| 5.7 | Ensure that 'Transparent Data Encryption' is 'On' for SQL databases | TDERule | 🔄 PHASE-2 | Check TDE status |

### General Security (2 controls)

| Control | Description | Rule | Status | Notes |
|---------|-------------|------|--------|-------|
| 6.1 | Ensure that Microsoft Defender for Cloud is enabled on the subscription | DefenderForCloudRule | 🔄 PHASE-3 | Check Defender status |
| 6.2 | Ensure that Microsoft Defender for Cloud is set to Standard tier for all resource types | DefenderStandardTierRule | 🔄 PHASE-3 | Check tier level |

### Overall Progress: 2/38 Controls Implemented (5%)

**Implemented (✅)**:
- Public blob storage detection
- Unencrypted SQL database detection

**Phase 2-3 (🔄)**: 36 controls queued for implementation

---

## Implementation Roadmap

### Phase 1 (Complete) - MVP Foundation
- [x] CloudTrail enabled check
- [x] Public S3 bucket detection
- [x] Unencrypted RDS detection
- [x] Overly permissive security groups
- [x] Public blob storage detection
- [x] Unencrypted SQL database detection

**CIS Coverage**: 5/75 controls (7%)

### Phase 2 - Core Logging & Storage
- [ ] CloudTrail validation and encryption
- [ ] S3 bucket encryption and lifecycle
- [ ] RDS backup and deletion protection
- [ ] Azure monitoring alerts
- [ ] Storage encryption and HTTPS

**Target CIS Coverage**: 15/75 controls (20%)

### Phase 3 - Advanced Monitoring & Networking
- [ ] VPC Flow Logs
- [ ] Network Watcher and flow logs
- [ ] Private endpoints
- [ ] CloudFront logging
- [ ] Alert rules for security changes

**Target CIS Coverage**: 25/75 controls (33%)

### Phase 4 - Identity & Access Management
- [ ] MFA enforcement checks
- [ ] IAM policy attachment validation
- [ ] Root account usage monitoring
- [ ] Service principal security
- [ ] Role assignment reviews

**Target CIS Coverage**: 40/75 controls (53%)

### Phase 5 - Advanced Security
- [ ] Access key rotation tracking
- [ ] Unused credentials cleanup
- [ ] Service account MFA
- [ ] Multi-tenant configuration
- [ ] Advanced ML anomaly detection

**Target CIS Coverage**: 60/75 controls (80%)

---

## Compliance Score Calculation

**Formula**:
```
Compliance Score = (Controls Passed / Total Applicable Controls) × 100%
```

**Severity Weights** (optional, for weighted scoring):
```
- CRITICAL violation: -5 points per control
- HIGH violation: -3 points per control
- MEDIUM violation: -1 point per control
- LOW violation: -0.5 points per control
```

**Example**:
```
AWS Account with 37 controls:
- 32 PASS
- 3 FAIL (HIGH severity)
- 2 N/A

Score = (32 / 35) × 100% = 91.4% (GOOD)
Deduction = 3 × 3 = 9 points
Adjusted = 91.4% - 9 = 82.4% (GOOD)
```

---

## Compliance Reporting

Reports include:
- Overall compliance score by framework
- Per-control pass/fail status
- High-severity failing controls highlighted
- Remediation recommendations
- Historical trend (score over 30 days)
- Resources affected by each control

## Future Compliance Frameworks

- [ ] HIPAA (healthcare)
- [ ] PCI-DSS (payment card data)
- [ ] GDPR (data privacy)
- [ ] SOC 2 Type II
- [ ] FedRAMP (government)
- [ ] ISO 27001 (information security)
