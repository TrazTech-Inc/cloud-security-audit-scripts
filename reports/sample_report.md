# Cloud Security Audit Report

**Provider:** AWS  
**AWS Account:** 123456789012  
**Region:** us-east-1  
**Generated:** 2026-09-09T14:30:00+00:00  
**Tool:** [Cloud Security Audit Scripts](https://github.com/TrazTech-Inc/cloud-security-audit-scripts)  
**Maintained by:** [TrazTech](https://traztech.ca): Security & Compliance Consultancy, Toronto

---

## Executive Summary

| Metric | Count |
|--------|------:|
| Total Checks | 23 |
| Passed | 12 |
| Failed | 8 |
| Warnings | 3 |
| Errors | 0 |

### Non-Passing Findings by Severity

| Severity | Count |
|----------|------:|
| CRITICAL | 2 |
| HIGH | 6 |
| MEDIUM | 3 |

---

## IAM

| Severity | Check | Status | Resource | SOC 2 | Details |
|----------|-------|--------|----------|-------|---------|
| CRITICAL | Root account MFA | FAIL | arn:aws:iam::123456789012:root | CC6.1 | Root account does not have MFA enabled. This is a critical security risk. |
| HIGH | Password policy strength | FAIL | Account password policy | CC6.1 | Min length 8 (recommend 14+); Symbols not required; Max password age: 0 days (recommend <= 90) |
| MEDIUM | Unused credentials (90+ days) | WARNING | old-deploy-bot | CC6.2 | old-deploy-bot (access key 1 last used 2026-04-21T10:00:00+00:00) |
| HIGH | IAM users without MFA | FAIL | arn:aws:iam::123456789012:user/developer-3 | CC6.1 | Console user 'developer-3' does not have MFA enabled. |
| INFO | Overly permissive policies | PASS | Customer-managed policies | CC6.3 | No attached customer-managed policies with Action:* Resource:* found. |
| INFO | Access key age (>90 days) | PASS | All IAM users | CC6.2 | All active access keys are under 90 days old. |

## Encryption

| Severity | Check | Status | Resource | SOC 2 | Details |
|----------|-------|--------|----------|-------|---------|
| HIGH | S3 default encryption | FAIL | my-data-bucket-prod | CC6.7 | Bucket 'my-data-bucket-prod' does not have default encryption configured. |
| MEDIUM | EBS volume encryption | WARNING | vol-0abc123def456 | CC6.7 | Unencrypted EBS volume: vol-0abc123def456 (attached to i-0123456789abcdef) |
| INFO | RDS encryption at rest | PASS | production-db | CC6.7 | |
| INFO | KMS key rotation | PASS | alias/app-encryption-key | CC6.7 | |

## Network

| Severity | Check | Status | Resource | SOC 2 | Details |
|----------|-------|--------|----------|-------|---------|
| HIGH | S3 account-level public access block | FAIL | Account 123456789012 | CC6.6 | Account-level S3 public access block is not fully enabled. |
| CRITICAL | Security group open to world | FAIL | sg-0abc123 (web-server-sg) | CC6.6 | Port 22 (SSH) open to 0.0.0.0/0. |
| HIGH | Security group open to world | FAIL | sg-0def456 (db-sg) | CC6.6 | Port 3306 (MySQL) open to 0.0.0.0/0. |
| INFO | Default VPC usage | PASS | vpc-0abc123 | CC6.6 | Default VPC exists but has no running instances. |
| INFO | RDS public accessibility | PASS | production-db | CC6.6 | |

## Logging

| Severity | Check | Status | Resource | SOC 2 | Details |
|----------|-------|--------|----------|-------|---------|
| HIGH | CloudTrail multi-region | FAIL | Account | CC7.1 | No multi-region trail found. Activity in some regions may not be logged. |
| INFO | CloudTrail log file validation | PASS | arn:aws:cloudtrail:us-east-1:123456789012:trail/my-audit-trail | CC7.1 | |
| INFO | S3 access logging | PASS | my-data-bucket-prod | CC7.2 | Server access logging enabled. |

## Backups

| Severity | Check | Status | Resource | SOC 2 | Details |
|----------|-------|--------|----------|-------|---------|
| INFO | S3 versioning | PASS | my-data-bucket-prod | A1.2 | Versioning enabled. |
| INFO | RDS automated backups | PASS | production-db | A1.2 | Backup retention: 7 days. |
| MEDIUM | RDS Multi-AZ | WARNING | staging-db | A1.2 | RDS instance 'staging-db' is not configured for Multi-AZ. |

## Posture

| Severity | Check | Status | Resource | SOC 2 | Details |
|----------|-------|--------|----------|-------|---------|
| INFO | CloudWatch alarms | PASS | CloudWatch | CC7.2 | 8 alarm(s) configured. |

## Governance

| Severity | Check | Status | Resource | SOC 2 | Details |
|----------|-------|--------|----------|-------|---------|
| INFO | AWS Config recording | PASS | Config recorder: default | CC8.1 | |

---

## Compliance Mapping Reference

| SOC 2 Criteria | Description |
|----------------|-------------|
| CC6.1 | Logical and Physical Access - Access security mechanisms |
| CC6.2 | Logical and Physical Access - Credentials and access provisioning |
| CC6.3 | Logical and Physical Access - Role-based access and least privilege |
| CC6.6 | Logical and Physical Access - Security of system boundaries |
| CC6.7 | Logical and Physical Access - Encryption of data in transit |
| CC6.8 | Logical and Physical Access - Prevention of malicious software |
| CC7.1 | System Operations - Detection of changes and anomalies |
| CC7.2 | System Operations - Monitoring of system components |
| CC8.1 | Change Management - Authorization and management of changes |
| A1.2 | Availability - Recovery mechanisms and backup |

For a complete SOC 2 readiness walkthrough, see the [TrazTech SOC 2 Readiness Checklist](https://traztech.ca/soc-2-readiness-checklist).

---

## Disclaimer

This report was generated by automated scripts and represents a point-in-time assessment. It does
not constitute a formal audit or certification. Results should be reviewed by qualified security
professionals. For professional cloud security assessments, contact [TrazTech](https://traztech.ca).

## Resources

- [TrazTech Cloud Security Posture Check](https://traztech.ca/tools/cloud-security-posture-check): Free automated assessment
- [TrazTech SOC 2 Readiness Checklist](https://traztech.ca/soc-2-readiness-checklist)
- [TrazTech Blog](https://traztech.ca/blog): 100+ articles on cloud security and compliance
