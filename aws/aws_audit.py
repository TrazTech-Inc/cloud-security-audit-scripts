#!/usr/bin/env python3
"""
AWS Cloud Security Audit Script

Comprehensive read-only security assessment for AWS environments.
Checks IAM, S3, CloudTrail, EC2/VPC, RDS, KMS, CloudWatch, and AWS Config.

Findings are mapped to SOC 2 Trust Services Criteria for audit readiness.
Categories align with the TrazTech Cloud Security Posture Check
(https://traztech.ca/tools/cloud-security-posture-check):
IAM, Logging, Encryption, Network, Backups, Secrets, Posture, Governance.

Usage:
    python aws/aws_audit.py --profile production --region us-east-1
    python aws/aws_audit.py --output-format json --output-dir reports/

Maintained by TrazTech (https://traztech.ca)
Principal: Jacob Masse | 5 CVEs including CVE-2024-45163 (CVSS 9.1)
"""

from __future__ import annotations

import csv
import io
import json
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import click

# Allow running from repo root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, BotoCoreError
from rich.console import Console

from utils.common import (
    AuditReport,
    Category,
    Finding,
    ReportGenerator,
    Severity,
    Status,
    print_banner,
    print_finding,
    print_summary,
)

console = Console()

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _get_session(profile: Optional[str], region: Optional[str]) -> boto3.Session:
    """Create a boto3 session with optional profile and region."""
    kwargs: Dict[str, str] = {}
    if profile:
        kwargs["profile_name"] = profile
    if region:
        kwargs["region_name"] = region
    return boto3.Session(**kwargs)


def _get_account_id(session: boto3.Session) -> str:
    """Retrieve the AWS account ID via STS."""
    try:
        sts = session.client("sts")
        return sts.get_caller_identity()["Account"]
    except (ClientError, NoCredentialsError) as exc:
        console.print(f"[red]Failed to get account ID: {exc}[/red]")
        return "unknown"


# ---------------------------------------------------------------------------
# IAM checks
# ---------------------------------------------------------------------------

def check_root_mfa(session: boto3.Session, report: AuditReport) -> None:
    """CC6.1 - Verify root account has MFA enabled."""
    iam = session.client("iam")
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        mfa_enabled = summary.get("AccountMFAEnabled", 0) == 1
        report.add_finding(Finding(
            severity=Severity.CRITICAL,
            category=Category.IAM,
            check="Root account MFA",
            status=Status.PASS if mfa_enabled else Status.FAIL,
            resource=f"arn:aws:iam::{report.account_id}:root",
            details="" if mfa_enabled else "Root account does not have MFA enabled. This is a critical security risk.",
            soc2_mapping="CC6.1",
            provider="AWS",
        ))
    except ClientError as exc:
        report.add_finding(Finding(
            severity=Severity.CRITICAL,
            category=Category.IAM,
            check="Root account MFA",
            status=Status.ERROR,
            resource="account",
            details=f"Unable to check root MFA: {exc}",
            soc2_mapping="CC6.1",
            provider="AWS",
        ))


def check_password_policy(session: boto3.Session, report: AuditReport) -> None:
    """CC6.1 - Evaluate account password policy strength."""
    iam = session.client("iam")
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        min_len = policy.get("MinimumPasswordLength", 0)
        require_upper = policy.get("RequireUppercaseCharacters", False)
        require_lower = policy.get("RequireLowercaseCharacters", False)
        require_numbers = policy.get("RequireNumbers", False)
        require_symbols = policy.get("RequireSymbols", False)
        max_age = policy.get("MaxPasswordAge", 0)

        issues: List[str] = []
        if min_len < 14:
            issues.append(f"Min length {min_len} (recommend 14+)")
        if not require_upper:
            issues.append("Uppercase not required")
        if not require_lower:
            issues.append("Lowercase not required")
        if not require_numbers:
            issues.append("Numbers not required")
        if not require_symbols:
            issues.append("Symbols not required")
        if max_age == 0 or max_age > 90:
            issues.append(f"Max password age: {max_age} days (recommend <= 90)")

        if not issues:
            status = Status.PASS
            severity = Severity.INFO
            details = "Password policy meets recommended standards."
        elif len(issues) <= 2:
            status = Status.WARNING
            severity = Severity.MEDIUM
            details = "; ".join(issues)
        else:
            status = Status.FAIL
            severity = Severity.HIGH
            details = "; ".join(issues)

        report.add_finding(Finding(
            severity=severity,
            category=Category.IAM,
            check="Password policy strength",
            status=status,
            resource="Account password policy",
            details=details,
            soc2_mapping="CC6.1",
            provider="AWS",
        ))
    except iam.exceptions.NoSuchEntityException:
        report.add_finding(Finding(
            severity=Severity.HIGH,
            category=Category.IAM,
            check="Password policy strength",
            status=Status.FAIL,
            resource="Account password policy",
            details="No custom password policy configured. AWS default policy is weak.",
            soc2_mapping="CC6.1",
            provider="AWS",
        ))
    except ClientError as exc:
        report.add_finding(Finding(
            severity=Severity.HIGH,
            category=Category.IAM,
            check="Password policy strength",
            status=Status.ERROR,
            resource="Account password policy",
            details=f"Unable to retrieve password policy: {exc}",
            soc2_mapping="CC6.1",
            provider="AWS",
        ))


def check_unused_credentials(session: boto3.Session, report: AuditReport) -> None:
    """CC6.2 - Identify credentials unused for 90+ days."""
    iam = session.client("iam")
    try:
        # Generate credential report
        iam.generate_credential_report()
        import time
        for _ in range(10):
            try:
                resp = iam.get_credential_report()
                break
            except iam.exceptions.CredentialReportNotReadyException:
                time.sleep(2)
        else:
            report.add_finding(Finding(
                severity=Severity.MEDIUM,
                category=Category.IAM,
                check="Unused credentials (90+ days)",
                status=Status.ERROR,
                resource="Credential report",
                details="Credential report generation timed out.",
                soc2_mapping="CC6.2",
                provider="AWS",
            ))
            return

        content = resp["Content"].decode("utf-8")
        reader = csv.DictReader(io.StringIO(content))
        now = datetime.now(timezone.utc)
        threshold = timedelta(days=90)
        stale_users: List[str] = []

        for row in reader:
            user = row["user"]
            if user == "<root_account>":
                continue

            # Check password last used
            pwd_last = row.get("password_last_used", "N/A")
            if pwd_last not in ("N/A", "no_information", "not_supported"):
                try:
                    last_used = datetime.fromisoformat(pwd_last.replace("Z", "+00:00"))
                    if (now - last_used) > threshold:
                        stale_users.append(f"{user} (password last used {pwd_last})")
                except (ValueError, TypeError):
                    pass

            # Check access key 1
            ak1_active = row.get("access_key_1_active", "false") == "true"
            ak1_last = row.get("access_key_1_last_used_date", "N/A")
            if ak1_active and ak1_last not in ("N/A", "no_information", "not_supported"):
                try:
                    last_used = datetime.fromisoformat(ak1_last.replace("Z", "+00:00"))
                    if (now - last_used) > threshold:
                        stale_users.append(f"{user} (access key 1 last used {ak1_last})")
                except (ValueError, TypeError):
                    pass

            # Check access key 2
            ak2_active = row.get("access_key_2_active", "false") == "true"
            ak2_last = row.get("access_key_2_last_used_date", "N/A")
            if ak2_active and ak2_last not in ("N/A", "no_information", "not_supported"):
                try:
                    last_used = datetime.fromisoformat(ak2_last.replace("Z", "+00:00"))
                    if (now - last_used) > threshold:
                        stale_users.append(f"{user} (access key 2 last used {ak2_last})")
                except (ValueError, TypeError):
                    pass

        if stale_users:
            for stale in stale_users:
                report.add_finding(Finding(
                    severity=Severity.MEDIUM,
                    category=Category.IAM,
                    check="Unused credentials (90+ days)",
                    status=Status.WARNING,
                    resource=stale.split(" (")[0],
                    details=stale,
                    soc2_mapping="CC6.2",
                    provider="AWS",
                ))
        else:
            report.add_finding(Finding(
                severity=Severity.INFO,
                category=Category.IAM,
                check="Unused credentials (90+ days)",
                status=Status.PASS,
                resource="All IAM users",
                details="No credentials unused for 90+ days.",
                soc2_mapping="CC6.2",
                provider="AWS",
            ))
    except ClientError as exc:
        report.add_finding(Finding(
            severity=Severity.MEDIUM,
            category=Category.IAM,
            check="Unused credentials (90+ days)",
            status=Status.ERROR,
            resource="Credential report",
            details=f"Unable to generate credential report: {exc}",
            soc2_mapping="CC6.2",
            provider="AWS",
        ))


def check_users_without_mfa(session: boto3.Session, report: AuditReport) -> None:
    """CC6.1 - Find IAM users with console access but no MFA."""
    iam = session.client("iam")
    try:
        paginator = iam.get_paginator("list_users")
        no_mfa_users: List[str] = []

        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                # Check if user has console access (login profile)
                try:
                    iam.get_login_profile(UserName=username)
                except iam.exceptions.NoSuchEntityException:
                    continue  # No console access, skip
                except ClientError:
                    continue

                # Check MFA devices
                try:
                    mfa_resp = iam.list_mfa_devices(UserName=username)
                    if not mfa_resp["MFADevices"]:
                        no_mfa_users.append(username)
                except ClientError:
                    pass

        if no_mfa_users:
            for user in no_mfa_users:
                report.add_finding(Finding(
                    severity=Severity.HIGH,
                    category=Category.IAM,
                    check="IAM users without MFA",
                    status=Status.FAIL,
                    resource=f"arn:aws:iam::{report.account_id}:user/{user}",
                    details=f"Console user '{user}' does not have MFA enabled.",
                    soc2_mapping="CC6.1",
                    provider="AWS",
                ))
        else:
            report.add_finding(Finding(
                severity=Severity.INFO,
                category=Category.IAM,
                check="IAM users without MFA",
                status=Status.PASS,
                resource="All console users",
                details="All IAM users with console access have MFA enabled.",
                soc2_mapping="CC6.1",
                provider="AWS",
            ))
    except ClientError as exc:
        report.add_finding(Finding(
            severity=Severity.HIGH,
            category=Category.IAM,
            check="IAM users without MFA",
            status=Status.ERROR,
            resource="IAM",
            details=f"Unable to list users or MFA devices: {exc}",
            soc2_mapping="CC6.1",
            provider="AWS",
        ))


def check_overly_permissive_policies(session: boto3.Session, report: AuditReport) -> None:
    """CC6.3 - Detect customer-managed policies with Action: * and Resource: *."""
    iam = session.client("iam")
    try:
        paginator = iam.get_paginator("list_policies")
        wild_policies: List[str] = []

        for page in paginator.paginate(Scope="Local", OnlyAttached=True):
            for policy in page["Policies"]:
                arn = policy["Arn"]
                version_id = policy["DefaultVersionId"]
                try:
                    version = iam.get_policy_version(
                        PolicyArn=arn, VersionId=version_id
                    )
                    doc = version["PolicyVersion"]["Document"]
                    if isinstance(doc, str):
                        doc = json.loads(doc)
                    statements = doc.get("Statement", [])
                    if isinstance(statements, dict):
                        statements = [statements]
                    for stmt in statements:
                        if stmt.get("Effect") == "Allow":
                            actions = stmt.get("Action", [])
                            resources = stmt.get("Resource", [])
                            if isinstance(actions, str):
                                actions = [actions]
                            if isinstance(resources, str):
                                resources = [resources]
                            if "*" in actions and "*" in resources:
                                wild_policies.append(arn)
                                break
                except ClientError:
                    pass

        if wild_policies:
            for p in wild_policies:
                report.add_finding(Finding(
                    severity=Severity.HIGH,
                    category=Category.IAM,
                    check="Overly permissive policies",
                    status=Status.FAIL,
                    resource=p,
                    details="Policy grants Action:* on Resource:* (full admin). Review for least privilege.",
                    soc2_mapping="CC6.3",
                    provider="AWS",
                ))
        else:
            report.add_finding(Finding(
                severity=Severity.INFO,
                category=Category.IAM,
                check="Overly permissive policies",
                status=Status.PASS,
                resource="Customer-managed policies",
                details="No attached customer-managed policies with Action:* Resource:* found.",
                soc2_mapping="CC6.3",
                provider="AWS",
            ))
    except ClientError as exc:
        report.add_finding(Finding(
            severity=Severity.HIGH,
            category=Category.IAM,
            check="Overly permissive policies",
            status=Status.ERROR,
            resource="IAM policies",
            details=f"Unable to evaluate policies: {exc}",
            soc2_mapping="CC6.3",
            provider="AWS",
        ))


def check_access_key_age(session: boto3.Session, report: AuditReport) -> None:
    """CC6.2 - Check for access keys older than 90 days."""
    iam = session.client("iam")
    try:
        paginator = iam.get_paginator("list_users")
        now = datetime.now(timezone.utc)
        old_keys: List[str] = []

        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                try:
                    keys_resp = iam.list_access_keys(UserName=username)
                    for key_meta in keys_resp["AccessKeyMetadata"]:
                        if key_meta["Status"] == "Active":
                            age = (now - key_meta["CreateDate"]).days
                            if age > 90:
                                old_keys.append(
                                    f"{username}/{key_meta['AccessKeyId']} ({age} days old)"
                                )
                except ClientError:
                    pass

        if old_keys:
            for k in old_keys:
                report.add_finding(Finding(
                    severity=Severity.MEDIUM,
                    category=Category.IAM,
                    check="Access key age (>90 days)",
                    status=Status.WARNING,
                    resource=k.split(" ")[0],
                    details=k,
                    soc2_mapping="CC6.2",
                    provider="AWS",
                ))
        else:
            report.add_finding(Finding(
                severity=Severity.INFO,
                category=Category.IAM,
                check="Access key age (>90 days)",
                status=Status.PASS,
                resource="All IAM users",
                details="All active access keys are under 90 days old.",
                soc2_mapping="CC6.2",
                provider="AWS",
            ))
    except ClientError as exc:
        report.add_finding(Finding(
            severity=Severity.MEDIUM,
            category=Category.IAM,
            check="Access key age (>90 days)",
            status=Status.ERROR,
            resource="IAM",
            details=f"Unable to check access key ages: {exc}",
            soc2_mapping="CC6.2",
            provider="AWS",
        ))


# ---------------------------------------------------------------------------
# S3 checks
# ---------------------------------------------------------------------------

def check_s3_public_buckets(session: boto3.Session, report: AuditReport) -> None:
    """CC6.6 - Identify S3 buckets with public access."""
    s3 = session.client("s3")
    s3control = session.client("s3control")
    try:
        # Check account-level public access block first
        try:
            account_block = s3control.get_public_access_block(AccountId=report.account_id)
            config = account_block["PublicAccessBlockConfiguration"]
            all_blocked = all([
                config.get("BlockPublicAcls", False),
                config.get("IgnorePublicAcls", False),
                config.get("BlockPublicPolicy", False),
                config.get("RestrictPublicBuckets", False),
            ])
            if all_blocked:
                report.add_finding(Finding(
                    severity=Severity.INFO,
                    category=Category.NETWORK,
                    check="S3 account-level public access block",
                    status=Status.PASS,
                    resource=f"Account {report.account_id}",
                    details="All S3 public access is blocked at the account level.",
                    soc2_mapping="CC6.6",
                    provider="AWS",
                ))
            else:
                report.add_finding(Finding(
                    severity=Severity.HIGH,
                    category=Category.NETWORK,
                    check="S3 account-level public access block",
                    status=Status.FAIL,
                    resource=f"Account {report.account_id}",
                    details="Account-level S3 public access block is not fully enabled.",
                    soc2_mapping="CC6.6",
                    provider="AWS",
                ))
        except ClientError:
            report.add_finding(Finding(
                severity=Severity.HIGH,
                category=Category.NETWORK,
                check="S3 account-level public access block",
                status=Status.WARNING,
                resource=f"Account {report.account_id}",
                details="Unable to check account-level public access block.",
                soc2_mapping="CC6.6",
                provider="AWS",
            ))

        # Per-bucket checks
        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets:
            name = bucket["Name"]
            try:
                pub_block = s3.get_public_access_block(Bucket=name)
                cfg = pub_block["PublicAccessBlockConfiguration"]
                blocked = all([
                    cfg.get("BlockPublicAcls", False),
                    cfg.get("IgnorePublicAcls", False),
                    cfg.get("BlockPublicPolicy", False),
                    cfg.get("RestrictPublicBuckets", False),
                ])
                if not blocked:
                    report.add_finding(Finding(
                        severity=Severity.HIGH,
                        category=Category.NETWORK,
                        check="S3 bucket public access block",
                        status=Status.FAIL,
                        resource=name,
                        details=f"Bucket '{name}' does not have all public access blocks enabled.",
                        soc2_mapping="CC6.6",
                        provider="AWS",
                    ))
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                    report.add_finding(Finding(
                        severity=Severity.HIGH,
                        category=Category.NETWORK,
                        check="S3 bucket public access block",
                        status=Status.FAIL,
                        resource=name,
                        details=f"Bucket '{name}' has no public access block configuration.",
                        soc2_mapping="CC6.6",
                        provider="AWS",
                    ))

    except ClientError as exc:
        report.add_finding(Finding(
            severity=Severity.HIGH,
            category=Category.NETWORK,
            check="S3 public bucket check",
            status=Status.ERROR,
            resource="S3",
            details=f"Unable to check S3 buckets: {exc}",
            soc2_mapping="CC6.6",
            provider="AWS",
        ))


def check_s3_encryption(session: boto3.Session, report: AuditReport) -> None:
    """CC6.7 - Verify S3 bucket default encryption."""
    s3 = session.client("s3")
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets:
            name = bucket["Name"]
            try:
                enc = s3.get_bucket_encryption(Bucket=name)
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                if rules:
                    algo = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get(
                        "SSEAlgorithm", "none"
                    )
                    report.add_finding(Finding(
                        severity=Severity.INFO,
                        category=Category.ENCRYPTION,
                        check="S3 default encryption",
                        status=Status.PASS,
                        resource=name,
                        details=f"Default encryption: {algo}",
                        soc2_mapping="CC6.7",
                        provider="AWS",
                    ))
                else:
                    report.add_finding(Finding(
                        severity=Severity.HIGH,
                        category=Category.ENCRYPTION,
                        check="S3 default encryption",
                        status=Status.FAIL,
                        resource=name,
                        details=f"Bucket '{name}' does not have default encryption configured.",
                        soc2_mapping="CC6.7",
                        provider="AWS",
                    ))
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "ServerSideEncryptionConfigurationNotFoundError":
                    report.add_finding(Finding(
                        severity=Severity.HIGH,
                        category=Category.ENCRYPTION,
                        check="S3 default encryption",
                        status=Status.FAIL,
                        resource=name,
                        details=f"Bucket '{name}' has no encryption configuration.",
                        soc2_mapping="CC6.7",
                        provider="AWS",
                    ))
    except ClientError as exc:
        report.add_finding(Finding(
            severity=Severity.HIGH,
            category=Category.ENCRYPTION,
            check="S3 default encryption",
            status=Status.ERROR,
            resource="S3",
            details=f"Unable to check S3 encryption: {exc}",
            soc2_mapping="CC6.7",
            provider="AWS",
        ))


def check_s3_versioning(session: boto3.Session, report: AuditReport) -> None:
    """A1.2 - Check S3 bucket versioning for data recovery."""
    s3 = session.client("s3")
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets:
            name = bucket["Name"]
            try:
                ver = s3.get_bucket_versioning(Bucket=name)
                status_val = ver.get("Status", "Disabled")
                if status_val == "Enabled":
                    report.add_finding(Finding(
                        severity=Severity.INFO,
                        category=Category.BACKUPS,
                        check="S3 versioning",
                        status=Status.PASS,
                        resource=name,
                        details="Versioning enabled.",
                        soc2_mapping="A1.2",
                        provider="AWS",
                    ))
                else:
                    report.add_finding(Finding(
                        severity=Severity.MEDIUM,
                        category=Category.BACKUPS,
                        check="S3 versioning",
                        status=Status.WARNING,
                        resource=name,
                        details=f"Versioning is {status_val}. Enable for data protection.",
                        soc2_mapping="A1.2",
                        provider="AWS",
                    ))
            except ClientError:
                pass
    except ClientError as exc:
        report.add_finding(Finding(
            severity=Severity.MEDIUM,
            category=Category.BACKUPS,
            check="S3 versioning",
            status=Status.ERROR,
            resource="S3",
            details=f"Unable to check versioning: {exc}",
            soc2_mapping="A1.2",
            provider="AWS",
        ))


def check_s3_access_logging(session: boto3.Session, report: AuditReport) -> None:
    """CC7.2 - Check S3 bucket access logging."""
    s3 = session.client("s3")
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets:
            name = bucket["Name"]
            try:
                logging_conf = s3.get_bucket_logging(Bucket=name)
                if logging_conf.get("LoggingEnabled"):
                    report.add_finding(Finding(
                        severity=Severity.INFO,
                        category=Category.LOGGING,
                        check="S3 access logging",
                        status=Status.PASS,
                        resource=name,
                        details="Server access logging enabled.",
                        soc2_mapping="CC7.2",
                        provider="AWS",
                    ))
                else:
                    report.add_finding(Finding(
                        severity=Severity.LOW,
                        category=Category.LOGGING,
                        check="S3 access logging",
                        status=Status.WARNING,
                        resource=name,
                        details=f"Bucket '{name}' does not have access logging enabled.",
                        soc2_mapping="CC7.2",
                        provider="AWS",
                    ))
            except ClientError:
                pass
    except ClientError as exc:
        report.add_finding(Finding(
            severity=Severity.LOW,
            category=Category.LOGGING,
            check="S3 access logging",
            status=Status.ERROR,
            resource="S3",
            details=f"Unable to check S3 logging: {exc}",
            soc2_mapping="CC7.2",
            provider="AWS",
        ))


# ---------------------------------------------------------------------------
# CloudTrail checks
# ---------------------------------------------------------------------------

def check_cloudtrail(session: boto3.Session, report: AuditReport) -> None:
    """CC7.1 - Verify CloudTrail configuration."""
    ct = session.client("cloudtrail")
    try:
        trails = ct.describe_trails().get("trailList", [])
        if not trails:
            report.add_finding(Finding(
                severity=Severity.CRITICAL,
                category=Category.LOGGING,
                check="CloudTrail enabled",
                status=Status.FAIL,
                resource="Account",
                details="No CloudTrail trails configured. API activity is not being logged.",
                soc2_mapping="CC7.1",
                provider="AWS",
            ))
            return

        has_multiregion = False
        for trail in trails:
            trail_name = trail.get("Name", "unknown")
            trail_arn = trail.get("TrailARN", trail_name)

            # Multi-region
            if trail.get("IsMultiRegionTrail", False):
                has_multiregion = True

            # Log file validation
            validation = trail.get("LogFileValidationEnabled", False)
            report.add_finding(Finding(
                severity=Severity.MEDIUM if not validation else Severity.INFO,
                category=Category.LOGGING,
                check="CloudTrail log file validation",
                status=Status.PASS if validation else Status.FAIL,
                resource=trail_arn,
                details="" if validation else "Log file integrity validation is not enabled.",
                soc2_mapping="CC7.1",
                provider="AWS",
            ))

            # Check if trail is logging
            try:
                status_resp = ct.get_trail_status(Name=trail_arn)
                is_logging = status_resp.get("IsLogging", False)
                if not is_logging:
                    report.add_finding(Finding(
                        severity=Severity.CRITICAL,
                        category=Category.LOGGING,
                        check="CloudTrail logging active",
                        status=Status.FAIL,
                        resource=trail_arn,
                        details=f"Trail '{trail_name}' exists but is not actively logging.",
                        soc2_mapping="CC7.1",
                        provider="AWS",
                    ))
            except ClientError:
                pass

        report.add_finding(Finding(
            severity=Severity.HIGH if not has_multiregion else Severity.INFO,
            category=Category.LOGGING,
            check="CloudTrail multi-region",
            status=Status.PASS if has_multiregion else Status.FAIL,
            resource="Account",
            details="" if has_multiregion else "No multi-region trail found. Activity in some regions may not be logged.",
            soc2_mapping="CC7.1",
            provider="AWS",
        ))

    except ClientError as exc:
        report.add_finding(Finding(
            severity=Severity.CRITICAL,
            category=Category.LOGGING,
            check="CloudTrail",
            status=Status.ERROR,
            resource="CloudTrail",
            details=f"Unable to describe trails: {exc}",
            soc2_mapping="CC7.1",
            provider="AWS",
        ))


# ---------------------------------------------------------------------------
# EC2 / VPC checks
# ---------------------------------------------------------------------------

SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
}


def check_security_groups(session: boto3.Session, report: AuditReport) -> None:
    """CC6.6 - Find security groups with 0.0.0.0/0 on sensitive ports."""
    ec2 = session.client("ec2")
    try:
        paginator = ec2.get_paginator("describe_security_groups")
        open_findings: List[Finding] = []

        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                sg_id = sg["GroupId"]
                sg_name = sg.get("GroupName", "")
                for perm in sg.get("IpPermissions", []):
                    from_port = perm.get("FromPort", 0)
                    to_port = perm.get("ToPort", 65535)
                    for ip_range in perm.get("IpRanges", []):
                        cidr = ip_range.get("CidrIp", "")
                        if cidr in ("0.0.0.0/0",):
                            _check_port_range(
                                from_port, to_port, sg_id, sg_name,
                                cidr, open_findings, report,
                            )
                    for ip6_range in perm.get("Ipv6Ranges", []):
                        cidr6 = ip6_range.get("CidrIpv6", "")
                        if cidr6 == "::/0":
                            _check_port_range(
                                from_port, to_port, sg_id, sg_name,
                                cidr6, open_findings, report,
                            )

        if not open_findings:
            report.add_finding(Finding(
                severity=Severity.INFO,
                category=Category.NETWORK,
                check="Security groups open to world",
                status=Status.PASS,
                resource="All security groups",
                details="No sensitive ports open to 0.0.0.0/0 or ::/0.",
                soc2_mapping="CC6.6",
                provider="AWS",
            ))
        else:
            for f in open_findings:
                report.add_finding(f)

    except ClientError as exc:
        report.add_finding(Finding(
            severity=Severity.HIGH,
            category=Category.NETWORK,
            check="Security groups",
            status=Status.ERROR,
            resource="EC2",
            details=f"Unable to describe security groups: {exc}",
            soc2_mapping="CC6.6",
            provider="AWS",
        ))


def _check_port_range(
    from_port: int, to_port: int, sg_id: str, sg_name: str,
    cidr: str, findings_list: List[Finding], report: AuditReport,
) -> None:
    """Helper to check if a port range overlaps sensitive ports."""
    for port, service in SENSITIVE_PORTS.items():
        if from_port <= port <= to_port:
            sev = Severity.CRITICAL if port in (22, 3389) else Severity.HIGH
            f = Finding(
                severity=sev,
                category=Category.NETWORK,
                check="Security group open to world",
                status=Status.FAIL,
                resource=f"{sg_id} ({sg_name})",
                details=f"Port {port} ({service}) open to {cidr}.",
                soc2_mapping="CC6.6",
                provider="AWS",
            )
            findings_list.append(f)


def check_default_vpc(session: boto3.Session, report: AuditReport) -> None:
    """CC6.6 - Check for resources in the default VPC."""
    ec2 = session.client("ec2")
    try:
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])
        default_vpcs = vpcs.get("Vpcs", [])
        if not default_vpcs:
            report.add_finding(Finding(
                severity=Severity.INFO,
                category=Category.NETWORK,
                check="Default VPC usage",
                status=Status.PASS,
                resource="VPC",
                details="No default VPC found in this region.",
                soc2_mapping="CC6.6",
                provider="AWS",
            ))
            return

        for vpc in default_vpcs:
            vpc_id = vpc["VpcId"]
            # Check if any instances run in the default VPC
            instances = ec2.describe_instances(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
            )
            instance_count = sum(
                len(r["Instances"]) for r in instances.get("Reservations", [])
            )
            if instance_count > 0:
                report.add_finding(Finding(
                    severity=Severity.MEDIUM,
                    category=Category.NETWORK,
                    check="Default VPC usage",
                    status=Status.WARNING,
                    resource=vpc_id,
                    details=f"{instance_count} instance(s) running in default VPC. Use custom VPCs.",
                    soc2_mapping="CC6.6",
                    provider="AWS",
                ))
            else:
                report.add_finding(Finding(
                    severity=Severity.INFO,
                    category=Category.NETWORK,
                    check="Default VPC usage",
                    status=Status.PASS,
                    resource=vpc_id,
                    details="Default VPC exists but has no running instances.",
                    soc2_mapping="CC6.6",
                    provider="AWS",
                ))
    except ClientError as exc:
        report.add_finding(Finding(
            severity=Severity.MEDIUM,
            category=Category.NETWORK,
            check="Default VPC usage",
            status=Status.ERROR,
            resource="VPC",
            details=f"Unable to check default VPC: {exc}",
            soc2_mapping="CC6.6",
            provider="AWS",
        ))


def check_ebs_encryption(session: boto3.Session, report: AuditReport) -> None:
    """CC6.7 - Check if EBS volumes are encrypted."""
    ec2 = session.client("ec2")
    try:
        paginator = ec2.get_paginator("describe_volumes")
        unencrypted: List[str] = []

        for page in paginator.paginate():
            for vol in page["Volumes"]:
                if not vol.get("Encrypted", False):
                    attachments = vol.get("Attachments", [])
                    instance_id = attachments[0]["InstanceId"] if attachments else "detached"
                    unencrypted.append(f"{vol['VolumeId']} (attached to {instance_id})")

        if unencrypted:
            for v in unencrypted:
                report.add_finding(Finding(
                    severity=Severity.MEDIUM,
                    category=Category.ENCRYPTION,
                    check="EBS volume encryption",
                    status=Status.WARNING,
                    resource=v.split(" ")[0],
                    details=f"Unencrypted EBS volume: {v}",
                    soc2_mapping="CC6.7",
                    provider="AWS",
                ))
        else:
            report.add_finding(Finding(
                severity=Severity.INFO,
                category=Category.ENCRYPTION,
                check="EBS volume encryption",
                status=Status.PASS,
                resource="All EBS volumes",
                details="All EBS volumes are encrypted.",
                soc2_mapping="CC6.7",
                provider="AWS",
            ))
    except ClientError as exc:
        report.add_finding(Finding(
            severity=Severity.MEDIUM,
            category=Category.ENCRYPTION,
            check="EBS volume encryption",
            status=Status.ERROR,
            resource="EBS",
            details=f"Unable to check EBS encryption: {exc}",
            soc2_mapping="CC6.7",
            provider="AWS",
        ))


# ---------------------------------------------------------------------------
# RDS checks
# ---------------------------------------------------------------------------

def check_rds(session: boto3.Session, report: AuditReport) -> None:
    """Check RDS instances for public access, encryption, backups, multi-AZ."""
    rds = session.client("rds")
    try:
        paginator = rds.get_paginator("describe_db_instances")
        found_any = False

        for page in paginator.paginate():
            for db in page["DBInstances"]:
                found_any = True
                db_id = db["DBInstanceIdentifier"]
                db_arn = db["DBInstanceArn"]

                # Public accessibility (CC6.6)
                public = db.get("PubliclyAccessible", False)
                report.add_finding(Finding(
                    severity=Severity.CRITICAL if public else Severity.INFO,
                    category=Category.NETWORK,
                    check="RDS public accessibility",
                    status=Status.FAIL if public else Status.PASS,
                    resource=db_id,
                    details=f"RDS instance '{db_id}' is publicly accessible!" if public else "",
                    soc2_mapping="CC6.6",
                    provider="AWS",
                ))

                # Encryption at rest (CC6.7)
                encrypted = db.get("StorageEncrypted", False)
                report.add_finding(Finding(
                    severity=Severity.HIGH if not encrypted else Severity.INFO,
                    category=Category.ENCRYPTION,
                    check="RDS encryption at rest",
                    status=Status.PASS if encrypted else Status.FAIL,
                    resource=db_id,
                    details="" if encrypted else f"RDS instance '{db_id}' storage is not encrypted.",
                    soc2_mapping="CC6.7",
                    provider="AWS",
                ))

                # Automated backups (A1.2)
                retention = db.get("BackupRetentionPeriod", 0)
                report.add_finding(Finding(
                    severity=Severity.HIGH if retention == 0 else (Severity.MEDIUM if retention < 7 else Severity.INFO),
                    category=Category.BACKUPS,
                    check="RDS automated backups",
                    status=Status.FAIL if retention == 0 else (Status.WARNING if retention < 7 else Status.PASS),
                    resource=db_id,
                    details=f"Backup retention: {retention} days." + (" Enable automated backups." if retention == 0 else ""),
                    soc2_mapping="A1.2",
                    provider="AWS",
                ))

                # Multi-AZ (A1.2)
                multi_az = db.get("MultiAZ", False)
                report.add_finding(Finding(
                    severity=Severity.MEDIUM if not multi_az else Severity.INFO,
                    category=Category.BACKUPS,
                    check="RDS Multi-AZ",
                    status=Status.PASS if multi_az else Status.WARNING,
                    resource=db_id,
                    details="" if multi_az else f"RDS instance '{db_id}' is not configured for Multi-AZ.",
                    soc2_mapping="A1.2",
                    provider="AWS",
                ))

        if not found_any:
            report.add_finding(Finding(
                severity=Severity.INFO,
                category=Category.BACKUPS,
                check="RDS instances",
                status=Status.PASS,
                resource="RDS",
                details="No RDS instances found in this region.",
                soc2_mapping="A1.2",
                provider="AWS",
            ))

    except ClientError as exc:
        report.add_finding(Finding(
            severity=Severity.HIGH,
            category=Category.BACKUPS,
            check="RDS audit",
            status=Status.ERROR,
            resource="RDS",
            details=f"Unable to describe RDS instances: {exc}",
            soc2_mapping="A1.2",
            provider="AWS",
        ))


# ---------------------------------------------------------------------------
# KMS checks
# ---------------------------------------------------------------------------

def check_kms_rotation(session: boto3.Session, report: AuditReport) -> None:
    """CC6.7 - Verify KMS key rotation is enabled."""
    kms = session.client("kms")
    try:
        paginator = kms.get_paginator("list_keys")
        found_any = False

        for page in paginator.paginate():
            for key in page["Keys"]:
                key_id = key["KeyId"]
                try:
                    meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                    # Only check customer-managed symmetric keys
                    if meta.get("KeyManager") != "CUSTOMER":
                        continue
                    if meta.get("KeySpec") != "SYMMETRIC_DEFAULT":
                        continue
                    if meta.get("KeyState") != "Enabled":
                        continue

                    found_any = True
                    rotation = kms.get_key_rotation_status(KeyId=key_id)
                    rotating = rotation.get("KeyRotationEnabled", False)
                    alias = key_id
                    try:
                        aliases = kms.list_aliases(KeyId=key_id).get("Aliases", [])
                        if aliases:
                            alias = aliases[0].get("AliasName", key_id)
                    except ClientError:
                        pass

                    report.add_finding(Finding(
                        severity=Severity.MEDIUM if not rotating else Severity.INFO,
                        category=Category.ENCRYPTION,
                        check="KMS key rotation",
                        status=Status.PASS if rotating else Status.FAIL,
                        resource=alias,
                        details="" if rotating else f"Key rotation not enabled for {alias}.",
                        soc2_mapping="CC6.7",
                        provider="AWS",
                    ))
                except ClientError:
                    pass

        if not found_any:
            report.add_finding(Finding(
                severity=Severity.INFO,
                category=Category.ENCRYPTION,
                check="KMS key rotation",
                status=Status.PASS,
                resource="KMS",
                details="No customer-managed KMS keys found.",
                soc2_mapping="CC6.7",
                provider="AWS",
            ))

    except ClientError as exc:
        report.add_finding(Finding(
            severity=Severity.MEDIUM,
            category=Category.ENCRYPTION,
            check="KMS key rotation",
            status=Status.ERROR,
            resource="KMS",
            details=f"Unable to check KMS keys: {exc}",
            soc2_mapping="CC6.7",
            provider="AWS",
        ))


# ---------------------------------------------------------------------------
# CloudWatch checks
# ---------------------------------------------------------------------------

def check_cloudwatch_alarms(session: boto3.Session, report: AuditReport) -> None:
    """CC7.2 - Verify CloudWatch alarms are configured."""
    cw = session.client("cloudwatch")
    try:
        alarms = cw.describe_alarms(StateValue="OK")
        alarm_count = len(alarms.get("MetricAlarms", []))
        alarms_insuff = cw.describe_alarms(StateValue="INSUFFICIENT_DATA")
        alarm_count += len(alarms_insuff.get("MetricAlarms", []))
        alarms_alarm = cw.describe_alarms(StateValue="ALARM")
        alarm_count += len(alarms_alarm.get("MetricAlarms", []))
        in_alarm = len(alarms_alarm.get("MetricAlarms", []))

        if alarm_count == 0:
            report.add_finding(Finding(
                severity=Severity.MEDIUM,
                category=Category.POSTURE,
                check="CloudWatch alarms",
                status=Status.WARNING,
                resource="CloudWatch",
                details="No CloudWatch metric alarms configured. Set up alarms for key metrics.",
                soc2_mapping="CC7.2",
                provider="AWS",
            ))
        else:
            details = f"{alarm_count} alarm(s) configured."
            if in_alarm > 0:
                details += f" {in_alarm} currently in ALARM state."
            report.add_finding(Finding(
                severity=Severity.INFO,
                category=Category.POSTURE,
                check="CloudWatch alarms",
                status=Status.PASS,
                resource="CloudWatch",
                details=details,
                soc2_mapping="CC7.2",
                provider="AWS",
            ))
    except ClientError as exc:
        report.add_finding(Finding(
            severity=Severity.MEDIUM,
            category=Category.POSTURE,
            check="CloudWatch alarms",
            status=Status.ERROR,
            resource="CloudWatch",
            details=f"Unable to describe CloudWatch alarms: {exc}",
            soc2_mapping="CC7.2",
            provider="AWS",
        ))


# ---------------------------------------------------------------------------
# AWS Config checks
# ---------------------------------------------------------------------------

def check_aws_config(session: boto3.Session, report: AuditReport) -> None:
    """CC8.1 - Verify AWS Config is enabled and recording."""
    config = session.client("config")
    try:
        recorders = config.describe_configuration_recorder_status()
        recorder_statuses = recorders.get("ConfigurationRecordersStatus", [])

        if not recorder_statuses:
            report.add_finding(Finding(
                severity=Severity.HIGH,
                category=Category.GOVERNANCE,
                check="AWS Config enabled",
                status=Status.FAIL,
                resource="AWS Config",
                details="No AWS Config recorders found. Enable Config for change tracking.",
                soc2_mapping="CC8.1",
                provider="AWS",
            ))
        else:
            for rec in recorder_statuses:
                recording = rec.get("recording", False)
                name = rec.get("name", "default")
                report.add_finding(Finding(
                    severity=Severity.HIGH if not recording else Severity.INFO,
                    category=Category.GOVERNANCE,
                    check="AWS Config recording",
                    status=Status.PASS if recording else Status.FAIL,
                    resource=f"Config recorder: {name}",
                    details="" if recording else f"Config recorder '{name}' is not recording.",
                    soc2_mapping="CC8.1",
                    provider="AWS",
                ))
    except ClientError as exc:
        report.add_finding(Finding(
            severity=Severity.HIGH,
            category=Category.GOVERNANCE,
            check="AWS Config",
            status=Status.ERROR,
            resource="AWS Config",
            details=f"Unable to check AWS Config: {exc}",
            soc2_mapping="CC8.1",
            provider="AWS",
        ))


# ---------------------------------------------------------------------------
# CLI and main
# ---------------------------------------------------------------------------

@click.command()
@click.option("--profile", default=None, help="AWS CLI profile name.")
@click.option("--region", default=None, help="AWS region (defaults to session default).")
@click.option(
    "--output-format",
    type=click.Choice(["markdown", "json", "both"]),
    default="markdown",
    help="Report output format.",
)
@click.option("--output-dir", default="reports", help="Directory for report output.")
def main(profile: Optional[str], region: Optional[str], output_format: str, output_dir: str) -> None:
    """
    Run a comprehensive AWS security audit.

    All checks are read-only. No resources are modified.
    Maintained by TrazTech (https://traztech.ca).
    """
    print_banner("AWS")

    session = _get_session(profile, region)
    account_id = _get_account_id(session)
    effective_region = session.region_name or "us-east-1"

    report = AuditReport(
        provider="AWS",
        account_id=account_id,
        region=effective_region,
        metadata={
            "profile": profile or "default",
            "tool": "cloud-security-audit-scripts",
            "maintainer": "TrazTech (https://traztech.ca)",
        },
    )

    console.print(f"\n[bold]Account:[/bold] {account_id}")
    console.print(f"[bold]Region:[/bold]  {effective_region}\n")

    checks = [
        ("IAM: Root MFA", check_root_mfa),
        ("IAM: Password policy", check_password_policy),
        ("IAM: Unused credentials", check_unused_credentials),
        ("IAM: Users without MFA", check_users_without_mfa),
        ("IAM: Overly permissive policies", check_overly_permissive_policies),
        ("IAM: Access key age", check_access_key_age),
        ("S3: Public buckets", check_s3_public_buckets),
        ("S3: Encryption", check_s3_encryption),
        ("S3: Versioning", check_s3_versioning),
        ("S3: Access logging", check_s3_access_logging),
        ("CloudTrail", check_cloudtrail),
        ("EC2/VPC: Security groups", check_security_groups),
        ("EC2/VPC: Default VPC", check_default_vpc),
        ("EC2: EBS encryption", check_ebs_encryption),
        ("RDS", check_rds),
        ("KMS: Key rotation", check_kms_rotation),
        ("CloudWatch: Alarms", check_cloudwatch_alarms),
        ("AWS Config", check_aws_config),
    ]

    for label, check_fn in checks:
        console.print(f"[cyan]Checking {label}...[/cyan]")
        try:
            check_fn(session, report)
        except Exception as exc:
            console.print(f"[red]  Unexpected error in {label}: {exc}[/red]")

    # Print findings
    console.print("\n[bold]--- Findings ---[/bold]\n")
    for finding in report.findings:
        print_finding(finding)

    print_summary(report)

    # Generate reports
    os.makedirs(output_dir, exist_ok=True)
    gen = ReportGenerator()
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = f"aws-audit-{account_id}-{ts}"

    if output_format in ("markdown", "both"):
        md_path = os.path.join(output_dir, f"{base}.md")
        gen.to_markdown(report, md_path)
        console.print(f"\n[green]Markdown report:[/green] {md_path}")

    if output_format in ("json", "both"):
        json_path = os.path.join(output_dir, f"{base}.json")
        gen.to_json(report, json_path)
        console.print(f"[green]JSON report:[/green] {json_path}")

    console.print(
        "\n[dim]For a comprehensive cloud security assessment, visit "
        "https://traztech.ca/tools/cloud-security-posture-check[/dim]\n"
    )


if __name__ == "__main__":
    main()
