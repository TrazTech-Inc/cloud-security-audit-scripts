#!/usr/bin/env python3
"""
AWS S3 Security Audit Script

Focused security audit for Amazon S3 buckets. Checks:
- Public access (account-level and per-bucket blocks)
- Bucket policies for public/wildcard principals
- Default encryption configuration
- Versioning and MFA delete
- Server access logging
- Object Lock (WORM)
- SSL-only enforcement in bucket policy
- Cross-region replication

All operations are read-only. No bucket configurations are modified.

Usage:
    python aws/aws_s3_audit.py --profile production
    python aws/aws_s3_audit.py --bucket my-specific-bucket --output-format json

Maintained by TrazTech (https://traztech.ca)
Blog: https://traztech.ca/blog -- 100+ articles on cloud security
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import click

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
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


def _get_session(profile: Optional[str], region: Optional[str]) -> boto3.Session:
    kwargs: Dict[str, str] = {}
    if profile:
        kwargs["profile_name"] = profile
    if region:
        kwargs["region_name"] = region
    return boto3.Session(**kwargs)


def _get_account_id(session: boto3.Session) -> str:
    try:
        return session.client("sts").get_caller_identity()["Account"]
    except (ClientError, NoCredentialsError) as exc:
        console.print(f"[red]Failed to get account ID: {exc}[/red]")
        return "unknown"


def _list_buckets(s3, bucket_filter: Optional[str]) -> List[Dict]:
    """List S3 buckets, optionally filtering to a single one."""
    buckets = s3.list_buckets().get("Buckets", [])
    if bucket_filter:
        buckets = [b for b in buckets if b["Name"] == bucket_filter]
        if not buckets:
            console.print(f"[red]Bucket '{bucket_filter}' not found.[/red]")
    return buckets


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_account_public_access_block(session: boto3.Session, report: AuditReport) -> None:
    """Check the account-level S3 public access block."""
    s3control = session.client("s3control")
    try:
        resp = s3control.get_public_access_block(AccountId=report.account_id)
        cfg = resp["PublicAccessBlockConfiguration"]
        settings = {
            "BlockPublicAcls": cfg.get("BlockPublicAcls", False),
            "IgnorePublicAcls": cfg.get("IgnorePublicAcls", False),
            "BlockPublicPolicy": cfg.get("BlockPublicPolicy", False),
            "RestrictPublicBuckets": cfg.get("RestrictPublicBuckets", False),
        }
        all_on = all(settings.values())
        disabled = [k for k, v in settings.items() if not v]

        report.add_finding(Finding(
            severity=Severity.INFO if all_on else Severity.HIGH,
            category=Category.NETWORK,
            check="S3 account-level public access block",
            status=Status.PASS if all_on else Status.FAIL,
            resource=f"Account {report.account_id}",
            details="" if all_on else f"Disabled settings: {', '.join(disabled)}",
            soc2_mapping="CC6.6",
            provider="AWS",
        ))
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            report.add_finding(Finding(
                severity=Severity.HIGH,
                category=Category.NETWORK,
                check="S3 account-level public access block",
                status=Status.FAIL,
                resource=f"Account {report.account_id}",
                details="No account-level public access block configured.",
                soc2_mapping="CC6.6",
                provider="AWS",
            ))
        else:
            report.add_finding(Finding(
                severity=Severity.MEDIUM,
                category=Category.NETWORK,
                check="S3 account-level public access block",
                status=Status.ERROR,
                resource=f"Account {report.account_id}",
                details=f"Unable to check: {e}",
                soc2_mapping="CC6.6",
                provider="AWS",
            ))


def check_bucket_public_access(s3, bucket_name: str, report: AuditReport) -> None:
    """Check per-bucket public access block."""
    try:
        resp = s3.get_public_access_block(Bucket=bucket_name)
        cfg = resp["PublicAccessBlockConfiguration"]
        all_on = all([
            cfg.get("BlockPublicAcls", False),
            cfg.get("IgnorePublicAcls", False),
            cfg.get("BlockPublicPolicy", False),
            cfg.get("RestrictPublicBuckets", False),
        ])
        if not all_on:
            disabled = [
                k for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
                if not cfg.get(k, False)
            ]
            report.add_finding(Finding(
                severity=Severity.HIGH,
                category=Category.NETWORK,
                check="Bucket public access block",
                status=Status.FAIL,
                resource=bucket_name,
                details=f"Disabled: {', '.join(disabled)}",
                soc2_mapping="CC6.6",
                provider="AWS",
            ))
        else:
            report.add_finding(Finding(
                severity=Severity.INFO,
                category=Category.NETWORK,
                check="Bucket public access block",
                status=Status.PASS,
                resource=bucket_name,
                details="All public access block settings enabled.",
                soc2_mapping="CC6.6",
                provider="AWS",
            ))
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            report.add_finding(Finding(
                severity=Severity.HIGH,
                category=Category.NETWORK,
                check="Bucket public access block",
                status=Status.FAIL,
                resource=bucket_name,
                details="No public access block configuration.",
                soc2_mapping="CC6.6",
                provider="AWS",
            ))


def check_bucket_policy_public(s3, bucket_name: str, report: AuditReport) -> None:
    """Check bucket policy for wildcard principals (public access)."""
    try:
        policy_str = s3.get_bucket_policy(Bucket=bucket_name)["Policy"]
        policy = json.loads(policy_str)
        stmts = policy.get("Statement", [])
        public_stmts: List[str] = []

        for stmt in stmts:
            principal = stmt.get("Principal", {})
            effect = stmt.get("Effect", "")
            if effect != "Allow":
                continue
            # Check for wildcard principal
            if principal == "*" or principal == {"AWS": "*"}:
                sid = stmt.get("Sid", "unnamed")
                # Check if there's a condition that restricts it
                if not stmt.get("Condition"):
                    public_stmts.append(sid)

        if public_stmts:
            report.add_finding(Finding(
                severity=Severity.CRITICAL,
                category=Category.NETWORK,
                check="Bucket policy public access",
                status=Status.FAIL,
                resource=bucket_name,
                details=f"Policy allows public access (wildcard principal) in statement(s): {', '.join(public_stmts)}",
                soc2_mapping="CC6.6",
                provider="AWS",
            ))
        else:
            report.add_finding(Finding(
                severity=Severity.INFO,
                category=Category.NETWORK,
                check="Bucket policy public access",
                status=Status.PASS,
                resource=bucket_name,
                details="No unrestricted wildcard principals in bucket policy.",
                soc2_mapping="CC6.6",
                provider="AWS",
            ))
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
            report.add_finding(Finding(
                severity=Severity.INFO,
                category=Category.NETWORK,
                check="Bucket policy public access",
                status=Status.PASS,
                resource=bucket_name,
                details="No bucket policy attached.",
                soc2_mapping="CC6.6",
                provider="AWS",
            ))


def check_bucket_policy_ssl(s3, bucket_name: str, report: AuditReport) -> None:
    """Check if bucket policy enforces SSL-only (aws:SecureTransport)."""
    try:
        policy_str = s3.get_bucket_policy(Bucket=bucket_name)["Policy"]
        policy = json.loads(policy_str)
        stmts = policy.get("Statement", [])
        ssl_enforced = False

        for stmt in stmts:
            if stmt.get("Effect") == "Deny":
                condition = stmt.get("Condition", {})
                bool_cond = condition.get("Bool", {})
                if bool_cond.get("aws:SecureTransport") == "false":
                    ssl_enforced = True
                    break

        report.add_finding(Finding(
            severity=Severity.MEDIUM if not ssl_enforced else Severity.INFO,
            category=Category.ENCRYPTION,
            check="Bucket SSL-only policy",
            status=Status.PASS if ssl_enforced else Status.WARNING,
            resource=bucket_name,
            details="" if ssl_enforced else "No deny statement for aws:SecureTransport=false. Consider enforcing HTTPS.",
            soc2_mapping="CC6.7",
            provider="AWS",
        ))
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
            report.add_finding(Finding(
                severity=Severity.MEDIUM,
                category=Category.ENCRYPTION,
                check="Bucket SSL-only policy",
                status=Status.WARNING,
                resource=bucket_name,
                details="No bucket policy; SSL not enforced at policy level.",
                soc2_mapping="CC6.7",
                provider="AWS",
            ))


def check_encryption(s3, bucket_name: str, report: AuditReport) -> None:
    """Check default encryption configuration."""
    try:
        enc = s3.get_bucket_encryption(Bucket=bucket_name)
        rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        if rules:
            algo = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "unknown")
            kms_key = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("KMSMasterKeyID", "")
            details = f"Algorithm: {algo}"
            if kms_key:
                details += f", KMS Key: {kms_key}"
            report.add_finding(Finding(
                severity=Severity.INFO,
                category=Category.ENCRYPTION,
                check="Default encryption",
                status=Status.PASS,
                resource=bucket_name,
                details=details,
                soc2_mapping="CC6.7",
                provider="AWS",
            ))
        else:
            report.add_finding(Finding(
                severity=Severity.HIGH,
                category=Category.ENCRYPTION,
                check="Default encryption",
                status=Status.FAIL,
                resource=bucket_name,
                details="No default encryption rules configured.",
                soc2_mapping="CC6.7",
                provider="AWS",
            ))
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            report.add_finding(Finding(
                severity=Severity.HIGH,
                category=Category.ENCRYPTION,
                check="Default encryption",
                status=Status.FAIL,
                resource=bucket_name,
                details="No encryption configuration found.",
                soc2_mapping="CC6.7",
                provider="AWS",
            ))


def check_versioning(s3, bucket_name: str, report: AuditReport) -> None:
    """Check bucket versioning and MFA delete."""
    try:
        ver = s3.get_bucket_versioning(Bucket=bucket_name)
        status_val = ver.get("Status", "Disabled")
        mfa_delete = ver.get("MFADelete", "Disabled")

        report.add_finding(Finding(
            severity=Severity.INFO if status_val == "Enabled" else Severity.MEDIUM,
            category=Category.BACKUPS,
            check="Bucket versioning",
            status=Status.PASS if status_val == "Enabled" else Status.WARNING,
            resource=bucket_name,
            details=f"Versioning: {status_val}" if status_val == "Enabled" else "Versioning not enabled. Enable for data protection.",
            soc2_mapping="A1.2",
            provider="AWS",
        ))

        if status_val == "Enabled":
            report.add_finding(Finding(
                severity=Severity.LOW if mfa_delete != "Enabled" else Severity.INFO,
                category=Category.BACKUPS,
                check="MFA delete",
                status=Status.PASS if mfa_delete == "Enabled" else Status.WARNING,
                resource=bucket_name,
                details="" if mfa_delete == "Enabled" else "MFA delete not enabled. Consider for critical buckets.",
                soc2_mapping="A1.2",
                provider="AWS",
            ))
    except ClientError:
        pass


def check_logging(s3, bucket_name: str, report: AuditReport) -> None:
    """Check server access logging."""
    try:
        log_conf = s3.get_bucket_logging(Bucket=bucket_name)
        enabled = log_conf.get("LoggingEnabled") is not None
        report.add_finding(Finding(
            severity=Severity.INFO if enabled else Severity.LOW,
            category=Category.LOGGING,
            check="Server access logging",
            status=Status.PASS if enabled else Status.WARNING,
            resource=bucket_name,
            details="" if enabled else "Access logging not enabled.",
            soc2_mapping="CC7.2",
            provider="AWS",
        ))
    except ClientError:
        pass


def check_object_lock(s3, bucket_name: str, report: AuditReport) -> None:
    """Check if Object Lock (WORM) is configured."""
    try:
        lock = s3.get_object_lock_configuration(Bucket=bucket_name)
        enabled = lock.get("ObjectLockConfiguration", {}).get("ObjectLockEnabled") == "Enabled"
        report.add_finding(Finding(
            severity=Severity.INFO,
            category=Category.BACKUPS,
            check="Object Lock (WORM)",
            status=Status.PASS if enabled else Status.WARNING,
            resource=bucket_name,
            details="Object Lock enabled." if enabled else "Object Lock not configured. Consider for compliance data.",
            soc2_mapping="A1.2",
            provider="AWS",
        ))
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "ObjectLockConfigurationNotFoundError":
            report.add_finding(Finding(
                severity=Severity.INFO,
                category=Category.BACKUPS,
                check="Object Lock (WORM)",
                status=Status.PASS,
                resource=bucket_name,
                details="Object Lock not configured (not required for all buckets).",
                soc2_mapping="A1.2",
                provider="AWS",
            ))


def check_replication(s3, bucket_name: str, report: AuditReport) -> None:
    """Check cross-region replication configuration."""
    try:
        repl = s3.get_bucket_replication(Bucket=bucket_name)
        rules = repl.get("ReplicationConfiguration", {}).get("Rules", [])
        active_rules = [r for r in rules if r.get("Status") == "Enabled"]
        report.add_finding(Finding(
            severity=Severity.INFO,
            category=Category.BACKUPS,
            check="Cross-region replication",
            status=Status.PASS if active_rules else Status.WARNING,
            resource=bucket_name,
            details=f"{len(active_rules)} active replication rule(s)." if active_rules else "No replication configured.",
            soc2_mapping="A1.2",
            provider="AWS",
        ))
    except ClientError as e:
        if e.response["Error"]["Code"] == "ReplicationConfigurationNotFoundError":
            report.add_finding(Finding(
                severity=Severity.INFO,
                category=Category.BACKUPS,
                check="Cross-region replication",
                status=Status.PASS,
                resource=bucket_name,
                details="No replication configured (may not be required).",
                soc2_mapping="A1.2",
                provider="AWS",
            ))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.command()
@click.option("--profile", default=None, help="AWS CLI profile name.")
@click.option("--region", default=None, help="AWS region.")
@click.option("--bucket", default=None, help="Audit a specific bucket only.")
@click.option(
    "--output-format",
    type=click.Choice(["markdown", "json", "both"]),
    default="markdown",
)
@click.option("--output-dir", default="reports")
def main(
    profile: Optional[str],
    region: Optional[str],
    bucket: Optional[str],
    output_format: str,
    output_dir: str,
) -> None:
    """
    Run a focused AWS S3 security audit.

    All operations are read-only. Maintained by TrazTech (https://traztech.ca).
    """
    print_banner("AWS (S3 Focus)")

    session = _get_session(profile, region)
    account_id = _get_account_id(session)
    s3 = session.client("s3")

    report = AuditReport(
        provider="AWS",
        account_id=account_id,
        region=session.region_name or "global",
        metadata={
            "scope": f"S3 {'bucket: ' + bucket if bucket else 'all buckets'}",
            "tool": "cloud-security-audit-scripts",
            "maintainer": "TrazTech (https://traztech.ca)",
        },
    )

    console.print(f"\n[bold]Account:[/bold] {account_id}")
    if bucket:
        console.print(f"[bold]Bucket:[/bold]  {bucket}\n")
    else:
        console.print("")

    # Account-level check
    console.print("[cyan]Checking account-level S3 public access block...[/cyan]")
    check_account_public_access_block(session, report)

    # Per-bucket checks
    console.print("[cyan]Listing buckets...[/cyan]")
    buckets = _list_buckets(s3, bucket)
    console.print(f"[bold]{len(buckets)} bucket(s) to audit.[/bold]\n")

    for b in buckets:
        name = b["Name"]
        console.print(f"[cyan]--- {name} ---[/cyan]")

        check_bucket_public_access(s3, name, report)
        check_bucket_policy_public(s3, name, report)
        check_bucket_policy_ssl(s3, name, report)
        check_encryption(s3, name, report)
        check_versioning(s3, name, report)
        check_logging(s3, name, report)
        check_object_lock(s3, name, report)
        check_replication(s3, name, report)

    # Output
    console.print("\n[bold]--- Findings ---[/bold]\n")
    for finding in report.findings:
        print_finding(finding)

    print_summary(report)

    os.makedirs(output_dir, exist_ok=True)
    gen = ReportGenerator()
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    scope = f"-{bucket}" if bucket else ""
    base = f"aws-s3-audit-{account_id}{scope}-{ts}"

    if output_format in ("markdown", "both"):
        path = os.path.join(output_dir, f"{base}.md")
        gen.to_markdown(report, path)
        console.print(f"\n[green]Markdown report:[/green] {path}")

    if output_format in ("json", "both"):
        path = os.path.join(output_dir, f"{base}.json")
        gen.to_json(report, path)
        console.print(f"[green]JSON report:[/green] {path}")

    console.print(
        "\n[dim]For a full S3 security review, visit "
        "https://traztech.ca/tools/cloud-security-posture-check[/dim]\n"
    )


if __name__ == "__main__":
    main()
