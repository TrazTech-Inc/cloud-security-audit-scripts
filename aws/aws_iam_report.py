#!/usr/bin/env python3
"""
AWS IAM Security Audit Script

Focused IAM audit with credential report analysis. Checks:
- Root account MFA and access key usage
- Password policy compliance
- IAM user MFA enrollment
- Unused credentials (90+ days)
- Access key age and rotation
- Overly permissive policies (Action:* Resource:*)
- Users with inline policies (prefer managed policies)
- Service-linked roles vs. custom roles

All operations are read-only. No IAM changes are made.

Usage:
    python aws/aws_iam_report.py --profile production
    python aws/aws_iam_report.py --output-format json --output-dir reports/

Maintained by TrazTech (https://traztech.ca)
SOC 2 / ISO 27001 readiness engagements
Free Cloud Security Posture Check: https://traztech.ca/tools/cloud-security-posture-check
"""

from __future__ import annotations

import csv
import io
import json
import os
import sys
import time
from datetime import datetime, timezone, timedelta
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


# ---------------------------------------------------------------------------
# Credential report parsing
# ---------------------------------------------------------------------------

def _get_credential_report(iam) -> Optional[List[Dict[str, str]]]:
    """Generate and retrieve the IAM credential report."""
    try:
        iam.generate_credential_report()
        for _ in range(15):
            try:
                resp = iam.get_credential_report()
                content = resp["Content"].decode("utf-8")
                reader = csv.DictReader(io.StringIO(content))
                return list(reader)
            except iam.exceptions.CredentialReportNotReadyException:
                time.sleep(2)
    except ClientError as exc:
        console.print(f"[red]Credential report error: {exc}[/red]")
    return None


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_root_account(iam, report: AuditReport, cred_rows: List[Dict]) -> None:
    """Check root account MFA and access key usage."""
    root_row = next((r for r in cred_rows if r["user"] == "<root_account>"), None)
    if not root_row:
        return

    # Root MFA
    mfa_active = root_row.get("mfa_active", "false") == "true"
    report.add_finding(Finding(
        severity=Severity.CRITICAL,
        category=Category.IAM,
        check="Root account MFA",
        status=Status.PASS if mfa_active else Status.FAIL,
        resource=f"arn:aws:iam::{report.account_id}:root",
        details="" if mfa_active else "Root account does not have MFA enabled.",
        soc2_mapping="CC6.1",
        provider="AWS",
    ))

    # Root access keys
    ak1 = root_row.get("access_key_1_active", "false") == "true"
    ak2 = root_row.get("access_key_2_active", "false") == "true"
    if ak1 or ak2:
        report.add_finding(Finding(
            severity=Severity.CRITICAL,
            category=Category.IAM,
            check="Root account access keys",
            status=Status.FAIL,
            resource=f"arn:aws:iam::{report.account_id}:root",
            details="Root account has active access keys. Remove them and use IAM roles instead.",
            soc2_mapping="CC6.1",
            provider="AWS",
        ))
    else:
        report.add_finding(Finding(
            severity=Severity.INFO,
            category=Category.IAM,
            check="Root account access keys",
            status=Status.PASS,
            resource=f"arn:aws:iam::{report.account_id}:root",
            details="No active access keys on root account.",
            soc2_mapping="CC6.1",
            provider="AWS",
        ))

    # Root last used
    pwd_last = root_row.get("password_last_used", "N/A")
    if pwd_last not in ("N/A", "no_information", "not_supported"):
        report.add_finding(Finding(
            severity=Severity.INFO,
            category=Category.IAM,
            check="Root account last login",
            status=Status.PASS,
            resource=f"arn:aws:iam::{report.account_id}:root",
            details=f"Root password last used: {pwd_last}. Minimize root usage.",
            soc2_mapping="CC6.1",
            provider="AWS",
        ))


def check_mfa_enrollment(iam, report: AuditReport, cred_rows: List[Dict]) -> None:
    """Check all console users have MFA enabled."""
    for row in cred_rows:
        user = row["user"]
        if user == "<root_account>":
            continue
        has_password = row.get("password_enabled", "false") == "true"
        has_mfa = row.get("mfa_active", "false") == "true"

        if has_password and not has_mfa:
            report.add_finding(Finding(
                severity=Severity.HIGH,
                category=Category.IAM,
                check="IAM user MFA",
                status=Status.FAIL,
                resource=f"arn:aws:iam::{report.account_id}:user/{user}",
                details=f"Console user '{user}' does not have MFA enabled.",
                soc2_mapping="CC6.1",
                provider="AWS",
            ))

    # Summary if all good
    users_without_mfa = [
        r["user"] for r in cred_rows
        if r["user"] != "<root_account>"
        and r.get("password_enabled") == "true"
        and r.get("mfa_active") != "true"
    ]
    if not users_without_mfa:
        report.add_finding(Finding(
            severity=Severity.INFO,
            category=Category.IAM,
            check="IAM user MFA",
            status=Status.PASS,
            resource="All console users",
            details="All IAM users with console access have MFA enabled.",
            soc2_mapping="CC6.1",
            provider="AWS",
        ))


def check_credential_staleness(report: AuditReport, cred_rows: List[Dict]) -> None:
    """Identify credentials unused for 90+ days."""
    now = datetime.now(timezone.utc)
    threshold = timedelta(days=90)
    stale_found = False

    for row in cred_rows:
        user = row["user"]
        if user == "<root_account>":
            continue

        for field_prefix, label in [
            ("password_last_used", "password"),
            ("access_key_1_last_used_date", "access key 1"),
            ("access_key_2_last_used_date", "access key 2"),
        ]:
            active_field = None
            if "access_key_1" in field_prefix:
                active_field = "access_key_1_active"
            elif "access_key_2" in field_prefix:
                active_field = "access_key_2_active"

            if active_field and row.get(active_field) != "true":
                continue

            val = row.get(field_prefix, "N/A")
            if val in ("N/A", "no_information", "not_supported"):
                continue
            try:
                last_used = datetime.fromisoformat(val.replace("Z", "+00:00"))
                age_days = (now - last_used).days
                if age_days > 90:
                    stale_found = True
                    report.add_finding(Finding(
                        severity=Severity.MEDIUM,
                        category=Category.IAM,
                        check=f"Credential staleness ({label})",
                        status=Status.WARNING,
                        resource=f"arn:aws:iam::{report.account_id}:user/{user}",
                        details=f"'{user}' {label} last used {age_days} days ago.",
                        soc2_mapping="CC6.2",
                        provider="AWS",
                    ))
            except (ValueError, TypeError):
                pass

    if not stale_found:
        report.add_finding(Finding(
            severity=Severity.INFO,
            category=Category.IAM,
            check="Credential staleness",
            status=Status.PASS,
            resource="All IAM users",
            details="No credentials unused for more than 90 days.",
            soc2_mapping="CC6.2",
            provider="AWS",
        ))


def check_access_key_rotation(report: AuditReport, cred_rows: List[Dict]) -> None:
    """Check access key age via credential report."""
    now = datetime.now(timezone.utc)
    old_keys_found = False

    for row in cred_rows:
        user = row["user"]
        if user == "<root_account>":
            continue

        for idx in ("1", "2"):
            active = row.get(f"access_key_{idx}_active", "false") == "true"
            rotated = row.get(f"access_key_{idx}_last_rotated", "N/A")
            if not active or rotated in ("N/A", "not_supported"):
                continue
            try:
                created = datetime.fromisoformat(rotated.replace("Z", "+00:00"))
                age = (now - created).days
                if age > 90:
                    old_keys_found = True
                    sev = Severity.HIGH if age > 180 else Severity.MEDIUM
                    report.add_finding(Finding(
                        severity=sev,
                        category=Category.IAM,
                        check=f"Access key {idx} age",
                        status=Status.WARNING if age <= 180 else Status.FAIL,
                        resource=f"arn:aws:iam::{report.account_id}:user/{user}",
                        details=f"'{user}' access key {idx} is {age} days old. Rotate regularly.",
                        soc2_mapping="CC6.2",
                        provider="AWS",
                    ))
            except (ValueError, TypeError):
                pass

    if not old_keys_found:
        report.add_finding(Finding(
            severity=Severity.INFO,
            category=Category.IAM,
            check="Access key age",
            status=Status.PASS,
            resource="All IAM users",
            details="All active access keys are under 90 days old.",
            soc2_mapping="CC6.2",
            provider="AWS",
        ))


def check_password_policy(iam, report: AuditReport) -> None:
    """Evaluate account password policy."""
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        issues: List[str] = []
        min_len = policy.get("MinimumPasswordLength", 0)
        if min_len < 14:
            issues.append(f"Min length {min_len} (recommend 14+)")
        if not policy.get("RequireUppercaseCharacters", False):
            issues.append("Uppercase not required")
        if not policy.get("RequireLowercaseCharacters", False):
            issues.append("Lowercase not required")
        if not policy.get("RequireNumbers", False):
            issues.append("Numbers not required")
        if not policy.get("RequireSymbols", False):
            issues.append("Symbols not required")
        max_age = policy.get("MaxPasswordAge", 0)
        if max_age == 0 or max_age > 90:
            issues.append(f"Max age {max_age} days (recommend <=90)")
        reuse = policy.get("PasswordReusePrevention", 0)
        if reuse < 12:
            issues.append(f"Reuse prevention: {reuse} (recommend 12+)")

        if not issues:
            report.add_finding(Finding(
                severity=Severity.INFO, category=Category.IAM,
                check="Password policy", status=Status.PASS,
                resource="Account password policy",
                details="Password policy meets all recommended standards.",
                soc2_mapping="CC6.1", provider="AWS",
            ))
        else:
            sev = Severity.HIGH if len(issues) > 3 else Severity.MEDIUM
            report.add_finding(Finding(
                severity=sev, category=Category.IAM,
                check="Password policy", status=Status.FAIL if len(issues) > 3 else Status.WARNING,
                resource="Account password policy",
                details="; ".join(issues),
                soc2_mapping="CC6.1", provider="AWS",
            ))
    except Exception:
        report.add_finding(Finding(
            severity=Severity.HIGH, category=Category.IAM,
            check="Password policy", status=Status.FAIL,
            resource="Account password policy",
            details="No custom password policy configured.",
            soc2_mapping="CC6.1", provider="AWS",
        ))


def check_inline_policies(iam, report: AuditReport) -> None:
    """Identify users with inline policies (prefer managed policies for governance)."""
    try:
        paginator = iam.get_paginator("list_users")
        inline_users: List[str] = []

        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                try:
                    policies = iam.list_user_policies(UserName=username)
                    if policies.get("PolicyNames"):
                        inline_users.append(username)
                except ClientError:
                    pass

        if inline_users:
            for u in inline_users:
                report.add_finding(Finding(
                    severity=Severity.LOW,
                    category=Category.GOVERNANCE,
                    check="Inline IAM policies",
                    status=Status.WARNING,
                    resource=f"arn:aws:iam::{report.account_id}:user/{u}",
                    details=f"User '{u}' has inline policies. Use managed policies for better governance.",
                    soc2_mapping="CC8.1",
                    provider="AWS",
                ))
        else:
            report.add_finding(Finding(
                severity=Severity.INFO,
                category=Category.GOVERNANCE,
                check="Inline IAM policies",
                status=Status.PASS,
                resource="All IAM users",
                details="No users with inline policies found.",
                soc2_mapping="CC8.1",
                provider="AWS",
            ))
    except ClientError as exc:
        report.add_finding(Finding(
            severity=Severity.LOW,
            category=Category.GOVERNANCE,
            check="Inline IAM policies",
            status=Status.ERROR,
            resource="IAM",
            details=f"Unable to check inline policies: {exc}",
            soc2_mapping="CC8.1",
            provider="AWS",
        ))


def check_overly_permissive_policies(iam, report: AuditReport) -> None:
    """Detect customer-managed policies with Action:* Resource:*."""
    try:
        paginator = iam.get_paginator("list_policies")
        wild: List[str] = []

        for page in paginator.paginate(Scope="Local", OnlyAttached=True):
            for policy in page["Policies"]:
                arn = policy["Arn"]
                vid = policy["DefaultVersionId"]
                try:
                    ver = iam.get_policy_version(PolicyArn=arn, VersionId=vid)
                    doc = ver["PolicyVersion"]["Document"]
                    if isinstance(doc, str):
                        doc = json.loads(doc)
                    stmts = doc.get("Statement", [])
                    if isinstance(stmts, dict):
                        stmts = [stmts]
                    for s in stmts:
                        if s.get("Effect") == "Allow":
                            acts = s.get("Action", [])
                            res = s.get("Resource", [])
                            if isinstance(acts, str):
                                acts = [acts]
                            if isinstance(res, str):
                                res = [res]
                            if "*" in acts and "*" in res:
                                wild.append(arn)
                                break
                except ClientError:
                    pass

        if wild:
            for w in wild:
                report.add_finding(Finding(
                    severity=Severity.HIGH, category=Category.IAM,
                    check="Overly permissive policies",
                    status=Status.FAIL, resource=w,
                    details="Policy grants Action:* on Resource:*. Review for least privilege.",
                    soc2_mapping="CC6.3", provider="AWS",
                ))
        else:
            report.add_finding(Finding(
                severity=Severity.INFO, category=Category.IAM,
                check="Overly permissive policies",
                status=Status.PASS, resource="Customer-managed policies",
                details="No attached policies with Action:* Resource:* found.",
                soc2_mapping="CC6.3", provider="AWS",
            ))
    except ClientError as exc:
        report.add_finding(Finding(
            severity=Severity.HIGH, category=Category.IAM,
            check="Overly permissive policies", status=Status.ERROR,
            resource="IAM", details=f"Unable to evaluate policies: {exc}",
            soc2_mapping="CC6.3", provider="AWS",
        ))


def check_user_count(iam, report: AuditReport) -> None:
    """Enumerate IAM users for review."""
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        count = summary.get("Users", 0)
        groups = summary.get("Groups", 0)
        roles = summary.get("Roles", 0)
        policies = summary.get("Policies", 0)
        report.add_finding(Finding(
            severity=Severity.INFO, category=Category.IAM,
            check="IAM resource summary", status=Status.PASS,
            resource="Account",
            details=f"{count} users, {groups} groups, {roles} roles, {policies} policies.",
            soc2_mapping="CC6.3", provider="AWS",
        ))
    except ClientError as exc:
        report.add_finding(Finding(
            severity=Severity.INFO, category=Category.IAM,
            check="IAM resource summary", status=Status.ERROR,
            resource="Account", details=f"Unable to get summary: {exc}",
            soc2_mapping="CC6.3", provider="AWS",
        ))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.command()
@click.option("--profile", default=None, help="AWS CLI profile name.")
@click.option("--region", default=None, help="AWS region.")
@click.option(
    "--output-format",
    type=click.Choice(["markdown", "json", "both"]),
    default="markdown",
)
@click.option("--output-dir", default="reports")
def main(profile: Optional[str], region: Optional[str], output_format: str, output_dir: str) -> None:
    """
    Run a focused AWS IAM security audit.

    All operations are read-only. Maintained by TrazTech (https://traztech.ca).
    """
    print_banner("AWS (IAM Focus)")

    session = _get_session(profile, region)
    account_id = _get_account_id(session)
    iam = session.client("iam")

    report = AuditReport(
        provider="AWS",
        account_id=account_id,
        region=session.region_name or "global",
        metadata={
            "scope": "IAM only",
            "tool": "cloud-security-audit-scripts",
            "maintainer": "TrazTech (https://traztech.ca)",
        },
    )

    console.print(f"\n[bold]Account:[/bold] {account_id}\n")

    # Generate credential report
    console.print("[cyan]Generating credential report...[/cyan]")
    cred_rows = _get_credential_report(iam)

    if cred_rows:
        console.print("[cyan]Checking root account...[/cyan]")
        check_root_account(iam, report, cred_rows)

        console.print("[cyan]Checking MFA enrollment...[/cyan]")
        check_mfa_enrollment(iam, report, cred_rows)

        console.print("[cyan]Checking credential staleness...[/cyan]")
        check_credential_staleness(report, cred_rows)

        console.print("[cyan]Checking access key rotation...[/cyan]")
        check_access_key_rotation(report, cred_rows)
    else:
        report.add_finding(Finding(
            severity=Severity.MEDIUM, category=Category.IAM,
            check="Credential report", status=Status.ERROR,
            resource="IAM", details="Could not generate credential report.",
            soc2_mapping="CC6.2", provider="AWS",
        ))

    console.print("[cyan]Checking password policy...[/cyan]")
    check_password_policy(iam, report)

    console.print("[cyan]Checking overly permissive policies...[/cyan]")
    check_overly_permissive_policies(iam, report)

    console.print("[cyan]Checking inline policies...[/cyan]")
    check_inline_policies(iam, report)

    console.print("[cyan]Getting IAM summary...[/cyan]")
    check_user_count(iam, report)

    # Output
    console.print("\n[bold]--- Findings ---[/bold]\n")
    for finding in report.findings:
        print_finding(finding)

    print_summary(report)

    os.makedirs(output_dir, exist_ok=True)
    gen = ReportGenerator()
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = f"aws-iam-audit-{account_id}-{ts}"

    if output_format in ("markdown", "both"):
        path = os.path.join(output_dir, f"{base}.md")
        gen.to_markdown(report, path)
        console.print(f"\n[green]Markdown report:[/green] {path}")

    if output_format in ("json", "both"):
        path = os.path.join(output_dir, f"{base}.json")
        gen.to_json(report, path)
        console.print(f"[green]JSON report:[/green] {path}")

    console.print(
        "\n[dim]For a full IAM review, see https://traztech.ca/tools/cloud-security-posture-check[/dim]\n"
    )


if __name__ == "__main__":
    main()
