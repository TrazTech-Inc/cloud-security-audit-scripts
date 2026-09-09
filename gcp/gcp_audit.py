#!/usr/bin/env python3
"""
GCP Cloud Security Audit Script

Comprehensive read-only security assessment for Google Cloud Platform.
Checks IAM, GCS, Compute/Firewall, Cloud SQL, Logging, and KMS.

Findings are mapped to SOC 2 Trust Services Criteria for audit readiness.
Categories align with the TrazTech Cloud Security Posture Check
(https://traztech.ca/tools/cloud-security-posture-check).

Usage:
    python gcp/gcp_audit.py --project my-project-id
    python gcp/gcp_audit.py --project my-project-id --output-format json

Prerequisites:
    - gcloud auth application-default login
    - gcloud config set project <PROJECT_ID>
    - Roles: roles/viewer, roles/iam.securityReviewer

Maintained by TrazTech (https://traztech.ca)
Principal: Jacob Masse | 5 CVEs including CVE-2024-45163 (CVSS 9.1)
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import click

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

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


def _safe_import(module_name: str):
    """Import a module and return it, or None if unavailable."""
    try:
        import importlib
        return importlib.import_module(module_name)
    except ImportError:
        console.print(f"[yellow]Warning: {module_name} not installed. Some checks will be skipped.[/yellow]")
        return None


# ---------------------------------------------------------------------------
# IAM checks
# ---------------------------------------------------------------------------

def check_overly_permissive_iam(project_id: str, report: AuditReport) -> None:
    """CC6.3 - Detect overly permissive IAM bindings (roles/owner, roles/editor on allUsers etc.)."""
    crm = _safe_import("googleapiclient.discovery")
    if not crm:
        return

    try:
        from google.auth import default as google_auth_default
        from googleapiclient.discovery import build

        credentials, _ = google_auth_default()
        service = build("cloudresourcemanager", "v1", credentials=credentials)
        policy = service.projects().getIamPolicy(
            resource=project_id, body={"options": {"requestedPolicyVersion": 3}}
        ).execute()

        dangerous_members = {"allUsers", "allAuthenticatedUsers"}
        broad_roles = {
            "roles/owner": Severity.CRITICAL,
            "roles/editor": Severity.HIGH,
            "roles/iam.securityAdmin": Severity.HIGH,
            "roles/iam.serviceAccountAdmin": Severity.HIGH,
        }

        found_issues = False
        for binding in policy.get("bindings", []):
            role = binding.get("role", "")
            members = set(binding.get("members", []))

            # Check for public access
            public_members = members.intersection(dangerous_members)
            if public_members:
                found_issues = True
                report.add_finding(Finding(
                    severity=Severity.CRITICAL,
                    category=Category.IAM,
                    check="Public IAM bindings",
                    status=Status.FAIL,
                    resource=f"projects/{project_id}",
                    details=f"Role '{role}' granted to {', '.join(public_members)}. This is effectively public access.",
                    soc2_mapping="CC6.3",
                    provider="GCP",
                ))

            # Check broad roles on user accounts (not service accounts for infra)
            if role in broad_roles:
                user_members = [
                    m for m in members
                    if m.startswith("user:") or m in dangerous_members
                ]
                if user_members:
                    found_issues = True
                    report.add_finding(Finding(
                        severity=broad_roles[role],
                        category=Category.IAM,
                        check="Overly permissive role assignment",
                        status=Status.WARNING,
                        resource=f"projects/{project_id}",
                        details=f"Role '{role}' assigned to: {', '.join(user_members)}. Apply least privilege.",
                        soc2_mapping="CC6.3",
                        provider="GCP",
                    ))

        if not found_issues:
            report.add_finding(Finding(
                severity=Severity.INFO,
                category=Category.IAM,
                check="IAM bindings review",
                status=Status.PASS,
                resource=f"projects/{project_id}",
                details="No overly permissive or public IAM bindings detected.",
                soc2_mapping="CC6.3",
                provider="GCP",
            ))

    except Exception as exc:
        report.add_finding(Finding(
            severity=Severity.HIGH,
            category=Category.IAM,
            check="IAM bindings review",
            status=Status.ERROR,
            resource=f"projects/{project_id}",
            details=f"Unable to retrieve IAM policy: {exc}",
            soc2_mapping="CC6.3",
            provider="GCP",
        ))


def check_service_account_keys(project_id: str, report: AuditReport) -> None:
    """CC6.2 - Check service account key age and identify unused SAs."""
    try:
        from google.auth import default as google_auth_default
        from googleapiclient.discovery import build

        credentials, _ = google_auth_default()
        iam_service = build("iam", "v1", credentials=credentials)

        sas = iam_service.projects().serviceAccounts().list(
            name=f"projects/{project_id}"
        ).execute()

        service_accounts = sas.get("accounts", [])
        if not service_accounts:
            report.add_finding(Finding(
                severity=Severity.INFO,
                category=Category.IAM,
                check="Service account keys",
                status=Status.PASS,
                resource=f"projects/{project_id}",
                details="No user-managed service accounts found.",
                soc2_mapping="CC6.2",
                provider="GCP",
            ))
            return

        now = datetime.now(timezone.utc)
        for sa in service_accounts:
            email = sa.get("email", "")
            sa_name = sa.get("name", "")
            disabled = sa.get("disabled", False)

            # Check if SA is disabled (potential cleanup candidate)
            if disabled:
                report.add_finding(Finding(
                    severity=Severity.LOW,
                    category=Category.IAM,
                    check="Disabled service account",
                    status=Status.WARNING,
                    resource=email,
                    details=f"Service account '{email}' is disabled. Consider deleting if unused.",
                    soc2_mapping="CC6.2",
                    provider="GCP",
                ))
                continue

            # Check user-managed keys
            try:
                keys_resp = iam_service.projects().serviceAccounts().keys().list(
                    name=sa_name,
                    keyTypes=["USER_MANAGED"],
                ).execute()

                keys = keys_resp.get("keys", [])
                if not keys:
                    continue

                for key in keys:
                    key_id = key.get("name", "").split("/")[-1]
                    valid_after = key.get("validAfterTime", "")
                    if valid_after:
                        try:
                            created = datetime.fromisoformat(
                                valid_after.replace("Z", "+00:00")
                            )
                            age_days = (now - created).days
                            if age_days > 90:
                                sev = Severity.HIGH if age_days > 180 else Severity.MEDIUM
                                report.add_finding(Finding(
                                    severity=sev,
                                    category=Category.SECRETS,
                                    check="Service account key age",
                                    status=Status.FAIL if age_days > 180 else Status.WARNING,
                                    resource=f"{email} (key: {key_id[:12]}...)",
                                    details=f"Key is {age_days} days old. Rotate keys regularly.",
                                    soc2_mapping="CC6.2",
                                    provider="GCP",
                                ))
                            else:
                                report.add_finding(Finding(
                                    severity=Severity.INFO,
                                    category=Category.SECRETS,
                                    check="Service account key age",
                                    status=Status.PASS,
                                    resource=f"{email} (key: {key_id[:12]}...)",
                                    details=f"Key is {age_days} days old.",
                                    soc2_mapping="CC6.2",
                                    provider="GCP",
                                ))
                        except (ValueError, TypeError):
                            pass
            except Exception:
                pass

    except Exception as exc:
        report.add_finding(Finding(
            severity=Severity.MEDIUM,
            category=Category.IAM,
            check="Service account keys",
            status=Status.ERROR,
            resource=f"projects/{project_id}",
            details=f"Unable to list service accounts: {exc}",
            soc2_mapping="CC6.2",
            provider="GCP",
        ))


# ---------------------------------------------------------------------------
# GCS checks
# ---------------------------------------------------------------------------

def check_gcs_buckets(project_id: str, report: AuditReport) -> None:
    """CC6.6 / CC6.7 - Check GCS bucket public access and settings."""
    storage = _safe_import("google.cloud.storage")
    if not storage:
        return

    try:
        client = storage.Client(project=project_id)
        buckets = list(client.list_buckets())

        if not buckets:
            report.add_finding(Finding(
                severity=Severity.INFO,
                category=Category.NETWORK,
                check="GCS buckets",
                status=Status.PASS,
                resource=f"projects/{project_id}",
                details="No GCS buckets found.",
                soc2_mapping="CC6.6",
                provider="GCP",
            ))
            return

        for bucket in buckets:
            name = bucket.name

            # Check IAM policy for public access
            try:
                policy = bucket.get_iam_policy(requested_policy_version=3)
                public_access = False
                for binding in policy.bindings:
                    members = set(binding.get("members", []))
                    if "allUsers" in members or "allAuthenticatedUsers" in members:
                        public_access = True
                        report.add_finding(Finding(
                            severity=Severity.CRITICAL,
                            category=Category.NETWORK,
                            check="GCS bucket public access",
                            status=Status.FAIL,
                            resource=name,
                            details=f"Bucket has public IAM binding: role={binding.get('role')}, members include allUsers/allAuthenticatedUsers.",
                            soc2_mapping="CC6.6",
                            provider="GCP",
                        ))
                        break

                if not public_access:
                    report.add_finding(Finding(
                        severity=Severity.INFO,
                        category=Category.NETWORK,
                        check="GCS bucket public access",
                        status=Status.PASS,
                        resource=name,
                        details="No public IAM bindings.",
                        soc2_mapping="CC6.6",
                        provider="GCP",
                    ))
            except Exception as exc:
                report.add_finding(Finding(
                    severity=Severity.MEDIUM,
                    category=Category.NETWORK,
                    check="GCS bucket public access",
                    status=Status.ERROR,
                    resource=name,
                    details=f"Unable to check IAM policy: {exc}",
                    soc2_mapping="CC6.6",
                    provider="GCP",
                ))

            # Uniform bucket-level access
            uba = bucket.iam_configuration.uniform_bucket_level_access_enabled
            report.add_finding(Finding(
                severity=Severity.INFO if uba else Severity.MEDIUM,
                category=Category.IAM,
                check="Uniform bucket-level access",
                status=Status.PASS if uba else Status.WARNING,
                resource=name,
                details="" if uba else "Uniform bucket-level access not enabled. ACLs may grant unintended access.",
                soc2_mapping="CC6.3",
                provider="GCP",
            ))

            # Versioning
            versioning = bucket.versioning_enabled
            report.add_finding(Finding(
                severity=Severity.INFO if versioning else Severity.MEDIUM,
                category=Category.BACKUPS,
                check="GCS bucket versioning",
                status=Status.PASS if versioning else Status.WARNING,
                resource=name,
                details="" if versioning else "Versioning not enabled.",
                soc2_mapping="A1.2",
                provider="GCP",
            ))

    except Exception as exc:
        report.add_finding(Finding(
            severity=Severity.HIGH,
            category=Category.NETWORK,
            check="GCS bucket audit",
            status=Status.ERROR,
            resource=f"projects/{project_id}",
            details=f"Unable to list GCS buckets: {exc}",
            soc2_mapping="CC6.6",
            provider="GCP",
        ))


# ---------------------------------------------------------------------------
# Compute / Firewall checks
# ---------------------------------------------------------------------------

SENSITIVE_PORTS_GCP = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
    6379: "Redis",
}


def check_firewall_rules(project_id: str, report: AuditReport) -> None:
    """CC6.6 - Check firewall rules for 0.0.0.0/0 on sensitive ports."""
    try:
        from google.auth import default as google_auth_default
        from googleapiclient.discovery import build

        credentials, _ = google_auth_default()
        compute = build("compute", "v1", credentials=credentials)

        result = compute.firewalls().list(project=project_id).execute()
        rules = result.get("items", [])
        found_open = False

        for rule in rules:
            if rule.get("direction", "INGRESS") != "INGRESS":
                continue
            if rule.get("disabled", False):
                continue

            source_ranges = rule.get("sourceRanges", [])
            if "0.0.0.0/0" not in source_ranges:
                continue

            name = rule.get("name", "unknown")
            allowed = rule.get("allowed", [])

            for allow in allowed:
                protocol = allow.get("IPProtocol", "")
                ports = allow.get("ports", [])

                if protocol == "all":
                    found_open = True
                    report.add_finding(Finding(
                        severity=Severity.CRITICAL,
                        category=Category.NETWORK,
                        check="Firewall rule open to world",
                        status=Status.FAIL,
                        resource=name,
                        details=f"Rule '{name}' allows ALL protocols/ports from 0.0.0.0/0.",
                        soc2_mapping="CC6.6",
                        provider="GCP",
                    ))
                    continue

                if protocol not in ("tcp", "udp"):
                    continue

                # Expand port ranges and check sensitive ports
                expanded_ports: List[int] = []
                for p in ports:
                    if "-" in str(p):
                        start, end = str(p).split("-", 1)
                        try:
                            expanded_ports.extend(range(int(start), int(end) + 1))
                        except ValueError:
                            pass
                    else:
                        try:
                            expanded_ports.append(int(p))
                        except ValueError:
                            pass

                if not ports:
                    # No ports specified means all ports for the protocol
                    expanded_ports = list(SENSITIVE_PORTS_GCP.keys())

                for port, service in SENSITIVE_PORTS_GCP.items():
                    if port in expanded_ports:
                        found_open = True
                        sev = Severity.CRITICAL if port in (22, 3389) else Severity.HIGH
                        report.add_finding(Finding(
                            severity=sev,
                            category=Category.NETWORK,
                            check="Firewall rule open to world",
                            status=Status.FAIL,
                            resource=name,
                            details=f"Rule '{name}' allows {protocol.upper()} port {port} ({service}) from 0.0.0.0/0.",
                            soc2_mapping="CC6.6",
                            provider="GCP",
                        ))

        if not found_open:
            report.add_finding(Finding(
                severity=Severity.INFO,
                category=Category.NETWORK,
                check="Firewall rules",
                status=Status.PASS,
                resource=f"projects/{project_id}",
                details="No sensitive ports open to 0.0.0.0/0 in firewall rules.",
                soc2_mapping="CC6.6",
                provider="GCP",
            ))

    except Exception as exc:
        report.add_finding(Finding(
            severity=Severity.HIGH,
            category=Category.NETWORK,
            check="Firewall rules",
            status=Status.ERROR,
            resource=f"projects/{project_id}",
            details=f"Unable to list firewall rules: {exc}",
            soc2_mapping="CC6.6",
            provider="GCP",
        ))


def check_compute_settings(project_id: str, report: AuditReport) -> None:
    """CC6.1 / CC7.1 - Check OS Login and serial port settings."""
    try:
        from google.auth import default as google_auth_default
        from googleapiclient.discovery import build

        credentials, _ = google_auth_default()
        compute = build("compute", "v1", credentials=credentials)

        project_info = compute.projects().get(project=project_id).execute()
        metadata_items = project_info.get("commonInstanceMetadata", {}).get("items", [])
        metadata = {item["key"]: item["value"] for item in metadata_items}

        # OS Login
        os_login = metadata.get("enable-oslogin", "").lower()
        report.add_finding(Finding(
            severity=Severity.INFO if os_login == "true" else Severity.MEDIUM,
            category=Category.IAM,
            check="OS Login enabled (project-level)",
            status=Status.PASS if os_login == "true" else Status.WARNING,
            resource=f"projects/{project_id}",
            details="" if os_login == "true" else "OS Login not enabled at project level. Enables IAM-based SSH access.",
            soc2_mapping="CC6.1",
            provider="GCP",
        ))

        # Serial port
        serial_port = metadata.get("serial-port-enable", "").lower()
        report.add_finding(Finding(
            severity=Severity.MEDIUM if serial_port == "true" else Severity.INFO,
            category=Category.NETWORK,
            check="Serial port access disabled",
            status=Status.FAIL if serial_port == "true" else Status.PASS,
            resource=f"projects/{project_id}",
            details="Serial port access enabled at project level. Disable for security." if serial_port == "true" else "",
            soc2_mapping="CC6.6",
            provider="GCP",
        ))

    except Exception as exc:
        report.add_finding(Finding(
            severity=Severity.MEDIUM,
            category=Category.IAM,
            check="Compute project settings",
            status=Status.ERROR,
            resource=f"projects/{project_id}",
            details=f"Unable to check project metadata: {exc}",
            soc2_mapping="CC6.1",
            provider="GCP",
        ))


# ---------------------------------------------------------------------------
# Cloud SQL checks
# ---------------------------------------------------------------------------

def check_cloud_sql(project_id: str, report: AuditReport) -> None:
    """CC6.6 / CC6.7 / A1.2 - Check Cloud SQL instances."""
    try:
        from google.auth import default as google_auth_default
        from googleapiclient.discovery import build

        credentials, _ = google_auth_default()
        sqladmin = build("sqladmin", "v1beta4", credentials=credentials)

        result = sqladmin.instances().list(project=project_id).execute()
        instances = result.get("items", [])

        if not instances:
            report.add_finding(Finding(
                severity=Severity.INFO,
                category=Category.BACKUPS,
                check="Cloud SQL instances",
                status=Status.PASS,
                resource=f"projects/{project_id}",
                details="No Cloud SQL instances found.",
                soc2_mapping="A1.2",
                provider="GCP",
            ))
            return

        for inst in instances:
            name = inst.get("name", "unknown")
            settings = inst.get("settings", {})
            ip_config = settings.get("ipConfiguration", {})

            # Public IP
            ip_addresses = inst.get("ipAddresses", [])
            has_public = any(
                ip.get("type") == "PRIMARY" for ip in ip_addresses
            )
            authorized_networks = ip_config.get("authorizedNetworks", [])
            open_networks = [
                n for n in authorized_networks
                if n.get("value") in ("0.0.0.0/0", "::/0")
            ]

            if has_public and open_networks:
                report.add_finding(Finding(
                    severity=Severity.CRITICAL,
                    category=Category.NETWORK,
                    check="Cloud SQL public access",
                    status=Status.FAIL,
                    resource=name,
                    details=f"Instance '{name}' has public IP with 0.0.0.0/0 authorized. Restrict access.",
                    soc2_mapping="CC6.6",
                    provider="GCP",
                ))
            elif has_public:
                report.add_finding(Finding(
                    severity=Severity.MEDIUM,
                    category=Category.NETWORK,
                    check="Cloud SQL public IP",
                    status=Status.WARNING,
                    resource=name,
                    details=f"Instance '{name}' has a public IP. Use private IP when possible.",
                    soc2_mapping="CC6.6",
                    provider="GCP",
                ))
            else:
                report.add_finding(Finding(
                    severity=Severity.INFO,
                    category=Category.NETWORK,
                    check="Cloud SQL public access",
                    status=Status.PASS,
                    resource=name,
                    details="No public IP assigned.",
                    soc2_mapping="CC6.6",
                    provider="GCP",
                ))

            # SSL enforcement
            require_ssl = ip_config.get("requireSsl", False)
            report.add_finding(Finding(
                severity=Severity.HIGH if not require_ssl else Severity.INFO,
                category=Category.ENCRYPTION,
                check="Cloud SQL SSL enforcement",
                status=Status.PASS if require_ssl else Status.FAIL,
                resource=name,
                details="" if require_ssl else f"SSL not required for connections to '{name}'.",
                soc2_mapping="CC6.7",
                provider="GCP",
            ))

            # Automated backups
            backup_config = settings.get("backupConfiguration", {})
            backups_enabled = backup_config.get("enabled", False)
            report.add_finding(Finding(
                severity=Severity.HIGH if not backups_enabled else Severity.INFO,
                category=Category.BACKUPS,
                check="Cloud SQL automated backups",
                status=Status.PASS if backups_enabled else Status.FAIL,
                resource=name,
                details="" if backups_enabled else f"Automated backups not enabled for '{name}'.",
                soc2_mapping="A1.2",
                provider="GCP",
            ))

    except Exception as exc:
        report.add_finding(Finding(
            severity=Severity.HIGH,
            category=Category.BACKUPS,
            check="Cloud SQL audit",
            status=Status.ERROR,
            resource=f"projects/{project_id}",
            details=f"Unable to list Cloud SQL instances: {exc}",
            soc2_mapping="A1.2",
            provider="GCP",
        ))


# ---------------------------------------------------------------------------
# Logging checks
# ---------------------------------------------------------------------------

def check_audit_logging(project_id: str, report: AuditReport) -> None:
    """CC7.1 - Check audit log configuration."""
    try:
        from google.auth import default as google_auth_default
        from googleapiclient.discovery import build

        credentials, _ = google_auth_default()
        crm = build("cloudresourcemanager", "v1", credentials=credentials)

        policy = crm.projects().getIamPolicy(
            resource=project_id,
            body={"options": {"requestedPolicyVersion": 3}},
        ).execute()

        audit_configs = policy.get("auditConfigs", [])
        if not audit_configs:
            report.add_finding(Finding(
                severity=Severity.HIGH,
                category=Category.LOGGING,
                check="Audit logging",
                status=Status.FAIL,
                resource=f"projects/{project_id}",
                details="No audit log configurations found. Enable data access audit logs.",
                soc2_mapping="CC7.1",
                provider="GCP",
            ))
        else:
            # Check for allServices audit config
            all_services = any(
                ac.get("service") == "allServices" for ac in audit_configs
            )
            report.add_finding(Finding(
                severity=Severity.INFO if all_services else Severity.MEDIUM,
                category=Category.LOGGING,
                check="Audit logging",
                status=Status.PASS if all_services else Status.WARNING,
                resource=f"projects/{project_id}",
                details=f"{len(audit_configs)} audit config(s) found." + ("" if all_services else " Consider enabling for allServices."),
                soc2_mapping="CC7.1",
                provider="GCP",
            ))

    except Exception as exc:
        report.add_finding(Finding(
            severity=Severity.HIGH,
            category=Category.LOGGING,
            check="Audit logging",
            status=Status.ERROR,
            resource=f"projects/{project_id}",
            details=f"Unable to check audit logging: {exc}",
            soc2_mapping="CC7.1",
            provider="GCP",
        ))


def check_log_sinks(project_id: str, report: AuditReport) -> None:
    """CC7.2 - Check if log sinks are configured for export."""
    logging_mod = _safe_import("google.cloud.logging")
    if not logging_mod:
        return

    try:
        client = logging_mod.Client(project=project_id)
        sinks = list(client.list_sinks())

        if not sinks:
            report.add_finding(Finding(
                severity=Severity.MEDIUM,
                category=Category.LOGGING,
                check="Log sinks",
                status=Status.WARNING,
                resource=f"projects/{project_id}",
                details="No log sinks configured. Export logs to GCS/BigQuery/Pub/Sub for retention.",
                soc2_mapping="CC7.2",
                provider="GCP",
            ))
        else:
            report.add_finding(Finding(
                severity=Severity.INFO,
                category=Category.LOGGING,
                check="Log sinks",
                status=Status.PASS,
                resource=f"projects/{project_id}",
                details=f"{len(sinks)} log sink(s) configured.",
                soc2_mapping="CC7.2",
                provider="GCP",
            ))

    except Exception as exc:
        report.add_finding(Finding(
            severity=Severity.MEDIUM,
            category=Category.LOGGING,
            check="Log sinks",
            status=Status.ERROR,
            resource=f"projects/{project_id}",
            details=f"Unable to list log sinks: {exc}",
            soc2_mapping="CC7.2",
            provider="GCP",
        ))


# ---------------------------------------------------------------------------
# KMS checks
# ---------------------------------------------------------------------------

def check_kms_rotation(project_id: str, report: AuditReport) -> None:
    """CC6.7 - Verify KMS key rotation."""
    kms_mod = _safe_import("google.cloud.kms")
    if not kms_mod:
        return

    try:
        client = kms_mod.KeyManagementServiceClient()
        # List all key rings across all locations (common ones)
        locations = ["global", "us", "us-central1", "us-east1", "europe-west1", "asia-east1"]
        found_keys = False

        for location in locations:
            parent = f"projects/{project_id}/locations/{location}"
            try:
                key_rings = client.list_key_rings(request={"parent": parent})
                for ring in key_rings:
                    keys = client.list_crypto_keys(request={"parent": ring.name})
                    for key in keys:
                        if key.purpose != kms_mod.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT:
                            continue
                        found_keys = True
                        has_rotation = key.rotation_period is not None and key.rotation_period.total_seconds() > 0
                        report.add_finding(Finding(
                            severity=Severity.MEDIUM if not has_rotation else Severity.INFO,
                            category=Category.ENCRYPTION,
                            check="KMS key rotation",
                            status=Status.PASS if has_rotation else Status.FAIL,
                            resource=key.name.split("/")[-1],
                            details="" if has_rotation else f"Key rotation not configured for '{key.name.split('/')[-1]}'.",
                            soc2_mapping="CC6.7",
                            provider="GCP",
                        ))
            except Exception:
                pass  # Location may not have key rings

        if not found_keys:
            report.add_finding(Finding(
                severity=Severity.INFO,
                category=Category.ENCRYPTION,
                check="KMS key rotation",
                status=Status.PASS,
                resource=f"projects/{project_id}",
                details="No customer-managed encryption keys found.",
                soc2_mapping="CC6.7",
                provider="GCP",
            ))

    except Exception as exc:
        report.add_finding(Finding(
            severity=Severity.MEDIUM,
            category=Category.ENCRYPTION,
            check="KMS key rotation",
            status=Status.ERROR,
            resource=f"projects/{project_id}",
            details=f"Unable to check KMS keys: {exc}",
            soc2_mapping="CC6.7",
            provider="GCP",
        ))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.command()
@click.option("--project", required=True, help="GCP project ID.")
@click.option(
    "--output-format",
    type=click.Choice(["markdown", "json", "both"]),
    default="markdown",
    help="Report output format.",
)
@click.option("--output-dir", default="reports", help="Directory for report output.")
def main(project: str, output_format: str, output_dir: str) -> None:
    """
    Run a comprehensive GCP security audit.

    All checks are read-only. No resources are modified.
    Maintained by TrazTech (https://traztech.ca).
    """
    print_banner("GCP")

    report = AuditReport(
        provider="GCP",
        project_id=project,
        metadata={
            "tool": "cloud-security-audit-scripts",
            "maintainer": "TrazTech (https://traztech.ca)",
        },
    )

    console.print(f"\n[bold]Project:[/bold] {project}\n")

    checks = [
        ("IAM: Overly permissive bindings", lambda: check_overly_permissive_iam(project, report)),
        ("IAM: Service account keys", lambda: check_service_account_keys(project, report)),
        ("GCS: Bucket security", lambda: check_gcs_buckets(project, report)),
        ("Compute: Firewall rules", lambda: check_firewall_rules(project, report)),
        ("Compute: OS Login / Serial port", lambda: check_compute_settings(project, report)),
        ("Cloud SQL: Instance security", lambda: check_cloud_sql(project, report)),
        ("Logging: Audit logs", lambda: check_audit_logging(project, report)),
        ("Logging: Log sinks", lambda: check_log_sinks(project, report)),
        ("KMS: Key rotation", lambda: check_kms_rotation(project, report)),
    ]

    for label, check_fn in checks:
        console.print(f"[cyan]Checking {label}...[/cyan]")
        try:
            check_fn()
        except Exception as exc:
            console.print(f"[red]  Unexpected error in {label}: {exc}[/red]")

    # Output
    console.print("\n[bold]--- Findings ---[/bold]\n")
    for finding in report.findings:
        print_finding(finding)

    print_summary(report)

    os.makedirs(output_dir, exist_ok=True)
    gen = ReportGenerator()
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = f"gcp-audit-{project}-{ts}"

    if output_format in ("markdown", "both"):
        path = os.path.join(output_dir, f"{base}.md")
        gen.to_markdown(report, path)
        console.print(f"\n[green]Markdown report:[/green] {path}")

    if output_format in ("json", "both"):
        path = os.path.join(output_dir, f"{base}.json")
        gen.to_json(report, path)
        console.print(f"[green]JSON report:[/green] {path}")

    console.print(
        "\n[dim]For a comprehensive GCP security assessment, visit "
        "https://traztech.ca/tools/cloud-security-posture-check[/dim]\n"
    )


if __name__ == "__main__":
    main()
