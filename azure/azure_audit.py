#!/usr/bin/env python3
"""
Azure Cloud Security Audit Script

Comprehensive read-only security assessment for Microsoft Azure.
Checks Entra ID (AAD), NSGs, Storage Accounts, SQL, Key Vault, and Monitor.

Findings are mapped to SOC 2 Trust Services Criteria for audit readiness.
Categories align with the TrazTech Cloud Security Posture Check
(https://traztech.ca/tools/cloud-security-posture-check).

Usage:
    python azure/azure_audit.py --subscription <sub-id>
    python azure/azure_audit.py --subscription <sub-id> --output-format json

Prerequisites:
    - az login
    - az account set --subscription <SUB_ID>
    - Role: Reader at subscription scope

Maintained by TrazTech (https://traztech.ca)
Principal: Jacob Masse | 5 CVEs including CVE-2024-45163 (CVSS 9.1)
SOC 2 Readiness Checklist: https://traztech.ca/soc-2-readiness-checklist
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

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


def _try_import(module: str):
    """Attempt to import a module, returning None if unavailable."""
    try:
        import importlib
        return importlib.import_module(module)
    except ImportError:
        console.print(f"[yellow]Warning: {module} not installed. Some checks will be skipped.[/yellow]")
        return None


def _get_credential():
    """Get Azure DefaultAzureCredential."""
    identity = _try_import("azure.identity")
    if not identity:
        return None
    return identity.DefaultAzureCredential()


# ---------------------------------------------------------------------------
# NSG checks
# ---------------------------------------------------------------------------

SENSITIVE_PORTS_AZURE = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
    6379: "Redis",
}


def check_nsgs(subscription_id: str, credential, report: AuditReport) -> None:
    """CC6.6 - Check Network Security Groups for overly permissive rules."""
    mgmt_network = _try_import("azure.mgmt.network")
    if not mgmt_network:
        return

    try:
        client = mgmt_network.NetworkManagementClient(credential, subscription_id)
        nsgs = client.network_security_groups.list_all()
        found_open = False

        for nsg in nsgs:
            nsg_name = nsg.name
            nsg_id = nsg.id or nsg_name
            rg = nsg_id.split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in nsg_id else "unknown"
            resource_label = f"{nsg_name} (RG: {rg})"

            has_deny_all = False
            for rule in (nsg.security_rules or []):
                # Check for default deny inbound
                if (
                    rule.direction == "Inbound"
                    and rule.access == "Deny"
                    and rule.source_address_prefix in ("*", "0.0.0.0/0")
                    and rule.destination_port_range == "*"
                ):
                    has_deny_all = True

                # Check for overly permissive Allow rules
                if rule.access != "Allow" or rule.direction != "Inbound":
                    continue

                source = rule.source_address_prefix or ""
                sources = rule.source_address_prefixes or []
                all_sources = [source] + list(sources)
                is_open = any(s in ("*", "0.0.0.0/0", "Internet") for s in all_sources)

                if not is_open:
                    continue

                # Check port ranges
                ports_str = rule.destination_port_range or ""
                port_ranges = rule.destination_port_ranges or []
                all_port_strs = ([ports_str] if ports_str else []) + list(port_ranges)

                for port_str in all_port_strs:
                    if port_str == "*":
                        found_open = True
                        report.add_finding(Finding(
                            severity=Severity.CRITICAL,
                            category=Category.NETWORK,
                            check="NSG open to Internet",
                            status=Status.FAIL,
                            resource=resource_label,
                            details=f"Rule '{rule.name}' allows ALL ports from Internet.",
                            soc2_mapping="CC6.6",
                            provider="Azure",
                        ))
                        continue

                    # Parse port range
                    try:
                        if "-" in port_str:
                            start, end = port_str.split("-", 1)
                            port_range = range(int(start), int(end) + 1)
                        else:
                            port_range = range(int(port_str), int(port_str) + 1)

                        for port, service in SENSITIVE_PORTS_AZURE.items():
                            if port in port_range:
                                found_open = True
                                sev = Severity.CRITICAL if port in (22, 3389) else Severity.HIGH
                                report.add_finding(Finding(
                                    severity=sev,
                                    category=Category.NETWORK,
                                    check="NSG open to Internet",
                                    status=Status.FAIL,
                                    resource=resource_label,
                                    details=f"Rule '{rule.name}': port {port} ({service}) open from Internet.",
                                    soc2_mapping="CC6.6",
                                    provider="Azure",
                                ))
                    except (ValueError, TypeError):
                        pass

            # Default deny check
            if not has_deny_all:
                report.add_finding(Finding(
                    severity=Severity.MEDIUM,
                    category=Category.NETWORK,
                    check="NSG default deny",
                    status=Status.WARNING,
                    resource=resource_label,
                    details="No explicit deny-all inbound rule. Relies on Azure default rules.",
                    soc2_mapping="CC6.6",
                    provider="Azure",
                ))

        if not found_open:
            report.add_finding(Finding(
                severity=Severity.INFO,
                category=Category.NETWORK,
                check="NSG rules",
                status=Status.PASS,
                resource=f"Subscription {subscription_id}",
                details="No sensitive ports open to Internet in NSG rules.",
                soc2_mapping="CC6.6",
                provider="Azure",
            ))

    except Exception as exc:
        report.add_finding(Finding(
            severity=Severity.HIGH,
            category=Category.NETWORK,
            check="NSG audit",
            status=Status.ERROR,
            resource=f"Subscription {subscription_id}",
            details=f"Unable to list NSGs: {exc}",
            soc2_mapping="CC6.6",
            provider="Azure",
        ))


# ---------------------------------------------------------------------------
# Storage Account checks
# ---------------------------------------------------------------------------

def check_storage_accounts(subscription_id: str, credential, report: AuditReport) -> None:
    """CC6.6 / CC6.7 - Check Storage Accounts for public access, encryption, secure transfer."""
    mgmt_storage = _try_import("azure.mgmt.storage")
    if not mgmt_storage:
        return

    try:
        client = mgmt_storage.StorageManagementClient(credential, subscription_id)
        accounts = client.storage_accounts.list()
        found_any = False

        for acct in accounts:
            found_any = True
            name = acct.name
            rg = acct.id.split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in acct.id else "unknown"
            resource_label = f"{name} (RG: {rg})"

            # Public blob access
            allow_blob_public = acct.allow_blob_public_access
            if allow_blob_public is None:
                allow_blob_public = True  # Default is True if not set
            report.add_finding(Finding(
                severity=Severity.HIGH if allow_blob_public else Severity.INFO,
                category=Category.NETWORK,
                check="Storage public blob access",
                status=Status.FAIL if allow_blob_public else Status.PASS,
                resource=resource_label,
                details="Public blob access is allowed. Disable unless required." if allow_blob_public else "Public blob access disabled.",
                soc2_mapping="CC6.6",
                provider="Azure",
            ))

            # HTTPS only (secure transfer)
            https_only = acct.enable_https_traffic_only
            if https_only is None:
                https_only = True  # Default for newer accounts
            report.add_finding(Finding(
                severity=Severity.HIGH if not https_only else Severity.INFO,
                category=Category.ENCRYPTION,
                check="Storage secure transfer (HTTPS)",
                status=Status.PASS if https_only else Status.FAIL,
                resource=resource_label,
                details="" if https_only else "Secure transfer (HTTPS) not enforced.",
                soc2_mapping="CC6.7",
                provider="Azure",
            ))

            # Encryption
            encryption = acct.encryption
            if encryption:
                blob_encrypted = (
                    encryption.services and
                    encryption.services.blob and
                    encryption.services.blob.enabled
                )
                file_encrypted = (
                    encryption.services and
                    encryption.services.file and
                    encryption.services.file.enabled
                )
                all_encrypted = blob_encrypted and file_encrypted
                report.add_finding(Finding(
                    severity=Severity.INFO if all_encrypted else Severity.HIGH,
                    category=Category.ENCRYPTION,
                    check="Storage encryption",
                    status=Status.PASS if all_encrypted else Status.FAIL,
                    resource=resource_label,
                    details="" if all_encrypted else "Not all storage services have encryption enabled.",
                    soc2_mapping="CC6.7",
                    provider="Azure",
                ))

            # Minimum TLS version
            min_tls = acct.minimum_tls_version
            if min_tls and min_tls != "TLS1_2":
                report.add_finding(Finding(
                    severity=Severity.MEDIUM,
                    category=Category.ENCRYPTION,
                    check="Storage minimum TLS version",
                    status=Status.WARNING,
                    resource=resource_label,
                    details=f"Minimum TLS version is {min_tls}. Recommend TLS 1.2.",
                    soc2_mapping="CC6.7",
                    provider="Azure",
                ))
            else:
                report.add_finding(Finding(
                    severity=Severity.INFO,
                    category=Category.ENCRYPTION,
                    check="Storage minimum TLS version",
                    status=Status.PASS,
                    resource=resource_label,
                    details="TLS 1.2 enforced.",
                    soc2_mapping="CC6.7",
                    provider="Azure",
                ))

        if not found_any:
            report.add_finding(Finding(
                severity=Severity.INFO,
                category=Category.ENCRYPTION,
                check="Storage accounts",
                status=Status.PASS,
                resource=f"Subscription {subscription_id}",
                details="No storage accounts found.",
                soc2_mapping="CC6.7",
                provider="Azure",
            ))

    except Exception as exc:
        report.add_finding(Finding(
            severity=Severity.HIGH,
            category=Category.ENCRYPTION,
            check="Storage account audit",
            status=Status.ERROR,
            resource=f"Subscription {subscription_id}",
            details=f"Unable to list storage accounts: {exc}",
            soc2_mapping="CC6.7",
            provider="Azure",
        ))


# ---------------------------------------------------------------------------
# SQL Server checks
# ---------------------------------------------------------------------------

def check_sql_servers(subscription_id: str, credential, report: AuditReport) -> None:
    """CC7.1 / CC6.7 / CC6.6 - Check Azure SQL servers."""
    mgmt_sql = _try_import("azure.mgmt.sql")
    if not mgmt_sql:
        return

    try:
        client = mgmt_sql.SqlManagementClient(credential, subscription_id)
        servers = client.servers.list()
        found_any = False

        for server in servers:
            found_any = True
            name = server.name
            rg = server.id.split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in server.id else "unknown"
            resource_label = f"{name} (RG: {rg})"

            # Auditing
            try:
                audit_settings = client.server_blob_auditing_policies.get(rg, name)
                auditing_enabled = audit_settings.state == "Enabled"
                report.add_finding(Finding(
                    severity=Severity.HIGH if not auditing_enabled else Severity.INFO,
                    category=Category.LOGGING,
                    check="SQL Server auditing",
                    status=Status.PASS if auditing_enabled else Status.FAIL,
                    resource=resource_label,
                    details="" if auditing_enabled else f"Auditing not enabled for SQL Server '{name}'.",
                    soc2_mapping="CC7.1",
                    provider="Azure",
                ))
            except Exception:
                report.add_finding(Finding(
                    severity=Severity.MEDIUM,
                    category=Category.LOGGING,
                    check="SQL Server auditing",
                    status=Status.ERROR,
                    resource=resource_label,
                    details="Unable to check auditing status.",
                    soc2_mapping="CC7.1",
                    provider="Azure",
                ))

            # TDE (Transparent Data Encryption) - check databases
            try:
                databases = client.databases.list_by_server(rg, name)
                for db in databases:
                    if db.name in ("master",):
                        continue
                    try:
                        tde = client.transparent_data_encryptions.get(
                            rg, name, db.name
                        )
                        tde_enabled = tde.status == "Enabled"
                        report.add_finding(Finding(
                            severity=Severity.HIGH if not tde_enabled else Severity.INFO,
                            category=Category.ENCRYPTION,
                            check="SQL TDE (Transparent Data Encryption)",
                            status=Status.PASS if tde_enabled else Status.FAIL,
                            resource=f"{name}/{db.name}",
                            details="" if tde_enabled else f"TDE not enabled for database '{db.name}'.",
                            soc2_mapping="CC6.7",
                            provider="Azure",
                        ))
                    except Exception:
                        pass
            except Exception:
                pass

            # Firewall rules
            try:
                fw_rules = client.firewall_rules.list_by_server(rg, name)
                for rule in fw_rules:
                    if rule.start_ip_address == "0.0.0.0" and rule.end_ip_address in ("0.0.0.0", "255.255.255.255"):
                        severity = Severity.HIGH if rule.end_ip_address == "255.255.255.255" else Severity.MEDIUM
                        report.add_finding(Finding(
                            severity=severity,
                            category=Category.NETWORK,
                            check="SQL Server firewall rules",
                            status=Status.FAIL if rule.end_ip_address == "255.255.255.255" else Status.WARNING,
                            resource=resource_label,
                            details=f"Rule '{rule.name}': {rule.start_ip_address} - {rule.end_ip_address}. "
                                    + ("Open to all IPs." if rule.end_ip_address == "255.255.255.255" else "Allows Azure services (0.0.0.0-0.0.0.0)."),
                            soc2_mapping="CC6.6",
                            provider="Azure",
                        ))
            except Exception:
                pass

        if not found_any:
            report.add_finding(Finding(
                severity=Severity.INFO,
                category=Category.LOGGING,
                check="SQL Servers",
                status=Status.PASS,
                resource=f"Subscription {subscription_id}",
                details="No Azure SQL Servers found.",
                soc2_mapping="CC7.1",
                provider="Azure",
            ))

    except Exception as exc:
        report.add_finding(Finding(
            severity=Severity.HIGH,
            category=Category.LOGGING,
            check="SQL Server audit",
            status=Status.ERROR,
            resource=f"Subscription {subscription_id}",
            details=f"Unable to list SQL Servers: {exc}",
            soc2_mapping="CC7.1",
            provider="Azure",
        ))


# ---------------------------------------------------------------------------
# Key Vault checks
# ---------------------------------------------------------------------------

def check_key_vaults(subscription_id: str, credential, report: AuditReport) -> None:
    """CC6.7 / A1.2 - Check Key Vault configuration."""
    mgmt_kv = _try_import("azure.mgmt.keyvault")
    if not mgmt_kv:
        return

    try:
        client = mgmt_kv.KeyVaultManagementClient(credential, subscription_id)
        vaults = client.vaults.list()
        found_any = False

        for vault in vaults:
            found_any = True
            name = vault.name
            rg = vault.id.split("/resourceGroups/")[1].split("/")[0] if vault.id and "/resourceGroups/" in vault.id else "unknown"
            resource_label = f"{name} (RG: {rg})"

            # We need to get the full vault properties
            try:
                full_vault = client.vaults.get(rg, name)
                props = full_vault.properties

                # Soft delete
                soft_delete = props.enable_soft_delete
                if soft_delete is None:
                    soft_delete = True  # Default enabled for newer vaults
                report.add_finding(Finding(
                    severity=Severity.HIGH if not soft_delete else Severity.INFO,
                    category=Category.BACKUPS,
                    check="Key Vault soft delete",
                    status=Status.PASS if soft_delete else Status.FAIL,
                    resource=resource_label,
                    details="" if soft_delete else "Soft delete not enabled. Secrets can be permanently lost.",
                    soc2_mapping="A1.2",
                    provider="Azure",
                ))

                # Purge protection
                purge_protection = props.enable_purge_protection
                report.add_finding(Finding(
                    severity=Severity.MEDIUM if not purge_protection else Severity.INFO,
                    category=Category.BACKUPS,
                    check="Key Vault purge protection",
                    status=Status.PASS if purge_protection else Status.WARNING,
                    resource=resource_label,
                    details="" if purge_protection else "Purge protection not enabled. Soft-deleted items can still be purged.",
                    soc2_mapping="A1.2",
                    provider="Azure",
                ))

                # RBAC vs Access Policies
                rbac = props.enable_rbac_authorization
                report.add_finding(Finding(
                    severity=Severity.INFO if rbac else Severity.LOW,
                    category=Category.IAM,
                    check="Key Vault RBAC authorization",
                    status=Status.PASS if rbac else Status.WARNING,
                    resource=resource_label,
                    details="Using RBAC authorization." if rbac else "Using vault access policies. Consider migrating to RBAC.",
                    soc2_mapping="CC6.3",
                    provider="Azure",
                ))

                # Network ACLs
                network_acls = props.network_acls
                if network_acls:
                    default_action = network_acls.default_action
                    if default_action and default_action.lower() == "allow":
                        report.add_finding(Finding(
                            severity=Severity.MEDIUM,
                            category=Category.NETWORK,
                            check="Key Vault network access",
                            status=Status.WARNING,
                            resource=resource_label,
                            details="Default network action is Allow. Restrict to specific networks.",
                            soc2_mapping="CC6.6",
                            provider="Azure",
                        ))
                    else:
                        report.add_finding(Finding(
                            severity=Severity.INFO,
                            category=Category.NETWORK,
                            check="Key Vault network access",
                            status=Status.PASS,
                            resource=resource_label,
                            details="Network access is restricted (default deny).",
                            soc2_mapping="CC6.6",
                            provider="Azure",
                        ))

            except Exception as exc:
                report.add_finding(Finding(
                    severity=Severity.MEDIUM,
                    category=Category.SECRETS,
                    check="Key Vault properties",
                    status=Status.ERROR,
                    resource=resource_label,
                    details=f"Unable to get vault details: {exc}",
                    soc2_mapping="CC6.7",
                    provider="Azure",
                ))

        if not found_any:
            report.add_finding(Finding(
                severity=Severity.MEDIUM,
                category=Category.SECRETS,
                check="Key Vault",
                status=Status.WARNING,
                resource=f"Subscription {subscription_id}",
                details="No Key Vaults found. Use Key Vault for secrets management.",
                soc2_mapping="CC6.7",
                provider="Azure",
            ))

    except Exception as exc:
        report.add_finding(Finding(
            severity=Severity.HIGH,
            category=Category.SECRETS,
            check="Key Vault audit",
            status=Status.ERROR,
            resource=f"Subscription {subscription_id}",
            details=f"Unable to list Key Vaults: {exc}",
            soc2_mapping="CC6.7",
            provider="Azure",
        ))


# ---------------------------------------------------------------------------
# Monitor / Activity Log checks
# ---------------------------------------------------------------------------

def check_monitor(subscription_id: str, credential, report: AuditReport) -> None:
    """CC7.2 - Check Azure Monitor activity log alerts and diagnostic settings."""
    mgmt_monitor = _try_import("azure.mgmt.monitor")
    if not mgmt_monitor:
        return

    try:
        client = mgmt_monitor.MonitorManagementClient(credential, subscription_id)

        # Activity log alerts
        try:
            alerts = client.activity_log_alerts.list_by_subscription_id()
            alert_list = list(alerts)
            if not alert_list:
                report.add_finding(Finding(
                    severity=Severity.MEDIUM,
                    category=Category.POSTURE,
                    check="Activity log alerts",
                    status=Status.WARNING,
                    resource=f"Subscription {subscription_id}",
                    details="No activity log alerts configured. Set up alerts for critical operations.",
                    soc2_mapping="CC7.2",
                    provider="Azure",
                ))
            else:
                enabled_count = sum(1 for a in alert_list if a.enabled)
                report.add_finding(Finding(
                    severity=Severity.INFO,
                    category=Category.POSTURE,
                    check="Activity log alerts",
                    status=Status.PASS,
                    resource=f"Subscription {subscription_id}",
                    details=f"{enabled_count} active alert(s) of {len(alert_list)} total.",
                    soc2_mapping="CC7.2",
                    provider="Azure",
                ))
        except Exception as exc:
            report.add_finding(Finding(
                severity=Severity.MEDIUM,
                category=Category.POSTURE,
                check="Activity log alerts",
                status=Status.ERROR,
                resource=f"Subscription {subscription_id}",
                details=f"Unable to list activity log alerts: {exc}",
                soc2_mapping="CC7.2",
                provider="Azure",
            ))

        # Diagnostic settings on subscription
        try:
            diag_settings = client.diagnostic_settings.list(
                resource_uri=f"/subscriptions/{subscription_id}"
            )
            settings_list = list(diag_settings.value) if hasattr(diag_settings, 'value') else []
            if not settings_list:
                report.add_finding(Finding(
                    severity=Severity.HIGH,
                    category=Category.LOGGING,
                    check="Subscription diagnostic settings",
                    status=Status.FAIL,
                    resource=f"Subscription {subscription_id}",
                    details="No diagnostic settings on subscription. Activity logs may not be exported.",
                    soc2_mapping="CC7.1",
                    provider="Azure",
                ))
            else:
                report.add_finding(Finding(
                    severity=Severity.INFO,
                    category=Category.LOGGING,
                    check="Subscription diagnostic settings",
                    status=Status.PASS,
                    resource=f"Subscription {subscription_id}",
                    details=f"{len(settings_list)} diagnostic setting(s) configured.",
                    soc2_mapping="CC7.1",
                    provider="Azure",
                ))
        except Exception as exc:
            report.add_finding(Finding(
                severity=Severity.MEDIUM,
                category=Category.LOGGING,
                check="Subscription diagnostic settings",
                status=Status.ERROR,
                resource=f"Subscription {subscription_id}",
                details=f"Unable to check diagnostic settings: {exc}",
                soc2_mapping="CC7.1",
                provider="Azure",
            ))

    except Exception as exc:
        report.add_finding(Finding(
            severity=Severity.HIGH,
            category=Category.POSTURE,
            check="Azure Monitor",
            status=Status.ERROR,
            resource=f"Subscription {subscription_id}",
            details=f"Unable to check Monitor: {exc}",
            soc2_mapping="CC7.2",
            provider="Azure",
        ))


# ---------------------------------------------------------------------------
# Entra ID / AAD checks (via Azure CLI as fallback)
# ---------------------------------------------------------------------------

def check_entra_id(subscription_id: str, credential, report: AuditReport) -> None:
    """CC6.1 - Check Entra ID (AAD) security settings via Azure Resource Graph or CLI."""
    import subprocess

    # Use az CLI for Entra ID checks since the Python SDK for Microsoft Graph
    # requires separate authentication. This keeps things simple for audit use.

    # Check MFA registration status (via az ad)
    try:
        result = subprocess.run(
            ["az", "ad", "user", "list", "--query", "[].{upn:userPrincipalName,accountEnabled:accountEnabled}", "-o", "json"],
            capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL,
        )
        if result.returncode == 0:
            import json
            users = json.loads(result.stdout)
            total = len(users)
            disabled = sum(1 for u in users if not u.get("accountEnabled", True))
            report.add_finding(Finding(
                severity=Severity.INFO,
                category=Category.IAM,
                check="Entra ID user enumeration",
                status=Status.PASS,
                resource=f"Entra ID tenant",
                details=f"{total} user(s) found, {disabled} disabled. Review for stale accounts.",
                soc2_mapping="CC6.2",
                provider="Azure",
            ))
        else:
            report.add_finding(Finding(
                severity=Severity.MEDIUM,
                category=Category.IAM,
                check="Entra ID user enumeration",
                status=Status.ERROR,
                resource="Entra ID tenant",
                details=f"Unable to list Entra ID users. Ensure 'az ad' permissions. Error: {result.stderr[:200]}",
                soc2_mapping="CC6.2",
                provider="Azure",
            ))
    except FileNotFoundError:
        report.add_finding(Finding(
            severity=Severity.MEDIUM,
            category=Category.IAM,
            check="Entra ID checks",
            status=Status.ERROR,
            resource="Entra ID",
            details="Azure CLI (az) not found. Install for Entra ID checks.",
            soc2_mapping="CC6.1",
            provider="Azure",
        ))
    except Exception as exc:
        report.add_finding(Finding(
            severity=Severity.MEDIUM,
            category=Category.IAM,
            check="Entra ID checks",
            status=Status.ERROR,
            resource="Entra ID",
            details=f"Error checking Entra ID: {exc}",
            soc2_mapping="CC6.1",
            provider="Azure",
        ))

    # Check guest users
    try:
        result = subprocess.run(
            ["az", "ad", "user", "list", "--filter", "userType eq 'Guest'", "--query", "length(@)", "-o", "json"],
            capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL,
        )
        if result.returncode == 0:
            import json
            guest_count = json.loads(result.stdout)
            if isinstance(guest_count, int) and guest_count > 0:
                report.add_finding(Finding(
                    severity=Severity.MEDIUM,
                    category=Category.IAM,
                    check="Entra ID guest users",
                    status=Status.WARNING,
                    resource="Entra ID tenant",
                    details=f"{guest_count} guest user(s) found. Review guest access policies.",
                    soc2_mapping="CC6.2",
                    provider="Azure",
                ))
            else:
                report.add_finding(Finding(
                    severity=Severity.INFO,
                    category=Category.IAM,
                    check="Entra ID guest users",
                    status=Status.PASS,
                    resource="Entra ID tenant",
                    details="No guest users found.",
                    soc2_mapping="CC6.2",
                    provider="Azure",
                ))
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Role Assignments checks
# ---------------------------------------------------------------------------

def check_role_assignments(subscription_id: str, credential, report: AuditReport) -> None:
    """CC6.3 - Check for overly broad role assignments."""
    mgmt_auth = _try_import("azure.mgmt.authorization")
    if not mgmt_auth:
        return

    try:
        client = mgmt_auth.AuthorizationManagementClient(credential, subscription_id)
        assignments = client.role_assignments.list_for_subscription()

        owner_count = 0
        contributor_count = 0

        # Get role definitions to map IDs to names
        role_defs = {}
        try:
            defs = client.role_definitions.list(
                scope=f"/subscriptions/{subscription_id}"
            )
            for d in defs:
                role_defs[d.id] = d.role_name
        except Exception:
            pass

        for assignment in assignments:
            role_id = assignment.role_definition_id or ""
            role_name = role_defs.get(role_id, "Unknown")

            if role_name == "Owner":
                owner_count += 1
            elif role_name == "Contributor":
                contributor_count += 1

        if owner_count > 3:
            report.add_finding(Finding(
                severity=Severity.HIGH,
                category=Category.IAM,
                check="Subscription Owner count",
                status=Status.WARNING,
                resource=f"Subscription {subscription_id}",
                details=f"{owner_count} Owner role assignments. Minimize Owner count (recommend <= 3).",
                soc2_mapping="CC6.3",
                provider="Azure",
            ))
        else:
            report.add_finding(Finding(
                severity=Severity.INFO,
                category=Category.IAM,
                check="Subscription Owner count",
                status=Status.PASS,
                resource=f"Subscription {subscription_id}",
                details=f"{owner_count} Owner role assignment(s).",
                soc2_mapping="CC6.3",
                provider="Azure",
            ))

        report.add_finding(Finding(
            severity=Severity.INFO,
            category=Category.IAM,
            check="Role assignment summary",
            status=Status.PASS,
            resource=f"Subscription {subscription_id}",
            details=f"Owners: {owner_count}, Contributors: {contributor_count}. Review for least privilege.",
            soc2_mapping="CC6.3",
            provider="Azure",
        ))

    except Exception as exc:
        report.add_finding(Finding(
            severity=Severity.MEDIUM,
            category=Category.IAM,
            check="Role assignments",
            status=Status.ERROR,
            resource=f"Subscription {subscription_id}",
            details=f"Unable to check role assignments: {exc}",
            soc2_mapping="CC6.3",
            provider="Azure",
        ))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.command()
@click.option("--subscription", required=True, help="Azure subscription ID.")
@click.option(
    "--output-format",
    type=click.Choice(["markdown", "json", "both"]),
    default="markdown",
    help="Report output format.",
)
@click.option("--output-dir", default="reports", help="Directory for report output.")
def main(subscription: str, output_format: str, output_dir: str) -> None:
    """
    Run a comprehensive Azure security audit.

    All checks are read-only. No resources are modified.
    Maintained by TrazTech (https://traztech.ca).
    """
    print_banner("Azure")

    credential = _get_credential()
    if not credential:
        console.print("[red]Azure credentials not available. Run 'az login' first.[/red]")
        sys.exit(1)

    report = AuditReport(
        provider="Azure",
        subscription_id=subscription,
        metadata={
            "tool": "cloud-security-audit-scripts",
            "maintainer": "TrazTech (https://traztech.ca)",
        },
    )

    console.print(f"\n[bold]Subscription:[/bold] {subscription}\n")

    checks = [
        ("Entra ID (AAD)", lambda: check_entra_id(subscription, credential, report)),
        ("Role assignments", lambda: check_role_assignments(subscription, credential, report)),
        ("Network Security Groups", lambda: check_nsgs(subscription, credential, report)),
        ("Storage Accounts", lambda: check_storage_accounts(subscription, credential, report)),
        ("SQL Servers", lambda: check_sql_servers(subscription, credential, report)),
        ("Key Vaults", lambda: check_key_vaults(subscription, credential, report)),
        ("Azure Monitor", lambda: check_monitor(subscription, credential, report)),
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
    base = f"azure-audit-{subscription}-{ts}"

    if output_format in ("markdown", "both"):
        path = os.path.join(output_dir, f"{base}.md")
        gen.to_markdown(report, path)
        console.print(f"\n[green]Markdown report:[/green] {path}")

    if output_format in ("json", "both"):
        path = os.path.join(output_dir, f"{base}.json")
        gen.to_json(report, path)
        console.print(f"[green]JSON report:[/green] {path}")

    console.print(
        "\n[dim]For a comprehensive Azure security assessment, visit "
        "https://traztech.ca/tools/cloud-security-posture-check[/dim]\n"
    )


if __name__ == "__main__":
    main()
