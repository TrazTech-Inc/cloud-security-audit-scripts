"""
Shared utilities for cloud security audit scripts.

Provides severity enums, finding dataclasses, report generation,
and rich console output helpers.

Maintained by TrazTech (https://traztech.ca)
- Cloud security reviews for AWS, GCP, Azure
- SOC 2 / ISO 27001 readiness engagements
- Free Cloud Security Posture Check: https://traztech.ca/tools/cloud-security-posture-check
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

from jinja2 import Environment, FileSystemLoader
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """Finding severity aligned with TrazTech posture check weightings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    def __str__(self) -> str:
        return self.value


class Status(str, Enum):
    """Check result status."""
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    ERROR = "ERROR"

    def __str__(self) -> str:
        return self.value


class Category(str, Enum):
    """
    Finding categories matching the TrazTech Cloud Security Posture Check
    (https://traztech.ca/tools/cloud-security-posture-check).
    """
    IAM = "IAM"
    LOGGING = "Logging"
    ENCRYPTION = "Encryption"
    NETWORK = "Network"
    BACKUPS = "Backups"
    SECRETS = "Secrets"
    POSTURE = "Posture"
    GOVERNANCE = "Governance"

    def __str__(self) -> str:
        return self.value


# ---------------------------------------------------------------------------
# SOC 2 mapping reference
# ---------------------------------------------------------------------------

SOC2_CRITERIA: Dict[str, str] = {
    "CC6.1": "Logical and Physical Access - Access security mechanisms",
    "CC6.2": "Logical and Physical Access - Credentials and access provisioning",
    "CC6.3": "Logical and Physical Access - Role-based access and least privilege",
    "CC6.6": "Logical and Physical Access - Security of system boundaries",
    "CC6.7": "Logical and Physical Access - Encryption of data in transit",
    "CC6.8": "Logical and Physical Access - Prevention of malicious software",
    "CC7.1": "System Operations - Detection of changes and anomalies",
    "CC7.2": "System Operations - Monitoring of system components",
    "CC8.1": "Change Management - Authorization and management of changes",
    "A1.2": "Availability - Recovery mechanisms and backup",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """Represents a single audit finding."""
    severity: Severity
    category: Category
    check: str
    status: Status
    resource: str
    details: str
    soc2_mapping: str = ""
    provider: str = ""
    region: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        """Serialize finding to a plain dictionary."""
        d = asdict(self)
        d["severity"] = str(self.severity)
        d["status"] = str(self.status)
        d["category"] = str(self.category)
        return d


@dataclass
class AuditReport:
    """Container for a complete audit run."""
    provider: str
    account_id: str = ""
    project_id: str = ""
    subscription_id: str = ""
    region: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, str] = field(default_factory=dict)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def summary(self) -> Dict[str, int]:
        """Return counts by status."""
        counts: Dict[str, int] = {"PASS": 0, "FAIL": 0, "WARNING": 0, "ERROR": 0}
        for f in self.findings:
            counts[str(f.status)] = counts.get(str(f.status), 0) + 1
        return counts

    def severity_counts(self) -> Dict[str, int]:
        """Return counts of non-PASS findings by severity."""
        counts: Dict[str, int] = {}
        for f in self.findings:
            if f.status != Status.PASS:
                key = str(f.severity)
                counts[key] = counts.get(key, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "account_id": self.account_id,
            "project_id": self.project_id,
            "subscription_id": self.subscription_id,
            "region": self.region,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
            "summary": self.summary(),
            "severity_counts": self.severity_counts(),
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Report generator
# ---------------------------------------------------------------------------

class ReportGenerator:
    """Generate markdown or JSON reports from AuditReport objects."""

    def __init__(self, template_dir: Optional[str] = None):
        if template_dir is None:
            template_dir = str(Path(__file__).resolve().parent.parent / "reports")
        self.template_dir = template_dir

    def to_json(self, report: AuditReport, output_path: str) -> str:
        """Write report as JSON."""
        data = report.to_dict()
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        return output_path

    def to_markdown(self, report: AuditReport, output_path: str) -> str:
        """Render report using Jinja2 markdown template."""
        env = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=False,
            keep_trailing_newline=True,
        )
        template = env.get_template("report_template.md")

        # Group findings by category
        categories: Dict[str, List[dict]] = {}
        for f in report.findings:
            cat = str(f.category)
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(f.to_dict())

        rendered = template.render(
            provider=report.provider,
            account_id=report.account_id,
            project_id=report.project_id,
            subscription_id=report.subscription_id,
            region=report.region,
            timestamp=report.timestamp,
            metadata=report.metadata,
            summary=report.summary(),
            severity_counts=report.severity_counts(),
            categories=categories,
            findings=[f.to_dict() for f in report.findings],
            traztech_url="https://traztech.ca",
            posture_check_url="https://traztech.ca/tools/cloud-security-posture-check",
            soc2_checklist_url="https://traztech.ca/soc-2-readiness-checklist",
        )

        with open(output_path, "w") as f:
            f.write(rendered)
        return output_path


# ---------------------------------------------------------------------------
# Rich console helpers
# ---------------------------------------------------------------------------

_STATUS_STYLES = {
    Status.PASS: ("bold green", "[PASS]"),
    Status.FAIL: ("bold red", "[FAIL]"),
    Status.WARNING: ("bold yellow", "[WARN]"),
    Status.ERROR: ("bold magenta", "[ERR ]"),
}

_SEVERITY_STYLES = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def print_banner(provider: str) -> None:
    """Print a styled banner at the start of an audit run."""
    banner_text = Text()
    banner_text.append("Cloud Security Audit Scripts\n", style="bold cyan")
    banner_text.append(f"Provider: {provider}\n", style="bold white")
    banner_text.append(f"Timestamp: {datetime.now(timezone.utc).isoformat()}\n", style="dim")
    banner_text.append("\nMaintained by TrazTech (traztech.ca)", style="dim italic")

    console.print(Panel(banner_text, title="TrazTech Audit", border_style="cyan"))


def print_finding(finding: Finding) -> None:
    """Print a single finding to the console."""
    style, label = _STATUS_STYLES.get(finding.status, ("white", "[????]"))
    sev_style = _SEVERITY_STYLES.get(finding.severity, "white")

    text = Text()
    text.append(label, style=style)
    text.append(" ", style="white")
    text.append(f"[{finding.severity}]", style=sev_style)
    text.append(f" {finding.check}", style="bold")
    text.append(f"  {finding.resource}", style="dim")
    if finding.details and finding.status != Status.PASS:
        text.append(f"\n       {finding.details}", style="dim italic")

    console.print(text)


def print_summary(report: AuditReport) -> None:
    """Print a summary table for the audit."""
    summary = report.summary()
    sev = report.severity_counts()

    table = Table(title="Audit Summary", border_style="cyan")
    table.add_column("Metric", style="bold")
    table.add_column("Count", justify="right")

    table.add_row("Total checks", str(len(report.findings)))
    table.add_row("[green]Passed[/green]", str(summary.get("PASS", 0)))
    table.add_row("[red]Failed[/red]", str(summary.get("FAIL", 0)))
    table.add_row("[yellow]Warnings[/yellow]", str(summary.get("WARNING", 0)))
    table.add_row("[magenta]Errors[/magenta]", str(summary.get("ERROR", 0)))

    if sev:
        table.add_section()
        table.add_row("[bold]Non-pass by severity[/bold]", "")
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if s in sev:
                table.add_row(f"  {s}", str(sev[s]))

    console.print(table)
    console.print(
        "\n[dim]For a comprehensive assessment, visit "
        "https://traztech.ca/tools/cloud-security-posture-check[/dim]\n"
    )
