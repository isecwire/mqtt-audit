"""Finding model and report generation for mqtt-audit."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


class Severity(str, Enum):
    """Finding severity levels aligned with common vulnerability scoring."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __str__(self) -> str:
        return self.value


_SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass
class Finding:
    """A single security finding produced by an audit check."""

    severity: Severity
    title: str
    description: str
    remediation: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditReport:
    """Complete audit report for a single broker."""

    host: str
    port: int
    tls_port: int
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def add(self, finding: Finding) -> None:
        """Append a finding to the report."""
        self.findings.append(finding)

    @property
    def sorted_findings(self) -> list[Finding]:
        """Return findings ordered by severity (critical first)."""
        return sorted(self.findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))

    # ------------------------------------------------------------------
    # JSON output
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serialise the report to a plain dict suitable for JSON."""
        data: dict[str, Any] = {
            "mqtt_audit_version": "0.2.0",
            "host": self.host,
            "port": self.port,
            "tls_port": self.tls_port,
            "timestamp": self.timestamp,
            "summary": {
                "total": len(self.findings),
                "critical": sum(1 for f in self.findings if f.severity == Severity.CRITICAL),
                "high": sum(1 for f in self.findings if f.severity == Severity.HIGH),
                "medium": sum(1 for f in self.findings if f.severity == Severity.MEDIUM),
                "low": sum(1 for f in self.findings if f.severity == Severity.LOW),
                "info": sum(1 for f in self.findings if f.severity == Severity.INFO),
            },
            "findings": [asdict(f) for f in self.sorted_findings],
            "metadata": self.metadata,
        }
        return data

    def write_json(self, path: str | Path) -> Path:
        """Write the report as a JSON file and return the resolved path."""
        dest = Path(path).resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(self.to_dict(), indent=2, default=str) + "\n", encoding="utf-8")
        return dest

    # ------------------------------------------------------------------
    # Rich console output
    # ------------------------------------------------------------------

    def print_console(self, console: Console | None = None) -> None:
        """Render a rich summary to the terminal."""
        con = console or Console()

        con.print()
        con.print(
            Panel(
                f"[bold]Target:[/bold] {self.host}:{self.port}  |  "
                f"[bold]TLS port:[/bold] {self.tls_port}  |  "
                f"[bold]Time:[/bold] {self.timestamp}",
                title="[bold blue]mqtt-audit report[/bold blue]",
                border_style="blue",
            )
        )

        if not self.findings:
            con.print("[green]No findings -- the broker configuration looks solid.[/green]")
            return

        table = Table(show_header=True, header_style="bold", expand=True)
        table.add_column("#", style="dim", width=4)
        table.add_column("Severity", width=10)
        table.add_column("Title", min_width=30)
        table.add_column("Remediation", ratio=1)

        for idx, finding in enumerate(self.sorted_findings, start=1):
            sev_text = Text(finding.severity.value.upper())
            sev_text.stylize(_SEVERITY_COLORS.get(finding.severity, ""))
            table.add_row(
                str(idx),
                sev_text,
                finding.title,
                finding.remediation,
            )

        con.print(table)

        # Summary line
        counts = ", ".join(
            f"[{_SEVERITY_COLORS[sev]}]{sev.value}: "
            f"{sum(1 for f in self.findings if f.severity == sev)}[/]"
            for sev in Severity
            if any(f.severity == sev for f in self.findings)
        )
        con.print(f"\n[bold]Total findings:[/bold] {len(self.findings)}  ({counts})")
        con.print()
