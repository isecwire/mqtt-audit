"""Rich terminal UI for mqtt-audit."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from mqtt_audit.report import AuditReport, Finding, Severity, _SEVERITY_COLORS, _SEVERITY_ORDER
from mqtt_audit.scoring import (
    ComplianceRef,
    ScoredFinding,
    executive_summary,
    overall_risk_score,
    score_all,
)


def _severity_badge(severity: Severity) -> Text:
    """Create a colored severity badge."""
    color = _SEVERITY_COLORS.get(severity, "")
    return Text(severity.value.upper(), style=color)


def _cvss_color(score: float) -> str:
    """Return a color string for a CVSS score."""
    if score >= 9.0:
        return "bold red"
    if score >= 7.0:
        return "red"
    if score >= 4.0:
        return "yellow"
    if score > 0:
        return "cyan"
    return "dim"


def print_findings_table(
    console: Console,
    scored: list[ScoredFinding],
) -> None:
    """Render findings as a rich table."""
    table = Table(show_header=True, header_style="bold", expand=True)
    table.add_column("#", style="dim", width=4)
    table.add_column("Severity", width=10)
    table.add_column("CVSS", width=6, justify="right")
    table.add_column("Title", min_width=30)
    table.add_column("Remediation", ratio=1)

    for idx, sf in enumerate(scored, start=1):
        sev_text = _severity_badge(sf.finding.severity)
        cvss_text = Text(f"{sf.cvss_score:.1f}", style=_cvss_color(sf.cvss_score))
        table.add_row(
            str(idx),
            sev_text,
            cvss_text,
            sf.finding.title,
            sf.finding.remediation,
        )

    console.print(table)


def print_compliance_table(
    console: Console,
    scored: list[ScoredFinding],
) -> None:
    """Render compliance references as a rich table."""
    # Collect unique refs with their associated findings
    ref_map: dict[str, tuple[ComplianceRef, list[str]]] = {}
    for sf in scored:
        for ref in sf.compliance_refs:
            key = f"{ref.framework}:{ref.reference}"
            if key not in ref_map:
                ref_map[key] = (ref, [])
            ref_map[key][1].append(sf.finding.title)

    if not ref_map:
        return

    table = Table(
        title="Compliance References",
        show_header=True,
        header_style="bold",
        expand=True,
    )
    table.add_column("Framework", width=20)
    table.add_column("Reference", width=12)
    table.add_column("Description", ratio=1)
    table.add_column("Related Findings", ratio=1)

    for _key, (ref, titles) in sorted(ref_map.items()):
        table.add_row(
            ref.framework,
            ref.reference,
            ref.description,
            "; ".join(titles[:3]) + ("..." if len(titles) > 3 else ""),
        )

    console.print()
    console.print(table)


def print_broker_info(console: Console, metadata: dict[str, Any]) -> None:
    """Render broker $SYS information as a panel."""
    sys_info = metadata.get("sys_info", {})
    if not sys_info:
        return

    lines = []
    for key, value in sorted(sys_info.items()):
        lines.append(f"[bold]{key}:[/bold] {value}")

    console.print()
    console.print(Panel(
        "\n".join(lines),
        title="[bold blue]Broker Information ($SYS)[/bold blue]",
        border_style="blue",
    ))


def print_topic_tree(console: Console, topics: list[str], title: str = "Topics") -> None:
    """Render topics as a tree view."""
    if not topics:
        return

    tree = Tree(f"[bold]{title}[/bold]")
    # Build hierarchical structure
    nodes: dict[str, Any] = {}

    for topic in sorted(topics):
        parts = topic.split("/")
        current = nodes
        for part in parts:
            if part not in current:
                current[part] = {}
            current = current[part]

    def _build_tree(parent: Tree, node_dict: dict[str, Any]) -> None:
        for name, children in sorted(node_dict.items()):
            child = parent.add(name)
            if children:
                _build_tree(child, children)

    _build_tree(tree, nodes)
    console.print()
    console.print(tree)


def print_executive_summary(
    console: Console,
    scored: list[ScoredFinding],
    host: str,
) -> None:
    """Render the executive summary panel."""
    summary_text = executive_summary(scored, host)
    risk = overall_risk_score(scored)

    if risk >= 9.0:
        border = "bold red"
    elif risk >= 7.0:
        border = "red"
    elif risk >= 4.0:
        border = "yellow"
    else:
        border = "green"

    console.print(Panel(
        summary_text,
        title=f"[bold]Executive Summary (Risk: {risk:.1f}/10.0)[/bold]",
        border_style=border,
    ))


def print_full_report(console: Console, report: AuditReport) -> None:
    """Render the complete audit report to the console."""
    scored = score_all(report.sorted_findings)

    console.print()
    console.print(Panel(
        f"[bold]Target:[/bold] {report.host}:{report.port}  |  "
        f"[bold]TLS port:[/bold] {report.tls_port}  |  "
        f"[bold]Time:[/bold] {report.timestamp}",
        title="[bold blue]mqtt-audit report[/bold blue]",
        border_style="blue",
    ))
    console.print()

    print_executive_summary(console, scored, report.host)

    if not report.findings:
        console.print("[green]No findings -- the broker configuration looks solid.[/green]")
        return

    console.print()
    print_findings_table(console, scored)

    # Compliance
    print_compliance_table(console, scored)

    # Broker info
    print_broker_info(console, report.metadata)

    # Topic trees from metadata
    if "enumerated_user_topics" in report.metadata:
        print_topic_tree(console, report.metadata["enumerated_user_topics"], "User Topics")
    if "enumerated_sys_topics" in report.metadata:
        print_topic_tree(console, report.metadata["enumerated_sys_topics"], "$SYS Topics")

    # Summary line
    counts = ", ".join(
        f"[{_SEVERITY_COLORS[sev]}]{sev.value}: "
        f"{sum(1 for f in report.findings if f.severity == sev)}[/]"
        for sev in Severity
        if any(f.severity == sev for f in report.findings)
    )
    console.print(f"\n[bold]Total findings:[/bold] {len(report.findings)}  ({counts})")
    console.print()


# ---------------------------------------------------------------------------
# Export formats
# ---------------------------------------------------------------------------

def to_json(report: AuditReport) -> str:
    """Serialize report to JSON including scores and compliance."""
    scored = score_all(report.sorted_findings)
    data = report.to_dict()
    data["executive_summary"] = executive_summary(scored, report.host)
    data["overall_risk_score"] = overall_risk_score(scored)

    for i, sf in enumerate(scored):
        if i < len(data["findings"]):
            data["findings"][i]["cvss_score"] = sf.cvss_score
            data["findings"][i]["cvss_vector"] = sf.cvss_vector
            data["findings"][i]["compliance_refs"] = [
                {
                    "framework": ref.framework,
                    "reference": ref.reference,
                    "description": ref.description,
                }
                for ref in sf.compliance_refs
            ]
    return json.dumps(data, indent=2, default=str) + "\n"


def to_csv(report: AuditReport) -> str:
    """Serialize report findings to CSV."""
    scored = score_all(report.sorted_findings)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "Severity", "CVSS Score", "Title", "Description",
        "Remediation", "Compliance References",
    ])
    for sf in scored:
        refs = "; ".join(
            f"{r.framework} {r.reference}" for r in sf.compliance_refs
        )
        writer.writerow([
            sf.finding.severity.value,
            f"{sf.cvss_score:.1f}",
            sf.finding.title,
            sf.finding.description,
            sf.finding.remediation,
            refs,
        ])
    return buf.getvalue()


def to_markdown(report: AuditReport) -> str:
    """Generate a markdown report."""
    scored = score_all(report.sorted_findings)
    lines: list[str] = []

    lines.append(f"# MQTT Security Audit Report")
    lines.append("")
    lines.append(f"**Target:** {report.host}:{report.port}")
    lines.append(f"**TLS Port:** {report.tls_port}")
    lines.append(f"**Timestamp:** {report.timestamp}")
    lines.append(f"**Overall Risk Score:** {overall_risk_score(scored):.1f}/10.0")
    lines.append("")

    lines.append("## Executive Summary")
    lines.append("")
    lines.append(executive_summary(scored, report.host))
    lines.append("")

    lines.append("## Findings Summary")
    lines.append("")
    for sev in Severity:
        count = sum(1 for s in scored if s.finding.severity == sev)
        if count > 0:
            lines.append(f"- **{sev.value.upper()}:** {count}")
    lines.append("")

    if scored:
        lines.append("## Detailed Findings")
        lines.append("")
        lines.append(
            "| # | Severity | CVSS | Title | Remediation |"
        )
        lines.append("|---|----------|------|-------|-------------|")
        for idx, sf in enumerate(scored, start=1):
            lines.append(
                f"| {idx} | {sf.finding.severity.value.upper()} | "
                f"{sf.cvss_score:.1f} | {sf.finding.title} | "
                f"{sf.finding.remediation} |"
            )
        lines.append("")

        # Compliance table
        ref_map: dict[str, tuple[ComplianceRef, list[str]]] = {}
        for sf in scored:
            for ref in sf.compliance_refs:
                key = f"{ref.framework}:{ref.reference}"
                if key not in ref_map:
                    ref_map[key] = (ref, [])
                ref_map[key][1].append(sf.finding.title)

        if ref_map:
            lines.append("## Compliance References")
            lines.append("")
            lines.append(
                "| Framework | Reference | Description | Related Findings |"
            )
            lines.append("|-----------|-----------|-------------|-----------------|")
            for _key, (ref, titles) in sorted(ref_map.items()):
                finding_list = "; ".join(titles[:3])
                lines.append(
                    f"| {ref.framework} | {ref.reference} | "
                    f"{ref.description} | {finding_list} |"
                )
            lines.append("")

    # Broker info
    sys_info = report.metadata.get("sys_info", {})
    if sys_info:
        lines.append("## Broker Information")
        lines.append("")
        for key, value in sorted(sys_info.items()):
            lines.append(f"- **{key}:** {value}")
        lines.append("")

    lines.append("---")
    lines.append("*Generated by mqtt-audit*")
    lines.append("")
    return "\n".join(lines)
