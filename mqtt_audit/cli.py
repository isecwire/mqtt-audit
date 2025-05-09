"""Command-line interface for mqtt-audit."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from rich.console import Console

from mqtt_audit import __version__
from mqtt_audit.scanner import AuditProfile, MqttAuditor


def build_parser() -> argparse.ArgumentParser:
    """Construct and return the argument parser."""
    parser = argparse.ArgumentParser(
        prog="mqtt-audit",
        description=(
            "MQTT broker security auditor. Tests for anonymous access, weak ACLs, "
            "missing TLS, default credentials, payload inspection, protocol abuse, "
            "and common misconfigurations."
        ),
        epilog="Example: mqtt-audit --host broker.example.com --profile thorough --format markdown --output report.md",
    )
    parser.add_argument(
        "--host",
        required=True,
        help="Hostname or IP address of the MQTT broker.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=1883,
        help="MQTT plaintext port (default: 1883).",
    )
    parser.add_argument(
        "--tls-port",
        type=int,
        default=8883,
        help="MQTT TLS port to probe (default: 8883).",
    )
    parser.add_argument(
        "--username",
        default=None,
        help="Username for authenticated checks.",
    )
    parser.add_argument(
        "--password",
        default=None,
        help="Password for authenticated checks.",
    )
    parser.add_argument(
        "--output",
        default=None,
        metavar="FILE",
        help="Write the report to a file (format inferred from --format).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Per-check timeout in seconds (default: 5).",
    )
    parser.add_argument(
        "--profile",
        choices=["quick", "standard", "thorough"],
        default="standard",
        help=(
            "Scan profile: quick (basic checks), standard (default, "
            "includes protocol probes), thorough (all checks including "
            "brute-force and deep ACL mapping)."
        ),
    )
    parser.add_argument(
        "--format",
        choices=["table", "json", "csv", "markdown"],
        default="table",
        dest="output_format",
        help="Output format (default: table).",
    )
    parser.add_argument(
        "--mqtt-version",
        choices=["3.1.1", "5"],
        default="3.1.1",
        help="MQTT protocol version to prefer (default: 3.1.1).",
    )
    parser.add_argument(
        "--websocket",
        action="store_true",
        help="Use WebSocket transport (ws:// / wss://) instead of raw TCP.",
    )
    parser.add_argument(
        "--wordlist",
        default=None,
        metavar="FILE",
        help="Path to a custom credential wordlist (username:password per line).",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug logging.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for the CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    console = Console(stderr=True)
    console.print(
        f"[bold blue]mqtt-audit {__version__}[/bold blue] -- MQTT broker security auditor\n"
    )

    transport = "WebSocket" if args.websocket else "TCP"
    console.print(
        f"Target: [bold]{args.host}:{args.port}[/bold]  "
        f"(TLS probe: {args.tls_port})  "
        f"Profile: [bold]{args.profile}[/bold]  "
        f"Transport: {transport}"
    )
    console.print()

    profile = AuditProfile(args.profile)

    auditor = MqttAuditor(
        host=args.host,
        port=args.port,
        tls_port=args.tls_port,
        username=args.username,
        password=args.password,
        timeout=args.timeout,
        profile=profile,
        wordlist_path=args.wordlist,
        use_websocket=args.websocket,
    )

    # Run with live progress display
    from rich.live import Live
    from rich.text import Text

    status_text = Text("Starting audit...", style="bold green")

    def progress_cb(name: str, current: int, total: int) -> None:
        status_text.plain = f"[{current + 1}/{total}] {name}..."

    with Live(status_text, console=console, refresh_per_second=4):
        report = auditor.run_all(progress_callback=progress_cb)

    # Output based on format
    from mqtt_audit.display import (
        print_full_report,
        to_csv,
        to_json,
        to_markdown,
    )

    output_console = Console()

    if args.output_format == "json":
        json_str = to_json(report)
        if args.output:
            Path(args.output).write_text(json_str, encoding="utf-8")
            console.print(f"[green]Report written to {args.output}[/green]")
        else:
            output_console.print_json(json_str)
    elif args.output_format == "csv":
        csv_str = to_csv(report)
        if args.output:
            Path(args.output).write_text(csv_str, encoding="utf-8")
            console.print(f"[green]Report written to {args.output}[/green]")
        else:
            output_console.print(csv_str)
    elif args.output_format == "markdown":
        md_str = to_markdown(report)
        if args.output:
            Path(args.output).write_text(md_str, encoding="utf-8")
            console.print(f"[green]Report written to {args.output}[/green]")
        else:
            output_console.print(md_str)
    else:
        # Default: rich table output
        print_full_report(output_console, report)
        if args.output:
            # Also write JSON as a companion file
            json_str = to_json(report)
            Path(args.output).write_text(json_str, encoding="utf-8")
            console.print(f"[green]Report written to {args.output}[/green]")

    # Exit code: 1 if any HIGH or CRITICAL finding exists, else 0.
    from mqtt_audit.report import Severity

    has_critical = any(
        f.severity in (Severity.CRITICAL, Severity.HIGH) for f in report.findings
    )
    return 1 if has_critical else 0


if __name__ == "__main__":
    sys.exit(main())
