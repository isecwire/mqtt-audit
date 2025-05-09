"""Tests for mqtt_audit.display module."""

from __future__ import annotations

import json
import unittest
from io import StringIO

from rich.console import Console

from mqtt_audit.report import AuditReport, Finding, Severity
from mqtt_audit.display import (
    print_full_report,
    to_csv,
    to_json,
    to_markdown,
)


class TestToJson(unittest.TestCase):
    """Tests for JSON export."""

    def _make_report(self) -> AuditReport:
        report = AuditReport(host="test", port=1883, tls_port=8883)
        report.add(Finding(
            severity=Severity.CRITICAL,
            title="Anonymous access allowed",
            description="Bad",
            remediation="Fix",
        ))
        report.add(Finding(
            severity=Severity.INFO,
            title="OK",
            description="Good",
            remediation="None",
        ))
        return report

    def test_json_is_valid(self) -> None:
        report = self._make_report()
        result = to_json(report)
        data = json.loads(result)
        self.assertIn("findings", data)
        self.assertIn("executive_summary", data)
        self.assertIn("overall_risk_score", data)

    def test_json_findings_have_cvss(self) -> None:
        report = self._make_report()
        data = json.loads(to_json(report))
        for f in data["findings"]:
            self.assertIn("cvss_score", f)
            self.assertIn("cvss_vector", f)
            self.assertIn("compliance_refs", f)

    def test_json_empty_report(self) -> None:
        report = AuditReport(host="empty", port=1883, tls_port=8883)
        data = json.loads(to_json(report))
        self.assertEqual(len(data["findings"]), 0)
        self.assertEqual(data["overall_risk_score"], 0.0)


class TestToCsv(unittest.TestCase):
    """Tests for CSV export."""

    def test_csv_has_header(self) -> None:
        report = AuditReport(host="test", port=1883, tls_port=8883)
        report.add(Finding(
            severity=Severity.HIGH,
            title="Test",
            description="D",
            remediation="R",
        ))
        csv_str = to_csv(report)
        lines = csv_str.strip().split("\n")
        self.assertGreaterEqual(len(lines), 2)
        self.assertIn("Severity", lines[0])
        self.assertIn("CVSS Score", lines[0])

    def test_csv_empty_report(self) -> None:
        report = AuditReport(host="test", port=1883, tls_port=8883)
        csv_str = to_csv(report)
        lines = csv_str.strip().split("\n")
        self.assertEqual(len(lines), 1)  # Header only


class TestToMarkdown(unittest.TestCase):
    """Tests for Markdown export."""

    def test_markdown_has_title(self) -> None:
        report = AuditReport(host="test.broker", port=1883, tls_port=8883)
        report.add(Finding(
            severity=Severity.MEDIUM,
            title="Medium issue",
            description="D",
            remediation="R",
        ))
        md = to_markdown(report)
        self.assertIn("# MQTT Security Audit Report", md)
        self.assertIn("test.broker", md)

    def test_markdown_has_executive_summary(self) -> None:
        report = AuditReport(host="test", port=1883, tls_port=8883)
        report.add(Finding(
            severity=Severity.CRITICAL,
            title="Bad",
            description="D",
            remediation="R",
        ))
        md = to_markdown(report)
        self.assertIn("## Executive Summary", md)

    def test_markdown_has_findings_table(self) -> None:
        report = AuditReport(host="test", port=1883, tls_port=8883)
        report.add(Finding(
            severity=Severity.HIGH,
            title="High issue",
            description="D",
            remediation="R",
        ))
        md = to_markdown(report)
        self.assertIn("## Detailed Findings", md)
        self.assertIn("High issue", md)

    def test_markdown_empty_report(self) -> None:
        report = AuditReport(host="test", port=1883, tls_port=8883)
        md = to_markdown(report)
        self.assertIn("# MQTT Security Audit Report", md)
        self.assertNotIn("## Detailed Findings", md)


class TestPrintFullReport(unittest.TestCase):
    """Tests for rich console output."""

    def _capture(self, report: AuditReport) -> str:
        buf = StringIO()
        console = Console(file=buf, force_terminal=False, width=120)
        print_full_report(console, report)
        return buf.getvalue()

    def test_output_contains_host(self) -> None:
        report = AuditReport(host="mybroker", port=1883, tls_port=8883)
        report.add(Finding(
            severity=Severity.HIGH,
            title="Bad thing",
            description="D",
            remediation="R",
        ))
        output = self._capture(report)
        self.assertIn("mybroker", output)

    def test_output_contains_executive_summary(self) -> None:
        report = AuditReport(host="test", port=1883, tls_port=8883)
        report.add(Finding(
            severity=Severity.CRITICAL,
            title="Critical thing",
            description="D",
            remediation="R",
        ))
        output = self._capture(report)
        self.assertIn("Executive Summary", output)

    def test_empty_report_message(self) -> None:
        report = AuditReport(host="clean", port=1883, tls_port=8883)
        output = self._capture(report)
        self.assertIn("No findings", output)


if __name__ == "__main__":
    unittest.main()
