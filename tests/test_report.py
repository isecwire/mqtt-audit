"""Tests for mqtt_audit.report module."""

from __future__ import annotations

import json
import tempfile
import unittest
from io import StringIO
from pathlib import Path

from rich.console import Console

from mqtt_audit.report import AuditReport, Finding, Severity


class TestSeverity(unittest.TestCase):
    """Tests for the Severity enum."""

    def test_all_severity_levels_exist(self) -> None:
        self.assertEqual(Severity.CRITICAL.value, "critical")
        self.assertEqual(Severity.HIGH.value, "high")
        self.assertEqual(Severity.MEDIUM.value, "medium")
        self.assertEqual(Severity.LOW.value, "low")
        self.assertEqual(Severity.INFO.value, "info")

    def test_severity_str(self) -> None:
        self.assertEqual(str(Severity.CRITICAL), "critical")
        self.assertEqual(str(Severity.INFO), "info")

    def test_severity_is_str_subclass(self) -> None:
        self.assertIsInstance(Severity.HIGH, str)


class TestFinding(unittest.TestCase):
    """Tests for the Finding dataclass."""

    def test_create_finding_all_severities(self) -> None:
        for sev in Severity:
            f = Finding(
                severity=sev,
                title=f"Test {sev.value}",
                description="A test finding.",
                remediation="Fix it.",
            )
            self.assertEqual(f.severity, sev)
            self.assertEqual(f.title, f"Test {sev.value}")
            self.assertIsInstance(f.details, dict)
            self.assertEqual(len(f.details), 0)

    def test_finding_with_details(self) -> None:
        details = {"topic": "test/topic", "count": 42}
        f = Finding(
            severity=Severity.MEDIUM,
            title="Detail test",
            description="Has details.",
            remediation="Check details.",
            details=details,
        )
        self.assertEqual(f.details["topic"], "test/topic")
        self.assertEqual(f.details["count"], 42)

    def test_finding_default_details_is_empty_dict(self) -> None:
        f1 = Finding(severity=Severity.LOW, title="A", description="B", remediation="C")
        f2 = Finding(severity=Severity.LOW, title="D", description="E", remediation="F")
        # Ensure default dicts are independent instances.
        f1.details["key"] = "value"
        self.assertNotIn("key", f2.details)


class TestAuditReport(unittest.TestCase):
    """Tests for the AuditReport dataclass."""

    def _make_report(self) -> AuditReport:
        report = AuditReport(host="broker.test", port=1883, tls_port=8883)
        report.add(Finding(
            severity=Severity.CRITICAL,
            title="Critical issue",
            description="Very bad.",
            remediation="Fix immediately.",
        ))
        report.add(Finding(
            severity=Severity.INFO,
            title="Info note",
            description="All good here.",
            remediation="No action required.",
        ))
        report.add(Finding(
            severity=Severity.HIGH,
            title="High issue",
            description="Pretty bad.",
            remediation="Fix soon.",
        ))
        report.add(Finding(
            severity=Severity.MEDIUM,
            title="Medium issue",
            description="Should fix.",
            remediation="Plan a fix.",
        ))
        return report

    def test_add_finding(self) -> None:
        report = AuditReport(host="localhost", port=1883, tls_port=8883)
        self.assertEqual(len(report.findings), 0)
        report.add(Finding(
            severity=Severity.LOW,
            title="Test",
            description="Desc",
            remediation="Rem",
        ))
        self.assertEqual(len(report.findings), 1)

    def test_sorted_findings_order(self) -> None:
        report = self._make_report()
        sorted_f = report.sorted_findings
        severities = [f.severity for f in sorted_f]
        self.assertEqual(
            severities,
            [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.INFO],
        )

    def test_sorted_findings_does_not_mutate_original(self) -> None:
        report = self._make_report()
        original_order = [f.title for f in report.findings]
        _ = report.sorted_findings
        self.assertEqual([f.title for f in report.findings], original_order)

    def test_to_dict_structure(self) -> None:
        report = self._make_report()
        d = report.to_dict()
        self.assertEqual(d["host"], "broker.test")
        self.assertEqual(d["port"], 1883)
        self.assertEqual(d["tls_port"], 8883)
        self.assertIn("timestamp", d)
        self.assertIn("summary", d)
        self.assertEqual(d["summary"]["total"], 4)
        self.assertEqual(d["summary"]["critical"], 1)
        self.assertEqual(d["summary"]["high"], 1)
        self.assertEqual(d["summary"]["medium"], 1)
        self.assertEqual(d["summary"]["info"], 1)
        self.assertEqual(d["summary"]["low"], 0)
        self.assertIsInstance(d["findings"], list)
        self.assertEqual(len(d["findings"]), 4)

    def test_to_dict_findings_sorted(self) -> None:
        report = self._make_report()
        d = report.to_dict()
        severities = [f["severity"] for f in d["findings"]]
        self.assertEqual(severities[0], "critical")
        self.assertEqual(severities[-1], "info")

    def test_json_serialization_roundtrip(self) -> None:
        report = self._make_report()
        json_str = json.dumps(report.to_dict(), indent=2, default=str)
        loaded = json.loads(json_str)
        self.assertEqual(loaded["host"], "broker.test")
        self.assertEqual(loaded["summary"]["total"], 4)
        self.assertEqual(len(loaded["findings"]), 4)

    def test_write_json_creates_file(self) -> None:
        report = self._make_report()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = report.write_json(Path(tmpdir) / "report.json")
            self.assertTrue(path.exists())
            with open(path) as fh:
                data = json.load(fh)
            self.assertEqual(data["host"], "broker.test")
            self.assertEqual(len(data["findings"]), 4)

    def test_write_json_creates_parent_dirs(self) -> None:
        report = AuditReport(host="x", port=1883, tls_port=8883)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = report.write_json(Path(tmpdir) / "sub" / "dir" / "report.json")
            self.assertTrue(path.exists())

    def test_empty_findings(self) -> None:
        report = AuditReport(host="empty.test", port=1883, tls_port=8883)
        d = report.to_dict()
        self.assertEqual(d["summary"]["total"], 0)
        self.assertEqual(len(d["findings"]), 0)
        self.assertEqual(report.sorted_findings, [])


class TestConsoleOutput(unittest.TestCase):
    """Tests for print_console rendering."""

    def _capture_console(self, report: AuditReport) -> str:
        buf = StringIO()
        console = Console(file=buf, force_terminal=False, width=120)
        report.print_console(console)
        return buf.getvalue()

    def test_console_output_contains_host(self) -> None:
        report = AuditReport(host="mybroker.local", port=1883, tls_port=8883)
        report.add(Finding(
            severity=Severity.HIGH,
            title="Something bad",
            description="Desc",
            remediation="Fix it",
        ))
        output = self._capture_console(report)
        self.assertIn("mybroker.local", output)

    def test_console_output_contains_finding_titles(self) -> None:
        report = AuditReport(host="test", port=1883, tls_port=8883)
        report.add(Finding(
            severity=Severity.CRITICAL,
            title="Anon access open",
            description="D",
            remediation="R",
        ))
        report.add(Finding(
            severity=Severity.LOW,
            title="Minor thing",
            description="D",
            remediation="R",
        ))
        output = self._capture_console(report)
        self.assertIn("Anon access open", output)
        self.assertIn("Minor thing", output)

    def test_console_empty_findings_message(self) -> None:
        report = AuditReport(host="clean", port=1883, tls_port=8883)
        output = self._capture_console(report)
        self.assertIn("No findings", output)

    def test_console_shows_severity_labels(self) -> None:
        report = AuditReport(host="test", port=1883, tls_port=8883)
        report.add(Finding(
            severity=Severity.MEDIUM,
            title="Medium issue",
            description="D",
            remediation="R",
        ))
        output = self._capture_console(report)
        # The severity label should appear uppercased in the table.
        self.assertIn("MEDIUM", output)


if __name__ == "__main__":
    unittest.main()
