"""Tests for mqtt_audit.cli module."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from mqtt_audit.cli import build_parser, main
from mqtt_audit import __version__


class TestBuildParser(unittest.TestCase):
    """Tests for the argument parser construction."""

    def setUp(self) -> None:
        self.parser = build_parser()

    def test_required_host_arg(self) -> None:
        args = self.parser.parse_args(["--host", "broker.test"])
        self.assertEqual(args.host, "broker.test")

    def test_default_port(self) -> None:
        args = self.parser.parse_args(["--host", "x"])
        self.assertEqual(args.port, 1883)

    def test_default_tls_port(self) -> None:
        args = self.parser.parse_args(["--host", "x"])
        self.assertEqual(args.tls_port, 8883)

    def test_default_timeout(self) -> None:
        args = self.parser.parse_args(["--host", "x"])
        self.assertEqual(args.timeout, 5.0)

    def test_default_username_none(self) -> None:
        args = self.parser.parse_args(["--host", "x"])
        self.assertIsNone(args.username)

    def test_default_password_none(self) -> None:
        args = self.parser.parse_args(["--host", "x"])
        self.assertIsNone(args.password)

    def test_default_output_none(self) -> None:
        args = self.parser.parse_args(["--host", "x"])
        self.assertIsNone(args.output)

    def test_verbose_default_false(self) -> None:
        args = self.parser.parse_args(["--host", "x"])
        self.assertFalse(args.verbose)

    def test_default_profile(self) -> None:
        args = self.parser.parse_args(["--host", "x"])
        self.assertEqual(args.profile, "standard")

    def test_default_format(self) -> None:
        args = self.parser.parse_args(["--host", "x"])
        self.assertEqual(args.output_format, "table")

    def test_default_mqtt_version(self) -> None:
        args = self.parser.parse_args(["--host", "x"])
        self.assertEqual(args.mqtt_version, "3.1.1")

    def test_default_websocket_false(self) -> None:
        args = self.parser.parse_args(["--host", "x"])
        self.assertFalse(args.websocket)

    def test_default_wordlist_none(self) -> None:
        args = self.parser.parse_args(["--host", "x"])
        self.assertIsNone(args.wordlist)

    def test_all_options(self) -> None:
        args = self.parser.parse_args([
            "--host", "10.0.0.1",
            "--port", "11883",
            "--tls-port", "18883",
            "--username", "admin",
            "--password", "secret",
            "--output", "report.json",
            "--timeout", "10.0",
            "--profile", "thorough",
            "--format", "markdown",
            "--mqtt-version", "5",
            "--websocket",
            "--wordlist", "/tmp/creds.txt",
            "--verbose",
        ])
        self.assertEqual(args.host, "10.0.0.1")
        self.assertEqual(args.port, 11883)
        self.assertEqual(args.tls_port, 18883)
        self.assertEqual(args.username, "admin")
        self.assertEqual(args.password, "secret")
        self.assertEqual(args.output, "report.json")
        self.assertEqual(args.timeout, 10.0)
        self.assertEqual(args.profile, "thorough")
        self.assertEqual(args.output_format, "markdown")
        self.assertEqual(args.mqtt_version, "5")
        self.assertTrue(args.websocket)
        self.assertEqual(args.wordlist, "/tmp/creds.txt")
        self.assertTrue(args.verbose)

    def test_verbose_short_flag(self) -> None:
        args = self.parser.parse_args(["--host", "x", "-v"])
        self.assertTrue(args.verbose)

    def test_missing_host_raises_error(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            self.parser.parse_args([])
        self.assertEqual(ctx.exception.code, 2)

    def test_version_flag(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            self.parser.parse_args(["--version"])
        self.assertEqual(ctx.exception.code, 0)

    def test_port_type_validation(self) -> None:
        with self.assertRaises(SystemExit):
            self.parser.parse_args(["--host", "x", "--port", "notanumber"])

    def test_invalid_profile_raises_error(self) -> None:
        with self.assertRaises(SystemExit):
            self.parser.parse_args(["--host", "x", "--profile", "invalid"])

    def test_invalid_format_raises_error(self) -> None:
        with self.assertRaises(SystemExit):
            self.parser.parse_args(["--host", "x", "--format", "xml"])

    def test_profile_choices(self) -> None:
        for profile in ("quick", "standard", "thorough"):
            args = self.parser.parse_args(["--host", "x", "--profile", profile])
            self.assertEqual(args.profile, profile)

    def test_format_choices(self) -> None:
        for fmt in ("table", "json", "csv", "markdown"):
            args = self.parser.parse_args(["--host", "x", "--format", fmt])
            self.assertEqual(args.output_format, fmt)


class TestMain(unittest.TestCase):
    """Tests for the main() entry point."""

    @patch("mqtt_audit.cli.MqttAuditor")
    @patch("mqtt_audit.cli.Console")
    def test_main_returns_zero_when_no_critical_findings(
        self, mock_console_cls: MagicMock, mock_auditor_cls: MagicMock,
    ) -> None:
        from mqtt_audit.report import AuditReport, Finding, Severity

        report = AuditReport(host="test", port=1883, tls_port=8883)
        report.add(Finding(
            severity=Severity.INFO,
            title="OK",
            description="D",
            remediation="R",
        ))

        mock_auditor = MagicMock()
        mock_auditor.run_all.return_value = report
        mock_auditor_cls.return_value = mock_auditor

        exit_code = main(["--host", "test"])
        self.assertEqual(exit_code, 0)

    @patch("mqtt_audit.cli.MqttAuditor")
    @patch("mqtt_audit.cli.Console")
    def test_main_returns_one_when_critical_finding(
        self, mock_console_cls: MagicMock, mock_auditor_cls: MagicMock,
    ) -> None:
        from mqtt_audit.report import AuditReport, Finding, Severity

        report = AuditReport(host="test", port=1883, tls_port=8883)
        report.add(Finding(
            severity=Severity.CRITICAL,
            title="Bad",
            description="D",
            remediation="R",
        ))

        mock_auditor = MagicMock()
        mock_auditor.run_all.return_value = report
        mock_auditor_cls.return_value = mock_auditor

        exit_code = main(["--host", "test"])
        self.assertEqual(exit_code, 1)

    @patch("mqtt_audit.cli.MqttAuditor")
    @patch("mqtt_audit.cli.Console")
    def test_main_returns_one_when_high_finding(
        self, mock_console_cls: MagicMock, mock_auditor_cls: MagicMock,
    ) -> None:
        from mqtt_audit.report import AuditReport, Finding, Severity

        report = AuditReport(host="test", port=1883, tls_port=8883)
        report.add(Finding(
            severity=Severity.HIGH,
            title="High",
            description="D",
            remediation="R",
        ))

        mock_auditor = MagicMock()
        mock_auditor.run_all.return_value = report
        mock_auditor_cls.return_value = mock_auditor

        exit_code = main(["--host", "test"])
        self.assertEqual(exit_code, 1)

    @patch("mqtt_audit.cli.MqttAuditor")
    @patch("mqtt_audit.cli.Console")
    def test_main_medium_findings_exit_zero(
        self, mock_console_cls: MagicMock, mock_auditor_cls: MagicMock,
    ) -> None:
        from mqtt_audit.report import AuditReport, Finding, Severity

        report = AuditReport(host="test", port=1883, tls_port=8883)
        report.add(Finding(
            severity=Severity.MEDIUM,
            title="Med",
            description="D",
            remediation="R",
        ))

        mock_auditor = MagicMock()
        mock_auditor.run_all.return_value = report
        mock_auditor_cls.return_value = mock_auditor

        exit_code = main(["--host", "test"])
        self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
