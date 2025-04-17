"""Tests for mqtt_audit.scanner module."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch, PropertyMock

from mqtt_audit.report import AuditReport, Finding, Severity
from mqtt_audit.scanner import AuditProfile, MqttAuditor, _reason_ok


class TestReasonOk(unittest.TestCase):
    """Tests for the _reason_ok helper."""

    def test_int_zero_is_ok(self) -> None:
        self.assertTrue(_reason_ok(0))

    def test_int_nonzero_is_not_ok(self) -> None:
        self.assertFalse(_reason_ok(5))
        self.assertFalse(_reason_ok(128))

    def test_reason_code_zero_is_ok(self) -> None:
        from paho.mqtt.reasoncodes import ReasonCode
        rc_real = MagicMock(spec=ReasonCode)
        rc_real.value = 0
        self.assertTrue(_reason_ok(rc_real))

    def test_reason_code_nonzero_is_not_ok(self) -> None:
        from paho.mqtt.reasoncodes import ReasonCode
        rc = MagicMock(spec=ReasonCode)
        rc.value = 134
        self.assertFalse(_reason_ok(rc))


class TestMqttAuditorInit(unittest.TestCase):
    """Tests for MqttAuditor initialization."""

    def test_default_config(self) -> None:
        auditor = MqttAuditor(host="broker.test")
        self.assertEqual(auditor.host, "broker.test")
        self.assertEqual(auditor.port, 1883)
        self.assertEqual(auditor.tls_port, 8883)
        self.assertIsNone(auditor.username)
        self.assertIsNone(auditor.password)
        self.assertEqual(auditor.timeout, 5.0)
        self.assertEqual(auditor.profile, AuditProfile.STANDARD)
        self.assertFalse(auditor.use_websocket)
        self.assertIsNone(auditor.wordlist_path)
        self.assertIsInstance(auditor.report, AuditReport)
        self.assertEqual(auditor.report.host, "broker.test")

    def test_custom_config(self) -> None:
        auditor = MqttAuditor(
            host="10.0.0.1",
            port=11883,
            tls_port=18883,
            username="admin",
            password="secret",
            timeout=10.0,
            profile=AuditProfile.THOROUGH,
            use_websocket=True,
            wordlist_path="/tmp/creds.txt",
        )
        self.assertEqual(auditor.host, "10.0.0.1")
        self.assertEqual(auditor.port, 11883)
        self.assertEqual(auditor.tls_port, 18883)
        self.assertEqual(auditor.username, "admin")
        self.assertEqual(auditor.password, "secret")
        self.assertEqual(auditor.timeout, 10.0)
        self.assertEqual(auditor.profile, AuditProfile.THOROUGH)
        self.assertTrue(auditor.use_websocket)
        self.assertEqual(auditor.wordlist_path, "/tmp/creds.txt")

    def test_report_initialized_with_correct_params(self) -> None:
        auditor = MqttAuditor(host="h", port=2000, tls_port=3000)
        self.assertEqual(auditor.report.port, 2000)
        self.assertEqual(auditor.report.tls_port, 3000)


class TestAuditProfile(unittest.TestCase):
    """Tests for profile-based check selection."""

    def test_quick_profile_has_fewer_checks(self) -> None:
        auditor = MqttAuditor(host="test", profile=AuditProfile.QUICK)
        checks = auditor._get_checks_for_profile()
        self.assertLessEqual(len(checks), 5)

    def test_standard_profile_has_more_checks(self) -> None:
        auditor = MqttAuditor(host="test", profile=AuditProfile.STANDARD)
        checks = auditor._get_checks_for_profile()
        self.assertGreater(len(checks), 5)

    def test_thorough_profile_has_most_checks(self) -> None:
        auditor = MqttAuditor(host="test", profile=AuditProfile.THOROUGH)
        checks = auditor._get_checks_for_profile()
        standard_checks = MqttAuditor(host="test", profile=AuditProfile.STANDARD)._get_checks_for_profile()
        self.assertGreater(len(checks), len(standard_checks))

    def test_profile_check_names_are_strings(self) -> None:
        auditor = MqttAuditor(host="test")
        for name, func in auditor._get_checks_for_profile():
            self.assertIsInstance(name, str)
            self.assertTrue(callable(func))


class TestAnonymousAccess(unittest.TestCase):
    """Tests for test_anonymous_access using mocked connections."""

    @patch.object(MqttAuditor, "_try_connect", return_value=True)
    @patch.object(MqttAuditor, "_disconnect")
    @patch.object(MqttAuditor, "_new_client")
    def test_anonymous_allowed_creates_critical_finding(
        self, mock_new_client: MagicMock, mock_disconnect: MagicMock, mock_connect: MagicMock,
    ) -> None:
        mock_client = MagicMock()
        mock_new_client.return_value = mock_client

        auditor = MqttAuditor(host="test")
        auditor.test_anonymous_access()

        self.assertEqual(len(auditor.report.findings), 1)
        finding = auditor.report.findings[0]
        self.assertEqual(finding.severity, Severity.CRITICAL)
        self.assertIn("Anonymous access allowed", finding.title)

    @patch.object(MqttAuditor, "_try_connect", return_value=False)
    @patch.object(MqttAuditor, "_disconnect")
    @patch.object(MqttAuditor, "_new_client")
    def test_anonymous_denied_creates_info_finding(
        self, mock_new_client: MagicMock, mock_disconnect: MagicMock, mock_connect: MagicMock,
    ) -> None:
        mock_client = MagicMock()
        mock_new_client.return_value = mock_client

        auditor = MqttAuditor(host="test")
        auditor.test_anonymous_access()

        self.assertEqual(len(auditor.report.findings), 1)
        finding = auditor.report.findings[0]
        self.assertEqual(finding.severity, Severity.INFO)
        self.assertIn("denied", finding.title.lower())


class TestTlsAvailable(unittest.TestCase):
    """Tests for test_tls_available."""

    @patch.object(MqttAuditor, "_try_connect", return_value=True)
    @patch.object(MqttAuditor, "_disconnect")
    @patch.object(MqttAuditor, "_new_client")
    def test_tls_available_creates_info_finding(
        self, mock_new_client: MagicMock, mock_disconnect: MagicMock, mock_connect: MagicMock,
    ) -> None:
        mock_new_client.return_value = MagicMock()
        auditor = MqttAuditor(host="test")
        auditor.test_tls_available()

        self.assertEqual(len(auditor.report.findings), 1)
        finding = auditor.report.findings[0]
        self.assertEqual(finding.severity, Severity.INFO)
        self.assertIn("TLS available", finding.title)

    @patch.object(MqttAuditor, "_try_connect", return_value=False)
    @patch.object(MqttAuditor, "_disconnect")
    @patch.object(MqttAuditor, "_new_client")
    def test_tls_unavailable_creates_high_finding(
        self, mock_new_client: MagicMock, mock_disconnect: MagicMock, mock_connect: MagicMock,
    ) -> None:
        mock_new_client.return_value = MagicMock()
        auditor = MqttAuditor(host="test")
        auditor.test_tls_available()

        self.assertEqual(len(auditor.report.findings), 1)
        finding = auditor.report.findings[0]
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertIn("TLS not available", finding.title)

    @patch.object(MqttAuditor, "_try_connect", return_value=True)
    @patch.object(MqttAuditor, "_disconnect")
    @patch.object(MqttAuditor, "_new_client")
    def test_tls_check_uses_tls_port(
        self, mock_new_client: MagicMock, mock_disconnect: MagicMock, mock_connect: MagicMock,
    ) -> None:
        mock_new_client.return_value = MagicMock()
        auditor = MqttAuditor(host="test", tls_port=9999)
        auditor.test_tls_available()

        mock_connect.assert_called_once()
        _, kwargs = mock_connect.call_args
        self.assertEqual(kwargs.get("port"), 9999)
        self.assertTrue(kwargs.get("use_tls"))


class TestCredentialsRequired(unittest.TestCase):
    """Tests for test_credentials_required."""

    @patch.object(MqttAuditor, "_try_connect", return_value=True)
    @patch.object(MqttAuditor, "_disconnect")
    @patch.object(MqttAuditor, "_new_client")
    def test_bad_creds_accepted_creates_critical(
        self, mock_new_client: MagicMock, mock_disconnect: MagicMock, mock_connect: MagicMock,
    ) -> None:
        mock_new_client.return_value = MagicMock()
        auditor = MqttAuditor(host="test")
        auditor.test_credentials_required()

        finding = auditor.report.findings[0]
        self.assertEqual(finding.severity, Severity.CRITICAL)
        self.assertIn("invalid credentials", finding.title.lower())

    @patch.object(MqttAuditor, "_try_connect", return_value=False)
    @patch.object(MqttAuditor, "_disconnect")
    @patch.object(MqttAuditor, "_new_client")
    def test_bad_creds_rejected_creates_info(
        self, mock_new_client: MagicMock, mock_disconnect: MagicMock, mock_connect: MagicMock,
    ) -> None:
        mock_new_client.return_value = MagicMock()
        auditor = MqttAuditor(host="test")
        auditor.test_credentials_required()

        finding = auditor.report.findings[0]
        self.assertEqual(finding.severity, Severity.INFO)


class TestWriteAccess(unittest.TestCase):
    """Tests for test_write_access."""

    @patch.object(MqttAuditor, "_try_connect", return_value=False)
    @patch.object(MqttAuditor, "_disconnect")
    @patch.object(MqttAuditor, "_new_client")
    def test_write_no_connection_produces_no_finding(
        self, mock_new_client: MagicMock, mock_disconnect: MagicMock, mock_connect: MagicMock,
    ) -> None:
        mock_new_client.return_value = MagicMock()
        auditor = MqttAuditor(host="test")
        auditor.test_write_access()

        self.assertEqual(len(auditor.report.findings), 0)

    @patch.object(MqttAuditor, "_try_connect", return_value=True)
    @patch.object(MqttAuditor, "_disconnect")
    @patch.object(MqttAuditor, "_new_client")
    def test_write_not_acknowledged_creates_info(
        self, mock_new_client: MagicMock, mock_disconnect: MagicMock, mock_connect: MagicMock,
    ) -> None:
        mock_client = MagicMock()
        mock_client.publish.return_value = MagicMock()
        mock_new_client.return_value = mock_client

        auditor = MqttAuditor(host="test", timeout=0.1)
        auditor.test_write_access()

        self.assertEqual(len(auditor.report.findings), 1)
        finding = auditor.report.findings[0]
        self.assertEqual(finding.severity, Severity.INFO)
        self.assertIn("restricted", finding.title.lower())


class TestTopicEnumeration(unittest.TestCase):
    """Tests for test_topic_enumeration."""

    @patch("mqtt_audit.scanner.time.sleep")
    @patch.object(MqttAuditor, "_try_connect", return_value=False)
    @patch.object(MqttAuditor, "_disconnect")
    @patch.object(MqttAuditor, "_new_client")
    def test_no_connection_produces_no_finding(
        self,
        mock_new_client: MagicMock,
        mock_disconnect: MagicMock,
        mock_connect: MagicMock,
        mock_sleep: MagicMock,
    ) -> None:
        mock_new_client.return_value = MagicMock()
        auditor = MqttAuditor(host="test")
        auditor.test_topic_enumeration()

        self.assertEqual(len(auditor.report.findings), 0)

    @patch("mqtt_audit.scanner.time.sleep")
    @patch.object(MqttAuditor, "_try_connect", return_value=True)
    @patch.object(MqttAuditor, "_disconnect")
    @patch.object(MqttAuditor, "_new_client")
    def test_no_messages_creates_info(
        self,
        mock_new_client: MagicMock,
        mock_disconnect: MagicMock,
        mock_connect: MagicMock,
        mock_sleep: MagicMock,
    ) -> None:
        mock_client = MagicMock()
        mock_new_client.return_value = mock_client

        auditor = MqttAuditor(host="test", timeout=0.1)
        auditor.test_topic_enumeration()

        self.assertEqual(len(auditor.report.findings), 1)
        finding = auditor.report.findings[0]
        self.assertEqual(finding.severity, Severity.INFO)
        self.assertIn("No topics observed", finding.title)


class TestWildcardSubscribe(unittest.TestCase):
    """Tests for test_wildcard_subscribe."""

    @patch.object(MqttAuditor, "_try_connect", return_value=False)
    @patch.object(MqttAuditor, "_disconnect")
    @patch.object(MqttAuditor, "_new_client")
    def test_no_connection_produces_no_finding(
        self, mock_new_client: MagicMock, mock_disconnect: MagicMock, mock_connect: MagicMock,
    ) -> None:
        mock_new_client.return_value = MagicMock()
        auditor = MqttAuditor(host="test")
        auditor.test_wildcard_subscribe()

        self.assertEqual(len(auditor.report.findings), 0)


class TestRunAll(unittest.TestCase):
    """Tests for the run_all orchestrator."""

    def test_run_all_returns_audit_report(self) -> None:
        """Verify run_all returns an AuditReport with quick profile."""
        with patch.object(MqttAuditor, "_try_connect", return_value=False), \
             patch.object(MqttAuditor, "_disconnect"), \
             patch.object(MqttAuditor, "_new_client") as mock_new_client:
            mock_new_client.return_value = MagicMock()
            auditor = MqttAuditor(host="test", profile=AuditProfile.QUICK, timeout=0.1)
            result = auditor.run_all()
            self.assertIsInstance(result, AuditReport)

    def test_run_all_calls_progress_callback(self) -> None:
        """Verify progress callback is called for each check."""
        with patch.object(MqttAuditor, "_try_connect", return_value=False), \
             patch.object(MqttAuditor, "_disconnect"), \
             patch.object(MqttAuditor, "_new_client") as mock_new_client:
            mock_new_client.return_value = MagicMock()
            auditor = MqttAuditor(host="test", profile=AuditProfile.QUICK, timeout=0.1)

            calls: list[tuple[str, int, int]] = []
            def cb(name: str, cur: int, total: int) -> None:
                calls.append((name, cur, total))

            auditor.run_all(progress_callback=cb)
            # Should have calls for each check + final "Complete"
            self.assertTrue(len(calls) > 0)
            self.assertEqual(calls[-1][0], "Complete")

    def test_run_all_handles_check_exception(self) -> None:
        """Verify that exceptions in checks are caught."""
        with patch.object(MqttAuditor, "_try_connect", side_effect=RuntimeError("boom")), \
             patch.object(MqttAuditor, "_disconnect"), \
             patch.object(MqttAuditor, "_new_client") as mock_new_client:
            mock_new_client.return_value = MagicMock()
            auditor = MqttAuditor(host="test", profile=AuditProfile.QUICK, timeout=0.1)
            result = auditor.run_all()

            error_findings = [f for f in result.findings if "Check error" in f.title]
            self.assertGreater(len(error_findings), 0)

    def test_all_check_methods_return_findings(self) -> None:
        """Verify that each test method produces Finding objects in the report."""
        with patch.object(MqttAuditor, "_try_connect", return_value=True), \
             patch.object(MqttAuditor, "_disconnect"), \
             patch.object(MqttAuditor, "_new_client") as mock_new_client, \
             patch("mqtt_audit.scanner.time.sleep"):

            mock_client = MagicMock()
            mock_client.publish.return_value = MagicMock()
            mock_new_client.return_value = mock_client

            auditor = MqttAuditor(host="test", profile=AuditProfile.QUICK, timeout=0.1)
            auditor.run_all()

            for f in auditor.report.findings:
                self.assertIsInstance(f, Finding)
                self.assertIsInstance(f.severity, Severity)
                self.assertTrue(len(f.title) > 0)
                self.assertTrue(len(f.description) > 0)
                self.assertTrue(len(f.remediation) > 0)


if __name__ == "__main__":
    unittest.main()
