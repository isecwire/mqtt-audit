"""Tests for mqtt_audit.checks modules."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from mqtt_audit.report import Finding, Severity
from mqtt_audit.scanner import MqttAuditor


class TestDefaultCredentials(unittest.TestCase):
    """Tests for checks.credentials module."""

    @patch.object(MqttAuditor, "_try_connect", return_value=False)
    @patch.object(MqttAuditor, "_disconnect")
    @patch.object(MqttAuditor, "_new_client")
    def test_no_default_creds_found(
        self, mock_new_client: MagicMock, mock_disconnect: MagicMock, mock_connect: MagicMock,
    ) -> None:
        mock_new_client.return_value = MagicMock()
        auditor = MqttAuditor(host="test", timeout=0.1)

        from mqtt_audit.checks.credentials import test_default_credentials
        test_default_credentials(auditor)

        self.assertEqual(len(auditor.report.findings), 1)
        self.assertEqual(auditor.report.findings[0].severity, Severity.INFO)
        self.assertIn("No default credentials", auditor.report.findings[0].title)

    @patch.object(MqttAuditor, "_try_connect", return_value=True)
    @patch.object(MqttAuditor, "_disconnect")
    @patch.object(MqttAuditor, "_new_client")
    def test_default_creds_found(
        self, mock_new_client: MagicMock, mock_disconnect: MagicMock, mock_connect: MagicMock,
    ) -> None:
        mock_new_client.return_value = MagicMock()
        auditor = MqttAuditor(host="test", timeout=0.1)

        from mqtt_audit.checks.credentials import test_default_credentials
        test_default_credentials(auditor)

        crit_findings = [f for f in auditor.report.findings if f.severity == Severity.CRITICAL]
        self.assertGreater(len(crit_findings), 0)
        self.assertIn("Default credentials", crit_findings[0].title)


class TestPayloadInspection(unittest.TestCase):
    """Tests for checks.payload module."""

    def test_analyze_payload_detects_password(self) -> None:
        from mqtt_audit.checks.payload import _analyze_payload
        payload = b'{"username": "admin", "password": "secret123"}'
        matches = _analyze_payload(payload)
        categories = [m[0] for m in matches]
        self.assertIn("password_field", categories)

    def test_analyze_payload_detects_email(self) -> None:
        from mqtt_audit.checks.payload import _analyze_payload
        payload = b'{"email": "user@example.com", "data": 42}'
        matches = _analyze_payload(payload)
        categories = [m[0] for m in matches]
        self.assertIn("email_address", categories)

    def test_analyze_payload_detects_credit_card(self) -> None:
        from mqtt_audit.checks.payload import _analyze_payload
        payload = b'card: 4111111111111111'
        matches = _analyze_payload(payload)
        categories = [m[0] for m in matches]
        self.assertIn("credit_card", categories)

    def test_analyze_payload_detects_jwt(self) -> None:
        from mqtt_audit.checks.payload import _analyze_payload
        payload = b'token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'
        matches = _analyze_payload(payload)
        categories = [m[0] for m in matches]
        self.assertIn("jwt_token", categories)

    def test_analyze_payload_clean_data(self) -> None:
        from mqtt_audit.checks.payload import _analyze_payload
        payload = b'{"temperature": 22.5, "humidity": 65}'
        matches = _analyze_payload(payload)
        self.assertEqual(len(matches), 0)

    def test_analyze_payload_binary(self) -> None:
        from mqtt_audit.checks.payload import _analyze_payload
        payload = bytes(range(256))
        matches = _analyze_payload(payload)
        # Should not crash on binary data
        self.assertIsInstance(matches, list)


class TestQos2Abuse(unittest.TestCase):
    """Tests for checks.protocol QoS 2 check."""

    @patch.object(MqttAuditor, "_try_connect", return_value=False)
    @patch.object(MqttAuditor, "_disconnect")
    @patch.object(MqttAuditor, "_new_client")
    def test_no_connection(
        self, mock_new_client: MagicMock, mock_disconnect: MagicMock, mock_connect: MagicMock,
    ) -> None:
        mock_new_client.return_value = MagicMock()
        auditor = MqttAuditor(host="test", timeout=0.1)

        from mqtt_audit.checks.protocol import test_qos2_abuse
        test_qos2_abuse(auditor)

        # No finding when connection fails (just returns)
        self.assertEqual(len(auditor.report.findings), 0)


class TestWillMessage(unittest.TestCase):
    """Tests for checks.protocol will message check."""

    @patch.object(MqttAuditor, "_try_connect", return_value=True)
    @patch.object(MqttAuditor, "_disconnect")
    @patch.object(MqttAuditor, "_new_client")
    def test_will_accepted(
        self, mock_new_client: MagicMock, mock_disconnect: MagicMock, mock_connect: MagicMock,
    ) -> None:
        mock_new_client.return_value = MagicMock()
        auditor = MqttAuditor(host="test", timeout=0.1)

        from mqtt_audit.checks.protocol import test_will_message
        test_will_message(auditor)

        self.assertEqual(len(auditor.report.findings), 1)
        self.assertIn("will message", auditor.report.findings[0].title.lower())


class TestRetainedMessages(unittest.TestCase):
    """Tests for checks.acl retained messages check."""

    @patch.object(MqttAuditor, "_try_connect", return_value=False)
    @patch.object(MqttAuditor, "_disconnect")
    @patch.object(MqttAuditor, "_new_client")
    def test_no_connection(
        self, mock_new_client: MagicMock, mock_disconnect: MagicMock, mock_connect: MagicMock,
    ) -> None:
        mock_new_client.return_value = MagicMock()
        auditor = MqttAuditor(host="test", timeout=0.1)

        from mqtt_audit.checks.acl import test_retained_messages
        test_retained_messages(auditor)

        self.assertEqual(len(auditor.report.findings), 0)


class TestWordlistLoading(unittest.TestCase):
    """Tests for credential wordlist loading."""

    def test_load_builtin_wordlist(self) -> None:
        from mqtt_audit.checks.credentials import _load_wordlist
        creds = _load_wordlist()
        self.assertGreater(len(creds), 10)
        # Each entry should be a tuple of (username, password)
        for user, passwd in creds:
            self.assertIsInstance(user, str)
            self.assertIsInstance(passwd, str)
            self.assertTrue(len(user) > 0)
            self.assertTrue(len(passwd) > 0)

    def test_load_custom_wordlist(self) -> None:
        import tempfile
        import os

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("# Comment\n")
            f.write("testuser:testpass\n")
            f.write("admin:secret\n")
            f.write("\n")
            f.write("# Another comment\n")
            tmppath = f.name

        try:
            from mqtt_audit.checks.credentials import _load_wordlist
            creds = _load_wordlist(tmppath)
            self.assertEqual(len(creds), 2)
            self.assertEqual(creds[0], ("testuser", "testpass"))
            self.assertEqual(creds[1], ("admin", "secret"))
        finally:
            os.unlink(tmppath)


if __name__ == "__main__":
    unittest.main()
