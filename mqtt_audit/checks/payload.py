"""Payload inspection -- detect sensitive data in MQTT messages."""

from __future__ import annotations

import logging
import re
import threading
import time
from typing import TYPE_CHECKING, Any

import paho.mqtt.client as mqtt

from mqtt_audit.report import Finding, Severity

if TYPE_CHECKING:
    from mqtt_audit.scanner import MqttAuditor

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "password_field": [
        re.compile(r'"password"\s*:\s*"[^"]{1,}"', re.IGNORECASE),
        re.compile(r'"passwd"\s*:\s*"[^"]{1,}"', re.IGNORECASE),
        re.compile(r'"pass"\s*:\s*"[^"]{1,}"', re.IGNORECASE),
        re.compile(r'"secret"\s*:\s*"[^"]{1,}"', re.IGNORECASE),
        re.compile(r'"api_key"\s*:\s*"[^"]{1,}"', re.IGNORECASE),
        re.compile(r'"apikey"\s*:\s*"[^"]{1,}"', re.IGNORECASE),
        re.compile(r'"token"\s*:\s*"[^"]{1,}"', re.IGNORECASE),
        re.compile(r'password\s*=\s*\S+', re.IGNORECASE),
    ],
    "email_address": [
        re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    ],
    "credit_card": [
        # Visa
        re.compile(r'\b4[0-9]{12}(?:[0-9]{3})?\b'),
        # Mastercard
        re.compile(r'\b5[1-5][0-9]{14}\b'),
        # Amex
        re.compile(r'\b3[47][0-9]{13}\b'),
    ],
    "pii_ssn": [
        re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    ],
    "pii_phone": [
        re.compile(r'\b\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{4}\b'),
    ],
    "ip_address": [
        re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    ],
    "jwt_token": [
        re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'),
    ],
    "private_key": [
        re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
    ],
    "aws_key": [
        re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    ],
}


def _analyze_payload(payload: bytes) -> list[tuple[str, str]]:
    """Analyze a single payload for sensitive data patterns.

    Returns a list of (pattern_name, matched_text) tuples.
    """
    matches: list[tuple[str, str]] = []
    try:
        text = payload.decode("utf-8", errors="replace")
    except Exception:
        return matches

    for category, patterns in _PATTERNS.items():
        for pattern in patterns:
            found = pattern.search(text)
            if found:
                # Truncate matched text for reporting
                matched = found.group()
                if len(matched) > 60:
                    matched = matched[:57] + "..."
                matches.append((category, matched))
                break  # One match per category is enough

    return matches


def test_payload_inspection(auditor: MqttAuditor) -> None:
    """Subscribe to all topics and analyze payloads for sensitive data.

    Collects messages for the configured timeout period, then inspects
    each payload for passwords, PII, credit card numbers, and other
    sensitive data patterns.
    """
    logger.info("Starting payload inspection on %s:%d ...", auditor.host, auditor.port)
    client = auditor._new_client("mqtt-audit-payload")

    if auditor.username:
        client.username_pw_set(auditor.username, auditor.password)

    findings_map: dict[str, list[dict[str, str]]] = {}
    lock = threading.Lock()
    message_count = 0

    def on_message(
        _client: mqtt.Client,
        _userdata: Any,
        message: mqtt.MQTTMessage,
    ) -> None:
        nonlocal message_count
        message_count += 1
        matches = _analyze_payload(message.payload)
        if matches:
            with lock:
                for category, matched in matches:
                    if category not in findings_map:
                        findings_map[category] = []
                    if len(findings_map[category]) < 5:  # Cap examples
                        findings_map[category].append({
                            "topic": message.topic,
                            "match": matched,
                        })

    client.on_message = on_message

    if not auditor._try_connect(client):
        logger.warning("Could not connect for payload inspection.")
        auditor._disconnect(client)
        return

    client.subscribe("#", qos=0)
    time.sleep(auditor.timeout)
    auditor._disconnect(client)

    if not findings_map:
        if message_count > 0:
            auditor.report.add(Finding(
                severity=Severity.INFO,
                title="No sensitive data detected in payloads",
                description=(
                    f"Analyzed {message_count} message(s). No plaintext "
                    f"passwords, PII, or credit card patterns were detected."
                ),
                remediation="No action required.",
            ))
        return

    # Report password/secret findings
    if any(k in findings_map for k in ("password_field", "jwt_token", "private_key", "aws_key")):
        secret_details = {}
        for k in ("password_field", "jwt_token", "private_key", "aws_key"):
            if k in findings_map:
                secret_details[k] = findings_map[k]

        auditor.report.add(Finding(
            severity=Severity.CRITICAL,
            title="Plaintext secrets detected in payloads",
            description=(
                "Message payloads contain plaintext passwords, API keys, "
                "tokens, or private keys. This data is readable by any "
                "client with subscribe access."
            ),
            remediation=(
                "Encrypt sensitive payload data at the application layer. "
                "Never transmit credentials or secrets in MQTT payloads. "
                "Use dedicated secret management systems."
            ),
            details=secret_details,
        ))

    # Report PII findings
    pii_keys = {"email_address", "pii_ssn", "pii_phone"}
    if any(k in findings_map for k in pii_keys):
        pii_details = {k: findings_map[k] for k in pii_keys if k in findings_map}
        auditor.report.add(Finding(
            severity=Severity.HIGH,
            title="PII detected in payloads",
            description=(
                "Message payloads contain personally identifiable information "
                "such as email addresses, SSNs, or phone numbers."
            ),
            remediation=(
                "Anonymize or encrypt PII before transmission. Review data "
                "handling practices against GDPR, CCPA, and other privacy "
                "regulations."
            ),
            details=pii_details,
        ))

    # Report credit card findings
    if "credit_card" in findings_map:
        auditor.report.add(Finding(
            severity=Severity.CRITICAL,
            title="Credit card numbers detected in payloads",
            description=(
                "Message payloads contain patterns matching credit card "
                "numbers. This is a PCI DSS violation."
            ),
            remediation=(
                "Never transmit credit card numbers through MQTT. Use "
                "tokenization and ensure PCI DSS compliance."
            ),
            details={"credit_card": findings_map["credit_card"]},
        ))
