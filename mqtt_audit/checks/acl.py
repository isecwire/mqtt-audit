"""ACL mapping -- systematically probe topic read/write permissions."""

from __future__ import annotations

import logging
import threading
import time
import uuid
from typing import TYPE_CHECKING, Any

import paho.mqtt.client as mqtt
from paho.mqtt.reasoncodes import ReasonCode

from mqtt_audit.report import Finding, Severity

if TYPE_CHECKING:
    from mqtt_audit.scanner import MqttAuditor

logger = logging.getLogger(__name__)

# Topic patterns to probe for read/write access
_PROBE_TOPICS = [
    # System / admin topics
    "$SYS/#",
    "$SYS/broker/version",
    # Common IoT topic hierarchies
    "device/#",
    "devices/#",
    "sensor/#",
    "sensors/#",
    "telemetry/#",
    "command/#",
    "commands/#",
    "control/#",
    "config/#",
    "ota/#",
    "firmware/#",
    "status/#",
    # Home automation
    "home/#",
    "homeassistant/#",
    "zigbee2mqtt/#",
    "tasmota/#",
    # Industrial
    "factory/#",
    "plant/#",
    "scada/#",
    "plc/#",
    "modbus/#",
    # General
    "admin/#",
    "system/#",
    "internal/#",
    "private/#",
    "test/#",
    "debug/#",
    "log/#",
    "logs/#",
]


def _check_subscribe_access(
    auditor: MqttAuditor,
    topic: str,
) -> bool | None:
    """Test if a subscription to *topic* is granted.

    Returns True if granted, False if denied, None if inconclusive.
    """
    client = auditor._new_client(f"mqtt-audit-acl-r-{uuid.uuid4().hex[:6]}")
    if auditor.username:
        client.username_pw_set(auditor.username, auditor.password)

    if not auditor._try_connect(client):
        auditor._disconnect(client)
        return None

    result_event = threading.Event()
    granted: list[bool] = []

    def on_subscribe(
        _client: mqtt.Client,
        _userdata: Any,
        mid: int,
        rc_list: list[ReasonCode] | tuple[int, ...] = (),
        properties: Any = None,
    ) -> None:
        for rc in rc_list:
            code = rc.value if isinstance(rc, ReasonCode) else int(rc)
            granted.append(code < 128)
        result_event.set()

    client.on_subscribe = on_subscribe
    client.subscribe(topic, qos=0)
    result_event.wait(timeout=auditor.timeout)
    auditor._disconnect(client)

    if not granted:
        return None
    return any(granted)


def _check_publish_access(
    auditor: MqttAuditor,
    topic: str,
) -> bool:
    """Test if publishing to *topic* is acknowledged."""
    client = auditor._new_client(f"mqtt-audit-acl-w-{uuid.uuid4().hex[:6]}")
    if auditor.username:
        client.username_pw_set(auditor.username, auditor.password)

    if not auditor._try_connect(client):
        auditor._disconnect(client)
        return False

    pub_event = threading.Event()

    def on_publish(
        _client: mqtt.Client,
        _userdata: Any,
        mid: int,
        rc: ReasonCode | int = 0,
        properties: Any = None,
    ) -> None:
        pub_event.set()

    client.on_publish = on_publish
    # Publish a harmless probe payload
    client.publish(topic.rstrip("#").rstrip("/") + "/__mqtt_audit_probe", payload=b"acl-test", qos=1)
    pub_event.wait(timeout=auditor.timeout)
    auditor._disconnect(client)
    return pub_event.is_set()


def test_acl_mapping(auditor: MqttAuditor) -> None:
    """Systematically probe read/write permissions on common topic patterns.

    For each topic pattern, test both subscribe and publish access to
    build a map of what the current identity can access.
    """
    logger.info("Mapping ACLs on %s:%d ...", auditor.host, auditor.port)
    identity = auditor.username or "anonymous"

    readable: list[str] = []
    writable: list[str] = []

    for topic in _PROBE_TOPICS:
        # Test subscribe access
        sub_ok = _check_subscribe_access(auditor, topic)
        if sub_ok:
            readable.append(topic)

    # Test write access on a subset (non-wildcard, non-$SYS)
    write_topics = [t for t in _PROBE_TOPICS if not t.startswith("$") and not t.endswith("#")]
    # Also test some base topics for write
    write_test_topics = [
        "device", "sensor", "telemetry", "command", "control",
        "config", "ota", "admin", "system", "test",
    ]
    for topic in write_test_topics:
        if _check_publish_access(auditor, topic):
            writable.append(topic)

    # Report findings
    if readable:
        sev = Severity.HIGH if len(readable) > 5 else Severity.MEDIUM
        auditor.report.add(Finding(
            severity=sev,
            title=f"Broad read ACL: {identity} can subscribe to {len(readable)} topic patterns",
            description=(
                f"The identity '{identity}' was granted subscribe access "
                f"to {len(readable)} topic pattern(s): "
                f"{', '.join(readable[:10])}"
                f"{'...' if len(readable) > 10 else ''}. "
                f"Overly permissive read ACLs expose data across the "
                f"broker to any connected client."
            ),
            remediation=(
                "Implement per-client read ACLs that restrict each client "
                "to its own topic namespace. Use the principle of least "
                "privilege."
            ),
            details={"readable_topics": readable, "identity": identity},
        ))

    if writable:
        sev = Severity.HIGH if len(writable) > 3 else Severity.MEDIUM
        auditor.report.add(Finding(
            severity=sev,
            title=f"Broad write ACL: {identity} can publish to {len(writable)} topics",
            description=(
                f"The identity '{identity}' was granted publish access "
                f"to {len(writable)} topic(s): "
                f"{', '.join(writable[:10])}"
                f"{'...' if len(writable) > 10 else ''}. "
                f"Write access to command, control, or config topics "
                f"enables command injection attacks."
            ),
            remediation=(
                "Implement per-client write ACLs. Especially restrict "
                "write access to command, control, firmware, and config "
                "topics."
            ),
            details={"writable_topics": writable, "identity": identity},
        ))

    if not readable and not writable:
        auditor.report.add(Finding(
            severity=Severity.INFO,
            title="ACL mapping: no broad access detected",
            description=(
                f"The identity '{identity}' was not granted access to any "
                f"of the {len(_PROBE_TOPICS)} tested topic patterns."
            ),
            remediation="No action required.",
        ))


def test_retained_messages(auditor: MqttAuditor) -> None:
    """Check for sensitive data in retained messages.

    Retained messages persist on the broker and are delivered to new
    subscribers immediately. If sensitive data is stored as retained
    messages, it remains accessible indefinitely.
    """
    logger.info("Checking retained messages on %s:%d ...", auditor.host, auditor.port)
    client = auditor._new_client("mqtt-audit-retained")

    if auditor.username:
        client.username_pw_set(auditor.username, auditor.password)

    retained_topics: dict[str, str] = {}
    lock = threading.Lock()

    def on_message(
        _client: mqtt.Client,
        _userdata: Any,
        message: mqtt.MQTTMessage,
    ) -> None:
        if message.retain:
            with lock:
                try:
                    payload = message.payload.decode("utf-8", errors="replace")[:200]
                except Exception:
                    payload = repr(message.payload[:200])
                retained_topics[message.topic] = payload

    client.on_message = on_message

    if not auditor._try_connect(client):
        logger.warning("Could not connect for retained message audit.")
        auditor._disconnect(client)
        return

    # Subscribe to broad wildcards to discover retained messages
    client.subscribe("#", qos=0)
    client.subscribe("$SYS/#", qos=0)

    # Retained messages are delivered immediately on subscribe,
    # so we need a short wait
    time.sleep(min(auditor.timeout, 3.0))
    auditor._disconnect(client)

    if retained_topics:
        auditor.report.add(Finding(
            severity=Severity.MEDIUM,
            title=f"Retained messages found on {len(retained_topics)} topic(s)",
            description=(
                f"Found {len(retained_topics)} retained message(s). "
                f"Retained messages persist on the broker and are "
                f"delivered to any new subscriber. Topics: "
                f"{', '.join(list(retained_topics.keys())[:5])}"
                f"{'...' if len(retained_topics) > 5 else ''}"
            ),
            remediation=(
                "Review retained messages for sensitive content. Clear "
                "unnecessary retained messages by publishing empty "
                "payloads with the retain flag. Restrict retain "
                "permissions via ACLs."
            ),
            details={
                "retained_count": len(retained_topics),
                "topics": list(retained_topics.keys())[:20],
                "samples": dict(list(retained_topics.items())[:5]),
            },
        ))
    else:
        auditor.report.add(Finding(
            severity=Severity.INFO,
            title="No retained messages found",
            description="No retained messages were received on wildcard subscriptions.",
            remediation="No action required.",
        ))
