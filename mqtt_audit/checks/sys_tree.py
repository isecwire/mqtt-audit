"""$SYS topic tree analysis -- extract broker metadata."""

from __future__ import annotations

import logging
import threading
import time
from typing import TYPE_CHECKING, Any

import paho.mqtt.client as mqtt

from mqtt_audit.report import Finding, Severity

if TYPE_CHECKING:
    from mqtt_audit.scanner import MqttAuditor

logger = logging.getLogger(__name__)

# Well-known $SYS topics to look for
_SYS_TOPICS_OF_INTEREST = {
    "$SYS/broker/version": "broker_version",
    "$SYS/broker/uptime": "broker_uptime",
    "$SYS/broker/timestamp": "broker_timestamp",
    "$SYS/broker/clients/connected": "clients_connected",
    "$SYS/broker/clients/total": "clients_total",
    "$SYS/broker/clients/maximum": "clients_maximum",
    "$SYS/broker/clients/active": "clients_active",
    "$SYS/broker/messages/received": "messages_received",
    "$SYS/broker/messages/sent": "messages_sent",
    "$SYS/broker/messages/stored": "messages_stored",
    "$SYS/broker/bytes/received": "bytes_received",
    "$SYS/broker/bytes/sent": "bytes_sent",
    "$SYS/broker/subscriptions/count": "subscriptions_count",
    "$SYS/broker/load/messages/received/1min": "load_recv_1min",
    "$SYS/broker/load/messages/sent/1min": "load_sent_1min",
    "$SYS/broker/load/publish/received/1min": "load_pub_recv_1min",
    "$SYS/broker/load/publish/sent/1min": "load_pub_sent_1min",
    "$SYS/broker/publish/messages/received": "publish_messages_received",
    "$SYS/broker/publish/messages/sent": "publish_messages_sent",
    "$SYS/broker/retained messages/count": "retained_messages_count",
    "$SYS/broker/heap/current": "heap_current",
    "$SYS/broker/heap/maximum": "heap_maximum",
}


def test_sys_tree_analysis(auditor: MqttAuditor) -> None:
    """Subscribe to $SYS/# and extract broker metadata.

    The $SYS topic tree exposes operational metadata including broker
    version, connected client counts, and throughput statistics. This
    information helps attackers fingerprint the broker and plan further
    attacks.
    """
    logger.info("Analyzing $SYS topic tree on %s:%d ...", auditor.host, auditor.port)
    client = auditor._new_client("mqtt-audit-sys")

    if auditor.username:
        client.username_pw_set(auditor.username, auditor.password)

    sys_data: dict[str, str] = {}
    all_sys_topics: list[str] = []
    lock = threading.Lock()

    def on_message(
        _client: mqtt.Client,
        _userdata: Any,
        message: mqtt.MQTTMessage,
    ) -> None:
        topic = message.topic
        try:
            payload = message.payload.decode("utf-8", errors="replace").strip()
        except Exception:
            payload = repr(message.payload)

        with lock:
            if topic not in all_sys_topics:
                all_sys_topics.append(topic)
            # Map known topics
            if topic in _SYS_TOPICS_OF_INTEREST:
                key = _SYS_TOPICS_OF_INTEREST[topic]
                sys_data[key] = payload

    client.on_message = on_message

    if not auditor._try_connect(client):
        logger.warning("Could not connect for $SYS tree analysis.")
        auditor._disconnect(client)
        return

    client.subscribe("$SYS/#", qos=0)
    time.sleep(auditor.timeout)
    auditor._disconnect(client)

    if not all_sys_topics:
        auditor.report.add(Finding(
            severity=Severity.INFO,
            title="$SYS tree not accessible",
            description=(
                "No $SYS topics were received. The broker may restrict "
                "access to the $SYS topic tree or it may not be a "
                "Mosquitto-compatible broker."
            ),
            remediation="No action required.",
        ))
        return

    # Store in report metadata for display
    auditor.report.metadata["sys_info"] = sys_data
    auditor.report.metadata["enumerated_sys_topics"] = all_sys_topics[:50]

    # Check for version disclosure
    version = sys_data.get("broker_version", "")
    if version:
        auditor.report.add(Finding(
            severity=Severity.MEDIUM,
            title=f"Broker version disclosed: {version}",
            description=(
                f"The $SYS topic tree reveals the broker version: {version}. "
                f"Version disclosure helps attackers identify known "
                f"vulnerabilities for the specific broker release."
            ),
            remediation=(
                "Restrict $SYS/broker/version access via ACLs. Consider "
                "disabling $SYS topic publication for non-admin clients."
            ),
            details={"version": version},
        ))

    # Check for client count disclosure
    clients_connected = sys_data.get("clients_connected", "")
    if clients_connected:
        auditor.report.add(Finding(
            severity=Severity.LOW,
            title=f"Connected client count disclosed: {clients_connected}",
            description=(
                f"The $SYS tree reveals {clients_connected} connected "
                f"client(s). This helps attackers gauge the size and "
                f"activity of the deployment."
            ),
            remediation=(
                "Restrict $SYS access to monitoring accounts only."
            ),
            details={"clients_connected": clients_connected},
        ))

    # Overall $SYS exposure finding
    if len(all_sys_topics) > 5:
        auditor.report.add(Finding(
            severity=Severity.MEDIUM,
            title=f"$SYS tree extensively exposed ({len(all_sys_topics)} topics)",
            description=(
                f"The broker exposes {len(all_sys_topics)} $SYS topics "
                f"including operational metrics such as message rates, "
                f"heap usage, and subscription counts. This metadata "
                f"assists in reconnaissance and attack planning."
            ),
            remediation=(
                "Restrict $SYS/# access via ACL rules. Only monitoring "
                "and admin accounts should be able to read system topics."
            ),
            details={
                "total_sys_topics": len(all_sys_topics),
                "sample": all_sys_topics[:20],
                "extracted_data": sys_data,
            },
        ))
