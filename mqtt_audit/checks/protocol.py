"""Protocol compliance checks -- QoS, MQTT v5 features, rate limiting, will messages."""

from __future__ import annotations

import logging
import ssl
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


def test_qos2_abuse(auditor: MqttAuditor) -> None:
    """Test whether QoS 2 is available (resource exhaustion vector).

    QoS 2 requires the broker to maintain state for each message until
    the four-step handshake completes. Unrestricted QoS 2 can be abused
    for resource exhaustion attacks.
    """
    logger.info("Testing QoS 2 availability on %s:%d ...", auditor.host, auditor.port)
    client = auditor._new_client("mqtt-audit-qos2")

    if auditor.username:
        client.username_pw_set(auditor.username, auditor.password)

    if not auditor._try_connect(client):
        logger.warning("Could not connect for QoS 2 test.")
        auditor._disconnect(client)
        return

    # Subscribe with QoS 2
    suback_event = threading.Event()
    granted_qos: list[int] = []

    def on_subscribe(
        _client: mqtt.Client,
        _userdata: Any,
        mid: int,
        rc_list: list[ReasonCode] | tuple[int, ...] = (),
        properties: Any = None,
    ) -> None:
        for rc in rc_list:
            code = rc.value if isinstance(rc, ReasonCode) else int(rc)
            granted_qos.append(code)
        suback_event.set()

    client.on_subscribe = on_subscribe

    topic = f"__mqtt_audit/{uuid.uuid4().hex[:12]}/qos2_test"
    client.subscribe(topic, qos=2)
    suback_event.wait(timeout=auditor.timeout)

    # Also try publishing at QoS 2
    publish_ok = threading.Event()

    def on_publish(
        _client: mqtt.Client,
        _userdata: Any,
        mid: int,
        rc: ReasonCode | int = 0,
        properties: Any = None,
    ) -> None:
        publish_ok.set()

    client.on_publish = on_publish
    client.publish(topic, payload=b"qos2-test", qos=2)
    publish_ok.wait(timeout=auditor.timeout)

    auditor._disconnect(client)

    qos2_granted = any(q == 2 for q in granted_qos)
    pub_ok = publish_ok.is_set()

    if qos2_granted or pub_ok:
        auditor.report.add(Finding(
            severity=Severity.MEDIUM,
            title="QoS 2 available -- resource exhaustion vector",
            description=(
                "The broker allows QoS 2 (exactly-once delivery). Each QoS 2 "
                "message requires the broker to maintain session state through "
                "a four-step handshake, which can be exploited for resource "
                "exhaustion if not rate-limited."
            ),
            remediation=(
                "Restrict QoS 2 to trusted clients via ACL or broker "
                "configuration. Set maximum inflight message limits. "
                "Monitor for QoS 2 abuse patterns."
            ),
            details={
                "qos2_subscribe_granted": qos2_granted,
                "qos2_publish_acknowledged": pub_ok,
            },
        ))
    else:
        auditor.report.add(Finding(
            severity=Severity.INFO,
            title="QoS 2 restricted",
            description="The broker did not grant QoS 2 subscriptions or acknowledge QoS 2 publishes.",
            remediation="No action required.",
        ))


def test_will_message(auditor: MqttAuditor) -> None:
    """Test if arbitrary will messages can be set.

    Will messages are published by the broker when a client disconnects
    unexpectedly. If any client can set a will message on any topic,
    this can be abused to inject messages.
    """
    logger.info("Testing will message abuse on %s:%d ...", auditor.host, auditor.port)
    client = auditor._new_client("mqtt-audit-will")

    if auditor.username:
        client.username_pw_set(auditor.username, auditor.password)

    # Set a will message on a test topic
    will_topic = f"__mqtt_audit/{uuid.uuid4().hex[:12]}/will_test"
    client.will_set(will_topic, payload=b"mqtt-audit will probe", qos=1, retain=False)

    if auditor._try_connect(client):
        auditor.report.add(Finding(
            severity=Severity.LOW,
            title="Will message injection possible",
            description=(
                f"The broker accepted a connection with a will message on "
                f"'{will_topic}'. If will message topics are not restricted "
                f"by ACLs, a client can inject messages into arbitrary topics "
                f"by disconnecting uncleanly."
            ),
            remediation=(
                "Apply ACL rules to will message topics. Ensure clients can "
                "only set will messages on topics they are authorized to "
                "publish to."
            ),
            details={"will_topic": will_topic},
        ))
    else:
        auditor.report.add(Finding(
            severity=Severity.INFO,
            title="Will message test inconclusive",
            description="Could not connect with a will message set.",
            remediation="No action required.",
        ))
    auditor._disconnect(client)


def test_max_connections(auditor: MqttAuditor) -> None:
    """Test for connection rate limiting / max connection enforcement.

    Rapidly opens multiple connections to test whether the broker
    enforces rate limits or maximum connection counts.
    """
    logger.info("Testing connection rate limiting on %s:%d ...", auditor.host, auditor.port)
    max_test = 10
    clients: list[mqtt.Client] = []
    connected = 0

    for i in range(max_test):
        client = auditor._new_client(f"mqtt-audit-rate-{i}")
        if auditor.username:
            client.username_pw_set(auditor.username, auditor.password)
        if auditor._try_connect(client):
            connected += 1
            clients.append(client)
        else:
            auditor._disconnect(client)
            break

    # Clean up
    for c in clients:
        auditor._disconnect(c)

    if connected >= max_test:
        auditor.report.add(Finding(
            severity=Severity.MEDIUM,
            title="No connection rate limiting detected",
            description=(
                f"Successfully opened {connected} simultaneous connections "
                f"without being rate-limited or rejected. A lack of connection "
                f"limits enables denial-of-service attacks."
            ),
            remediation=(
                "Configure maximum connection limits per client ID or IP "
                "address. Enable connection rate limiting in the broker. "
                "Consider using a reverse proxy or firewall rules."
            ),
            details={"connections_opened": connected, "test_limit": max_test},
        ))
    elif connected > 0:
        auditor.report.add(Finding(
            severity=Severity.INFO,
            title="Connection limiting may be in effect",
            description=(
                f"Opened {connected}/{max_test} connections before being "
                f"rejected. The broker may enforce connection limits."
            ),
            remediation="No action required.",
            details={"connections_opened": connected, "test_limit": max_test},
        ))


def test_client_id_enumeration(auditor: MqttAuditor) -> None:
    """Try connecting with predictable client IDs.

    If a broker allows connections with common/predictable client IDs,
    it may be possible to hijack existing sessions.
    """
    logger.info("Testing client ID enumeration on %s:%d ...", auditor.host, auditor.port)
    predictable_ids = [
        "client1", "client2", "device1", "device2",
        "sensor1", "sensor2", "gateway", "edge",
        "publisher", "subscriber", "admin", "test",
    ]

    accepted_ids: list[str] = []

    for cid in predictable_ids:
        client = auditor._new_client(cid)
        if auditor.username:
            client.username_pw_set(auditor.username, auditor.password)
        if auditor._try_connect(client):
            accepted_ids.append(cid)
        auditor._disconnect(client)

    if accepted_ids:
        auditor.report.add(Finding(
            severity=Severity.LOW,
            title="Predictable client IDs accepted",
            description=(
                f"The broker accepted connections with {len(accepted_ids)} "
                f"predictable client ID(s): {', '.join(accepted_ids[:5])}. "
                f"If existing sessions use predictable IDs, connecting with "
                f"the same ID will disconnect the original client."
            ),
            remediation=(
                "Enforce unique, unpredictable client IDs. Use the broker's "
                "client ID validation features to reject generic names. "
                "Consider using client certificates for identity."
            ),
            details={"accepted_ids": accepted_ids},
        ))
    else:
        auditor.report.add(Finding(
            severity=Severity.INFO,
            title="Predictable client IDs rejected",
            description="The broker rejected all tested predictable client IDs.",
            remediation="No action required.",
        ))


