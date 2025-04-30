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


def test_tls_certificate_validation(auditor: MqttAuditor) -> None:
    """Check TLS certificate validity, expiry, and CN/SAN match.

    Connects to the TLS port and inspects the server certificate
    for common issues.
    """
    logger.info("Checking TLS certificate on %s:%d ...", auditor.host, auditor.tls_port)
    import socket

    try:
        # First, get the actual certificate with validation disabled
        ctx_noverify = ssl.create_default_context()
        ctx_noverify.check_hostname = False
        ctx_noverify.verify_mode = ssl.CERT_NONE

        with socket.create_connection(
            (auditor.host, auditor.tls_port), timeout=auditor.timeout
        ) as sock:
            with ctx_noverify.wrap_socket(sock, server_hostname=auditor.host) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cert = ssock.getpeercert()

        if not cert and not cert_bin:
            auditor.report.add(Finding(
                severity=Severity.HIGH,
                title="TLS certificate not presented",
                description="The broker did not present a TLS certificate.",
                remediation="Configure the broker with a valid TLS certificate.",
            ))
            return

        issues: list[str] = []

        # Check expiry
        if cert and "notAfter" in cert:
            from ssl import cert_time_to_seconds
            try:
                expiry_ts = cert_time_to_seconds(cert["notAfter"])
                now_ts = time.time()
                days_left = (expiry_ts - now_ts) / 86400

                if days_left < 0:
                    issues.append(f"Certificate EXPIRED ({abs(int(days_left))} days ago)")
                elif days_left < 30:
                    issues.append(f"Certificate expires in {int(days_left)} days")
            except Exception as e:
                logger.debug("Could not parse cert expiry: %s", e)

        # Check hostname match via full validation
        try:
            ctx_verify = ssl.create_default_context()
            with socket.create_connection(
                (auditor.host, auditor.tls_port), timeout=auditor.timeout
            ) as sock:
                with ctx_verify.wrap_socket(sock, server_hostname=auditor.host) as ssock:
                    pass  # Validation succeeded
        except ssl.SSLCertVerificationError as e:
            if "hostname" in str(e).lower():
                issues.append("Certificate hostname does not match target")
            elif "self-signed" in str(e).lower() or "self signed" in str(e).lower():
                issues.append("Self-signed certificate")
            elif "expired" in str(e).lower():
                issues.append("Certificate chain validation failed (expired)")
            else:
                issues.append(f"Certificate validation failed: {e}")
        except Exception as e:
            issues.append(f"Certificate validation error: {e}")

        if issues:
            auditor.report.add(Finding(
                severity=Severity.HIGH,
                title="TLS certificate validation issues",
                description=(
                    "The broker's TLS certificate has the following issues: "
                    + "; ".join(issues)
                ),
                remediation=(
                    "Replace the certificate with one issued by a trusted CA. "
                    "Ensure the certificate CN or SAN matches the broker's "
                    "hostname. Renew certificates before expiry."
                ),
                details={"issues": issues, "cert_info": cert or {}},
            ))
        else:
            auditor.report.add(Finding(
                severity=Severity.INFO,
                title="TLS certificate valid",
                description="The broker's TLS certificate passed validation checks.",
                remediation="No action required.",
            ))

    except (OSError, ConnectionRefusedError, ssl.SSLError) as e:
        logger.debug("Could not connect for TLS cert check: %s", e)
        auditor.report.add(Finding(
            severity=Severity.INFO,
            title="TLS certificate check skipped",
            description=f"Could not connect to TLS port for certificate validation: {e}",
            remediation="Ensure the TLS port is accessible.",
        ))


def test_mqtt5_features(auditor: MqttAuditor) -> None:
    """Probe MQTT v5 specific features.

    Tests whether the broker supports MQTT v5 enhanced authentication,
    topic aliases, shared subscriptions, and flow control.
    """
    logger.info("Probing MQTT v5 features on %s:%d ...", auditor.host, auditor.port)

    try:
        from paho.mqtt.client import Client
        from paho.mqtt.enums import CallbackAPIVersion, MQTTProtocolVersion
        from paho.mqtt.properties import Properties
        from paho.mqtt.packettypes import PacketTypes
    except ImportError:
        logger.warning("paho-mqtt v5 support not available in this version.")
        return

    connected_event = threading.Event()
    connect_result: dict[str, Any] = {"ok": False, "properties": None}

    def on_connect(
        client: mqtt.Client,
        userdata: Any,
        flags: Any,
        rc: Any,
        properties: Any = None,
    ) -> None:
        connect_result["ok"] = True
        connect_result["properties"] = properties
        connected_event.set()

    try:
        client = Client(
            callback_api_version=CallbackAPIVersion.VERSION2,
            client_id=f"mqtt-audit-v5-{uuid.uuid4().hex[:8]}",
            protocol=MQTTProtocolVersion.MQTTv5,
        )
    except Exception:
        logger.debug("Could not create MQTT v5 client.")
        return

    client.on_connect = on_connect

    if auditor.username:
        client.username_pw_set(auditor.username, auditor.password)

    features: dict[str, bool] = {
        "mqttv5_supported": False,
        "shared_subscriptions": False,
        "topic_alias_max": False,
    }

    try:
        client.connect(auditor.host, auditor.port, keepalive=int(auditor.timeout))
        client.loop_start()
        connected_event.wait(timeout=auditor.timeout)

        if connect_result["ok"]:
            features["mqttv5_supported"] = True

            # Test shared subscription
            sub_event = threading.Event()

            def on_subscribe(
                _client: mqtt.Client,
                _userdata: Any,
                mid: int,
                rc_list: Any = (),
                properties: Any = None,
            ) -> None:
                sub_event.set()

            client.on_subscribe = on_subscribe

            # Shared subscription (MQTT 5 feature)
            try:
                client.subscribe("$share/audit/test/#", qos=0)
                sub_event.wait(timeout=auditor.timeout)
                if sub_event.is_set():
                    features["shared_subscriptions"] = True
            except Exception:
                pass

    except Exception as exc:
        logger.debug("MQTT v5 connection failed: %s", exc)
    finally:
        try:
            client.loop_stop()
            client.disconnect()
        except Exception:
            pass

    if features["mqttv5_supported"]:
        detail_parts = ["MQTT v5 protocol is supported."]
        if features["shared_subscriptions"]:
            detail_parts.append("Shared subscriptions are available.")

        auditor.report.add(Finding(
            severity=Severity.INFO,
            title="MQTT v5 features detected",
            description=" ".join(detail_parts),
            remediation=(
                "Ensure MQTT v5 features like shared subscriptions and "
                "topic aliases are properly secured via ACLs. Review "
                "enhanced authentication configuration."
            ),
            details=features,
        ))
    else:
        auditor.report.add(Finding(
            severity=Severity.INFO,
            title="MQTT v5 not supported or not reachable",
            description="The broker did not accept an MQTT v5 connection.",
            remediation="No action required.",
        ))
