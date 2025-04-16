"""Core MQTT security auditing logic."""

from __future__ import annotations

import logging
import ssl
import threading
import time
import uuid
from enum import Enum
from typing import Any, Callable

import paho.mqtt.client as mqtt
from paho.mqtt.enums import CallbackAPIVersion, MQTTErrorCode
from paho.mqtt.reasoncodes import ReasonCode

from mqtt_audit.report import AuditReport, Finding, Severity

logger = logging.getLogger(__name__)

# A unique prefix so we never collide with real topics.
_TEST_TOPIC_PREFIX = f"__mqtt_audit/{uuid.uuid4().hex[:12]}"


class AuditProfile(str, Enum):
    """Scan intensity profiles."""

    QUICK = "quick"
    STANDARD = "standard"
    THOROUGH = "thorough"


def _reason_ok(rc: int | ReasonCode | MQTTErrorCode) -> bool:
    """Return True when an MQTT reason / return code signals success."""
    if isinstance(rc, ReasonCode):
        return rc.value == 0
    return int(rc) == 0


class MqttAuditor:
    """Runs a battery of security checks against a single MQTT broker.

    Each ``test_*`` method is self-contained: it creates its own client,
    connects, performs the check, disconnects, and appends any findings
    to *self.report*.
    """

    def __init__(
        self,
        host: str,
        port: int = 1883,
        tls_port: int = 8883,
        username: str | None = None,
        password: str | None = None,
        timeout: float = 5.0,
        profile: AuditProfile = AuditProfile.STANDARD,
        wordlist_path: str | None = None,
        use_websocket: bool = False,
    ) -> None:
        self.host = host
        self.port = port
        self.tls_port = tls_port
        self.username = username
        self.password = password
        self.timeout = timeout
        self.profile = profile
        self.wordlist_path = wordlist_path
        self.use_websocket = use_websocket
        self.report = AuditReport(host=host, port=port, tls_port=tls_port)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _new_client(self, client_id: str | None = None) -> mqtt.Client:
        """Create a fresh paho-mqtt v2 Client."""
        cid = client_id or f"mqtt-audit-{uuid.uuid4().hex[:8]}"
        transport = "websockets" if self.use_websocket else "tcp"
        return mqtt.Client(
            callback_api_version=CallbackAPIVersion.VERSION2,
            client_id=cid,
            transport=transport,
        )

    def _try_connect(
        self,
        client: mqtt.Client,
        port: int | None = None,
        use_tls: bool = False,
    ) -> bool:
        """Attempt to connect *client* to the broker.

        Returns True on a successful CONNACK, False otherwise.
        """
        target_port = port or self.port
        connected = threading.Event()
        connect_result: dict[str, Any] = {"ok": False, "rc": None}

        def on_connect(
            client: mqtt.Client,
            userdata: Any,
            flags: Any,
            rc: ReasonCode | int,
            properties: Any = None,
        ) -> None:
            connect_result["ok"] = _reason_ok(rc)
            connect_result["rc"] = rc
            connected.set()

        client.on_connect = on_connect

        if use_tls:
            ctx = ssl.create_default_context()
            # We deliberately allow unverified certs -- we are probing,
            # not trusting.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            client.tls_set_context(ctx)

        try:
            client.connect(self.host, target_port, keepalive=int(self.timeout))
            client.loop_start()
            connected.wait(timeout=self.timeout)
            return connect_result["ok"]
        except (OSError, ConnectionRefusedError, ssl.SSLError, mqtt.MQTTException) as exc:
            logger.debug("Connection to %s:%d failed: %s", self.host, target_port, exc)
            return False

    @staticmethod
    def _disconnect(client: mqtt.Client) -> None:
        """Gracefully tear down a client."""
        try:
            client.loop_stop()
            client.disconnect()
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------
    # Original audit checks
    # ------------------------------------------------------------------

    def test_anonymous_access(self) -> None:
        """Try to connect without any credentials."""
        logger.info("Testing anonymous access on %s:%d ...", self.host, self.port)
        client = self._new_client("mqtt-audit-anon")
        client.username_pw_set(None, None)

        if self._try_connect(client):
            self.report.add(
                Finding(
                    severity=Severity.CRITICAL,
                    title="Anonymous access allowed",
                    description=(
                        "The broker accepts connections without any username or "
                        "password. Any network-reachable client can subscribe to "
                        "topics and publish messages."
                    ),
                    remediation=(
                        "Disable anonymous access in the broker configuration "
                        "(e.g. 'allow_anonymous false' in Mosquitto) and enforce "
                        "username/password or certificate-based authentication."
                    ),
                )
            )
        else:
            self.report.add(
                Finding(
                    severity=Severity.INFO,
                    title="Anonymous access denied",
                    description="The broker correctly rejected an unauthenticated connection.",
                    remediation="No action required.",
                )
            )
        self._disconnect(client)

    def test_tls_available(self) -> None:
        """Probe the TLS port to see whether encrypted transport is offered."""
        logger.info("Testing TLS availability on %s:%d ...", self.host, self.tls_port)
        client = self._new_client("mqtt-audit-tls")

        if self.username:
            client.username_pw_set(self.username, self.password)

        if self._try_connect(client, port=self.tls_port, use_tls=True):
            self.report.add(
                Finding(
                    severity=Severity.INFO,
                    title="TLS available on port " + str(self.tls_port),
                    description="The broker accepts TLS-encrypted connections.",
                    remediation="Ensure the non-TLS listener is disabled in production.",
                )
            )
        else:
            self.report.add(
                Finding(
                    severity=Severity.HIGH,
                    title="TLS not available on port " + str(self.tls_port),
                    description=(
                        "The broker does not appear to offer TLS on the expected "
                        f"port ({self.tls_port}). All traffic -- including credentials "
                        "-- may be transmitted in plaintext."
                    ),
                    remediation=(
                        "Configure a TLS listener with a valid certificate. "
                        "Disable the plaintext listener or restrict it to localhost."
                    ),
                )
            )
        self._disconnect(client)

    def test_topic_enumeration(self) -> None:
        """Subscribe to ``#`` and ``$SYS/#`` and collect topics."""
        logger.info("Enumerating topics on %s:%d ...", self.host, self.port)
        client = self._new_client("mqtt-audit-enum")

        if self.username:
            client.username_pw_set(self.username, self.password)

        collected_topics: dict[str, int] = {}
        lock = threading.Lock()

        def on_message(
            client: mqtt.Client,
            userdata: Any,
            message: mqtt.MQTTMessage,
        ) -> None:
            with lock:
                topic = message.topic
                collected_topics[topic] = collected_topics.get(topic, 0) + 1

        client.on_message = on_message

        if not self._try_connect(client):
            logger.warning("Could not connect for topic enumeration.")
            self._disconnect(client)
            return

        client.subscribe("#", qos=0)
        client.subscribe("$SYS/#", qos=0)

        time.sleep(self.timeout)
        self._disconnect(client)

        sys_topics = [t for t in collected_topics if t.startswith("$SYS")]
        user_topics = [t for t in collected_topics if not t.startswith("$SYS")]

        details: dict[str, Any] = {
            "sys_topics_count": len(sys_topics),
            "user_topics_count": len(user_topics),
            "sys_topics_sample": sys_topics[:20],
            "user_topics_sample": user_topics[:20],
        }

        # Store in report metadata for tree display
        if user_topics:
            self.report.metadata["enumerated_user_topics"] = user_topics[:50]
        if sys_topics:
            self.report.metadata["enumerated_sys_topics"] = sys_topics[:50]

        if sys_topics:
            self.report.add(
                Finding(
                    severity=Severity.MEDIUM,
                    title="$SYS topic tree exposed",
                    description=(
                        f"Collected {len(sys_topics)} $SYS topic(s). The $SYS "
                        "hierarchy reveals broker internals such as connected "
                        "client counts, byte counters, and version information."
                    ),
                    remediation=(
                        "Restrict access to $SYS/# via ACL rules so that only "
                        "monitoring accounts can read system topics."
                    ),
                    details=details,
                )
            )

        if user_topics:
            self.report.add(
                Finding(
                    severity=Severity.HIGH,
                    title="Wildcard subscribe exposes user topics",
                    description=(
                        f"Subscribing to '#' returned messages on {len(user_topics)} "
                        "user-defined topic(s). An attacker can passively observe "
                        "all device telemetry and command traffic."
                    ),
                    remediation=(
                        "Implement per-client ACLs that restrict each client to "
                        "its own topic namespace. Deny wildcard '#' subscriptions "
                        "for non-admin accounts."
                    ),
                    details=details,
                )
            )

        if not sys_topics and not user_topics:
            self.report.add(
                Finding(
                    severity=Severity.INFO,
                    title="No topics observed during enumeration",
                    description=(
                        "No messages were received during the collection window. "
                        "The broker may restrict wildcard subscriptions or there "
                        "is simply no traffic."
                    ),
                    remediation="No action required.",
                )
            )

