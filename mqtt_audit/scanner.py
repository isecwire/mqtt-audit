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

    def test_write_access(self) -> None:
        """Attempt to publish a message to a test topic."""
        logger.info("Testing write access on %s:%d ...", self.host, self.port)
        client = self._new_client("mqtt-audit-write")

        if self.username:
            client.username_pw_set(self.username, self.password)

        if not self._try_connect(client):
            logger.warning("Could not connect for write-access test.")
            self._disconnect(client)
            return

        publish_ok = threading.Event()

        def on_publish(
            client: mqtt.Client,
            userdata: Any,
            mid: int,
            rc: ReasonCode | int = 0,
            properties: Any = None,
        ) -> None:
            publish_ok.set()

        client.on_publish = on_publish

        topic = f"{_TEST_TOPIC_PREFIX}/write_test"
        result = client.publish(topic, payload=b"mqtt-audit probe", qos=1)

        publish_ok.wait(timeout=self.timeout)
        published = publish_ok.is_set()

        self._disconnect(client)

        if published:
            identity = self.username or "anonymous"
            self.report.add(
                Finding(
                    severity=Severity.MEDIUM,
                    title=f"Write access granted to '{identity}'",
                    description=(
                        f"Successfully published to '{topic}'. The current "
                        "identity is allowed to write to arbitrary topics."
                    ),
                    remediation=(
                        "Configure publish ACLs to restrict each client to its "
                        "own set of writable topics."
                    ),
                    details={"topic": topic},
                )
            )
        else:
            self.report.add(
                Finding(
                    severity=Severity.INFO,
                    title="Write access restricted",
                    description="The broker did not acknowledge a publish to the test topic.",
                    remediation="No action required.",
                )
            )

    def test_credentials_required(self) -> None:
        """Verify that the broker enforces authentication."""
        logger.info("Testing credential enforcement on %s:%d ...", self.host, self.port)
        client = self._new_client("mqtt-audit-badcred")
        client.username_pw_set("mqtt_audit_bogus_user", "mqtt_audit_bogus_pass")

        if self._try_connect(client):
            self.report.add(
                Finding(
                    severity=Severity.CRITICAL,
                    title="Broker accepts invalid credentials",
                    description=(
                        "A connection with fabricated username/password was "
                        "accepted. The broker either ignores credentials entirely "
                        "or has a dangerously permissive authentication backend."
                    ),
                    remediation=(
                        "Review the authentication plugin or password file. "
                        "Ensure every connecting client is verified against a "
                        "credential store."
                    ),
                )
            )
        else:
            self.report.add(
                Finding(
                    severity=Severity.INFO,
                    title="Invalid credentials rejected",
                    description="The broker correctly refused a connection with bogus credentials.",
                    remediation="No action required.",
                )
            )
        self._disconnect(client)

    def test_wildcard_subscribe(self) -> None:
        """Check whether multi-level wildcard subscriptions are restricted."""
        logger.info("Testing wildcard subscribe restrictions on %s:%d ...", self.host, self.port)
        client = self._new_client("mqtt-audit-wildcard")

        if self.username:
            client.username_pw_set(self.username, self.password)

        suback_result: dict[str, Any] = {"granted_qos": None}
        suback_event = threading.Event()

        def on_subscribe(
            client: mqtt.Client,
            userdata: Any,
            mid: int,
            rc_list: list[ReasonCode] | tuple[int, ...] = (),
            properties: Any = None,
        ) -> None:
            suback_result["granted_qos"] = rc_list
            suback_event.set()

        client.on_subscribe = on_subscribe

        if not self._try_connect(client):
            logger.warning("Could not connect for wildcard subscribe test.")
            self._disconnect(client)
            return

        client.subscribe("#", qos=0)
        suback_event.wait(timeout=self.timeout)
        self._disconnect(client)

        granted = suback_result.get("granted_qos")
        if granted is None:
            self.report.add(
                Finding(
                    severity=Severity.INFO,
                    title="No SUBACK received for wildcard subscribe",
                    description="The broker did not respond to the subscribe request in time.",
                    remediation="Verify broker health and network connectivity.",
                )
            )
            return

        denied = False
        for rc in granted:
            code = rc.value if isinstance(rc, ReasonCode) else int(rc)
            if code >= 128:
                denied = True

        if denied:
            self.report.add(
                Finding(
                    severity=Severity.INFO,
                    title="Wildcard subscribe denied",
                    description="The broker refused a root-level '#' subscription.",
                    remediation="No action required.",
                )
            )
        else:
            identity = self.username or "anonymous"
            self.report.add(
                Finding(
                    severity=Severity.HIGH,
                    title=f"Wildcard subscribe allowed for '{identity}'",
                    description=(
                        "The broker accepted a root-level '#' subscription. "
                        "This allows the client to receive every message published "
                        "on the broker."
                    ),
                    remediation=(
                        "Restrict wildcard subscriptions via ACL rules. Only "
                        "dedicated monitoring or admin accounts should be able to "
                        "subscribe to '#'."
                    ),
                )
            )

    # ------------------------------------------------------------------
    # Run all checks
    # ------------------------------------------------------------------

    def _get_checks_for_profile(
        self,
    ) -> list[tuple[str, Callable[[], None]]]:
        """Return the list of checks to run based on the scan profile."""
        from mqtt_audit.checks.credentials import test_default_credentials
        from mqtt_audit.checks.payload import test_payload_inspection
        from mqtt_audit.checks.protocol import (
            test_client_id_enumeration,
            test_max_connections,
            test_mqtt5_features,
            test_qos2_abuse,
            test_tls_certificate_validation,
            test_will_message,
        )
        from mqtt_audit.checks.sys_tree import test_sys_tree_analysis
        from mqtt_audit.checks.acl import test_acl_mapping, test_retained_messages

        # Quick: only essential checks
        quick: list[tuple[str, Callable[[], None]]] = [
            ("Anonymous access", self.test_anonymous_access),
            ("Credential enforcement", self.test_credentials_required),
            ("TLS availability", self.test_tls_available),
            ("Wildcard subscribe", self.test_wildcard_subscribe),
        ]

        # Standard: quick + enumeration + protocol checks
        standard: list[tuple[str, Callable[[], None]]] = quick + [
            ("Topic enumeration", self.test_topic_enumeration),
            ("Write access", self.test_write_access),
            ("$SYS tree analysis", lambda: test_sys_tree_analysis(self)),
            ("QoS 2 abuse", lambda: test_qos2_abuse(self)),
            ("Will message", lambda: test_will_message(self)),
            ("Retained messages", lambda: test_retained_messages(self)),
            ("MQTT v5 features", lambda: test_mqtt5_features(self)),
        ]

        # Thorough: standard + brute-force + deep analysis
        thorough: list[tuple[str, Callable[[], None]]] = standard + [
            ("Default credentials", lambda: test_default_credentials(self, self.wordlist_path)),
            ("Payload inspection", lambda: test_payload_inspection(self)),
            ("TLS certificate validation", lambda: test_tls_certificate_validation(self)),
            ("Client ID enumeration", lambda: test_client_id_enumeration(self)),
            ("Connection rate limiting", lambda: test_max_connections(self)),
            ("ACL mapping", lambda: test_acl_mapping(self)),
        ]

        profiles = {
            AuditProfile.QUICK: quick,
            AuditProfile.STANDARD: standard,
            AuditProfile.THOROUGH: thorough,
        }

        return profiles.get(self.profile, standard)

    def run_all(
        self,
        progress_callback: Callable[[str, int, int], None] | None = None,
    ) -> AuditReport:
        """Execute audit checks based on the configured profile.

        *progress_callback*, if provided, is called with
        ``(check_name, current_index, total_count)`` before each check.
        """
        checks = self._get_checks_for_profile()
        total = len(checks)

        for idx, (name, check) in enumerate(checks):
            if progress_callback:
                progress_callback(name, idx, total)
            try:
                check()
            except Exception as exc:  # noqa: BLE001
                logger.error("Check '%s' failed unexpectedly: %s", name, exc)
                self.report.add(
                    Finding(
                        severity=Severity.INFO,
                        title=f"Check error: {name}",
                        description=f"An unexpected error occurred: {exc}",
                        remediation="Review the error and retry the scan.",
                    )
                )

        if progress_callback:
            progress_callback("Complete", total, total)

        return self.report
