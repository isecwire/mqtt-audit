"""Credential brute-force and default credential testing."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from mqtt_audit.report import Finding, Severity

if TYPE_CHECKING:
    from mqtt_audit.scanner import MqttAuditor

logger = logging.getLogger(__name__)


def _load_wordlist(path: str | None = None) -> list[tuple[str, str]]:
    """Load username:password pairs from a wordlist file.

    If *path* is ``None``, the built-in default_creds.txt is used.
    """
    creds: list[tuple[str, str]] = []

    if path is not None:
        text = Path(path).read_text(encoding="utf-8")
    else:
        # Load from package data
        wl_path = Path(__file__).resolve().parent.parent / "wordlists" / "default_creds.txt"
        text = wl_path.read_text(encoding="utf-8")

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            user, passwd = line.split(":", 1)
            creds.append((user, passwd))

    return creds


def test_default_credentials(
    auditor: MqttAuditor,
    wordlist_path: str | None = None,
) -> None:
    """Try common default credentials against the broker.

    Each credential pair is tested with a fresh connection attempt.
    Successful logins are recorded as CRITICAL findings.
    """
    creds = _load_wordlist(wordlist_path)
    logger.info("Testing %d credential pairs against %s:%d ...", len(creds), auditor.host, auditor.port)

    successful: list[tuple[str, str]] = []

    for username, password in creds:
        client = auditor._new_client(f"mqtt-audit-cred-{username[:8]}")
        client.username_pw_set(username, password)

        if auditor._try_connect(client):
            successful.append((username, password))
            logger.warning("Default credentials accepted: %s:%s", username, "****")
        auditor._disconnect(client)

        # Stop after 5 successful pairs to avoid noise
        if len(successful) >= 5:
            break

    if successful:
        cred_list = ", ".join(f"{u}:{p}" for u, p in successful)
        auditor.report.add(Finding(
            severity=Severity.CRITICAL,
            title="Default credentials accepted",
            description=(
                f"The broker accepted {len(successful)} default credential "
                f"pair(s): {cred_list}. Attackers commonly scan for default "
                f"credentials on IoT brokers."
            ),
            remediation=(
                "Change all default passwords immediately. Implement a "
                "password policy that requires strong, unique credentials. "
                "Consider certificate-based authentication."
            ),
            details={
                "successful_credentials": [
                    {"username": u, "password": p} for u, p in successful
                ],
                "total_tested": len(creds),
            },
        ))
    else:
        auditor.report.add(Finding(
            severity=Severity.INFO,
            title="No default credentials found",
            description=(
                f"Tested {len(creds)} common default credential pairs. "
                f"None were accepted by the broker."
            ),
            remediation="No action required.",
        ))
