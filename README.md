# mqtt-audit

<p align="center">
  <img src="assets/screenshot.svg" alt="mqtt-audit terminal output" width="900">
</p>

**MQTT broker security auditor** (v1.0.0 stable) -- comprehensive security testing for MQTT brokers covering authentication, encryption, access control, payload inspection, protocol abuse, and compliance mapping.

Part of the [isecwire](https://isecwire.com) open-source IoT security toolkit.

## Why

MQTT is the dominant messaging protocol in IoT and industrial environments. A misconfigured broker can expose telemetry data, allow unauthorised command injection to actuators, and leak operational metadata through the `$SYS` topic tree. Despite this, many production deployments still ship with anonymous access enabled, no TLS, and no topic-level ACLs.

**mqtt-audit** provides a fast, non-destructive way to surface these issues before an attacker does.

## Checks

### Core checks (all profiles)

| Check | What it tests | Severity on fail |
|---|---|---|
| `test_anonymous_access` | Connects without credentials | Critical |
| `test_credentials_required` | Connects with bogus credentials | Critical |
| `test_tls_available` | Probes the TLS port (default 8883) | High |
| `test_wildcard_subscribe` | Subscribes to `#` and inspects SUBACK | High |

### Standard profile (default)

| Check | What it tests | Severity on fail |
|---|---|---|
| `test_topic_enumeration` | Subscribes to `#` and `$SYS/#`, collects traffic | Medium / High |
| `test_write_access` | Publishes to a random test topic | Medium |
| `test_sys_tree_analysis` | Extracts broker version, uptime, client counts from `$SYS` | Medium |
| `test_qos2_abuse` | Tests if QoS 2 is available (resource exhaustion) | Medium |
| `test_will_message` | Tests will message injection on arbitrary topics | Low |
| `test_retained_messages` | Checks for sensitive data in retained messages | Medium |
| `test_mqtt5_features` | Probes MQTT v5 enhanced auth, shared subscriptions | Info |

### Thorough profile

| Check | What it tests | Severity on fail |
|---|---|---|
| `test_default_credentials` | Brute-force with common default credentials | Critical |
| `test_payload_inspection` | Detects plaintext passwords, PII, credit cards in payloads | Critical / High |
| `test_tls_certificate_validation` | Checks cert validity, expiry, CN/SAN match | High |
| `test_client_id_enumeration` | Tests predictable client IDs for session hijacking | Low |
| `test_max_connections` | Tests for connection rate limiting | Medium |
| `test_acl_mapping` | Probes read/write ACLs on common topic hierarchies | High / Medium |

## Features

- **Scan profiles:** `quick`, `standard`, `thorough` -- choose your depth
- **Output formats:** Rich terminal tables, JSON, CSV, Markdown reports
- **CVSS scoring:** Each finding receives a CVSS 3.1 score (0-10)
- **Compliance mapping:** Findings mapped to OWASP IoT Top 10, IEC 62443, CIS Controls, PCI DSS, GDPR
- **Executive summary:** Risk-scored overview for management reports
- **WebSocket support:** Test brokers accessible via ws:// and wss://
- **MQTT v5 probing:** Test enhanced authentication, shared subscriptions, topic aliases
- **Custom wordlists:** Supply your own credential lists for brute-force testing
- **Rich terminal UI:** Colored severity badges, progress display, topic tree views

## Installation

```bash
pip install .
```

Or install directly from the repository:

```bash
pip install git+https://github.com/isecwire/mqtt-audit.git
```

Requires Python 3.9+.

## Usage

```bash
# Quick scan against a local broker
mqtt-audit --host localhost --profile quick

# Standard scan (default) with credentials and JSON output
mqtt-audit --host broker.example.com --username admin --password secret --format json --output report.json

# Thorough scan with markdown report
mqtt-audit --host 10.0.0.50 --profile thorough --format markdown --output report.md

# Scan via WebSocket transport
mqtt-audit --host broker.example.com --port 8080 --websocket

# Custom credential wordlist
mqtt-audit --host broker.example.com --profile thorough --wordlist /path/to/creds.txt

# CSV output for spreadsheet import
mqtt-audit --host localhost --format csv --output findings.csv

# Verbose output for debugging
mqtt-audit --host localhost -v
```

Run as a Python module:

```bash
python -m mqtt_audit --host localhost
```

