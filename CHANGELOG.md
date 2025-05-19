# Changelog

## [1.0.0] - 2026-04-03
### Added
- Stable release, production-ready
- SARIF output format for CI/CD integration (--format sarif)
- Passive traffic analysis mode — sniff MQTT without active probing (--passive)
- Broker comparison — scan two brokers and diff security posture (--compare)
- Plugin system for custom checks (drop .py files into checks.d/)
- JUnit XML output for test framework integration (--format junit)
### Changed
- Default profile changed from "standard" to match broker type auto-detection
- Rich output now includes executive summary with overall risk gauge
- Credential brute-force uses timing-based detection evasion
### Fixed
- WebSocket transport failing with some nginx reverse proxies
- Topic enumeration timeout not respected on slow brokers
- CSV export escaping for findings with commas in descriptions

## [0.2.0] - 2026-03-01
### Added
- 17 security checks (up from 6)
- Credential brute-force with built-in wordlist
- Payload inspection (passwords, PII, credit cards)
- QoS 2 abuse testing
- $SYS tree analysis
- MQTT v5 feature probing
- Topic ACL mapping
- Scan profiles (quick/standard/thorough)
- CVSS scoring per finding with compliance mapping
- Rich terminal output with colored tables and progress
- Multiple output formats (table, json, csv, markdown)
- WebSocket transport support

## [0.1.0] - 2025-12-12
### Added
- Initial release
- Anonymous access detection
- TLS availability check
- Topic enumeration via wildcard subscribe
- Write access testing
- Credential requirement verification
- JSON and console report output
