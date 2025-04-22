"""CVSS-style scoring and compliance mapping for mqtt-audit findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mqtt_audit.report import Finding, Severity


@dataclass
class ComplianceRef:
    """A reference to a specific compliance framework requirement."""

    framework: str
    reference: str
    description: str


@dataclass
class ScoredFinding:
    """A finding enriched with CVSS score and compliance references."""

    finding: Finding
    cvss_score: float
    cvss_vector: str
    compliance_refs: list[ComplianceRef] = field(default_factory=list)


# ---------------------------------------------------------------------------
# CVSS scoring rules keyed by finding title pattern
# ---------------------------------------------------------------------------

_CVSS_RULES: dict[str, tuple[float, str]] = {
    "anonymous access allowed": (
        9.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ),
    "broker accepts invalid credentials": (
        9.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ),
    "default credentials accepted": (
        9.1,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    ),
    "tls not available": (
        7.5,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    ),
    "certificate validation": (
        6.5,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    ),
    "wildcard subscribe allowed": (
        7.5,
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    ),
    "topic tree exposed": (
        5.3,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    ),
    "write access granted": (
        6.5,
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
    ),
    "user topics": (
        7.5,
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    ),
    "plaintext": (
        7.2,
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    ),
    "pii detected": (
        7.5,
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    ),
    "credit card": (
        8.0,
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    ),
    "qos 2": (
        4.3,
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L",
    ),
    "retained message": (
        5.3,
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
    ),
    "broker version": (
        3.7,
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
    ),
    "client id": (
        4.3,
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
    ),
    "no connection rate limiting": (
        5.3,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
    ),
    "will message": (
        4.3,
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
    ),
    "acl": (
        6.5,
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    ),
}

# Default score for findings that do not match any rule
_DEFAULT_CVSS: dict[Severity, tuple[float, str]] = {
    Severity.CRITICAL: (9.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    Severity.HIGH: (7.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    Severity.MEDIUM: (5.0, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"),
    Severity.LOW: (3.0, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N"),
    Severity.INFO: (0.0, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N"),
}

# ---------------------------------------------------------------------------
# Compliance mapping
# ---------------------------------------------------------------------------

_COMPLIANCE_MAP: dict[str, list[ComplianceRef]] = {
    "anonymous access": [
        ComplianceRef("OWASP IoT Top 10", "I1", "Weak, Guessable, or Hardcoded Passwords"),
        ComplianceRef("IEC 62443-4-2", "CR 1.1", "Human user identification and authentication"),
        ComplianceRef("CIS Controls", "5.2", "Use unique passwords"),
    ],
    "invalid credentials": [
        ComplianceRef("OWASP IoT Top 10", "I1", "Weak, Guessable, or Hardcoded Passwords"),
        ComplianceRef("IEC 62443-4-2", "CR 1.1", "Human user identification and authentication"),
    ],
    "default credentials": [
        ComplianceRef("OWASP IoT Top 10", "I1", "Weak, Guessable, or Hardcoded Passwords"),
        ComplianceRef("IEC 62443-4-2", "CR 1.2", "Software process and device identification"),
        ComplianceRef("CIS Controls", "5.2", "Use unique passwords"),
        ComplianceRef("NIST SP 800-82", "5.7", "Default credentials on industrial devices"),
    ],
    "tls": [
        ComplianceRef("OWASP IoT Top 10", "I7", "Insecure Data Transfer and Storage"),
        ComplianceRef("IEC 62443-4-2", "CR 3.1", "Communication integrity"),
        ComplianceRef("CIS Controls", "3.10", "Encrypt sensitive data in transit"),
    ],
    "certificate": [
        ComplianceRef("OWASP IoT Top 10", "I7", "Insecure Data Transfer and Storage"),
        ComplianceRef("IEC 62443-4-2", "CR 3.1", "Communication integrity"),
    ],
    "wildcard": [
        ComplianceRef("OWASP IoT Top 10", "I3", "Insecure Ecosystem Interfaces"),
        ComplianceRef("IEC 62443-4-2", "CR 2.1", "Authorization enforcement"),
        ComplianceRef("CIS Controls", "6.8", "Define and maintain role-based access control"),
    ],
    "topic": [
        ComplianceRef("OWASP IoT Top 10", "I6", "Insufficient Privacy Protection"),
        ComplianceRef("IEC 62443-4-2", "CR 2.1", "Authorization enforcement"),
    ],
    "write access": [
        ComplianceRef("OWASP IoT Top 10", "I3", "Insecure Ecosystem Interfaces"),
        ComplianceRef("IEC 62443-4-2", "CR 2.1", "Authorization enforcement"),
    ],
    "$sys": [
        ComplianceRef("OWASP IoT Top 10", "I6", "Insufficient Privacy Protection"),
        ComplianceRef("IEC 62443-4-2", "CR 7.6", "Network and security configuration settings"),
    ],
    "plaintext": [
        ComplianceRef("OWASP IoT Top 10", "I7", "Insecure Data Transfer and Storage"),
        ComplianceRef("IEC 62443-4-2", "CR 3.4", "Software and information integrity"),
    ],
    "pii": [
        ComplianceRef("OWASP IoT Top 10", "I6", "Insufficient Privacy Protection"),
        ComplianceRef("GDPR", "Art. 32", "Security of processing"),
    ],
    "credit card": [
        ComplianceRef("PCI DSS", "3.4", "Render PAN unreadable anywhere it is stored"),
        ComplianceRef("OWASP IoT Top 10", "I7", "Insecure Data Transfer and Storage"),
    ],
    "qos": [
        ComplianceRef("IEC 62443-4-2", "CR 7.1", "Denial of service protection"),
    ],
    "retained": [
        ComplianceRef("OWASP IoT Top 10", "I7", "Insecure Data Transfer and Storage"),
        ComplianceRef("IEC 62443-4-2", "CR 3.4", "Software and information integrity"),
    ],
    "rate limit": [
        ComplianceRef("IEC 62443-4-2", "CR 7.1", "Denial of service protection"),
        ComplianceRef("CIS Controls", "13.4", "Perform traffic filtering"),
    ],
    "acl": [
        ComplianceRef("IEC 62443-4-2", "CR 2.1", "Authorization enforcement"),
        ComplianceRef("CIS Controls", "6.8", "Define and maintain role-based access control"),
    ],
    "will message": [
        ComplianceRef("OWASP IoT Top 10", "I3", "Insecure Ecosystem Interfaces"),
    ],
}


def score_finding(finding: Finding) -> ScoredFinding:
    """Assign a CVSS score and compliance references to a finding."""
    title_lower = finding.title.lower()

    # Find matching CVSS rule
    cvss_score, cvss_vector = _DEFAULT_CVSS.get(
        finding.severity, (0.0, "")
    )
    for pattern, (score, vector) in _CVSS_RULES.items():
        if pattern in title_lower:
            cvss_score = score
            cvss_vector = vector
            break

    # Find matching compliance references
    refs: list[ComplianceRef] = []
    for pattern, comp_refs in _COMPLIANCE_MAP.items():
        if pattern in title_lower or pattern in finding.description.lower():
            refs.extend(comp_refs)

    # Deduplicate
    seen: set[str] = set()
    unique_refs: list[ComplianceRef] = []
    for ref in refs:
        key = f"{ref.framework}:{ref.reference}"
        if key not in seen:
            seen.add(key)
            unique_refs.append(ref)

    return ScoredFinding(
        finding=finding,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        compliance_refs=unique_refs,
    )


def score_all(findings: list[Finding]) -> list[ScoredFinding]:
    """Score all findings in a report."""
    return [score_finding(f) for f in findings]


def overall_risk_score(scored: list[ScoredFinding]) -> float:
    """Compute a weighted overall risk score (0-10)."""
    if not scored:
        return 0.0
    # Use the max score with a small penalty for breadth
    max_score = max(s.cvss_score for s in scored)
    nonzero = [s for s in scored if s.cvss_score > 0]
    if len(nonzero) <= 1:
        return max_score
    # Add up to 1.0 for multiple findings, capped at 10
    breadth_bonus = min(1.0, (len(nonzero) - 1) * 0.1)
    return min(10.0, max_score + breadth_bonus)


def executive_summary(scored: list[ScoredFinding], host: str) -> str:
    """Generate an executive summary paragraph."""
    if not scored:
        return (
            f"The MQTT broker at {host} was audited and no security findings "
            f"were identified. The broker configuration appears sound."
        )

    total = len(scored)
    critical = sum(1 for s in scored if s.finding.severity == Severity.CRITICAL)
    high = sum(1 for s in scored if s.finding.severity == Severity.HIGH)
    medium = sum(1 for s in scored if s.finding.severity == Severity.MEDIUM)
    risk = overall_risk_score(scored)

    risk_label = "LOW"
    if risk >= 9.0:
        risk_label = "CRITICAL"
    elif risk >= 7.0:
        risk_label = "HIGH"
    elif risk >= 4.0:
        risk_label = "MEDIUM"

    parts = []
    parts.append(
        f"The MQTT broker at {host} was audited and {total} security "
        f"finding(s) were identified."
    )
    parts.append(f"Overall risk rating: {risk_label} ({risk:.1f}/10.0).")

    if critical > 0:
        parts.append(
            f"{critical} CRITICAL finding(s) require immediate remediation."
        )
    if high > 0:
        parts.append(
            f"{high} HIGH-severity finding(s) should be addressed urgently."
        )
    if medium > 0:
        parts.append(
            f"{medium} MEDIUM-severity finding(s) should be scheduled for remediation."
        )

    # Top compliance gaps
    frameworks: set[str] = set()
    for s in scored:
        for ref in s.compliance_refs:
            frameworks.add(ref.framework)
    if frameworks:
        fw_list = ", ".join(sorted(frameworks))
        parts.append(
            f"Findings relate to the following compliance frameworks: {fw_list}."
        )

    return " ".join(parts)
