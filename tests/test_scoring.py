"""Tests for mqtt_audit.scoring module."""

from __future__ import annotations

import unittest

from mqtt_audit.report import Finding, Severity
from mqtt_audit.scoring import (
    ComplianceRef,
    ScoredFinding,
    executive_summary,
    overall_risk_score,
    score_all,
    score_finding,
)


class TestScoreFinding(unittest.TestCase):
    """Tests for individual finding scoring."""

    def test_critical_finding_gets_high_cvss(self) -> None:
        f = Finding(
            severity=Severity.CRITICAL,
            title="Anonymous access allowed",
            description="The broker accepts anonymous connections.",
            remediation="Disable anonymous access.",
        )
        scored = score_finding(f)
        self.assertGreaterEqual(scored.cvss_score, 9.0)
        self.assertIn("CVSS:3.1", scored.cvss_vector)

    def test_info_finding_gets_zero_cvss(self) -> None:
        f = Finding(
            severity=Severity.INFO,
            title="Everything is fine",
            description="No issues.",
            remediation="No action required.",
        )
        scored = score_finding(f)
        self.assertEqual(scored.cvss_score, 0.0)

    def test_tls_finding_gets_compliance_refs(self) -> None:
        f = Finding(
            severity=Severity.HIGH,
            title="TLS not available on port 8883",
            description="No TLS encryption.",
            remediation="Enable TLS.",
        )
        scored = score_finding(f)
        frameworks = {r.framework for r in scored.compliance_refs}
        self.assertIn("OWASP IoT Top 10", frameworks)

    def test_default_credentials_gets_matched(self) -> None:
        f = Finding(
            severity=Severity.CRITICAL,
            title="Default credentials accepted",
            description="admin:admin was accepted.",
            remediation="Change defaults.",
        )
        scored = score_finding(f)
        self.assertGreaterEqual(scored.cvss_score, 9.0)

    def test_compliance_refs_are_deduplicated(self) -> None:
        f = Finding(
            severity=Severity.CRITICAL,
            title="Anonymous access allowed with wildcard",
            description="Anonymous access and wildcard topics.",
            remediation="Fix it.",
        )
        scored = score_finding(f)
        keys = [f"{r.framework}:{r.reference}" for r in scored.compliance_refs]
        self.assertEqual(len(keys), len(set(keys)))


class TestScoreAll(unittest.TestCase):
    """Tests for batch scoring."""

    def test_score_all_returns_list(self) -> None:
        findings = [
            Finding(severity=Severity.HIGH, title="A", description="D", remediation="R"),
            Finding(severity=Severity.LOW, title="B", description="D", remediation="R"),
        ]
        scored = score_all(findings)
        self.assertEqual(len(scored), 2)
        self.assertIsInstance(scored[0], ScoredFinding)

    def test_score_all_empty_list(self) -> None:
        self.assertEqual(score_all([]), [])


class TestOverallRiskScore(unittest.TestCase):
    """Tests for overall risk score calculation."""

    def test_empty_list_returns_zero(self) -> None:
        self.assertEqual(overall_risk_score([]), 0.0)

    def test_single_finding_returns_its_score(self) -> None:
        f = Finding(severity=Severity.HIGH, title="TLS not available", description="D", remediation="R")
        scored = [score_finding(f)]
        risk = overall_risk_score(scored)
        self.assertEqual(risk, scored[0].cvss_score)

    def test_multiple_findings_add_breadth_bonus(self) -> None:
        findings = [
            Finding(severity=Severity.HIGH, title="A", description="D", remediation="R"),
            Finding(severity=Severity.MEDIUM, title="B", description="D", remediation="R"),
        ]
        scored = score_all(findings)
        single_risk = max(s.cvss_score for s in scored)
        overall = overall_risk_score(scored)
        self.assertGreaterEqual(overall, single_risk)

    def test_capped_at_ten(self) -> None:
        findings = [
            Finding(severity=Severity.CRITICAL, title="Anonymous access allowed", description="D", remediation="R"),
        ] * 20
        scored = score_all(findings)
        self.assertLessEqual(overall_risk_score(scored), 10.0)


class TestExecutiveSummary(unittest.TestCase):
    """Tests for executive summary generation."""

    def test_no_findings_summary(self) -> None:
        summary = executive_summary([], "localhost")
        self.assertIn("localhost", summary)
        self.assertIn("no security findings", summary)

    def test_critical_findings_mentioned(self) -> None:
        f = Finding(severity=Severity.CRITICAL, title="Bad", description="D", remediation="R")
        scored = [score_finding(f)]
        summary = executive_summary(scored, "broker.test")
        self.assertIn("CRITICAL", summary)
        self.assertIn("broker.test", summary)

    def test_summary_contains_risk_rating(self) -> None:
        f = Finding(severity=Severity.MEDIUM, title="Med", description="D", remediation="R")
        scored = [score_finding(f)]
        summary = executive_summary(scored, "test")
        self.assertIn("/10.0", summary)


if __name__ == "__main__":
    unittest.main()
