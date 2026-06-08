from __future__ import annotations

from app.scoring.risk_engine import RiskLevel, Severity, assess_website_risk


def test_risk_engine_scores_hardened_website_as_low_risk() -> None:
    scan_result = {
        "target_url": "https://example.com",
        "availability": {
            "is_reachable": True,
            "status_code": 200,
        },
        "ssl_tls": {
            "uses_https": True,
            "certificate_valid": True,
            "certificate_expired": False,
            "days_to_expiry": 90,
            "tls_protocols": ["TLSv1.2", "TLSv1.3"],
        },
        "security_headers": {
            "headers": {
                "Content-Security-Policy": (
                    "default-src 'self'; object-src 'none'; frame-ancestors 'none'"
                ),
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
                "Server": "nginx",
            }
        },
        "dns_email_security": {
            "spf": "v=spf1 include:_spf.example.com -all",
            "dmarc": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
            "dkim": "selector._domainkey.example.com",
            "dnssec": True,
        },
        "open_ports": [80, 443],
    }

    assessment = assess_website_risk(scan_result)

    assert assessment.security_score == 100
    assert assessment.grade == "A+"
    assert assessment.risk_level == RiskLevel.MINIMAL
    assert assessment.total_deduction == 0
    assert assessment.scoring_deductions == []
    assert assessment.assessment_coverage["availability"] is True
    assert assessment.assessment_coverage["transport_security"] is True
    assert assessment.assessment_coverage["http_security_headers"] is True
    assert assessment.assessment_coverage["dns_email_security"] is True
    assert assessment.assessment_coverage["exposure_management"] is True


def test_risk_engine_detects_critical_website_risks() -> None:
    scan_result = {
        "target_url": "http://vulnerable.test",
        "availability": {
            "is_reachable": True,
            "status_code": 200,
        },
        "ssl_tls": {
            "uses_https": False,
            "certificate_valid": False,
            "certificate_expired": True,
            "days_to_expiry": 0,
            "tls_protocols": ["TLSv1.0", "TLSv1.1"],
        },
        "security_headers": {
            "headers": {
                "Server": "Apache/2.4.49",
            },
            "missing_headers": [
                "Content-Security-Policy",
                "Strict-Transport-Security",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Referrer-Policy",
                "Permissions-Policy",
            ],
        },
        "dns_email_security": {
            "spf": None,
            "dmarc": None,
            "dkim": None,
            "dnssec": False,
        },
        "open_ports": [
            {"port": 22, "state": "open"},
            {"port": 3389, "state": "open"},
            {"port": 3306, "state": "open"},
        ],
    }

    assessment = assess_website_risk(scan_result)
    rule_ids = {deduction.rule_id for deduction in assessment.scoring_deductions}

    assert assessment.security_score == 0
    assert assessment.grade == "F"
    assert assessment.risk_level == RiskLevel.CRITICAL
    assert assessment.total_deduction == 100

    assert "TLS-001" in rule_ids
    assert "TLS-002" in rule_ids
    assert "TLS-004" in rule_ids
    assert "HDR-001" in rule_ids
    assert "HDR-003" in rule_ids
    assert "PORT-001" in rule_ids
    assert "INFO-001" in rule_ids

    assert assessment.severity_counts[Severity.CRITICAL.value] >= 2
    assert assessment.category_counts["Transport Security"] >= 3
    assert len(assessment.key_risk_drivers) <= 5
    assert len(assessment.priority_actions) <= 6


def test_risk_engine_detects_unreachable_website() -> None:
    scan_result = {
        "target_url": "https://offline.test",
        "availability": {
            "is_reachable": False,
            "error": "Connection timed out",
        },
    }

    assessment = assess_website_risk(scan_result)

    assert assessment.security_score == 65
    assert assessment.grade == "C+"
    assert assessment.risk_level == RiskLevel.HIGH
    assert assessment.scoring_deductions[0].rule_id == "AVAIL-001"
    assert assessment.scoring_deductions[0].severity == Severity.CRITICAL
    assert "Connection timed out" in assessment.scoring_deductions[0].evidence


def test_risk_engine_output_is_serializable_to_dict() -> None:
    scan_result = {
        "target_url": "https://headers-missing.test",
        "availability": {
            "is_reachable": True,
            "status_code": 200,
        },
        "ssl_tls": {
            "uses_https": True,
            "certificate_valid": True,
        },
        "security_headers": {
            "headers": {
                "X-Content-Type-Options": "nosniff",
            }
        },
    }

    assessment = assess_website_risk(scan_result)
    payload = assessment.to_dict()

    assert isinstance(payload, dict)
    assert payload["target"] == "https://headers-missing.test"
    assert isinstance(payload["security_score"], int)
    assert isinstance(payload["positive_security_signals"], list)
    assert isinstance(payload["scoring_deductions"], list)
    assert payload["risk_level"] in {
        "minimal",
        "low",
        "moderate",
        "high",
        "critical",
    }
    assert payload["scoring_version"] == "1.0.0"


def test_risk_engine_accepts_explicit_target_override() -> None:
    scan_result = {
        "availability": {
            "is_reachable": True,
            "status_code": 200,
        }
    }

    assessment = assess_website_risk(
        scan_result,
        target="https://manual-target.example",
    )

    assert assessment.target == "https://manual-target.example"