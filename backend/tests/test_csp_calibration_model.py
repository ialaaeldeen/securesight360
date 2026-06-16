from app.scoring.risk_engine import assess_website_risk


def _base_payload(csp_value):
    return {
        "target": "https://example.com",
        "availability": {
            "is_available": True,
            "status_code": 200,
            "response_time_ms": 100,
        },
        "ssl": {
            "https_enabled": True,
            "certificate_valid": True,
            "issuer": "Test CA",
            "subject": "example.com",
        },
        "security_headers": {
            "checked_headers": {
                "Content-Security-Policy": {
                    "status": "present",
                    "value": csp_value,
                },
                "Strict-Transport-Security": {
                    "status": "present",
                    "value": "max-age=31536000; includeSubDomains",
                },
                "X-Frame-Options": {
                    "status": "present",
                    "value": "DENY",
                },
                "X-Content-Type-Options": {
                    "status": "present",
                    "value": "nosniff",
                },
                "Referrer-Policy": {
                    "status": "present",
                    "value": "strict-origin-when-cross-origin",
                },
                "Permissions-Policy": {
                    "status": "present",
                    "value": "camera=(), microphone=(), geolocation=()",
                },
            }
        },
        "dns": {
            "records": {
                "A": ["203.0.113.10"],
                "MX": ["10 mail.example.com."],
                "TXT": ["v=spf1 include:_spf.example.com ~all"],
                "DMARC": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
                "CAA": ["0 issue \"letsencrypt.org\""],
            },
            "spf_found": True,
            "dmarc_found": True,
        },
        "dns_records": {
            "A": ["203.0.113.10"],
            "MX": ["10 mail.example.com."],
            "TXT": ["v=spf1 include:_spf.example.com ~all"],
            "DMARC": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
            "CAA": ["0 issue \"letsencrypt.org\""],
        },
        "spf_found": True,
        "dmarc_found": True,
    }


def _csp_finding(payload):
    assessment = assess_website_risk(payload).to_dict()

    for item in assessment.get("scoring_deductions", []):
        if item.get("title") == "Content-Security-Policy appears weak":
            return item

    return None


def test_restrictive_csp_with_object_src_none_has_no_weak_csp_finding():
    payload = _base_payload(
        "default-src 'none'; script-src 'self'; object-src 'none'; frame-ancestors 'none'"
    )

    finding = _csp_finding(payload)

    assert finding is None


def test_script_src_unsafe_inline_is_medium_csp_finding():
    payload = _base_payload(
        "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'"
    )

    finding = _csp_finding(payload)

    assert finding is not None
    assert finding["severity"] == "medium"
    assert "script-src allows unsafe-inline" in finding["evidence"]


def test_style_src_unsafe_inline_only_is_low_csp_hardening_finding():
    payload = _base_payload(
        "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
    )

    finding = _csp_finding(payload)

    assert finding is not None
    assert finding["severity"] == "low"
    assert "style-src allows unsafe-inline" in finding["evidence"]


def test_csp_with_only_frame_ancestors_is_medium_because_default_src_is_not_restrictive():
    payload = _base_payload(
        "frame-ancestors 'self'"
    )

    finding = _csp_finding(payload)

    assert finding is not None
    assert finding["severity"] == "medium"
    assert "default-src is not restrictive" in finding["evidence"]


def test_script_wildcard_is_medium_csp_finding():
    payload = _base_payload(
        "default-src 'self'; script-src *; object-src 'none'; frame-ancestors 'none'"
    )

    finding = _csp_finding(payload)

    assert finding is not None
    assert finding["severity"] == "medium"
    assert "broad wildcard" in finding["evidence"]