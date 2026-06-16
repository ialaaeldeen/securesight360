from app.scoring.risk_engine import assess_website_risk


def _assessment_titles(payload):
    assessment = assess_website_risk(payload)
    data = assessment.to_dict()
    return {item["title"] for item in data.get("scoring_deductions", [])}


def _base_payload(dmarc_records):
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
                    "value": "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
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
                "DMARC": dmarc_records,
            },
            "spf_found": True,
            "dmarc_found": bool(dmarc_records),
        },
        "dns_records": {
            "A": ["203.0.113.10"],
            "MX": ["10 mail.example.com."],
            "TXT": ["v=spf1 include:_spf.example.com ~all"],
            "DMARC": dmarc_records,
        },
        "spf_found": True,
        "dmarc_found": bool(dmarc_records),
    }


def test_dmarc_reject_record_is_not_reported_as_missing():
    payload = _base_payload(["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"])

    titles = _assessment_titles(payload)

    assert "DMARC record not detected" not in titles
    assert "DMARC policy is monitoring-only" not in titles


def test_dmarc_quarantine_record_is_not_reported_as_missing():
    payload = _base_payload(["v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"])

    titles = _assessment_titles(payload)

    assert "DMARC record not detected" not in titles
    assert "DMARC policy is monitoring-only" not in titles


def test_dmarc_p_none_is_monitoring_only_not_missing():
    payload = _base_payload(["v=DMARC1; p=none; rua=mailto:dmarc@example.com"])

    titles = _assessment_titles(payload)

    assert "DMARC record not detected" not in titles
    assert "DMARC policy is monitoring-only" in titles


def test_missing_dmarc_is_reported_as_missing():
    payload = _base_payload([])

    titles = _assessment_titles(payload)

    assert "DMARC record not detected" in titles