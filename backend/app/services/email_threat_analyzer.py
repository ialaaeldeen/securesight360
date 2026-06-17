from __future__ import annotations

import re
from email.utils import parseaddr
from pathlib import PurePath
from urllib.parse import urlparse

from app.schemas.email_threat import (
    EmailAttachmentAnalysis,
    EmailBehaviorFinding,
    EmailThreatAnalysisRequest,
    EmailThreatAnalysisResponse,
)

URL_RE = re.compile(r"https?://[^\s<>()\"']+|www\.[^\s<>()\"']+", re.IGNORECASE)

URL_SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "s.id",
    "lnkd.in",
}

DANGEROUS_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".jse",
    ".wsf",
    ".jar",
    ".iso",
    ".img",
    ".lnk",
    ".hta",
    ".com",
    ".pif",
}

SUSPICIOUS_ATTACHMENT_EXTENSIONS = {
    ".html",
    ".htm",
    ".shtml",
    ".svg",
    ".docm",
    ".xlsm",
    ".pptm",
    ".zip",
    ".rar",
    ".7z",
}

BRAND_TERMS = {
    "microsoft": {"microsoft.com", "office.com", "outlook.com", "live.com"},
    "paypal": {"paypal.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "amazon": {"amazon.com"},
    "apple": {"apple.com"},
    "google": {"google.com"},
    "meta": {"meta.com", "facebook.com", "instagram.com"},
    "bank": set(),
    "netflix": {"netflix.com"},
}

URGENCY_PATTERNS = [
    "urgent",
    "immediately",
    "immediate action",
    "act now",
    "within 24 hours",
    "final warning",
    "account will be suspended",
    "your account has been locked",
    "last chance",
    "verify now",
]

CREDENTIAL_PATTERNS = [
    "verify your account",
    "confirm your password",
    "reset your password",
    "login to continue",
    "sign in to continue",
    "update your credentials",
    "validate your mailbox",
    "password expires",
    "account verification",
    "credential",
]

PAYMENT_PATTERNS = [
    "invoice",
    "payment",
    "wire transfer",
    "bank details",
    "new account details",
    "beneficiary",
    "purchase order",
    "po attached",
    "overdue",
    "remittance",
    "swift",
]

BEC_PATTERNS = [
    "are you available",
    "kindly process",
    "gift cards",
    "confidential request",
    "do not call",
    "send me your mobile",
    "change of bank details",
    "updated bank account",
]

ATTACHMENT_LURE_PATTERNS = [
    "attached invoice",
    "see attached",
    "attached document",
    "open the attachment",
    "review attached",
    "payment copy attached",
]


def analyze_email_threat(payload: EmailThreatAnalysisRequest) -> EmailThreatAnalysisResponse:
    subject = payload.subject or ""
    sender = payload.sender or ""
    reply_to = payload.reply_to or ""
    body = payload.body or ""
    headers = payload.headers or ""

    combined = " ".join([subject, sender, reply_to, body, headers]).lower()
    links = _collect_links(payload.links, body)

    findings: list[EmailBehaviorFinding] = []
    attachment_results = [_analyze_attachment(att) for att in payload.attachments]

    sender_name, sender_email = parseaddr(sender)
    reply_name, reply_email = parseaddr(reply_to)
    sender_domain = _domain_from_email(sender_email)
    reply_domain = _domain_from_email(reply_email)

    if sender_name and _brand_terms_in_text(sender_name) and sender_domain:
        brand_hits = _brand_terms_in_text(sender_name)
        if not _domain_matches_any_brand(sender_domain, brand_hits):
            findings.append(
                EmailBehaviorFinding(
                    behavior="Display-name spoofing",
                    severity="high",
                    explanation="The display name references a known brand or trusted identity, but the sender domain does not clearly match that identity.",
                    evidence=f"display_name={sender_name}; sender_domain={sender_domain}",
                )
            )

    if reply_domain and sender_domain and reply_domain != sender_domain:
        findings.append(
            EmailBehaviorFinding(
                behavior="Reply-To mismatch",
                severity="high",
                explanation="The Reply-To domain differs from the sender domain. This is commonly used to redirect replies to an attacker-controlled mailbox.",
                evidence=f"sender_domain={sender_domain}; reply_to_domain={reply_domain}",
            )
        )

    if sender_domain:
        brand_hits = _brand_terms_in_text(sender_domain)
        if brand_hits and not _domain_matches_any_brand(sender_domain, brand_hits):
            findings.append(
                EmailBehaviorFinding(
                    behavior="Domain impersonation",
                    severity="high",
                    explanation="The sender domain appears to reference a recognizable brand or trusted service but does not match the expected official domain.",
                    evidence=f"sender_domain={sender_domain}",
                )
            )

        if _looks_like_lookalike_domain(sender_domain):
            findings.append(
                EmailBehaviorFinding(
                    behavior="Lookalike domain",
                    severity="medium",
                    explanation="The sender domain has characteristics often seen in lookalike or impersonation domains.",
                    evidence=sender_domain,
                )
            )

    suspicious_link_count = 0
    shortener_count = 0
    link_domains: list[str] = []

    for link in links:
        domain = _domain_from_url(link)
        if domain:
            link_domains.append(domain)

        if domain in URL_SHORTENER_DOMAINS:
            shortener_count += 1
            suspicious_link_count += 1

        if domain and _looks_like_lookalike_domain(domain):
            suspicious_link_count += 1

    if shortener_count:
        findings.append(
            EmailBehaviorFinding(
                behavior="URL shortener",
                severity="medium",
                explanation="The email contains shortened URLs, which can hide the final destination from the recipient.",
                evidence=f"{shortener_count} shortened link(s) detected",
            )
        )

    if suspicious_link_count:
        findings.append(
            EmailBehaviorFinding(
                behavior="Suspicious links",
                severity="high",
                explanation="The email contains links with suspicious characteristics such as shorteners or lookalike domains.",
                evidence=", ".join(sorted(set(link_domains)))[:500] or None,
            )
        )

    if _contains_any(combined, URGENCY_PATTERNS):
        findings.append(
            EmailBehaviorFinding(
                behavior="Urgency or pressure language",
                severity="medium",
                explanation="The email uses urgency or pressure language to push the recipient into taking quick action.",
                evidence=_first_matching_pattern(combined, URGENCY_PATTERNS),
            )
        )

    if _contains_any(combined, CREDENTIAL_PATTERNS):
        findings.append(
            EmailBehaviorFinding(
                behavior="Credential harvesting language",
                severity="high",
                explanation="The email asks the user to verify, update, reset, or confirm account credentials.",
                evidence=_first_matching_pattern(combined, CREDENTIAL_PATTERNS),
            )
        )

    if _contains_any(combined, PAYMENT_PATTERNS):
        findings.append(
            EmailBehaviorFinding(
                behavior="Fake invoice or payment request",
                severity="high",
                explanation="The email contains invoice, payment, wire transfer, or banking language commonly used in financial fraud attempts.",
                evidence=_first_matching_pattern(combined, PAYMENT_PATTERNS),
            )
        )

    if _contains_any(combined, BEC_PATTERNS):
        findings.append(
            EmailBehaviorFinding(
                behavior="Business Email Compromise pattern",
                severity="high",
                explanation="The message contains language often seen in business email compromise or executive impersonation attempts.",
                evidence=_first_matching_pattern(combined, BEC_PATTERNS),
            )
        )

    if _contains_any(combined, ATTACHMENT_LURE_PATTERNS):
        findings.append(
            EmailBehaviorFinding(
                behavior="Attachment lure",
                severity="medium",
                explanation="The message encourages the recipient to open or review an attachment.",
                evidence=_first_matching_pattern(combined, ATTACHMENT_LURE_PATTERNS),
            )
        )

    auth_findings = _analyze_header_authentication(headers)
    findings.extend(auth_findings)

    for attachment in attachment_results:
        for indicator in attachment.risk_indicators:
            severity = "high" if "dangerous" in indicator.lower() or "macro" in indicator.lower() else "medium"
            findings.append(
                EmailBehaviorFinding(
                    behavior="Attachment-based threat suspicion",
                    severity=severity,
                    explanation=indicator,
                    evidence=attachment.file_name,
                )
            )

    unique_findings = _deduplicate_findings(findings)
    unique_findings = _filter_contextual_false_positive_findings(unique_findings, combined)
    verdict = _choose_verdict(unique_findings, attachment_results, links)
    confidence = _choose_confidence(unique_findings)
    evidence_strength = _choose_evidence_strength(
        findings=unique_findings,
        attachments=attachment_results,
        links=links,
        headers=headers,
    )

    technical_evidence = {
        "sender_domain": sender_domain,
        "reply_to_domain": reply_domain,
        "link_count": len(links),
        "link_domains": sorted(set(link_domains)),
        "attachment_count": len(payload.attachments),
        "headers_provided": bool(headers.strip()),
        "numeric_score_used": False,
        "assessment_method": "behavioral_rules_and_static_indicators",
        "links_opened": False,
        "attachments_executed": False,
    }

    return EmailThreatAnalysisResponse(
        verdict=verdict,
        confidence=confidence,
        evidence_strength=evidence_strength,
        summary=_build_summary(verdict, unique_findings),
        verdict_reasoning=_build_verdict_reasoning(verdict, unique_findings, attachment_results),
        confidence_rationale=_build_confidence_rationale(confidence, evidence_strength, unique_findings, headers, links),
        key_indicators=_build_key_indicators(unique_findings),
        detected_behaviors=unique_findings,
        structured_analysis=_build_structured_analysis(
            verdict=verdict,
            findings=unique_findings,
            attachments=attachment_results,
            sender_domain=sender_domain,
            reply_domain=reply_domain,
            links=links,
            headers=headers,
        ),
        attachment_analysis=attachment_results,
        recommended_actions=_recommended_actions(
            verdict=verdict,
            findings=unique_findings,
            attachments=attachment_results,
            links=links,
            headers=headers,
        ),
        limitations=_build_limitations(payload),
        privacy_and_safety_notes=[
            "Email content is analyzed only when submitted by the user.",
            "SecureSight360 does not automatically read inboxes.",
            "Suspicious links are not opened automatically.",
            "Attachments are not executed.",
            "Full email body should not be stored by default.",
        ],
        technical_evidence=technical_evidence,
        evaluation_metadata=_build_evaluation_metadata(
            verdict=verdict,
            confidence=confidence,
            evidence_strength=evidence_strength,
            findings=unique_findings,
            payload=payload,
        ),
    )


def _collect_links(user_links: list[str], body: str) -> list[str]:
    found = list(user_links or [])
    found.extend(URL_RE.findall(body or ""))

    cleaned: list[str] = []
    for link in found:
        value = link.strip().rstrip(".,);]")
        if value and value not in cleaned:
            cleaned.append(value)

    return cleaned[:100]


def _domain_from_email(email: str) -> str:
    if not email or "@" not in email:
        return ""

    return email.rsplit("@", 1)[-1].strip().lower().strip("<>.,;:")


def _domain_from_url(url: str) -> str:
    raw = (url or "").strip()

    if not raw:
        return ""

    if raw.startswith("www."):
        raw = f"https://{raw}"

    parsed = urlparse(raw)
    host = parsed.netloc.lower()

    if "@" in host:
        host = host.rsplit("@", 1)[-1]

    if ":" in host:
        host = host.split(":", 1)[0]

    return host.strip(".")


def _brand_terms_in_text(text: str) -> set[str]:
    lowered = (text or "").lower()
    return {brand for brand in BRAND_TERMS if brand in lowered}


def _domain_matches_any_brand(domain: str, brands: set[str]) -> bool:
    domain = (domain or "").lower().strip(".")

    for brand in brands:
        official_domains = BRAND_TERMS.get(brand, set())

        if not official_domains:
            continue

        if domain in official_domains or any(domain.endswith(f".{official}") for official in official_domains):
            return True

    return False


def _looks_like_lookalike_domain(domain: str) -> bool:
    domain = (domain or "").lower()

    if not domain:
        return False

    suspicious_tokens = ["secure-", "login-", "verify-", "account-", "support-", "-secure", "-login", "-verify"]

    if any(token in domain for token in suspicious_tokens):
        return True

    if domain.count("-") >= 2:
        return True

    if domain.count(".") >= 3:
        return True

    # Very light homoglyph-style indicator. Full confusable detection can be added later.
    if any(ch in domain for ch in ["0", "1"]) and any(brand in domain for brand in BRAND_TERMS):
        return True

    return False


def _contains_any(text: str, patterns: list[str]) -> bool:
    return any(pattern in text for pattern in patterns)


def _first_matching_pattern(text: str, patterns: list[str]) -> str | None:
    for pattern in patterns:
        if pattern in text:
            return pattern

    return None


def _analyze_header_authentication(headers: str) -> list[EmailBehaviorFinding]:
    value = (headers or "").lower()

    if not value.strip():
        return []

    findings: list[EmailBehaviorFinding] = []

    if "authentication-results" in value:
        if "spf=fail" in value or "spf=softfail" in value:
            findings.append(
                EmailBehaviorFinding(
                    behavior="Header authentication issue",
                    severity="high",
                    explanation="Email headers indicate SPF failed or soft-failed.",
                    evidence="SPF fail/softfail detected",
                )
            )

        if "dkim=fail" in value:
            findings.append(
                EmailBehaviorFinding(
                    behavior="Header authentication issue",
                    severity="high",
                    explanation="Email headers indicate DKIM failed.",
                    evidence="DKIM fail detected",
                )
            )

        if "dmarc=fail" in value:
            findings.append(
                EmailBehaviorFinding(
                    behavior="Header authentication issue",
                    severity="high",
                    explanation="Email headers indicate DMARC failed.",
                    evidence="DMARC fail detected",
                )
            )

    return findings


def _analyze_attachment(attachment) -> EmailAttachmentAnalysis:
    name = (attachment.file_name or "").strip()
    extension = PurePath(name).suffix.lower()
    indicators: list[str] = []
    safe_handling = [
        "Do not execute the attachment.",
        "Do not enable macros.",
        "Verify the sender through a trusted channel before opening.",
    ]

    content = " ".join(
        [
            name,
            attachment.content_type or "",
            attachment.text_preview or "",
        ]
    ).lower()

    if extension in DANGEROUS_EXTENSIONS:
        indicators.append(f"Dangerous executable or script-like file extension detected: {extension}")

    if extension in {".docm", ".xlsm", ".pptm"}:
        indicators.append("Macro-enabled Office attachment detected. Macro-enabled files are frequently abused in phishing campaigns.")

    if extension in {".html", ".htm", ".shtml"}:
        indicators.append("HTML attachment detected. HTML attachments are commonly used for credential phishing pages.")

    if extension in {".zip", ".rar", ".7z"}:
        indicators.append("Archive attachment detected. Attackers often hide malicious files inside compressed archives.")

    if _contains_any(content, CREDENTIAL_PATTERNS):
        indicators.append("Attachment text preview contains credential-harvesting language.")

    if _contains_any(content, PAYMENT_PATTERNS):
        indicators.append("Attachment text preview contains invoice, payment, or banking language.")

    if URL_RE.search(content):
        indicators.append("Attachment text preview contains links or URLs.")

    if attachment.size_bytes is not None and attachment.size_bytes > 15_000_000:
        indicators.append("Large attachment detected. Large files should be reviewed carefully before opening.")

    return EmailAttachmentAnalysis(
        file_name=name or "unnamed attachment",
        content_type=attachment.content_type,
        size_bytes=attachment.size_bytes,
        sha256=attachment.sha256,
        risk_indicators=indicators,
        safe_handling=safe_handling,
    )



def _filter_contextual_false_positive_findings(
    findings: list[EmailBehaviorFinding],
    combined_text: str,
) -> list[EmailBehaviorFinding]:
    """Reduce false positives from harmless business language.

    Example:
    "There is no urgent action required today" should not be treated as
    phishing pressure language.
    """
    if not findings:
        return findings

    text = (combined_text or "").lower()

    benign_urgency_phrases = [
        "no urgent action required",
        "no immediate action required",
        "not urgent",
        "not an urgent",
        "there is no urgent action required",
        "no action required today",
        "no urgent request",
        "nothing urgent",
        "not required today",
    ]

    threat_context_terms = [
        "password",
        "verify",
        "login",
        "account",
        "suspended",
        "blocked",
        "locked",
        "mfa",
        "otp",
        "code",
        "credential",
        "bank",
        "payment",
        "invoice",
        "wire",
        "transfer",
        "gift card",
        "click",
        "link",
        "download",
        "open attachment",
        "enable macros",
        "confirm your identity",
        "update your information",
        "security alert",
    ]

    has_benign_urgency_negation = any(
        phrase in text for phrase in benign_urgency_phrases
    )
    has_threat_context = any(term in text for term in threat_context_terms)

    filtered: list[EmailBehaviorFinding] = []

    for finding in findings:
        if finding.behavior == "Urgency or pressure language":
            if has_benign_urgency_negation:
                continue

            if not has_threat_context:
                continue

        filtered.append(finding)

    return filtered


def _choose_verdict(findings: list[EmailBehaviorFinding], attachments: list[EmailAttachmentAnalysis], links: list[str]) -> str:
    behaviors = {finding.behavior for finding in findings}
    high_count = sum(1 for finding in findings if finding.severity in {"high", "critical"})
    attachment_indicator_count = sum(len(item.risk_indicators) for item in attachments)

    # Choose the most specific primary intent first. Attachment suspicion remains
    # visible in attachment_analysis and detected_behaviors, but it should not
    # override a stronger credential theft, BEC, payment fraud, or impersonation pattern.
    if "Credential harvesting language" in behaviors:
        return "Credential Theft Attempt"

    if "Business Email Compromise pattern" in behaviors:
        return "Business Email Compromise Attempt"

    if "Fake invoice or payment request" in behaviors:
        return "Payment or Invoice Fraud Attempt"

    if {"Display-name spoofing", "Reply-To mismatch", "Domain impersonation"} & behaviors:
        return "Impersonation Attempt"

    if "Suspicious links" in behaviors or ("URL shortener" in behaviors and links):
        return "Link-Based Phishing Attempt"

    if attachment_indicator_count:
        return "Attachment-Based Threat Suspicion"

    if high_count >= 3:
        return "Malicious"

    if findings:
        return "Suspicious"

    return "Safe / No obvious threat detected"


def _choose_confidence(findings: list[EmailBehaviorFinding]) -> str:
    high_count = sum(1 for finding in findings if finding.severity in {"high", "critical"})
    total = len(findings)

    if high_count >= 2 or total >= 4:
        return "High"

    if high_count == 1 or total >= 2:
        return "Medium"

    return "Low"


def _build_summary(verdict: str, findings: list[EmailBehaviorFinding]) -> str:
    if verdict == "Safe / No obvious threat detected":
        return "No obvious phishing or malicious behavior was detected from the submitted email content. This does not guarantee the message is safe."

    behavior_names = sorted({finding.behavior for finding in findings})

    return (
        f"The submitted email shows indicators consistent with {verdict}. "
        f"Detected behavior categories include: {', '.join(behavior_names)}."
    )



def _choose_evidence_strength(
    findings: list[EmailBehaviorFinding],
    attachments: list[EmailAttachmentAnalysis],
    links: list[str],
    headers: str,
) -> str:
    high_count = sum(1 for finding in findings if finding.severity in {"high", "critical"})
    medium_count = sum(1 for finding in findings if finding.severity == "medium")
    attachment_indicator_count = sum(len(item.risk_indicators) for item in attachments)
    has_headers = bool((headers or "").strip())

    if high_count >= 2 and (links or has_headers or attachment_indicator_count):
        return "Strong"

    if high_count >= 1 or medium_count >= 2 or attachment_indicator_count:
        return "Moderate"

    return "Limited"


def _build_verdict_reasoning(
    verdict: str,
    findings: list[EmailBehaviorFinding],
    attachments: list[EmailAttachmentAnalysis],
) -> str:
    if verdict == "Safe / No obvious threat detected":
        return (
            "No strong phishing, impersonation, credential theft, payment fraud, "
            "or attachment-based threat indicators were identified in the submitted content."
        )

    grouped = _group_findings_by_severity(findings)
    high_items = grouped.get("high", []) + grouped.get("critical", [])
    medium_items = grouped.get("medium", [])
    attachment_indicator_count = sum(len(item.risk_indicators) for item in attachments)

    reasons: list[str] = []

    if high_items:
        reasons.append(
            "High-severity indicators were detected: "
            + ", ".join(sorted({item.behavior for item in high_items}))
            + "."
        )

    if medium_items:
        reasons.append(
            "Supporting medium-severity indicators were also present: "
            + ", ".join(sorted({item.behavior for item in medium_items}))
            + "."
        )

    if attachment_indicator_count:
        reasons.append(
            f"Attachment review found {attachment_indicator_count} static indicator(s), "
            "including file-type or content patterns commonly associated with phishing."
        )

    return " ".join(reasons)


def _build_confidence_rationale(
    confidence: str,
    evidence_strength: str,
    findings: list[EmailBehaviorFinding],
    headers: str,
    links: list[str],
) -> str:
    high_count = sum(1 for finding in findings if finding.severity in {"high", "critical"})
    total = len(findings)
    evidence_sources = []

    if findings:
        evidence_sources.append("message content and behavioral indicators")

    if links:
        evidence_sources.append("submitted or extracted links")

    if (headers or "").strip():
        evidence_sources.append("provided email headers")

    source_text = ", ".join(evidence_sources) if evidence_sources else "limited submitted content"

    return (
        f"Confidence is {confidence} because the analyzer found {total} indicator(s), "
        f"including {high_count} high-severity indicator(s), with {evidence_strength.lower()} evidence strength "
        f"from {source_text}. This is a static behavioral assessment, not a guarantee."
    )


def _build_key_indicators(findings: list[EmailBehaviorFinding]) -> list[str]:
    priority_order = {
        "Credential harvesting language": 1,
        "Business Email Compromise pattern": 2,
        "Fake invoice or payment request": 3,
        "Display-name spoofing": 4,
        "Domain impersonation": 5,
        "Reply-To mismatch": 6,
        "Header authentication issue": 7,
        "Suspicious links": 8,
        "Attachment-based threat suspicion": 9,
        "URL shortener": 10,
        "Urgency or pressure language": 11,
    }

    ordered = sorted(
        findings,
        key=lambda item: (
            priority_order.get(item.behavior, 99),
            item.behavior,
            item.evidence or "",
        ),
    )

    indicators: list[str] = []
    for finding in ordered:
        label = finding.behavior
        if finding.evidence:
            label = f"{label}: {finding.evidence}"

        if label not in indicators:
            indicators.append(label)

    return indicators[:8]


def _build_structured_analysis(
    verdict: str,
    findings: list[EmailBehaviorFinding],
    attachments: list[EmailAttachmentAnalysis],
    sender_domain: str,
    reply_domain: str,
    links: list[str],
    headers: str,
) -> dict:
    behaviors = {finding.behavior for finding in findings}

    return {
        "primary_verdict": verdict,
        "identity_and_sender_analysis": {
            "sender_domain": sender_domain or None,
            "reply_to_domain": reply_domain or None,
            "display_name_spoofing_detected": "Display-name spoofing" in behaviors,
            "reply_to_mismatch_detected": "Reply-To mismatch" in behaviors,
            "domain_impersonation_detected": "Domain impersonation" in behaviors,
            "lookalike_domain_detected": "Lookalike domain" in behaviors,
        },
        "link_analysis": {
            "links_detected": len(links),
            "suspicious_links_detected": "Suspicious links" in behaviors,
            "url_shortener_detected": "URL shortener" in behaviors,
            "links_opened": False,
        },
        "language_and_intent_analysis": {
            "urgency_or_pressure_detected": "Urgency or pressure language" in behaviors,
            "credential_harvesting_detected": "Credential harvesting language" in behaviors,
            "payment_or_invoice_theme_detected": "Fake invoice or payment request" in behaviors,
            "bec_pattern_detected": "Business Email Compromise pattern" in behaviors,
        },
        "header_authentication_analysis": {
            "headers_provided": bool((headers or "").strip()),
            "authentication_issue_detected": "Header authentication issue" in behaviors,
        },
        "attachment_safety_analysis": {
            "attachments_detected": len(attachments),
            "attachment_indicators_detected": sum(len(item.risk_indicators) for item in attachments),
            "attachments_executed": False,
        },
    }


def _build_limitations(payload: EmailThreatAnalysisRequest) -> list[str]:
    limitations = [
        "This is a static behavioral analysis and does not prove that the email is safe or malicious.",
        "Suspicious links are not opened, so final landing-page behavior is not verified in this MVP.",
        "Attachments are not executed, so runtime malware behavior is not assessed.",
    ]

    if not (payload.headers or "").strip():
        limitations.append("Email headers were not provided, so SPF, DKIM, DMARC, and routing evidence may be incomplete.")

    if not payload.attachments:
        limitations.append("No attachment metadata or safely extracted attachment preview was provided.")

    return limitations


def _build_evaluation_metadata(
    verdict: str,
    confidence: str,
    evidence_strength: str,
    findings: list[EmailBehaviorFinding],
    payload: EmailThreatAnalysisRequest,
) -> dict:
    severity_counts = {
        "critical": sum(1 for item in findings if item.severity == "critical"),
        "high": sum(1 for item in findings if item.severity == "high"),
        "medium": sum(1 for item in findings if item.severity == "medium"),
        "low": sum(1 for item in findings if item.severity == "low"),
        "info": sum(1 for item in findings if item.severity == "info"),
    }

    return {
        "verdict_model": "professional_behavioral_verdicts",
        "primary_verdict": verdict,
        "confidence": confidence,
        "evidence_strength": evidence_strength,
        "severity_counts": severity_counts,
        "signals_detected": len(findings),
        "headers_submitted": bool((payload.headers or "").strip()),
        "attachments_submitted": len(payload.attachments),
        "numeric_risk_score_used": False,
        "accuracy_note": (
            "The evaluation uses deterministic behavioral indicators and static evidence. "
            "Accuracy improves when full headers, sender details, links, and attachment metadata are provided."
        ),
    }


def _group_findings_by_severity(findings: list[EmailBehaviorFinding]) -> dict[str, list[EmailBehaviorFinding]]:
    grouped: dict[str, list[EmailBehaviorFinding]] = {}

    for finding in findings:
        grouped.setdefault(finding.severity, []).append(finding)

    return grouped

def _recommended_actions(
    *,
    verdict: str,
    findings: list[EmailBehaviorFinding],
    attachments: list[EmailAttachmentAnalysis],
    links: list[str],
    headers: str,
) -> list[str]:
    """Build actions that match what the submitted email actually contains."""
    behaviors = {finding.behavior for finding in findings}
    has_links = bool(links)
    has_attachments = bool(attachments)
    has_attachment_indicators = any(item.risk_indicators for item in attachments)
    has_headers = bool((headers or "").strip())

    actions: list[str] = []

    def add(action: str) -> None:
        if action not in actions:
            actions.append(action)

    if verdict == "Safe / No obvious threat detected":
        add("No obvious phishing or malicious behavior was detected from the submitted content.")
        add("Continue normal handling if the email was expected and the sender is known.")

        if has_links:
            add("Open links only if they are expected and match the sender or official organization.")

        if has_attachments:
            add("Open attachments only if they were expected and came from a trusted sender.")

        if not has_headers:
            add("For stronger verification, provide full email headers when available.")

        add("Do not share passwords, MFA codes, or payment details unless the request is independently confirmed.")
        return actions[:5]

    if "Credential harvesting language" in behaviors or "credential" in verdict.lower():
        add("Do not enter your password, MFA code, or account recovery information from this email.")
        add("Go to the official website or app manually instead of using email links.")
        add("If you already entered credentials, change the password immediately and review account activity.")

    if (
        "Suspicious links" in behaviors
        or "URL shortener" in behaviors
        or "Link-Based Phishing Attempt" in verdict
        or has_links
    ):
        add("Do not click the link until the sender and destination are verified.")
        add("Check the destination domain carefully for misspellings, extra words, or lookalike branding.")
        add("Use the official website directly instead of following links inside the email.")

    if "Business Email Compromise pattern" in behaviors or "Business Email Compromise" in verdict:
        add("Do not act on the request until it is verified through a trusted internal channel.")
        add("Confirm the request with the person or department using a known phone number or verified contact method.")
        add("Escalate the message to your manager, finance team, or IT/security team before taking action.")

    if "Fake invoice or payment request" in behaviors or "payment" in verdict.lower() or "invoice" in verdict.lower():
        add("Do not make payments or change bank details based only on this email.")
        add("Verify invoice numbers, payment instructions, and bank details through an approved company process.")
        add("Contact the vendor or requester using a trusted phone number or official portal.")

    if (
        "Display-name spoofing" in behaviors
        or "Reply-To mismatch" in behaviors
        or "Domain impersonation" in behaviors
        or "Impersonation" in verdict
    ):
        add("Do not reply directly until the sender identity is confirmed.")
        add("Compare the sender address, reply-to address, and organization domain carefully.")
        add("Contact the claimed sender using a known address or trusted communication channel.")

    if "Header authentication issue" in behaviors:
        add("Treat the message with caution because sender authentication evidence is weak or failed.")
        add("Ask an email administrator to review SPF, DKIM, DMARC, and routing headers.")

    if "Urgency or pressure language" in behaviors:
        add("Pause before acting. The message uses urgency or pressure to push quick action.")
        add("Verify the request independently before clicking, replying, paying, or downloading anything.")

    if has_attachment_indicators:
        add("Do not open, execute, or enable macros in the attachment.")
        add("Ask the sender to confirm the attachment through a trusted channel before opening it.")
        add("If this is a work email, submit the attachment to IT/security for safe review.")

    if has_attachments and not has_attachment_indicators:
        add("Only open attachments if they were expected and came from a trusted sender.")

    if not has_headers:
        add("Provide full email headers when possible to improve authentication and routing analysis.")

    add("If this is a work email, report it to your IT or security team.")

    return actions[:7]


def _deduplicate_findings(findings: list[EmailBehaviorFinding]) -> list[EmailBehaviorFinding]:
    seen: set[tuple[str, str | None]] = set()
    unique: list[EmailBehaviorFinding] = []

    for finding in findings:
        key = (finding.behavior, finding.evidence)
        if key in seen:
            continue

        seen.add(key)
        unique.append(finding)

    return unique


# === SecureSight360 Phase 16.2E/16.2F Email Calibration Patch ===
#
# Purpose:
# - Reduce false positives caused by harmless negated urgency phrases.
# - Keep the rule-based analyzer as the primary explainable engine.
# - Keep ML as a supporting signal only.
# - Generate context-aware recommended actions based on actual evidence.

import inspect as _ss360_inspect
import re as _ss360_re
from dataclasses import is_dataclass as _ss360_is_dataclass, asdict as _ss360_asdict


_SS360_NEGATED_URGENCY_PATTERNS = [
    r"\bno\s+urgent\s+action\s+(?:is\s+)?required(?:\s+today)?\b",
    r"\bno\s+immediate\s+action\s+(?:is\s+)?required(?:\s+today)?\b",
    r"\bnot\s+urgent\b",
    r"\bnothing\s+urgent\b",
    r"\bno\s+action\s+(?:is\s+)?required(?:\s+today)?\b",
    r"\bthere\s+is\s+no\s+urgent\s+action\s+required(?:\s+today)?\b",
    r"\bthere\s+is\s+no\s+immediate\s+action\s+required(?:\s+today)?\b",
]

_SS360_AUTH_PASS_VALUES = {"pass", "passed", "valid", "ok", "true", "authenticated"}


def _ss360_text(value):
    if value is None:
        return ""

    if isinstance(value, str):
        return value

    if isinstance(value, dict):
        chunks = []
        for key, item in value.items():
            chunks.append(str(key))
            chunks.append(_ss360_text(item))
        return " ".join(chunks)

    if isinstance(value, (list, tuple, set)):
        return " ".join(_ss360_text(v) for v in value)

    if _ss360_is_dataclass(value):
        try:
            return _ss360_text(_ss360_asdict(value))
        except Exception:
            return str(value)

    if hasattr(value, "model_dump"):
        try:
            return _ss360_text(value.model_dump())
        except Exception:
            return str(value)

    if hasattr(value, "__dict__"):
        try:
            return _ss360_text(vars(value))
        except Exception:
            return str(value)

    return str(value)


def _ss360_lower_text(*values):
    return " ".join(_ss360_text(v) for v in values).lower()


def _ss360_has_negated_urgency(text):
    lowered = _ss360_text(text).lower()
    return any(_ss360_re.search(pattern, lowered, flags=_ss360_re.IGNORECASE) for pattern in _SS360_NEGATED_URGENCY_PATTERNS)


def _ss360_has_link(text):
    lowered = _ss360_text(text).lower()
    return bool(_ss360_re.search(r"https?://|www\.|href\s*=|bit\.ly|tinyurl|t\.co|rebrand\.ly", lowered))


def _ss360_has_attachment_signal(text):
    lowered = _ss360_text(text).lower()
    return bool(
        _ss360_re.search(
            r"\battachment\b|\battached\b|\.docm\b|\.xlsm\b|\.exe\b|\.scr\b|\.js\b|\.vbs\b|\.bat\b|\.cmd\b|\.iso\b|\.zip\b|\.rar\b|\.html\b",
            lowered,
        )
    )


def _ss360_has_credential_signal(text):
    lowered = _ss360_text(text).lower()
    return bool(
        _ss360_re.search(
            r"\bpassword\b|\bmfa\b|\b2fa\b|\bone[- ]?time code\b|\botp\b|\blogin\b|\bsign in\b|\bverify your account\b|\baccount recovery\b|\bcredentials?\b",
            lowered,
        )
    )


def _ss360_has_payment_signal(text):
    lowered = _ss360_text(text).lower()
    return bool(
        _ss360_re.search(
            r"\binvoice\b|\bpayment\b|\bbank\b|\bwire\b|\biban\b|\bswift\b|\bvendor\b|\bsupplier\b|\bfinance\b|\bpurchase order\b|\bpo number\b|\baccount number\b",
            lowered,
        )
    )


def _ss360_has_impersonation_signal(text):
    lowered = _ss360_text(text).lower()
    return bool(
        _ss360_re.search(
            r"\bimpersonation\b|\breply-to\b|\breply to\b|\bmismatch\b|\bdisplay name\b|\bspoof\b|\bceo\b|\bcfo\b|\bmanager\b|\bdirector\b",
            lowered,
        )
    )


def _ss360_has_header_auth_issue(text):
    lowered = _ss360_text(text).lower()
    return bool(
        _ss360_re.search(
            r"\bspf\s*[:=]\s*(fail|softfail|neutral|none|missing)\b|\bdkim\s*[:=]\s*(fail|neutral|none|missing)\b|\bdmarc\s*[:=]\s*(fail|none|missing)\b|authentication.*fail|header.*authentication",
            lowered,
        )
    )


def _ss360_authentication_passed(text):
    lowered = _ss360_text(text).lower()

    spf_pass = bool(_ss360_re.search(r"\bspf\s*[:=]\s*pass\b|\bspf.*passed\b", lowered))
    dkim_pass = bool(_ss360_re.search(r"\bdkim\s*[:=]\s*pass\b|\bdkim.*passed\b", lowered))
    dmarc_pass = bool(_ss360_re.search(r"\bdmarc\s*[:=]\s*pass\b|\bdmarc.*passed\b", lowered))

    return spf_pass and dkim_pass and dmarc_pass


def _ss360_get_field(result, key, default=None):
    if isinstance(result, dict):
        return result.get(key, default)

    if hasattr(result, key):
        return getattr(result, key)

    return default



class _SS360DictPayload:
    def __init__(self, data):
        self._data = data if isinstance(data, dict) else {}

        for key, value in self._data.items():
            try:
                setattr(self, key, value)
            except Exception:
                pass

        self.subject = self._data.get("subject") or self._data.get("email_subject") or ""
        self.sender = self._data.get("sender") or self._data.get("from_email") or self._data.get("from") or ""
        self.body = (
            self._data.get("body")
            or self._data.get("email_body")
            or self._data.get("content")
            or self._data.get("message")
            or self._data.get("raw_email")
            or ""
        )
        self.headers = (
            self._data.get("headers")
            or self._data.get("email_headers")
            or self._data.get("authentication_results")
            or {}
        )
        self.reply_to = self._data.get("reply_to") or self._data.get("reply_to_email") or ""
        self.attachments = self._data.get("attachments") or []
        self.links = self._data.get("links") or self._data.get("urls") or []

    def __getattr__(self, name):
        if name in {"headers", "email_headers", "authentication_results"}:
            return {}
        if name in {"attachments", "links", "urls"}:
            return []
        return ""


def _ss360_update_result(result, updates):
    clean_updates = {k: v for k, v in updates.items() if v is not None}

    if isinstance(result, dict):
        result.update(clean_updates)
        return result

    if hasattr(result, "model_copy"):
        try:
            allowed = {}
            fields = getattr(result, "model_fields", None) or getattr(result, "__fields__", None) or {}
            for key, value in clean_updates.items():
                if key in fields or hasattr(result, key):
                    allowed[key] = value
            if allowed:
                return result.model_copy(update=allowed)
        except Exception:
            pass

    for key, value in clean_updates.items():
        if hasattr(result, key):
            try:
                setattr(result, key, value)
            except Exception:
                pass

    return result


def _ss360_indicator_to_text(indicator):
    return _ss360_text(indicator).lower()


def _ss360_is_urgency_only_indicator(indicator):
    text = _ss360_indicator_to_text(indicator)

    has_urgency = any(word in text for word in ["urgent", "immediate", "pressure", "action required", "today"])
    has_high_risk = any(
        word in text
        for word in [
            "password",
            "credential",
            "login",
            "mfa",
            "2fa",
            "invoice",
            "payment",
            "bank",
            "wire",
            "attachment",
            "macro",
            "link",
            "url",
            "domain",
            "reply-to",
            "impersonation",
            "spf",
            "dkim",
            "dmarc",
        ]
    )

    return has_urgency and not has_high_risk



_SS360_CONTENT_FIELD_NAMES = {
    "subject",
    "email_subject",
    "title",
    "sender",
    "from_email",
    "from_address",
    "sender_email",
    "body",
    "email_body",
    "content",
    "message",
    "message_body",
    "email_text",
    "raw_email",
    "reply_to",
    "reply_to_email",
}

_SS360_HEADER_FIELD_NAMES = {
    "headers",
    "email_headers",
    "authentication_results",
    "auth_results",
}

_SS360_LINK_FIELD_NAMES = {
    "links",
    "urls",
}

_SS360_ATTACHMENT_FIELD_NAMES = {
    "attachments",
    "files",
}

_SS360_RESULT_SIGNAL_FIELDS = {
    "verdict",
    "mapped_verdict",
    "threat_type",
    "category",
    "key_indicators",
    "indicators",
    "findings",
    "risk_factors",
}


def _ss360_header_text(value):
    if value is None:
        return ""

    if isinstance(value, str):
        return value

    if isinstance(value, dict):
        chunks = []
        for key, item in value.items():
            chunks.append(f"{key}={item}")
        return " ".join(chunks)

    if isinstance(value, (list, tuple, set)):
        return " ".join(_ss360_header_text(item) for item in value)

    return _ss360_text(value)


def _ss360_attachment_text(value):
    if value is None:
        return ""

    if isinstance(value, str):
        return value

    if isinstance(value, (list, tuple, set)):
        return " ".join(_ss360_attachment_text(item) for item in value)

    if isinstance(value, dict):
        chunks = []
        for field in [
            "file_name",
            "filename",
            "name",
            "content_type",
            "mime_type",
            "text_preview",
            "extracted_text",
            "preview",
            "content_preview",
        ]:
            if field in value and value.get(field):
                chunks.append(str(value.get(field)))
        return " ".join(chunks)

    chunks = []
    for field in [
        "file_name",
        "filename",
        "name",
        "content_type",
        "mime_type",
        "text_preview",
        "extracted_text",
        "preview",
        "content_preview",
    ]:
        try:
            item = getattr(value, field)
        except Exception:
            item = None

        if item:
            chunks.append(str(item))

    return " ".join(chunks)


def _ss360_link_text(value):
    if value is None:
        return ""

    if isinstance(value, str):
        return value

    if isinstance(value, (list, tuple, set)):
        return " ".join(_ss360_link_text(item) for item in value)

    if isinstance(value, dict):
        chunks = []
        for field in ["url", "href", "domain", "text", "display_text"]:
            if field in value and value.get(field):
                chunks.append(str(value.get(field)))
        return " ".join(chunks)

    chunks = []
    for field in ["url", "href", "domain", "text", "display_text"]:
        try:
            item = getattr(value, field)
        except Exception:
            item = None

        if item:
            chunks.append(str(item))

    return " ".join(chunks)


def _ss360_read_field(container, field):
    if container is None:
        return None

    if isinstance(container, dict):
        return container.get(field)

    try:
        return getattr(container, field)
    except Exception:
        return None


def _ss360_semantic_input_text(value, depth=0):
    if value is None or depth > 5:
        return ""

    if isinstance(value, str):
        return value

    if isinstance(value, (int, float, bool)):
        return str(value)

    if isinstance(value, (list, tuple, set)):
        return " ".join(_ss360_semantic_input_text(item, depth + 1) for item in value)

    if isinstance(value, dict):
        chunks = []

        for field in _SS360_CONTENT_FIELD_NAMES:
            if field in value:
                chunks.append(_ss360_semantic_input_text(value.get(field), depth + 1))

        for field in _SS360_HEADER_FIELD_NAMES:
            if field in value:
                chunks.append(_ss360_header_text(value.get(field)))

        for field in _SS360_LINK_FIELD_NAMES:
            if field in value:
                chunks.append(_ss360_link_text(value.get(field)))

        for field in _SS360_ATTACHMENT_FIELD_NAMES:
            if field in value:
                chunks.append(_ss360_attachment_text(value.get(field)))

        return " ".join(chunk for chunk in chunks if chunk)

    if _ss360_is_dataclass(value):
        try:
            return _ss360_semantic_input_text(_ss360_asdict(value), depth + 1)
        except Exception:
            return ""

    if hasattr(value, "model_dump"):
        try:
            return _ss360_semantic_input_text(value.model_dump(), depth + 1)
        except Exception:
            return ""

    chunks = []

    for field in _SS360_CONTENT_FIELD_NAMES:
        item = _ss360_read_field(value, field)
        if item:
            chunks.append(_ss360_semantic_input_text(item, depth + 1))

    for field in _SS360_HEADER_FIELD_NAMES:
        item = _ss360_read_field(value, field)
        if item:
            chunks.append(_ss360_header_text(item))

    for field in _SS360_LINK_FIELD_NAMES:
        item = _ss360_read_field(value, field)
        if item:
            chunks.append(_ss360_link_text(item))

    for field in _SS360_ATTACHMENT_FIELD_NAMES:
        item = _ss360_read_field(value, field)
        if item:
            chunks.append(_ss360_attachment_text(item))

    return " ".join(chunk for chunk in chunks if chunk)


def _ss360_result_signal_text(result):
    if result is None:
        return ""

    chunks = []

    if isinstance(result, dict):
        for field in _SS360_RESULT_SIGNAL_FIELDS:
            if field in result and result.get(field):
                chunks.append(_ss360_text(result.get(field)))
        return " ".join(chunks)

    if _ss360_is_dataclass(result):
        try:
            return _ss360_result_signal_text(_ss360_asdict(result))
        except Exception:
            return ""

    if hasattr(result, "model_dump"):
        try:
            return _ss360_result_signal_text(result.model_dump())
        except Exception:
            return ""

    for field in _SS360_RESULT_SIGNAL_FIELDS:
        item = _ss360_read_field(result, field)
        if item:
            chunks.append(_ss360_text(item))

    return " ".join(chunks)


def _ss360_context_aware_recommended_actions(*args, **kwargs):
    # Important:
    # This function intentionally avoids scanning previous recommended_actions,
    # model metadata, empty structural keys, or UI fields. It only uses semantic
    # evidence from the email payload and analyzer indicators.
    combined = _ss360_semantic_input_text(args).lower()

    actions = []

    credential_signal = _ss360_has_credential_signal(combined)
    # Link warnings should only appear when the message actually contains a URL/link
    # or the analyzer explicitly found a suspicious link.
    # A lookalike sender/domain is an identity-verification issue, not always a click-risk issue.
    link_signal = _ss360_has_link(combined) or "suspicious link" in combined
    lookalike_domain_signal = "lookalike domain" in combined

    payment_signal = _ss360_has_payment_signal(combined) or "business email compromise" in combined
    attachment_signal = _ss360_has_attachment_signal(combined) or "attachment-based threat" in combined
    header_signal = _ss360_has_header_auth_issue(combined) or "header authentication issue" in combined
    impersonation_signal = _ss360_has_impersonation_signal(combined) or lookalike_domain_signal

    is_safe_context = not any(
        [
            credential_signal,
            link_signal,
            payment_signal,
            attachment_signal,
            header_signal,
            impersonation_signal,
        ]
    )

    if is_safe_context:
        return [
            "Treat this email as normal business communication if it is expected and the sender is known.",
            "Continue with standard workplace handling and keep normal awareness for unusual future changes.",
        ]

    if credential_signal:
        actions.extend(
            [
                "Do not enter passwords, MFA codes, recovery codes, or account credentials from this email.",
                "Open the official website or app manually instead of using email-provided login paths.",
                "If credentials were already shared, change the password and start account recovery immediately.",
            ]
        )

    if link_signal:
        actions.extend(
            [
                "Do not click email links until the destination domain is verified.",
                "Check the visible link and actual destination domain carefully before taking action.",
                "Use the official website manually through the browser instead of relying on embedded links.",
            ]
        )

    if payment_signal:
        actions.extend(
            [
                "Verify invoice numbers, purchase orders, bank details, and vendor identity through approved finance records.",
                "Confirm payment or bank-detail changes through a trusted channel outside this email thread.",
                "Follow internal finance approval workflow before sending money or updating supplier details.",
            ]
        )

    if attachment_signal:
        actions.extend(
            [
                "Do not open unexpected attachments until they are verified.",
                "Do not enable macros, scripts, or active content in attached documents.",
                "Submit the message and attachment to IT or security for review if it was unexpected.",
            ]
        )

    if header_signal:
        actions.extend(
            [
                "Review SPF, DKIM, DMARC, and routing results before trusting the message.",
                "Ask IT or the mail administrator to validate the sender authentication path if the message is business-critical.",
            ]
        )

    if impersonation_signal:
        actions.extend(
            [
                "Verify the sender identity through a trusted channel such as known phone number, Teams, or official directory.",
                "Be cautious of reply-to mismatch, display-name spoofing, or unusual executive/vendor requests.",
            ]
        )

    if not actions:
        actions = [
            "Verify the sender and request through a trusted channel before taking action.",
            "Report the email to IT or security if the request is unexpected or unusual.",
        ]

    deduped = []
    seen = set()

    for action in actions:
        normalized = action.strip().lower()
        if normalized and normalized not in seen:
            seen.add(normalized)
            deduped.append(action.strip())

    return deduped


def _ss360_apply_email_context_calibration(result, *args, **kwargs):
    input_text = _ss360_semantic_input_text(args).lower()
    result_signal_text = _ss360_result_signal_text(result).lower()
    combined = " ".join([input_text, result_signal_text]).strip().lower()

    indicators = _ss360_get_field(result, "key_indicators", None)
    if indicators is None:
        indicators = _ss360_get_field(result, "indicators", None)
    if indicators is None:
        indicators = []

    if not isinstance(indicators, list):
        indicators = list(indicators) if isinstance(indicators, (tuple, set)) else [indicators]

    cleaned_indicators = indicators

    benign_negated_urgency = _ss360_has_negated_urgency(input_text)

    if benign_negated_urgency:
        cleaned_indicators = [
            indicator
            for indicator in indicators
            if not _ss360_is_urgency_only_indicator(indicator)
        ]

    material_context = " ".join([input_text, _ss360_text(cleaned_indicators)]).lower()

    has_material_threat_signal = (
        _ss360_has_link(material_context)
        or _ss360_has_attachment_signal(material_context)
        or _ss360_has_credential_signal(material_context)
        or _ss360_has_payment_signal(material_context)
        or _ss360_has_impersonation_signal(material_context)
        or _ss360_has_header_auth_issue(material_context)
        or "header authentication issue" in material_context
        or "lookalike domain" in material_context
        or "suspicious link" in material_context
        or "business email compromise" in material_context
        or "attachment-based threat" in material_context
    )

    safe_negated_urgency_only_case = (
        benign_negated_urgency
        and not cleaned_indicators
        and not has_material_threat_signal
        and _ss360_authentication_passed(input_text)
    )

    recommendation_context = " ".join([input_text, _ss360_text(cleaned_indicators), _ss360_result_signal_text(result)]).lower()
    recommended_actions = _ss360_context_aware_recommended_actions(recommendation_context)

    updates = {
        "recommended_actions": recommended_actions,
        "key_indicators": cleaned_indicators,
    }

    if safe_negated_urgency_only_case:
        updates.update(
            {
                "verdict": "Safe / No obvious threat detected",
                "confidence": "Low",
                "evidence": "Limited",
                "evidence_level": "Limited",
                "summary": "No obvious threat was detected. A harmless negated urgency phrase was identified and was not treated as pressure.",
                "explanation": "The email appears consistent with normal business communication. Authentication passed and no links, attachments, credential requests, payment requests, or impersonation indicators were found.",
                "key_indicators": [],
                "recommended_actions": [
                    "Treat this email as normal business communication if it is expected and the sender is known.",
                    "Continue with standard workplace handling and keep normal awareness for unusual future changes.",
                ],
            }
        )

    return _ss360_update_result(result, updates)


def _ss360_wrap_analysis_callable(original):
    if getattr(original, "_ss360_phase_16_2ef_wrapped", False):
        return original

    def wrapped(*args, **kwargs):
        try:
            result = original(*args, **kwargs)
        except AttributeError as exc:
            can_coerce_payload = (
                len(args) == 1
                and isinstance(args[0], dict)
                and "has no attribute" in str(exc)
            )

            if not can_coerce_payload:
                raise

            payload = _SS360DictPayload(args[0])
            result = original(payload, **kwargs)

        return _ss360_apply_email_context_calibration(result, *args, **kwargs)

    wrapped.__name__ = getattr(original, "__name__", "wrapped_email_analysis")
    wrapped.__doc__ = getattr(original, "__doc__", None)
    wrapped._ss360_phase_16_2ef_wrapped = True
    wrapped._ss360_phase_16_2ef_original = original
    return wrapped


def _ss360_install_phase_16_2ef_patches():
    module_globals = globals()

    for function_name in [
        "analyze_email",
        "analyze_email_threat",
        "analyze_threat",
        "analyze_message",
        "run_email_analysis",
    ]:
        original = module_globals.get(function_name)
        if callable(original):
            module_globals[function_name] = _ss360_wrap_analysis_callable(original)

    if callable(module_globals.get("_recommended_actions")):
        module_globals["_recommended_actions"] = _ss360_context_aware_recommended_actions

    for _, obj in list(module_globals.items()):
        if not _ss360_inspect.isclass(obj):
            continue

        class_name = getattr(obj, "__name__", "").lower()
        if "email" not in class_name or "analy" not in class_name:
            continue

        for method_name in [
            "analyze",
            "analyze_email",
            "analyze_threat",
            "analyze_message",
            "run",
        ]:
            method = getattr(obj, method_name, None)
            if callable(method):
                try:
                    setattr(obj, method_name, _ss360_wrap_analysis_callable(method))
                except Exception:
                    pass

        method = getattr(obj, "_recommended_actions", None)
        if callable(method):
            try:
                setattr(obj, "_recommended_actions", _ss360_context_aware_recommended_actions)
            except Exception:
                pass


_ss360_install_phase_16_2ef_patches()
# === End SecureSight360 Phase 16.2E/16.2F Email Calibration Patch ===

