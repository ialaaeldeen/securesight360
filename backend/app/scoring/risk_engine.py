from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from urllib.parse import urlparse


SCORING_VERSION = "1.0.0"
DEFAULT_BASE_SCORE = 100
MAX_SCORE = 100
MIN_SCORE = 0


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskLevel(str, Enum):
    MINIMAL = "minimal"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class ScoringDeduction:
    rule_id: str
    title: str
    category: str
    severity: Severity
    deduction: int
    evidence: str
    business_impact: str
    recommendation: str
    detection_method: str
    confidence: str
    mappings: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass(frozen=True, slots=True)
class PositiveSignal:
    title: str
    category: str
    evidence: str
    mappings: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    target: str | None
    security_score: int
    risk_level: RiskLevel
    grade: str
    executive_summary: str
    detection_summary: str
    key_risk_drivers: list[str]
    priority_actions: list[str]
    positive_security_signals: list[PositiveSignal]
    severity_counts: dict[str, int]
    category_counts: dict[str, int]
    scoring_deductions: list[ScoringDeduction]
    total_deduction: int
    assessment_coverage: dict[str, bool]
    scoring_version: str = SCORING_VERSION
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "security_score": self.security_score,
            "risk_level": self.risk_level.value,
            "grade": self.grade,
            "executive_summary": self.executive_summary,
            "detection_summary": self.detection_summary,
            "key_risk_drivers": self.key_risk_drivers,
            "priority_actions": self.priority_actions,
            "positive_security_signals": [
                signal.to_dict() for signal in self.positive_security_signals
            ],
            "severity_counts": self.severity_counts,
            "category_counts": self.category_counts,
            "scoring_deductions": [
                deduction.to_dict() for deduction in self.scoring_deductions
            ],
            "total_deduction": self.total_deduction,
            "assessment_coverage": self.assessment_coverage,
            "scoring_version": self.scoring_version,
            "generated_at": self.generated_at,
        }


@dataclass(frozen=True, slots=True)
class HeaderState:
    canonical_name: str
    present: bool | None
    value: str | None = None
    status: str | None = None
    evidence: str | None = None

    @property
    def is_present(self) -> bool:
        return self.present is True

    @property
    def is_missing(self) -> bool:
        return self.present is False

    @property
    def is_weak(self) -> bool:
        status = _clean_text(self.status).lower()
        value = _clean_text(self.value).lower()
        weak_status_terms = {
            "weak",
            "warning",
            "misconfigured",
            "insecure",
            "partial",
            "invalid",
        }
        return status in weak_status_terms or "weak" in status or "unsafe" in value


@dataclass(frozen=True, slots=True)
class RecordState:
    name: str
    present: bool | None
    value: str | None = None
    status: str | None = None
    evidence: str | None = None

    @property
    def is_present(self) -> bool:
        return self.present is True

    @property
    def is_missing(self) -> bool:
        return self.present is False


@dataclass(frozen=True, slots=True)
class PortFinding:
    port: int
    service: str
    severity: Severity


KNOWN_SECURITY_HEADERS: dict[str, tuple[str, ...]] = {
    "content-security-policy": (
        "content-security-policy",
        "csp",
    ),
    "strict-transport-security": (
        "strict-transport-security",
        "hsts",
    ),
    "x-frame-options": (
        "x-frame-options",
        "xfo",
    ),
    "x-content-type-options": (
        "x-content-type-options",
        "xcto",
    ),
    "referrer-policy": (
        "referrer-policy",
    ),
    "permissions-policy": (
        "permissions-policy",
        "feature-policy",
    ),
    "server": (
        "server",
    ),
    "set-cookie": (
        "set-cookie",
        "cookie",
        "cookies",
    ),
}

HEADER_ALIAS_TO_CANONICAL = {
    alias: canonical
    for canonical, aliases in KNOWN_SECURITY_HEADERS.items()
    for alias in aliases
}

MISSING_STATUS_TERMS = {
    "missing",
    "absent",
    "not-present",
    "not present",
    "not_present",
    "fail",
    "failed",
    "false",
    "none",
}

PRESENT_STATUS_TERMS = {
    "present",
    "enabled",
    "secure",
    "pass",
    "passed",
    "ok",
    "valid",
    "true",
    "configured",
}

RISKY_PORTS: dict[int, tuple[str, Severity]] = {
    21: ("FTP", Severity.HIGH),
    22: ("SSH", Severity.MEDIUM),
    23: ("Telnet", Severity.CRITICAL),
    25: ("SMTP", Severity.MEDIUM),
    110: ("POP3", Severity.MEDIUM),
    143: ("IMAP", Severity.MEDIUM),
    445: ("SMB", Severity.CRITICAL),
    1433: ("Microsoft SQL Server", Severity.HIGH),
    1521: ("Oracle Database", Severity.HIGH),
    2049: ("NFS", Severity.HIGH),
    2375: ("Docker API", Severity.CRITICAL),
    3306: ("MySQL", Severity.HIGH),
    3389: ("RDP", Severity.CRITICAL),
    5432: ("PostgreSQL", Severity.HIGH),
    5900: ("VNC", Severity.HIGH),
    6379: ("Redis", Severity.CRITICAL),
    9200: ("Elasticsearch", Severity.CRITICAL),
    11211: ("Memcached", Severity.HIGH),
    27017: ("MongoDB", Severity.CRITICAL),
}

EXPECTED_WEB_PORTS = {80, 443}

SEVERITY_SORT_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

DEFAULT_MAPPINGS: dict[str, dict[str, list[str]]] = {
    "security_misconfiguration": {
        "OWASP Top 10": ["A05:2021 Security Misconfiguration"],
        "NIST CSF 2.0": ["Protect (PR)", "Identify (ID)"],
    },
    "cryptographic_failures": {
        "OWASP Top 10": ["A02:2021 Cryptographic Failures"],
        "NIST CSF 2.0": ["Protect (PR)"],
    },
    "monitoring_detection": {
        "OWASP Top 10": ["A09:2021 Security Logging and Monitoring Failures"],
        "NIST CSF 2.0": ["Detect (DE)", "Respond (RS)"],
    },
    "identification_auth": {
        "OWASP Top 10": ["A07:2021 Identification and Authentication Failures"],
        "NIST CSF 2.0": ["Protect (PR)"],
    },
}


class RiskEngine:
    """Explainable rule-based risk engine for CyberShield360 website assessments."""

    def __init__(self, base_score: int = DEFAULT_BASE_SCORE) -> None:
        if not MIN_SCORE <= base_score <= MAX_SCORE:
            raise ValueError("base_score must be between 0 and 100")
        self.base_score = base_score

    def assess(self, scan_result: Any, target: str | None = None) -> RiskAssessment:
        data = _to_plain_data(scan_result)
        target = target or _extract_target(data)

        deductions: list[ScoringDeduction] = []
        positive_signals: list[PositiveSignal] = []

        self._evaluate_availability(data, deductions, positive_signals)
        self._evaluate_transport_security(data, target, deductions, positive_signals)
        self._evaluate_security_headers(data, deductions, positive_signals)
        self._evaluate_cookie_security(data, deductions, positive_signals)
        self._evaluate_dns_email_security(data, deductions, positive_signals)
        self._evaluate_exposed_ports(data, deductions, positive_signals)
        self._evaluate_information_disclosure(data, deductions, positive_signals)

        deductions = _deduplicate_deductions(deductions)
        deductions.sort(
            key=lambda item: (
                SEVERITY_SORT_ORDER[item.severity],
                -item.deduction,
                item.rule_id,
            )
        )

        raw_total_deduction = sum(item.deduction for item in deductions)
        capped_total_deduction = min(raw_total_deduction, self.base_score)
        security_score = max(MIN_SCORE, self.base_score - capped_total_deduction)
        risk_level = _risk_level_for_score(security_score)
        grade = _grade_for_score(security_score)

        severity_counts = _severity_counts(deductions)
        category_counts = dict(Counter(item.category for item in deductions))
        coverage = _assessment_coverage(data, target)

        return RiskAssessment(
            target=target,
            security_score=security_score,
            risk_level=risk_level,
            grade=grade,
            executive_summary=_build_executive_summary(
                target=target,
                score=security_score,
                grade=grade,
                risk_level=risk_level,
                deductions=deductions,
            ),
            detection_summary=_build_detection_summary(coverage, deductions),
            key_risk_drivers=_build_key_risk_drivers(deductions),
            priority_actions=_build_priority_actions(deductions),
            positive_security_signals=positive_signals,
            severity_counts=severity_counts,
            category_counts=category_counts,
            scoring_deductions=deductions,
            total_deduction=capped_total_deduction,
            assessment_coverage=coverage,
        )

    def _evaluate_availability(
        self,
        data: Any,
        deductions: list[ScoringDeduction],
        positive_signals: list[PositiveSignal],
    ) -> None:
        reachable = _extract_reachable(data)
        status_code = _extract_status_code(data)
        error = _find_first_text(data, ("error", "error_message", "exception"))

        if reachable is False:
            deductions.append(
                _deduction(
                    rule_id="AVAIL-001",
                    title="Website was not reachable during assessment",
                    category="Availability",
                    severity=Severity.CRITICAL,
                    deduction=35,
                    evidence=_evidence_join(
                        [
                            "Scanner reported the target as unreachable",
                            f"status_code={status_code}" if status_code else None,
                            f"error={error}" if error else None,
                        ]
                    ),
                    business_impact=(
                        "Users, customers, and automated integrations may be unable "
                        "to access the service. Security posture cannot be fully "
                        "verified while the target is unavailable."
                    ),
                    recommendation=(
                        "Confirm DNS resolution, hosting availability, firewall rules, "
                        "and upstream provider status. Re-run the scan after the site "
                        "is reachable."
                    ),
                    detection_method="HTTP availability probe and scanner reachability result.",
                    mappings=DEFAULT_MAPPINGS["monitoring_detection"],
                )
            )
            return

        if status_code and status_code >= 500:
            deductions.append(
                _deduction(
                    rule_id="AVAIL-002",
                    title="Server returned an error status code",
                    category="Availability",
                    severity=Severity.HIGH,
                    deduction=12,
                    evidence=f"HTTP status code {status_code} was observed.",
                    business_impact=(
                        "Server-side errors can reduce service reliability and may "
                        "expose operational weaknesses during traffic spikes or attacks."
                    ),
                    recommendation=(
                        "Review application logs, reverse proxy configuration, and "
                        "backend health checks. Fix the root cause before public release."
                    ),
                    detection_method="HTTP response status inspection.",
                    mappings=DEFAULT_MAPPINGS["monitoring_detection"],
                )
            )
            return

        if reachable is True or (status_code is not None and 200 <= status_code < 500):
            positive_signals.append(
                PositiveSignal(
                    title="Website is reachable",
                    category="Availability",
                    evidence=(
                        f"HTTP status code {status_code} observed."
                        if status_code
                        else "Scanner confirmed the target is reachable."
                    ),
                    mappings={"NIST CSF 2.0": ["Detect (DE)"]},
                )
            )

    def _evaluate_transport_security(
        self,
        data: Any,
        target: str | None,
        deductions: list[ScoringDeduction],
        positive_signals: list[PositiveSignal],
    ) -> None:
        https_used = _extract_https_used(data, target)
        cert_valid = _extract_certificate_valid(data)
        cert_expired = _extract_certificate_expired(data)
        days_to_expiry = _extract_certificate_days_to_expiry(data)
        tls_protocols = _extract_tls_protocols(data)

        if https_used is False:
            deductions.append(
                _deduction(
                    rule_id="TLS-001",
                    title="HTTPS is not enforced or target uses plain HTTP",
                    category="Transport Security",
                    severity=Severity.HIGH,
                    deduction=20,
                    evidence=(
                        f"Target URL uses scheme '{urlparse(target).scheme}'."
                        if target
                        else "Scanner did not confirm HTTPS usage."
                    ),
                    business_impact=(
                        "Credentials, session tokens, and user data may be exposed to "
                        "network interception or manipulation."
                    ),
                    recommendation=(
                        "Enable HTTPS site-wide, redirect HTTP to HTTPS, and deploy a "
                        "valid certificate from a trusted certificate authority."
                    ),
                    detection_method="URL scheme and HTTPS/TLS scanner evidence.",
                    mappings=DEFAULT_MAPPINGS["cryptographic_failures"],
                )
            )
        elif https_used is True:
            positive_signals.append(
                PositiveSignal(
                    title="HTTPS is used",
                    category="Transport Security",
                    evidence=(
                        "The target was assessed over HTTPS or scanner evidence confirms "
                        "HTTPS usage."
                    ),
                    mappings=DEFAULT_MAPPINGS["cryptographic_failures"],
                )
            )

        if cert_expired is True or cert_valid is False:
            deductions.append(
                _deduction(
                    rule_id="TLS-002",
                    title="TLS certificate is invalid or expired",
                    category="Transport Security",
                    severity=Severity.CRITICAL,
                    deduction=30,
                    evidence=_evidence_join(
                        [
                            (
                                f"certificate_valid={cert_valid}"
                                if cert_valid is not None
                                else None
                            ),
                            (
                                f"certificate_expired={cert_expired}"
                                if cert_expired is not None
                                else None
                            ),
                            (
                                f"days_to_expiry={days_to_expiry}"
                                if days_to_expiry is not None
                                else None
                            ),
                        ]
                    ),
                    business_impact=(
                        "Browsers may block access or show warnings, and users may lose "
                        "trust in the service. Invalid TLS can also create exposure to "
                        "man-in-the-middle attacks."
                    ),
                    recommendation=(
                        "Replace the certificate with a valid trusted certificate, check "
                        "the full certificate chain, and automate renewal monitoring."
                    ),
                    detection_method="TLS certificate validation result.",
                    mappings=DEFAULT_MAPPINGS["cryptographic_failures"],
                )
            )
        elif cert_valid is True:
            positive_signals.append(
                PositiveSignal(
                    title="TLS certificate is valid",
                    category="Transport Security",
                    evidence="Scanner evidence confirms a valid TLS certificate.",
                    mappings=DEFAULT_MAPPINGS["cryptographic_failures"],
                )
            )

        if days_to_expiry is not None and 0 <= days_to_expiry <= 14:
            deductions.append(
                _deduction(
                    rule_id="TLS-003",
                    title="TLS certificate expires soon",
                    category="Transport Security",
                    severity=Severity.MEDIUM,
                    deduction=8,
                    evidence=f"Certificate expires in {days_to_expiry} day(s).",
                    business_impact=(
                        "Certificate expiry can cause browser warnings and service "
                        "interruption if renewal is missed."
                    ),
                    recommendation=(
                        "Renew the certificate and configure automated renewal alerts "
                        "before the expiry window."
                    ),
                    detection_method="TLS certificate expiry inspection.",
                    mappings=DEFAULT_MAPPINGS["cryptographic_failures"],
                )
            )

        weak_protocols = sorted(
            protocol
            for protocol in tls_protocols
            if protocol.lower().replace(" ", "")
            in {"sslv2", "sslv3", "tlsv1", "tlsv1.0", "tlsv1.1"}
        )
        if weak_protocols:
            deductions.append(
                _deduction(
                    rule_id="TLS-004",
                    title="Weak TLS protocol support detected",
                    category="Transport Security",
                    severity=Severity.HIGH,
                    deduction=15,
                    evidence=f"Weak protocol(s): {', '.join(weak_protocols)}.",
                    business_impact=(
                        "Legacy TLS/SSL protocols increase exposure to downgrade and "
                        "cryptographic attacks."
                    ),
                    recommendation=(
                        "Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1. Prefer TLS 1.2+ "
                        "and modern cipher suites."
                    ),
                    detection_method="TLS protocol capability inspection.",
                    mappings=DEFAULT_MAPPINGS["cryptographic_failures"],
                )
            )

    def _evaluate_security_headers(
        self,
        data: Any,
        deductions: list[ScoringDeduction],
        positive_signals: list[PositiveSignal],
    ) -> None:
        if _extract_reachable(data) is False:
            return

        if not _has_header_evidence_section(data):
            return

        csp = _header_state(data, "content-security-policy")
        hsts = _header_state(data, "strict-transport-security")
        xfo = _header_state(data, "x-frame-options")
        xcto = _header_state(data, "x-content-type-options")
        referrer_policy = _header_state(data, "referrer-policy")
        permissions_policy = _header_state(data, "permissions-policy")

        if csp.is_missing:
            deductions.append(
                _missing_header_deduction(
                    rule_id="HDR-001",
                    header="Content-Security-Policy",
                    severity=Severity.HIGH,
                    deduction=12,
                    impact=(
                        "Without CSP, the site has less browser-level protection "
                        "against script injection and content injection risks."
                    ),
                    recommendation=(
                        "Deploy a restrictive Content-Security-Policy starting with "
                        "default-src 'self', object-src 'none', base-uri 'self', and "
                        "frame-ancestors as appropriate."
                    ),
                    evidence=csp.evidence,
                )
            )
        elif csp.is_present:
            positive_signals.append(
                PositiveSignal(
                    title="Content-Security-Policy is configured",
                    category="HTTP Security Headers",
                    evidence=_header_evidence(csp),
                    mappings=DEFAULT_MAPPINGS["security_misconfiguration"],
                )
            )

            csp_value = _clean_text(csp.value).lower()
            weak_csp_reasons: list[str] = []

            if "unsafe-inline" in csp_value:
                weak_csp_reasons.append("contains unsafe-inline")
            if "default-src *" in csp_value or "script-src *" in csp_value:
                weak_csp_reasons.append("uses wildcard source")
            if "object-src" not in csp_value:
                weak_csp_reasons.append("object-src directive not observed")

            if weak_csp_reasons or csp.is_weak:
                deductions.append(
                    _deduction(
                        rule_id="HDR-002",
                        title="Content-Security-Policy appears weak",
                        category="HTTP Security Headers",
                        severity=Severity.MEDIUM,
                        deduction=8,
                        evidence=(
                            "; ".join(weak_csp_reasons)
                            if weak_csp_reasons
                            else _header_evidence(csp)
                        ),
                        business_impact=(
                            "A weak CSP may provide limited protection against injected "
                            "scripts, malicious framing, or unsafe third-party content."
                        ),
                        recommendation=(
                            "Tighten CSP directives, remove unsafe-inline where possible, "
                            "avoid broad wildcards, and explicitly set object-src and "
                            "frame-ancestors."
                        ),
                        detection_method="HTTP security header value inspection.",
                        mappings=DEFAULT_MAPPINGS["security_misconfiguration"],
                    )
                )

        if hsts.is_missing:
            deductions.append(
                _missing_header_deduction(
                    rule_id="HDR-003",
                    header="Strict-Transport-Security",
                    severity=Severity.HIGH,
                    deduction=12,
                    impact=(
                        "Without HSTS, users may be exposed to protocol downgrade or "
                        "SSL-stripping scenarios when first accessing the site."
                    ),
                    recommendation=(
                        "Enable Strict-Transport-Security with an appropriate max-age. "
                        "Use includeSubDomains and preload only after testing all subdomains."
                    ),
                    evidence=hsts.evidence,
                )
            )
        elif hsts.is_present:
            positive_signals.append(
                PositiveSignal(
                    title="HTTP Strict Transport Security is configured",
                    category="HTTP Security Headers",
                    evidence=_header_evidence(hsts),
                    mappings=DEFAULT_MAPPINGS["cryptographic_failures"],
                )
            )

            hsts_max_age = _extract_hsts_max_age(hsts.value)
            if hsts_max_age is not None and hsts_max_age < 15552000:
                deductions.append(
                    _deduction(
                        rule_id="HDR-004",
                        title=(
                            "HSTS max-age is shorter than recommended for mature "
                            "deployments"
                        ),
                        category="HTTP Security Headers",
                        severity=Severity.LOW,
                        deduction=3,
                        evidence=_header_evidence(hsts),
                        business_impact=(
                            "A short HSTS duration reduces the time browsers remember to "
                            "force HTTPS for the site."
                        ),
                        recommendation=(
                            "Increase max-age after confirming HTTPS is stable across the "
                            "domain and subdomains."
                        ),
                        detection_method="Strict-Transport-Security directive inspection.",
                        mappings=DEFAULT_MAPPINGS["cryptographic_failures"],
                    )
                )

        if xfo.is_missing and not _csp_has_frame_ancestors(csp.value):
            deductions.append(
                _missing_header_deduction(
                    rule_id="HDR-005",
                    header="X-Frame-Options or CSP frame-ancestors",
                    severity=Severity.MEDIUM,
                    deduction=8,
                    impact=(
                        "The site may be more exposed to clickjacking if pages can be "
                        "embedded by untrusted origins."
                    ),
                    recommendation=(
                        "Set X-Frame-Options to DENY/SAMEORIGIN or define CSP "
                        "frame-ancestors with the allowed framing origins."
                    ),
                    evidence=xfo.evidence,
                )
            )
        elif xfo.is_present or _csp_has_frame_ancestors(csp.value):
            positive_signals.append(
                PositiveSignal(
                    title="Anti-clickjacking control is configured",
                    category="HTTP Security Headers",
                    evidence=(
                        _header_evidence(xfo)
                        if xfo.is_present
                        else "CSP frame-ancestors directive observed."
                    ),
                    mappings=DEFAULT_MAPPINGS["security_misconfiguration"],
                )
            )

        if xcto.is_missing:
            deductions.append(
                _missing_header_deduction(
                    rule_id="HDR-006",
                    header="X-Content-Type-Options",
                    severity=Severity.MEDIUM,
                    deduction=6,
                    impact=(
                        "Browsers may MIME-sniff responses, increasing exposure to "
                        "content-type confusion attacks."
                    ),
                    recommendation=(
                        "Set X-Content-Type-Options: nosniff on applicable responses."
                    ),
                    evidence=xcto.evidence,
                )
            )
        elif xcto.is_present:
            positive_signals.append(
                PositiveSignal(
                    title="X-Content-Type-Options is configured",
                    category="HTTP Security Headers",
                    evidence=_header_evidence(xcto),
                    mappings=DEFAULT_MAPPINGS["security_misconfiguration"],
                )
            )

        if referrer_policy.is_missing:
            deductions.append(
                _missing_header_deduction(
                    rule_id="HDR-007",
                    header="Referrer-Policy",
                    severity=Severity.LOW,
                    deduction=3,
                    impact=(
                        "Sensitive URL paths or query parameters may leak to external "
                        "sites through the Referer header."
                    ),
                    recommendation=(
                        "Set Referrer-Policy to strict-origin-when-cross-origin, "
                        "same-origin, or a stricter policy based on business needs."
                    ),
                    evidence=referrer_policy.evidence,
                )
            )
        elif referrer_policy.is_present:
            positive_signals.append(
                PositiveSignal(
                    title="Referrer-Policy is configured",
                    category="HTTP Security Headers",
                    evidence=_header_evidence(referrer_policy),
                    mappings=DEFAULT_MAPPINGS["security_misconfiguration"],
                )
            )

        if permissions_policy.is_missing:
            deductions.append(
                _missing_header_deduction(
                    rule_id="HDR-008",
                    header="Permissions-Policy",
                    severity=Severity.LOW,
                    deduction=3,
                    impact=(
                        "Browser features such as camera, microphone, or geolocation may "
                        "not be explicitly restricted."
                    ),
                    recommendation=(
                        "Define Permissions-Policy to disable browser capabilities not "
                        "required by the application."
                    ),
                    evidence=permissions_policy.evidence,
                )
            )
        elif permissions_policy.is_present:
            positive_signals.append(
                PositiveSignal(
                    title="Permissions-Policy is configured",
                    category="HTTP Security Headers",
                    evidence=_header_evidence(permissions_policy),
                    mappings=DEFAULT_MAPPINGS["security_misconfiguration"],
                )
            )

    def _evaluate_cookie_security(
        self,
        data: Any,
        deductions: list[ScoringDeduction],
        positive_signals: list[PositiveSignal],
    ) -> None:
        if _extract_reachable(data) is False:
            return

        if not _has_header_evidence_section(data):
            return

        cookies = _extract_set_cookie_values(data)
        if not cookies:
            return

        missing_secure: list[str] = []
        missing_httponly: list[str] = []
        missing_samesite: list[str] = []

        for cookie in cookies:
            cookie_lower = cookie.lower()
            cookie_name = cookie.split("=", 1)[0].strip() or "unnamed-cookie"

            if "secure" not in cookie_lower:
                missing_secure.append(cookie_name)
            if "httponly" not in cookie_lower:
                missing_httponly.append(cookie_name)
            if "samesite" not in cookie_lower:
                missing_samesite.append(cookie_name)

        if missing_secure:
            deductions.append(
                _deduction(
                    rule_id="COOKIE-001",
                    title="Cookies missing Secure attribute",
                    category="Session Security",
                    severity=Severity.HIGH,
                    deduction=10,
                    evidence=f"Cookie(s): {', '.join(sorted(set(missing_secure)))}.",
                    business_impact=(
                        "Session cookies without Secure may be transmitted over plain "
                        "HTTP if a downgrade or mixed access path exists."
                    ),
                    recommendation="Add the Secure attribute to session and sensitive cookies.",
                    detection_method="Set-Cookie header attribute inspection.",
                    mappings=DEFAULT_MAPPINGS["identification_auth"],
                )
            )

        if missing_httponly:
            deductions.append(
                _deduction(
                    rule_id="COOKIE-002",
                    title="Cookies missing HttpOnly attribute",
                    category="Session Security",
                    severity=Severity.MEDIUM,
                    deduction=8,
                    evidence=f"Cookie(s): {', '.join(sorted(set(missing_httponly)))}.",
                    business_impact=(
                        "Client-side scripts may be able to access sensitive cookies if "
                        "cross-site scripting occurs."
                    ),
                    recommendation="Add the HttpOnly attribute to session and sensitive cookies.",
                    detection_method="Set-Cookie header attribute inspection.",
                    mappings=DEFAULT_MAPPINGS["identification_auth"],
                )
            )

        if missing_samesite:
            deductions.append(
                _deduction(
                    rule_id="COOKIE-003",
                    title="Cookies missing SameSite attribute",
                    category="Session Security",
                    severity=Severity.LOW,
                    deduction=4,
                    evidence=f"Cookie(s): {', '.join(sorted(set(missing_samesite)))}.",
                    business_impact=(
                        "Cookies without SameSite have weaker browser-level protection "
                        "against cross-site request contexts."
                    ),
                    recommendation=(
                        "Set SameSite=Lax or SameSite=Strict unless cross-site usage is required."
                    ),
                    detection_method="Set-Cookie header attribute inspection.",
                    mappings=DEFAULT_MAPPINGS["identification_auth"],
                )
            )

        if not missing_secure and not missing_httponly and not missing_samesite:
            positive_signals.append(
                PositiveSignal(
                    title="Observed cookies include key security attributes",
                    category="Session Security",
                    evidence=(
                        "Set-Cookie headers include Secure, HttpOnly, and SameSite attributes."
                    ),
                    mappings=DEFAULT_MAPPINGS["identification_auth"],
                )
            )

    def _evaluate_dns_email_security(
        self,
        data: Any,
        deductions: list[ScoringDeduction],
        positive_signals: list[PositiveSignal],
    ) -> None:
        spf = _record_state(data, "spf")
        dmarc = _record_state(data, "dmarc")
        dkim = _record_state(data, "dkim")
        dnssec = _record_state(data, "dnssec")

        if spf.is_missing:
            deductions.append(
                _dns_deduction(
                    rule_id="DNS-001",
                    title="SPF record not detected",
                    severity=Severity.MEDIUM,
                    deduction=7,
                    evidence=spf.evidence,
                    impact=(
                        "Attackers may have an easier time spoofing email from the "
                        "domain, increasing phishing and brand abuse risk."
                    ),
                    recommendation=(
                        "Publish a valid SPF record that authorizes legitimate mail "
                        "senders."
                    ),
                )
            )
        elif spf.is_present:
            positive_signals.append(
                PositiveSignal(
                    title="SPF record detected",
                    category="DNS & Email Security",
                    evidence=_record_evidence(spf),
                    mappings=DEFAULT_MAPPINGS["security_misconfiguration"],
                )
            )

        if dmarc.is_missing:
            deductions.append(
                _dns_deduction(
                    rule_id="DNS-002",
                    title="DMARC record not detected",
                    severity=Severity.HIGH,
                    deduction=10,
                    evidence=dmarc.evidence,
                    impact=(
                        "Missing DMARC reduces domain-level control over spoofed mail "
                        "and weakens reporting visibility for abuse."
                    ),
                    recommendation=(
                        "Publish a DMARC record. Start with reporting, then move toward "
                        "quarantine or reject after validating legitimate senders."
                    ),
                )
            )
        elif dmarc.is_present:
            positive_signals.append(
                PositiveSignal(
                    title="DMARC record detected",
                    category="DNS & Email Security",
                    evidence=_record_evidence(dmarc),
                    mappings=DEFAULT_MAPPINGS["security_misconfiguration"],
                )
            )

            dmarc_value = _clean_text(dmarc.value).lower()
            if "p=none" in dmarc_value:
                deductions.append(
                    _dns_deduction(
                        rule_id="DNS-003",
                        title="DMARC policy is monitoring-only",
                        severity=Severity.LOW,
                        deduction=4,
                        evidence=_record_evidence(dmarc),
                        impact=(
                            "A p=none policy collects reports but does not instruct "
                            "receivers to quarantine or reject spoofed email."
                        ),
                        recommendation=(
                            "After reviewing reports and fixing legitimate sender "
                            "alignment, move DMARC policy toward quarantine or reject."
                        ),
                    )
                )

        if dkim.is_missing:
            deductions.append(
                _dns_deduction(
                    rule_id="DNS-004",
                    title="DKIM evidence not detected",
                    severity=Severity.MEDIUM,
                    deduction=7,
                    evidence=dkim.evidence,
                    impact=(
                        "Email receivers may have less assurance that messages were "
                        "authorized by the domain and not modified in transit."
                    ),
                    recommendation=(
                        "Enable DKIM signing for outbound mail and publish the selector "
                        "records used by the mail platform."
                    ),
                )
            )
        elif dkim.is_present:
            positive_signals.append(
                PositiveSignal(
                    title="DKIM evidence detected",
                    category="DNS & Email Security",
                    evidence=_record_evidence(dkim),
                    mappings=DEFAULT_MAPPINGS["security_misconfiguration"],
                )
            )

        if dnssec.is_missing:
            deductions.append(
                _dns_deduction(
                    rule_id="DNS-005",
                    title="DNSSEC not detected",
                    severity=Severity.LOW,
                    deduction=3,
                    evidence=dnssec.evidence,
                    impact=(
                        "DNS responses may not have cryptographic integrity validation "
                        "at the domain level."
                    ),
                    recommendation=(
                        "Enable DNSSEC through the DNS provider if operationally supported."
                    ),
                )
            )
        elif dnssec.is_present:
            positive_signals.append(
                PositiveSignal(
                    title="DNSSEC evidence detected",
                    category="DNS & Email Security",
                    evidence=_record_evidence(dnssec),
                    mappings=DEFAULT_MAPPINGS["security_misconfiguration"],
                )
            )

    def _evaluate_exposed_ports(
        self,
        data: Any,
        deductions: list[ScoringDeduction],
        positive_signals: list[PositiveSignal],
    ) -> None:
        open_ports = _extract_open_ports(data)
        if not open_ports:
            return

        risky_findings = [
            PortFinding(
                port=port,
                service=RISKY_PORTS[port][0],
                severity=RISKY_PORTS[port][1],
            )
            for port in sorted(open_ports)
            if port in RISKY_PORTS
        ]

        unexpected_web_ports = sorted(
            port
            for port in open_ports
            if port not in EXPECTED_WEB_PORTS and port not in RISKY_PORTS
        )

        if risky_findings:
            highest = min(
                risky_findings,
                key=lambda item: SEVERITY_SORT_ORDER[item.severity],
            ).severity

            if highest is Severity.CRITICAL:
                deduction = 18
            elif highest is Severity.HIGH:
                deduction = 12
            else:
                deduction = 6

            deductions.append(
                _deduction(
                    rule_id="PORT-001",
                    title="Sensitive network service exposed",
                    category="Exposure Management",
                    severity=highest,
                    deduction=deduction,
                    evidence=", ".join(
                        f"{finding.port}/{finding.service}"
                        for finding in risky_findings
                    ),
                    business_impact=(
                        "Publicly exposed administrative, database, or legacy services "
                        "increase attack surface and can become direct compromise paths."
                    ),
                    recommendation=(
                        "Restrict sensitive services behind VPN, private networking, or "
                        "allowlisted management access. Expose only required web ports "
                        "publicly."
                    ),
                    detection_method="Open port evidence from scanner result.",
                    mappings=DEFAULT_MAPPINGS["security_misconfiguration"],
                )
            )

        if unexpected_web_ports:
            deductions.append(
                _deduction(
                    rule_id="PORT-002",
                    title="Unexpected public ports observed",
                    category="Exposure Management",
                    severity=Severity.LOW,
                    deduction=4,
                    evidence=(
                        f"Open port(s): "
                        f"{', '.join(str(port) for port in unexpected_web_ports)}."
                    ),
                    business_impact=(
                        "Additional open services increase the number of assets that "
                        "must be monitored, patched, and access-controlled."
                    ),
                    recommendation=(
                        "Verify each exposed port is business-required. Close or restrict "
                        "anything not needed for the public website."
                    ),
                    detection_method="Open port evidence from scanner result.",
                    mappings=DEFAULT_MAPPINGS["security_misconfiguration"],
                )
            )

        if open_ports and set(open_ports).issubset(EXPECTED_WEB_PORTS):
            positive_signals.append(
                PositiveSignal(
                    title="Only expected web ports were observed",
                    category="Exposure Management",
                    evidence=(
                        f"Open port(s): "
                        f"{', '.join(str(port) for port in sorted(open_ports))}."
                    ),
                    mappings=DEFAULT_MAPPINGS["security_misconfiguration"],
                )
            )

    def _evaluate_information_disclosure(
        self,
        data: Any,
        deductions: list[ScoringDeduction],
        positive_signals: list[PositiveSignal],
    ) -> None:
        server = _header_state(data, "server")
        server_value = _clean_text(server.value)

        if not server_value:
            return

        if any(character.isdigit() for character in server_value) or "/" in server_value:
            deductions.append(
                _deduction(
                    rule_id="INFO-001",
                    title="Server banner exposes technology/version details",
                    category="Information Disclosure",
                    severity=Severity.LOW,
                    deduction=4,
                    evidence=f"Server header: {server_value}",
                    business_impact=(
                        "Detailed banners can help attackers fingerprint the technology "
                        "stack and map it to known vulnerabilities."
                    ),
                    recommendation=(
                        "Reduce server banner detail at the web server or reverse proxy. "
                        "Do not rely on banner hiding as a replacement for patching."
                    ),
                    detection_method="HTTP Server header inspection.",
                    mappings=DEFAULT_MAPPINGS["security_misconfiguration"],
                )
            )
        else:
            positive_signals.append(
                PositiveSignal(
                    title="Server banner does not expose obvious version details",
                    category="Information Disclosure",
                    evidence=f"Server header: {server_value}",
                    mappings=DEFAULT_MAPPINGS["security_misconfiguration"],
                )
            )


def assess_website_risk(scan_result: Any, target: str | None = None) -> RiskAssessment:
    return RiskEngine().assess(scan_result=scan_result, target=target)


def _deduction(
    *,
    rule_id: str,
    title: str,
    category: str,
    severity: Severity,
    deduction: int,
    evidence: str | None,
    business_impact: str,
    recommendation: str,
    detection_method: str,
    mappings: dict[str, list[str]],
    confidence: str = "high",
) -> ScoringDeduction:
    return ScoringDeduction(
        rule_id=rule_id,
        title=title,
        category=category,
        severity=severity,
        deduction=deduction,
        evidence=evidence or "No detailed evidence supplied by scanner output.",
        business_impact=business_impact,
        recommendation=recommendation,
        detection_method=detection_method,
        confidence=confidence,
        mappings=mappings,
    )


def _missing_header_deduction(
    *,
    rule_id: str,
    header: str,
    severity: Severity,
    deduction: int,
    impact: str,
    recommendation: str,
    evidence: str | None,
) -> ScoringDeduction:
    return _deduction(
        rule_id=rule_id,
        title=f"Missing {header} header/control",
        category="HTTP Security Headers",
        severity=severity,
        deduction=deduction,
        evidence=evidence or f"{header} was not observed in the scanner result.",
        business_impact=impact,
        recommendation=recommendation,
        detection_method="HTTP response security header inspection.",
        mappings=DEFAULT_MAPPINGS["security_misconfiguration"],
    )


def _dns_deduction(
    *,
    rule_id: str,
    title: str,
    severity: Severity,
    deduction: int,
    evidence: str | None,
    impact: str,
    recommendation: str,
) -> ScoringDeduction:
    return _deduction(
        rule_id=rule_id,
        title=title,
        category="DNS & Email Security",
        severity=severity,
        deduction=deduction,
        evidence=evidence,
        business_impact=impact,
        recommendation=recommendation,
        detection_method="DNS and email authentication record inspection.",
        mappings=DEFAULT_MAPPINGS["security_misconfiguration"],
    )


def _to_plain_data(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value

    if is_dataclass(value) and not isinstance(value, type):
        return _to_plain_data(asdict(value))

    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        try:
            return _to_plain_data(model_dump(mode="python"))
        except TypeError:
            return _to_plain_data(model_dump())

    legacy_dict = getattr(value, "dict", None)
    if callable(legacy_dict):
        return _to_plain_data(legacy_dict())

    if isinstance(value, Mapping):
        return {str(key): _to_plain_data(item) for key, item in value.items()}

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_to_plain_data(item) for item in value]

    return value


def _extract_target(data: Any) -> str | None:
    return _find_first_text(
        data,
        ("target", "target_url", "url", "website_url", "domain", "hostname"),
    )


def _extract_reachable(data: Any) -> bool | None:
    value = _find_first_value(
        data,
        ("is_available", "available", "reachable", "is_reachable", "online", "success"),
    )
    return _as_bool(value)


def _extract_status_code(data: Any) -> int | None:
    status_code = _as_int(
        _find_first_value(data, ("status_code", "http_status", "response_code"))
    )
    if status_code is not None and 100 <= status_code <= 599:
        return status_code
    return None


def _extract_https_used(data: Any, target: str | None) -> bool | None:
    explicit = _find_first_value(data, ("uses_https", "https_enabled", "https", "is_https"))
    explicit_bool = _as_bool(explicit)

    if explicit_bool is not None:
        return explicit_bool

    scheme = _find_first_text(data, ("scheme", "protocol"))

    if scheme:
        normalized = scheme.lower().replace(" ", "")
        if normalized == "https":
            return True
        if normalized == "http":
            return False

    if target:
        parsed = urlparse(target if "://" in target else f"//{target}")
        if parsed.scheme == "https":
            return True
        if parsed.scheme == "http":
            return False

    return None


def _extract_certificate_valid(data: Any) -> bool | None:
    value = _find_first_value(
        data,
        (
            "certificate_valid",
            "cert_valid",
            "tls_valid",
            "ssl_valid",
            "is_certificate_valid",
        ),
    )

    parsed = _as_bool(value)
    if parsed is not None:
        return parsed

    for node in _iter_mappings(data):
        if _node_name_suggests_tls(node):
            for key in ("valid", "is_valid", "status"):
                nested = _mapping_get_normalized(node, key)

                if nested is not None:
                    if key == "status":
                        status = _clean_text(nested).lower()
                        if status in PRESENT_STATUS_TERMS:
                            return True
                        if (
                            status in MISSING_STATUS_TERMS
                            or status in {"expired", "invalid"}
                        ):
                            return False

                    nested_bool = _as_bool(nested)
                    if nested_bool is not None:
                        return nested_bool

    return None


def _extract_certificate_expired(data: Any) -> bool | None:
    return _as_bool(
        _find_first_value(
            data,
            ("certificate_expired", "cert_expired", "expired", "is_expired"),
        )
    )


def _extract_certificate_days_to_expiry(data: Any) -> int | None:
    return _as_int(
        _find_first_value(
            data,
            (
                "days_to_expiry",
                "days_until_expiry",
                "valid_days_remaining",
                "expires_in_days",
                "certificate_days_remaining",
            ),
        )
    )


def _extract_tls_protocols(data: Any) -> set[str]:
    protocols: set[str] = set()
    values = _find_all_values(
        data,
        (
            "tls_protocols",
            "supported_protocols",
            "protocols",
            "protocol",
            "tls_version",
            "ssl_version",
        ),
    )

    for value in values:
        if isinstance(value, str):
            if value.upper().startswith(("TLS", "SSL")):
                protocols.add(value.strip())
        elif isinstance(value, Sequence) and not isinstance(
            value,
            (str, bytes, bytearray),
        ):
            for item in value:
                item_text = _clean_text(item)
                if item_text.upper().startswith(("TLS", "SSL")):
                    protocols.add(item_text)

    return protocols


def _header_state(data: Any, canonical_name: str) -> HeaderState:
    canonical_name = _normalize_header_name(canonical_name)
    observations = [
        item
        for item in _collect_header_observations(data)
        if item.canonical_name == canonical_name
    ]

    if not observations:
        if _has_header_evidence_section(data):
            return HeaderState(
                canonical_name=canonical_name,
                present=False,
                evidence=(
                    f"{canonical_name} was not found in the supplied HTTP header "
                    "scanner evidence."
                ),
            )

        return HeaderState(
            canonical_name=canonical_name,
            present=None,
            evidence=(
                f"No HTTP header evidence was supplied for {canonical_name}; "
                "the control was not scored."
            ),
        )

    value_observations = [item for item in observations if _clean_text(item.value)]
    explicit_present = [item for item in observations if item.present is True]
    explicit_missing = [item for item in observations if item.present is False]

    if value_observations:
        selected = value_observations[-1]
        return HeaderState(
            canonical_name=canonical_name,
            present=True,
            value=selected.value,
            status=selected.status,
            evidence=selected.evidence or f"{canonical_name} value observed.",
        )

    if explicit_present:
        selected = explicit_present[-1]
        return HeaderState(
            canonical_name=canonical_name,
            present=True,
            status=selected.status,
            evidence=selected.evidence or f"{canonical_name} marked as present.",
        )

    if explicit_missing:
        selected = explicit_missing[-1]
        return HeaderState(
            canonical_name=canonical_name,
            present=False,
            status=selected.status,
            evidence=selected.evidence or f"{canonical_name} marked as missing.",
        )

    return HeaderState(
        canonical_name=canonical_name,
        present=None,
        evidence=f"{canonical_name} evidence was inconclusive.",
    )


def _has_header_evidence_section(data: Any) -> bool:
    header_section_keys = {
        "headers",
        "response_headers",
        "raw_headers",
        "security_headers",
        "header_result",
        "header_results",
        "missing_headers",
        "present_headers",
        "header_checks",
        "security_header_checks",
    }

    normalized_header_section_keys = {
        _normalize_key(key) for key in header_section_keys
    }

    for node in _iter_mappings(data):
        normalized_node_keys = {
            _normalize_key(str(key)) for key in node.keys()
        }

        if normalized_node_keys.intersection(normalized_header_section_keys):
            return True

    return False




def _collect_header_observations(data: Any) -> list[HeaderState]:
    observations: list[HeaderState] = []

    for node in _iter_mappings(data):
        header_name = _first_text_from_mapping(
            node,
            ("name", "header", "header_name", "security_header", "key"),
        )

        if header_name:
            canonical = _canonical_header_name(header_name)

            if canonical:
                status = _first_text_from_mapping(node, ("status", "state", "result"))
                value = _first_text_from_mapping(
                    node,
                    ("value", "header_value", "observed_value"),
                )
                present = _presence_from_status_or_value(status, value)

                observations.append(
                    HeaderState(
                        canonical_name=canonical,
                        present=present,
                        value=value,
                        status=status,
                        evidence=_evidence_join(
                            [
                                f"header={header_name}",
                                f"status={status}" if status else None,
                                f"value={_truncate(value)}" if value else None,
                            ]
                        ),
                    )
                )

        for key, value in node.items():
            key_text = str(key)
            canonical = _canonical_header_name(key_text)

            if canonical:
                status = None
                header_value = None
                present: bool | None = None

                if isinstance(value, Mapping):
                    status = _first_text_from_mapping(
                        value,
                        ("status", "state", "result"),
                    )
                    header_value = _first_text_from_mapping(
                        value,
                        ("value", "header_value", "observed_value", "raw"),
                    )
                    present = _presence_from_status_or_value(status, header_value)
                elif isinstance(value, bool):
                    present = value
                elif value is None:
                    present = False
                else:
                    header_value = _clean_text(value)
                    present = bool(header_value)

                observations.append(
                    HeaderState(
                        canonical_name=canonical,
                        present=present,
                        value=header_value,
                        status=status,
                        evidence=_evidence_join(
                            [
                                f"header={key_text}",
                                f"status={status}" if status else None,
                                f"value={_truncate(header_value)}"
                                if header_value
                                else None,
                            ]
                        ),
                    )
                )

        missing_headers = _mapping_get_normalized(node, "missing_headers")
        if isinstance(missing_headers, Sequence) and not isinstance(
            missing_headers,
            (str, bytes, bytearray),
        ):
            for item in missing_headers:
                canonical = _canonical_header_name(_clean_text(item))
                if canonical:
                    observations.append(
                        HeaderState(
                            canonical_name=canonical,
                            present=False,
                            status="missing",
                            evidence=f"{canonical} listed in missing_headers.",
                        )
                    )

        present_headers = _mapping_get_normalized(node, "present_headers")
        if isinstance(present_headers, Sequence) and not isinstance(
            present_headers,
            (str, bytes, bytearray),
        ):
            for item in present_headers:
                canonical = _canonical_header_name(_clean_text(item))
                if canonical:
                    observations.append(
                        HeaderState(
                            canonical_name=canonical,
                            present=True,
                            status="present",
                            evidence=f"{canonical} listed in present_headers.",
                        )
                    )

    return observations


def _record_state(data: Any, record_name: str) -> RecordState:
    normalized_record = _normalize_key(record_name)
    candidates: list[RecordState] = []

    for node in _iter_mappings(data):
        for key, value in node.items():
            if _normalize_key(str(key)) == normalized_record:
                candidates.append(
                    _record_state_from_value(record_name, value, key_hint=str(key))
                )

        type_text = _first_text_from_mapping(node, ("type", "record_type", "name"))

        if type_text and _normalize_key(type_text) == normalized_record:
            present_value = _mapping_get_normalized(node, "present")
            status = _first_text_from_mapping(node, ("status", "state", "result"))
            value = _first_text_from_mapping(node, ("value", "record", "txt", "policy"))
            present = _as_bool(present_value)

            if present is None:
                present = _presence_from_status_or_value(status, value)

            candidates.append(
                RecordState(
                    name=record_name,
                    present=present,
                    value=value,
                    status=status,
                    evidence=_evidence_join(
                        [
                            f"record={type_text}",
                            f"status={status}" if status else None,
                            f"value={_truncate(value)}" if value else None,
                        ]
                    ),
                )
            )

    if not candidates:
        return RecordState(
            name=record_name,
            present=None,
            evidence=(
                f"No {record_name.upper()} evidence was supplied by the scanner output."
            ),
        )

    value_candidates = [
        candidate for candidate in candidates if _clean_text(candidate.value)
    ]
    explicit_present = [
        candidate for candidate in candidates if candidate.present is True
    ]
    explicit_missing = [
        candidate for candidate in candidates if candidate.present is False
    ]

    if value_candidates:
        return value_candidates[-1]
    if explicit_present:
        return explicit_present[-1]
    if explicit_missing:
        return explicit_missing[-1]

    return candidates[-1]


def _record_state_from_value(record_name: str, value: Any, key_hint: str) -> RecordState:
    if isinstance(value, Mapping):
        status = _first_text_from_mapping(value, ("status", "state", "result"))
        record_value = _first_text_from_mapping(
            value,
            ("value", "record", "txt", "policy"),
        )
        present_value = _mapping_get_normalized(value, "present")
        present = _as_bool(present_value)

        if present is None:
            present = _presence_from_status_or_value(status, record_value)

        return RecordState(
            name=record_name,
            present=present,
            value=record_value,
            status=status,
            evidence=_evidence_join(
                [
                    f"record={key_hint}",
                    f"status={status}" if status else None,
                    f"value={_truncate(record_value)}" if record_value else None,
                ]
            ),
        )

    if isinstance(value, bool):
        return RecordState(
            name=record_name,
            present=value,
            evidence=f"record={key_hint}; present={value}",
        )

    if value is None:
        return RecordState(
            name=record_name,
            present=False,
            evidence=f"record={key_hint}; value=None",
        )

    value_text = _clean_text(value)

    return RecordState(
        name=record_name,
        present=bool(value_text) and value_text.lower() not in MISSING_STATUS_TERMS,
        value=value_text,
        evidence=f"record={key_hint}; value={_truncate(value_text)}",
    )


def _extract_open_ports(data: Any) -> set[int]:
    ports: set[int] = set()

    for value in _find_all_values(data, ("open_ports", "ports", "port_scan_results")):
        if isinstance(value, Mapping):
            maybe_port = _mapping_get_normalized(value, "port")
            maybe_state = _first_text_from_mapping(value, ("state", "status"))
            port = _as_int(maybe_port)

            if port and (not maybe_state or maybe_state.lower() == "open"):
                ports.add(port)

        elif isinstance(value, Sequence) and not isinstance(
            value,
            (str, bytes, bytearray),
        ):
            for item in value:
                if isinstance(item, Mapping):
                    port = _as_int(_mapping_get_normalized(item, "port"))
                    state = _first_text_from_mapping(item, ("state", "status"))

                    if port and (not state or state.lower() == "open"):
                        ports.add(port)
                else:
                    port = _as_int(item)
                    if port:
                        ports.add(port)
        else:
            port = _as_int(value)
            if port:
                ports.add(port)

    return {port for port in ports if 1 <= port <= 65535}


def _extract_set_cookie_values(data: Any) -> list[str]:
    cookie_header = _header_state(data, "set-cookie")
    values: list[str] = []

    if cookie_header.value:
        values.extend(_split_cookie_header(cookie_header.value))

    for value in _find_all_values(data, ("set_cookie", "set_cookies", "cookies")):
        if isinstance(value, str):
            values.extend(_split_cookie_header(value))
        elif isinstance(value, Sequence) and not isinstance(
            value,
            (str, bytes, bytearray),
        ):
            for item in value:
                item_text = _clean_text(item)
                if item_text:
                    values.extend(_split_cookie_header(item_text))
        elif isinstance(value, Mapping):
            raw = _first_text_from_mapping(value, ("value", "raw", "set_cookie"))
            if raw:
                values.extend(_split_cookie_header(raw))

    unique_values: list[str] = []
    seen: set[str] = set()

    for value in values:
        if value not in seen:
            unique_values.append(value)
            seen.add(value)

    return unique_values


def _split_cookie_header(value: str) -> list[str]:
    cleaned = _clean_text(value)

    if not cleaned:
        return []

    if "\n" in cleaned:
        return [item.strip() for item in cleaned.splitlines() if item.strip()]

    return [cleaned]


def _find_first_value(data: Any, keys: Iterable[str]) -> Any:
    normalized_keys = {_normalize_key(key) for key in keys}

    for node in _iter_mappings(data):
        for key, value in node.items():
            if _normalize_key(str(key)) in normalized_keys:
                return value

    return None


def _find_first_text(data: Any, keys: Iterable[str]) -> str | None:
    value = _find_first_value(data, keys)
    text = _clean_text(value)
    return text or None


def _find_all_values(data: Any, keys: Iterable[str]) -> list[Any]:
    normalized_keys = {_normalize_key(key) for key in keys}
    values: list[Any] = []

    for node in _iter_mappings(data):
        for key, value in node.items():
            if _normalize_key(str(key)) in normalized_keys:
                values.append(value)

    return values


def _iter_mappings(data: Any) -> Iterable[Mapping[str, Any]]:
    if isinstance(data, Mapping):
        yield data

        for value in data.values():
            yield from _iter_mappings(value)

    elif isinstance(data, Sequence) and not isinstance(data, (str, bytes, bytearray)):
        for item in data:
            yield from _iter_mappings(item)


def _mapping_get_normalized(mapping: Mapping[str, Any], key: str) -> Any:
    normalized = _normalize_key(key)

    for candidate_key, value in mapping.items():
        if _normalize_key(str(candidate_key)) == normalized:
            return value

    return None


def _first_text_from_mapping(mapping: Mapping[str, Any], keys: Iterable[str]) -> str | None:
    for key in keys:
        value = _mapping_get_normalized(mapping, key)
        text = _clean_text(value)

        if text:
            return text

    return None


def _canonical_header_name(header_name: str) -> str | None:
    normalized = _normalize_header_name(header_name)

    if normalized in HEADER_ALIAS_TO_CANONICAL:
        return HEADER_ALIAS_TO_CANONICAL[normalized]

    return None


def _normalize_header_name(value: str) -> str:
    return _normalize_key(value).replace("_", "-")


def _normalize_key(value: str) -> str:
    return str(value).strip().lower().replace("_", "-")


def _presence_from_status_or_value(status: str | None, value: str | None) -> bool | None:
    normalized_status = _clean_text(status).lower()

    if normalized_status in PRESENT_STATUS_TERMS:
        return True
    if normalized_status in MISSING_STATUS_TERMS:
        return False
    if normalized_status in {"weak", "warning", "misconfigured", "insecure", "partial"}:
        return True
    if value is not None:
        return bool(_clean_text(value))

    return None


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None

    text = _clean_text(value).lower()

    if text in {
        "true",
        "yes",
        "y",
        "1",
        "enabled",
        "present",
        "pass",
        "passed",
        "ok",
        "valid",
        "online",
        "reachable",
        "available",
    }:
        return True

    if text in {
        "false",
        "no",
        "n",
        "0",
        "disabled",
        "missing",
        "absent",
        "fail",
        "failed",
        "invalid",
        "offline",
        "unreachable",
        "unavailable",
    }:
        return False

    return None


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)

    text = _clean_text(value)

    if not text:
        return None

    try:
        return int(float(text))
    except ValueError:
        return None


def _clean_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, Enum):
        return str(value.value).strip()
    if isinstance(value, (dict, list, tuple, set)):
        return ""
    return str(value).strip()


def _truncate(value: str | None, limit: int = 160) -> str:
    text = _clean_text(value)

    if len(text) <= limit:
        return text

    return f"{text[: limit - 3]}..."


def _evidence_join(parts: Sequence[str | None]) -> str:
    return "; ".join(part for part in parts if part)


def _header_evidence(header: HeaderState) -> str:
    if header.value:
        return f"{header.canonical_name}: {_truncate(header.value)}"
    if header.status:
        return f"{header.canonical_name}: status={header.status}"
    return header.evidence or f"{header.canonical_name} evidence observed."


def _record_evidence(record: RecordState) -> str:
    if record.value:
        return f"{record.name.upper()}: {_truncate(record.value)}"
    if record.status:
        return f"{record.name.upper()}: status={record.status}"
    return record.evidence or f"{record.name.upper()} evidence observed."


def _extract_hsts_max_age(value: str | None) -> int | None:
    text = _clean_text(value).lower()

    for directive in text.split(";"):
        directive = directive.strip()

        if directive.startswith("max-age="):
            return _as_int(directive.split("=", 1)[1])

    return None


def _csp_has_frame_ancestors(value: str | None) -> bool:
    return "frame-ancestors" in _clean_text(value).lower()


def _node_name_suggests_tls(node: Mapping[str, Any]) -> bool:
    for key in node.keys():
        normalized = _normalize_key(str(key))

        if normalized in {"ssl", "tls", "certificate", "cert", "certificate-chain"}:
            return True

    return False


def _deduplicate_deductions(
    deductions: list[ScoringDeduction],
) -> list[ScoringDeduction]:
    deduplicated: dict[str, ScoringDeduction] = {}

    for deduction in deductions:
        existing = deduplicated.get(deduction.rule_id)

        if existing is None or deduction.deduction > existing.deduction:
            deduplicated[deduction.rule_id] = deduction

    return list(deduplicated.values())


def _severity_counts(deductions: list[ScoringDeduction]) -> dict[str, int]:
    counts = Counter(item.severity.value for item in deductions)
    return {severity.value: counts.get(severity.value, 0) for severity in Severity}


def _assessment_coverage(data: Any, target: str | None) -> dict[str, bool]:
    return {
        "availability": _extract_status_code(data) is not None
        or _extract_reachable(data) is not None,
        "transport_security": _extract_https_used(data, target) is not None
        or _extract_certificate_valid(data) is not None
        or _extract_certificate_days_to_expiry(data) is not None,
        "http_security_headers": bool(_collect_header_observations(data)),
        "dns_email_security": any(
            _record_state(data, record).present is not None
            for record in ("spf", "dmarc", "dkim", "dnssec")
        ),
        "exposure_management": bool(_extract_open_ports(data)),
    }


def _build_key_risk_drivers(
    deductions: list[ScoringDeduction],
    limit: int = 5,
) -> list[str]:
    if not deductions:
        return [
            "No material risk drivers were identified from the available scanner evidence."
        ]

    return [
        f"{item.title} ({item.severity.value}, -{item.deduction}): {item.evidence}"
        for item in deductions[:limit]
    ]


def _build_priority_actions(
    deductions: list[ScoringDeduction],
    limit: int = 6,
) -> list[str]:
    if not deductions:
        return [
            "Maintain current controls and schedule periodic rescans to detect configuration drift."
        ]

    actions: list[str] = []
    seen: set[str] = set()

    for item in deductions:
        action = item.recommendation.strip()

        if action not in seen:
            actions.append(action)
            seen.add(action)

        if len(actions) >= limit:
            break

    return actions


def _build_executive_summary(
    *,
    target: str | None,
    score: int,
    grade: str,
    risk_level: RiskLevel,
    deductions: list[ScoringDeduction],
) -> str:
    target_text = target or "the assessed target"

    if not deductions:
        return (
            f"CyberShield360 assessed {target_text} and calculated a security score of "
            f"{score}/100 ({grade}) with {risk_level.value} risk. No material "
            "configuration weaknesses were identified from the available automated evidence."
        )

    highest = deductions[0]
    critical_high_count = sum(
        1 for item in deductions if item.severity in {Severity.CRITICAL, Severity.HIGH}
    )

    return (
        f"CyberShield360 assessed {target_text} and calculated a security score of "
        f"{score}/100 ({grade}) with {risk_level.value} risk. The assessment identified "
        f"{len(deductions)} security finding(s), including {critical_high_count} critical/high "
        f"priority item(s). The main risk driver is: {highest.title}."
    )


def _build_detection_summary(
    coverage: dict[str, bool],
    deductions: list[ScoringDeduction],
) -> str:
    covered = [name.replace("_", " ") for name, enabled in coverage.items() if enabled]
    uncovered = [
        name.replace("_", " ") for name, enabled in coverage.items() if not enabled
    ]

    summary = (
        "Automated passive checks evaluated "
        + (", ".join(covered) if covered else "the evidence supplied by the scanner")
        + "."
    )

    if uncovered:
        summary += " Evidence was not supplied for: " + ", ".join(uncovered) + "."

    if deductions:
        summary += (
            " Findings are prioritized using severity, business impact, and explainable "
            "score deductions."
        )
    else:
        summary += " No deductions were applied from the supplied evidence."

    return summary


def _risk_level_for_score(score: int) -> RiskLevel:
    if score >= 95:
        return RiskLevel.MINIMAL
    if score >= 85:
        return RiskLevel.LOW
    if score >= 70:
        return RiskLevel.MODERATE
    if score >= 50:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def _grade_for_score(score: int) -> str:
    if score >= 95:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 85:
        return "A-"
    if score >= 80:
        return "B+"
    if score >= 75:
        return "B"
    if score >= 70:
        return "B-"
    if score >= 65:
        return "C+"
    if score >= 60:
        return "C"
    if score >= 55:
        return "C-"
    if score >= 50:
        return "D"
    return "F"
