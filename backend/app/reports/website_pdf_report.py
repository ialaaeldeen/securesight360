from __future__ import annotations

import json

from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.lib.utils import ImageReader
from reportlab.platypus import (
    Flowable,
    Image,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.reports.report_branding import (
    BRAND_DANGER,
    BRAND_DARK,
    BRAND_MUTED,
    BRAND_PANEL,
    BRAND_PRIMARY,
    BRAND_SECONDARY,
    BRAND_SUCCESS,
    BRAND_TEXT,
    BRAND_WARNING,
    CONFIDENTIALITY_LABEL,
    COPYRIGHT_TEXT,
    LOGO_PATH,
    PROJECT_NAME,
    REPORT_SUBTITLE,
    REPORT_TITLE,
)
from app.reports.report_helpers import (
    format_score,
    risk_level_from_score,
    safe_text,
    security_rating_from_score,
)


PAGE_WIDTH, PAGE_HEIGHT = A4
MARGIN_X = 1.45 * cm
CONTENT_WIDTH = PAGE_WIDTH - (MARGIN_X * 2)

PAGE_BG = BRAND_DARK
PANEL = BRAND_PANEL
PANEL_2 = "#101A2F"
PANEL_3 = "#111C33"
BORDER = "#1E3A5F"
TEXT = BRAND_TEXT
MUTED = BRAND_MUTED
WHITE = "#FFFFFF"


class LogoFallback(Flowable):
    def __init__(self, size: float = 22 * mm):
        super().__init__()
        self.width = size
        self.height = size

    def draw(self) -> None:
        c = self.canv
        c.saveState()

        cx = self.width / 2
        cy = self.height / 2
        radius = self.width / 2.4

        c.setFillColor(colors.HexColor("#0B1220"))
        c.setStrokeColor(colors.HexColor(BRAND_PRIMARY))
        c.setLineWidth(1.4)
        c.circle(cx, cy, radius, fill=1, stroke=1)

        c.setFillColor(colors.HexColor(BRAND_PRIMARY))
        c.setFont("Helvetica-Bold", 10)
        c.drawCentredString(cx, cy - 3, "S")

        c.restoreState()


class AccentLine(Flowable):
    def __init__(self, width: float = CONTENT_WIDTH, color: str = BRAND_PRIMARY, height: float = 5):
        super().__init__()
        self.width = width
        self.height = height
        self.color = color

    def draw(self) -> None:
        c = self.canv
        c.saveState()
        c.setFillColor(colors.HexColor(self.color))
        c.roundRect(0, 1.5, self.width, 2.2, 1.1, fill=1, stroke=0)
        c.restoreState()


def build_website_security_report_pdf(
    *,
    scan: dict[str, Any],
    website_check: dict[str, Any] | None = None,
    findings: list[dict[str, Any]] | None = None,
) -> bytes:
    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=MARGIN_X,
        leftMargin=MARGIN_X,
        topMargin=1.85 * cm,
        bottomMargin=1.7 * cm,
        title=f"{PROJECT_NAME} Website Security Report",
        author=PROJECT_NAME,
        subject="Website Security Assessment Report",
    )

    styles = _build_styles()

    normalized_scan = dict(scan or {})
    normalized_check = _normalize_mapping(website_check)
    normalized_findings = [_normalize_mapping(item) for item in findings or []]

    story: list[Any] = []

    story.extend(_cover_page(normalized_scan, styles))
    story.append(PageBreak())

    story.extend(_executive_summary(normalized_scan, normalized_check, normalized_findings, styles))
    story.append(PageBreak())

    story.extend(_security_score_overview(normalized_scan, styles))
    story.append(Spacer(1, 7 * mm))
    story.extend(_risk_breakdown(normalized_scan, normalized_check, normalized_findings, styles))
    story.append(PageBreak())

    story.extend(_key_findings(normalized_scan, normalized_check, normalized_findings, styles))
    story.append(PageBreak())

    story.extend(_positive_signals(normalized_check, styles))
    story.append(Spacer(1, 7 * mm))
    story.extend(_priority_recommendations(normalized_scan, normalized_check, normalized_findings, styles))
    story.append(PageBreak())

    story.extend(_technical_evidence(normalized_scan, normalized_check, styles))
    story.append(PageBreak())

    story.extend(_next_steps_and_legal(normalized_scan, styles))

    document.build(
        story,
        onFirstPage=_draw_page_background_header_footer,
        onLaterPages=_draw_page_background_header_footer,
    )

    return buffer.getvalue()


def build_report_filename(scan: dict[str, Any]) -> str:
    scan_id = safe_text(scan.get("id"), "report")
    target = safe_text(scan.get("target") or scan.get("target_url"), "website")
    cleaned_target = (
        target.replace("https://", "")
        .replace("http://", "")
        .replace("/", "-")
        .replace(":", "-")
        .replace("?", "-")
        .replace("&", "-")
    )
    cleaned_target = "".join(
        char for char in cleaned_target if char.isalnum() or char in {"-", "_", "."}
    )
    cleaned_target = cleaned_target[:80] or "website"

    return f"securesight360-report-scan-{scan_id}-{cleaned_target}.pdf"


def _build_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()

    return {
        "brand": ParagraphStyle(
            "Brand",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=colors.HexColor(WHITE),
            alignment=TA_CENTER,
            spaceAfter=2,
        ),
        "brand_sub": ParagraphStyle(
            "BrandSub",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor(MUTED),
            alignment=TA_CENTER,
            spaceAfter=8,
        ),
        "cover_title": ParagraphStyle(
            "CoverTitle",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=25,
            textColor=colors.HexColor(WHITE),
            spaceAfter=8,
        ),
        "cover_body": ParagraphStyle(
            "CoverBody",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=14,
            textColor=colors.HexColor("#BFD7EA"),
            spaceAfter=6,
        ),
        "section": ParagraphStyle(
            "Section",
            parent=base["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=20,
            textColor=colors.HexColor(WHITE),
            spaceBefore=3,
            spaceAfter=4,
        ),
        "section_small": ParagraphStyle(
            "SectionSmall",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor(MUTED),
            spaceAfter=8,
        ),
        "h2": ParagraphStyle(
            "H2",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=11.5,
            leading=15,
            textColor=colors.HexColor(WHITE),
            spaceBefore=6,
            spaceAfter=5,
        ),
        "h3": ParagraphStyle(
            "H3",
            parent=base["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=9.4,
            leading=12,
            textColor=colors.HexColor("#DFF7FF"),
            spaceBefore=4,
            spaceAfter=3,
        ),
        "body": ParagraphStyle(
            "Body",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=9.0,
            leading=13.2,
            textColor=colors.HexColor("#D6E4F0"),
            spaceAfter=7,
        ),
        "muted": ParagraphStyle(
            "Muted",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=7.7,
            leading=10.5,
            textColor=colors.HexColor(MUTED),
            spaceAfter=4,
        ),
        "label": ParagraphStyle(
            "Label",
            parent=base["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=7.4,
            leading=9.5,
            textColor=colors.HexColor(MUTED),
        ),
        "value": ParagraphStyle(
            "Value",
            parent=base["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=11.5,
            leading=14,
            textColor=colors.HexColor(WHITE),
        ),
        "table_header": ParagraphStyle(
            "TableHeader",
            parent=base["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=7.7,
            leading=10,
            textColor=colors.HexColor("#BDEFFF"),
        ),
        "table_cell": ParagraphStyle(
            "TableCell",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=7.7,
            leading=10.5,
            textColor=colors.HexColor("#DDEBFA"),
        ),
        "table_cell_bold": ParagraphStyle(
            "TableCellBold",
            parent=base["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=7.9,
            leading=10.5,
            textColor=colors.HexColor(WHITE),
        ),
        "legal": ParagraphStyle(
            "Legal",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=8.0,
            leading=11.5,
            textColor=colors.HexColor("#C6D6E6"),
            spaceAfter=5,
        ),
    }


def _draw_page_background_header_footer(canvas: Any, document: Any) -> None:
    canvas.saveState()

    canvas.setFillColor(colors.HexColor(PAGE_BG))
    canvas.rect(0, 0, PAGE_WIDTH, PAGE_HEIGHT, fill=1, stroke=0)

    canvas.setStrokeColor(colors.HexColor("#123A55"))
    canvas.setLineWidth(0.8)
    canvas.line(MARGIN_X, PAGE_HEIGHT - 1.28 * cm, PAGE_WIDTH - MARGIN_X, PAGE_HEIGHT - 1.28 * cm)

    canvas.setFillColor(colors.HexColor(WHITE))
    canvas.setFont("Helvetica-Bold", 8.6)
    canvas.drawString(MARGIN_X, PAGE_HEIGHT - 0.95 * cm, PROJECT_NAME)

    canvas.setFillColor(colors.HexColor(MUTED))
    canvas.setFont("Helvetica", 7.1)
    canvas.drawRightString(PAGE_WIDTH - MARGIN_X, PAGE_HEIGHT - 0.95 * cm, CONFIDENTIALITY_LABEL)

    canvas.setStrokeColor(colors.HexColor("#123A55"))
    canvas.setLineWidth(0.6)
    canvas.line(MARGIN_X, 1.18 * cm, PAGE_WIDTH - MARGIN_X, 1.18 * cm)

    canvas.setFillColor(colors.HexColor(MUTED))
    canvas.setFont("Helvetica", 7.0)
    canvas.drawString(MARGIN_X, 0.78 * cm, COPYRIGHT_TEXT)
    canvas.drawRightString(PAGE_WIDTH - MARGIN_X, 0.78 * cm, f"Page {document.page}")

    canvas.restoreState()


def _cover_page(scan: dict[str, Any], styles: dict[str, ParagraphStyle]) -> list[Any]:
    score = scan.get("security_score")
    rating = _display_rating(scan)
    risk = _display_risk(scan)
    target = safe_text(scan.get("target") or scan.get("target_url"))
    scan_date = _format_datetime(
        scan.get("completed_at") or scan.get("created_at") or datetime.now(timezone.utc).isoformat()
    )
    prepared_for = safe_text(scan.get("user_email") or scan.get("user_full_name"), "Authorized SecureSight360 user")
    scope = _assessment_scope(scan)
    assessment_type = safe_text(
        scope.get("assessment_type") or scan.get("assessment_type"),
        "Basic External Website Security Posture Assessment",
    )
    coverage_text = _scope_list_text(
        scope,
        "coverage",
        "Availability, HTTPS/TLS, security headers, DNS/email security, CAA, basic technology evidence, risk scoring, and PDF reporting.",
    )
    limitations_text = _scope_list_text(
        scope,
        "limitations",
        "No exploitation, no authenticated testing, no deep crawling, no port scanning, no subdomain enumeration, and not a full penetration test.",
    )

    logo = _cover_logo_flowable()
    logo.hAlign = "CENTER"

    return [
        logo,
        Spacer(1, 7 * mm),
        _cover_hero(target, scan_date, styles),
        Spacer(1, 7 * mm),
        _metric_cards(
            [
                ("Security Score", format_score(score), _score_color(score)),
                ("Security Rating", rating, _rating_color(rating)),
                ("Risk Level", risk, _risk_color(risk)),
            ],
            styles,
        ),
        Spacer(1, 6 * mm),
        _detail_table(
            [
                ("Report Title", REPORT_TITLE),
                ("Target Website / Domain", target),
                ("Scan Date and Time", scan_date),
                ("Scan ID", safe_text(scan.get("id"))),
                ("Scan Status", _pretty(scan.get("status"))),
                ("Prepared For", prepared_for),
                ("Prepared By", PROJECT_NAME),
            ],
            styles,
        ),
        Spacer(1, 7 * mm),
        _notice_box(
            "Report Classification",
            "Confidential. This report may contain sensitive security information and should only be shared with authorized stakeholders.",
            BRAND_PRIMARY,
            styles,
        ),
    ]


def _cover_hero(target: str, scan_date: str, styles: dict[str, ParagraphStyle]) -> Table:
    left = [
        Paragraph(_html(REPORT_TITLE), styles["cover_title"]),
        Paragraph(
            _html("Authorized, non-invasive website security assessment prepared for executive and technical review."),
            styles["cover_body"],
        ),
        Paragraph(_html(CONFIDENTIALITY_LABEL.upper()), styles["table_cell_bold"]),
    ]

    assessment_type = "Basic External Website Security Posture Assessment"
    coverage_text = (
        "Availability, HTTPS/TLS, security headers, DNS/email security, CAA, "
        "basic technology evidence, risk scoring, and PDF reporting."
    )
    limitations_text = (
        "No exploitation, no authenticated testing, no deep crawling, no port scanning, "
        "no subdomain enumeration, and not a full penetration test."
    )

    right = [
        Paragraph(_html("Assessment Scope"), styles["table_cell_bold"]),
        Spacer(1, 2 * mm),
        Paragraph(_html(f"Assessment type: {assessment_type}"), styles["table_cell"]),
        Paragraph(_html(f"Target: {target}"), styles["table_cell"]),
        Paragraph(_html(f"Scan time: {scan_date}"), styles["table_cell"]),
        Spacer(1, 2 * mm),
        Paragraph(_html(f"Coverage: {coverage_text}"), styles["table_cell"]),
        Paragraph(_html(f"Limitations: {limitations_text}"), styles["table_cell"]),
        Spacer(1, 4 * mm),
        AccentLine(width=4.7 * cm, color=BRAND_PRIMARY),
    ]

    table = Table([[left, right]], colWidths=[10.2 * cm, 5.8 * cm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#071225")),
                ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#0F766E")),
                ("BOX", (0, 0), (-1, -1), 0.9, colors.HexColor("#164E63")),
                ("LEFTPADDING", (0, 0), (-1, -1), 14),
                ("RIGHTPADDING", (0, 0), (-1, -1), 14),
                ("TOPPADDING", (0, 0), (-1, -1), 16),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 16),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    return table


def _section_header(number: str, title: str, description: str, styles: dict[str, ParagraphStyle]) -> list[Any]:
    return [
        Paragraph(_html(f"{number}. {title}"), styles["section"]),
        AccentLine(width=CONTENT_WIDTH, color=BRAND_PRIMARY),
        Spacer(1, 2 * mm),
        Paragraph(_html(description), styles["section_small"]),
    ]


def _executive_summary(
    scan: dict[str, Any],
    website_check: dict[str, Any],
    findings: list[dict[str, Any]],
    styles: dict[str, ParagraphStyle],
) -> list[Any]:
    score = scan.get("security_score")
    rating = _display_rating(scan)
    risk = _display_risk(scan)
    target = safe_text(scan.get("target") or scan.get("target_url"))

    summary = _extract_executive_summary(scan, website_check)
    if not summary:
        summary = (
            f"The assessed target, {target}, received a Security Rating of {rating} with a score of "
            f"{format_score(score)}. This indicates a {risk.lower()} risk posture based on the controls "
            "observed during the scan. The results should be used to prioritize remediation and confirm that "
            "important website security controls are consistently implemented."
        )

    content: list[Any] = []
    content.extend(
        _section_header(
            "1",
            "Executive Summary",
            "A client-friendly overview of the website security posture, risk meaning, and immediate priorities.",
            styles,
        )
    )
    content.append(_large_text_panel(summary, styles))
    content.append(Spacer(1, 5 * mm))
    content.append(
        _insight_grid(
            [
                ("Overall Security Posture", _posture_sentence(score), BRAND_SECONDARY),
                ("Main Risks Discovered", _main_risk_sentence(scan, website_check, findings), BRAND_WARNING),
                ("Positive Security Signals", _positive_signal_sentence(website_check), BRAND_SUCCESS),
                ("Most Important Recommendation", _recommendation_sentence(scan, website_check, findings), BRAND_DANGER),
            ],
            styles,
        )
    )
    content.append(Spacer(1, 5 * mm))
    content.append(Paragraph("Executive Snapshot", styles["h2"]))
    content.append(
        _detail_table(
            [
                ("Target", target),
                ("Security Score", format_score(score)),
                ("Security Rating", rating),
                ("Risk Level", risk),
                ("Scan Status", _pretty(scan.get("status"))),
                ("Completed At", _format_datetime(scan.get("completed_at") or scan.get("created_at"))),
            ],
            styles,
        )
    )
    return content


def _security_score_overview(scan: dict[str, Any], styles: dict[str, ParagraphStyle]) -> list[Any]:
    score = scan.get("security_score")
    rating = _display_rating(scan)
    risk = _display_risk(scan)

    content: list[Any] = []
    content.extend(
        _section_header(
            "2",
            "Security Score Overview",
            "The score translates technical observations into an executive-readable security rating.",
            styles,
        )
    )
    content.append(
        _metric_cards(
            [
                ("Security Score", format_score(score), _score_color(score)),
                ("Security Rating", rating, _rating_color(rating)),
                ("Risk Level", risk, _risk_color(risk)),
            ],
            styles,
        )
    )
    content.append(Spacer(1, 5 * mm))
    content.append(
        _modern_table(
            ["Rating", "Score Range", "Meaning"],
            [
                ["Excellent", "90-100", "Mature posture with strong observable controls."],
                ["Strong", "80-89", "Good posture with limited improvements recommended."],
                ["Moderate", "70-79", "Acceptable baseline with important gaps to address."],
                ["Weak", "40-69", "Multiple missing or weak controls require attention."],
                ["Critical", "0-39", "Serious exposure requiring urgent remediation."],
            ],
            styles,
            col_widths=[3.1 * cm, 3.2 * cm, 9.7 * cm],
        )
    )
    return content


def _risk_breakdown(
    scan: dict[str, Any],
    website_check: dict[str, Any],
    findings: list[dict[str, Any]],
    styles: dict[str, ParagraphStyle],
) -> list[Any]:
    content: list[Any] = []
    content.extend(
        _section_header(
            "3",
            "Risk Breakdown",
            "Risk areas are grouped so executives and technical teams can prioritize remediation.",
            styles,
        )
    )
    content.append(
        _modern_table(
            ["Area", "Observed Status", "Risk Meaning"],
            _risk_breakdown_rows(scan, website_check, findings),
            styles,
            col_widths=[4.1 * cm, 4.3 * cm, 7.6 * cm],
        )
    )
    return content


def _key_findings(
    scan: dict[str, Any],
    website_check: dict[str, Any],
    findings: list[dict[str, Any]],
    styles: dict[str, ParagraphStyle],
) -> list[Any]:
    report_findings = _collect_report_findings(scan, website_check, findings)

    if not report_findings:
        report_findings = [
            {
                "title": "No detailed findings recorded",
                "risk": _display_risk(scan),
                "why": "No detailed finding records were stored for this scan.",
                "recommendation": "Review the technical evidence section and run a fresh scan if more detail is required.",
                "evidence": "No detailed finding evidence was recorded by the scanner for this section.",
            }
        ]

    rows = []
    for index, finding in enumerate(report_findings[:10], start=1):
        rows.append(
            [
                str(index),
                safe_text(finding.get("title")),
                safe_text(finding.get("risk")),
                safe_text(finding.get("recommendation")),
            ]
        )

    content: list[Any] = []
    content.extend(
        _section_header(
            "4",
            "Key Findings",
            "Important observations from the scan, organized with risk and remediation guidance.",
            styles,
        )
    )
    content.append(
        _modern_table(
            ["#", "Finding", "Risk", "Recommended Action"],
            rows,
            styles,
            col_widths=[0.9 * cm, 5.2 * cm, 2.4 * cm, 7.5 * cm],
        )
    )

    content.append(Spacer(1, 5 * mm))
    content.append(Paragraph("Finding Evidence Detail", styles["h2"]))

    for index, finding in enumerate(report_findings[:5], start=1):
        content.append(
            KeepTogether(
                [
                    Paragraph(_html(f"{index}. {safe_text(finding.get('title'))}"), styles["h3"]),
                    _detail_table(
                        [
                            ("Why it matters", safe_text(finding.get("why"))),
                            ("Evidence", safe_text(finding.get("evidence"))),
                        ],
                        styles,
                    ),
                    Spacer(1, 3 * mm),
                ]
            )
        )

    return content


def _positive_signals(website_check: dict[str, Any], styles: dict[str, ParagraphStyle]) -> list[Any]:
    signals = _collect_positive_signals(website_check)
    if not signals:
        signals = [
            "No positive security signals were recorded by the scanner for this scan.",
        ]

    content: list[Any] = []
    content.extend(
        _section_header(
            "5",
            "Positive Security Signals",
            "Controls or evidence that indicate positive security posture and should be maintained.",
            styles,
        )
    )
    content.append(_bullet_panel(signals[:8], BRAND_SUCCESS, styles))
    return content


def _priority_recommendations(
    scan: dict[str, Any],
    website_check: dict[str, Any],
    findings: list[dict[str, Any]],
    styles: dict[str, ParagraphStyle],
) -> list[Any]:
    recommendations = _collect_priority_recommendations(scan, website_check, findings)

    if not recommendations:
        recommendations = [
            "No priority recommendations were recorded by the scanner for this scan.",
        ]

    content: list[Any] = []
    content.extend(
        _section_header(
            "6",
            "Priority Recommendations",
            "Practical actions that should be handled first to improve security posture.",
            styles,
        )
    )
    content.append(_bullet_panel(recommendations[:10], BRAND_DANGER, styles))
    return content


def _technical_evidence(scan: dict[str, Any], website_check: dict[str, Any], styles: dict[str, ParagraphStyle]) -> list[Any]:
    availability = _as_dict(website_check.get("availability"))
    ssl = _as_dict(website_check.get("ssl") or website_check.get("tls"))
    headers = _as_dict(website_check.get("headers") or website_check.get("security_headers"))
    dns = _as_dict(website_check.get("dns"))
    technologies = _as_dict(website_check.get("technologies") or website_check.get("technologies_detected"))

    content: list[Any] = []
    content.extend(
        _section_header(
            "7",
            "Technical Evidence",
            "Cleanly summarized scan evidence. Raw nested scanner output is intentionally not printed.",
            styles,
        )
    )

    groups = [
        (
            "Website Availability",
            [
                ("Target", safe_text(scan.get("target") or scan.get("target_url"))),
                ("Status", _pretty(scan.get("status"))),
                ("HTTP Status", safe_text(availability.get("status_code"))),
                ("Final URL", safe_text(availability.get("final_url"))),
                ("Response Time", _format_response_time(availability.get("response_time_ms"))),
            ],
        ),
        (
            "HTTPS / TLS",
            [
                ("HTTPS Enabled", _yes_no(ssl.get("https_enabled"))),
                ("Certificate Valid", _yes_no(ssl.get("certificate_valid"))),
                ("Issuer", _compact_value(ssl.get("issuer"))),
                ("Days Until Expiry", safe_text(ssl.get("days_until_expiry"))),
                ("Protocol", safe_text(ssl.get("protocol"))),
            ],
        ),
        ("Security Headers", _headers_summary(headers)),
        (
            "DNS / Email Security",
            [
                ("SPF Present", _yes_no(dns.get("spf_present"))),
                ("DMARC Present", _yes_no(dns.get("dmarc_present"))),
                ("MX Records Present", _yes_no(dns.get("mx_present"))),
                ("DKIM Guidance", safe_text(dns.get("dkim_guidance"))),
            ],
        ),
        (
            "Detected Technologies",
            [(clean_key(key), safe_text(value)) for key, value in technologies.items()] or [("Technologies", "Not available")],
        ),
    ]

    for title, items in groups:
        content.append(Paragraph(_html(title), styles["h2"]))
        content.append(_detail_table(items, styles))
        content.append(Spacer(1, 2.5 * mm))

    return content


def _next_steps_and_legal(scan: dict[str, Any], styles: dict[str, ParagraphStyle]) -> list[Any]:
    scope = _assessment_scope(scan)
    assessment_type = safe_text(
        scope.get("assessment_type") or scan.get("assessment_type"),
        "Basic External Website Security Posture Assessment",
    )
    coverage_text = _scope_list_text(
        scope,
        "coverage",
        "Availability, HTTPS/TLS, security headers, DNS/email security, CAA, basic technology evidence, risk scoring, and PDF reporting.",
    )
    limitations_text = _scope_list_text(
        scope,
        "limitations",
        "No exploitation, no authenticated testing, no deep crawling, no port scanning, no subdomain enumeration, and not a full penetration test.",
    )

    authorization_text = safe_text(
        scan.get("authorization_text"),
        "The user confirmed they are authorized to scan this website asset.",
    )

    content: list[Any] = []
    content.extend(
        _section_header(
            "8",
            "Next Steps and Legal Notice",
            "Recommended follow-up process, authorization statement, and report limitations.",
            styles,
        )
    )

    content.append(
        _bullet_panel(
            [
                "Assign ownership for each priority recommendation.",
                "Remediate high-impact issues first, especially HTTPS/TLS, headers, and DNS/email protections.",
                "Validate fixes in a controlled environment where possible.",
                "Run a new SecureSight360 scan after remediation to confirm improvement.",
                "Keep this report with internal security records for audit and follow-up tracking.",
            ],
            BRAND_SECONDARY,
            styles,
        )
    )

    content.append(Spacer(1, 6 * mm))
    content.append(Paragraph("Methodology", styles["h2"]))
    content.append(
        Paragraph(
            _html(
                "SecureSight360 performs a non-invasive website security assessment using safe checks such as availability, HTTPS/TLS, security headers, DNS/email security records, and explainable risk scoring."
            ),
            styles["legal"],
        )
    )
    content.append(Paragraph("Assessment Scope and Limitations", styles["h2"]))
    content.append(
        Paragraph(
            _html(
                f"{assessment_type}. Coverage includes: {coverage_text}. "
                f"Limitations: {limitations_text}."
            ),
            styles["legal"],
        )
    )
    content.append(Paragraph("Authorization Statement", styles["h2"]))
    content.append(Paragraph(_html(authorization_text), styles["legal"]))
    content.append(Paragraph("Disclaimer", styles["h2"]))
    content.append(
        Paragraph(
            _html(
                "This report is not a full penetration test. Results are based on evidence available at scan time. Security posture may change after the scan date, and results should be validated by qualified personnel before remediation decisions."
            ),
            styles["legal"],
        )
    )
    content.append(Paragraph("Confidentiality", styles["h2"]))
    content.append(
        Paragraph(
            _html("This report may contain sensitive security information and should only be shared with authorized stakeholders."),
            styles["legal"],
        )
    )
    content.append(Spacer(1, 7 * mm))
    content.append(
        _notice_box(
            "Copyright and Rights Notice",
            f"{COPYRIGHT_TEXT} No part of this report should be redistributed outside authorized stakeholders without permission from the asset owner or authorized organization.",
            BRAND_PRIMARY,
            styles,
        )
    )

    return content


def _scaled_logo_image(path: Path, max_width_mm: float, max_height_mm: float) -> Image | None:
    try:
        reader = ImageReader(str(path))
        original_width, original_height = reader.getSize()

        if not original_width or not original_height:
            return None

        max_width = max_width_mm * mm
        max_height = max_height_mm * mm

        width_ratio = max_width / float(original_width)
        height_ratio = max_height / float(original_height)
        scale = min(width_ratio, height_ratio)

        final_width = float(original_width) * scale
        final_height = float(original_height) * scale

        return Image(str(path), width=final_width, height=final_height)
    except Exception:
        return None


def _cover_logo_flowable() -> Flowable:
    path = Path(LOGO_PATH)

    if path.exists():
        image = _scaled_logo_image(path, max_width_mm=128, max_height_mm=32)
        if image is not None:
            return image

    return LogoFallback(size=24 * mm)


def _logo_flowable() -> Flowable:
    path = Path(LOGO_PATH)

    if path.exists():
        image = _scaled_logo_image(path, max_width_mm=24, max_height_mm=24)
        if image is not None:
            return image

    return LogoFallback(size=24 * mm)


def _metric_cards(items: list[tuple[str, str, str]], styles: dict[str, ParagraphStyle]) -> Table:
    cells = []

    for label, value, color in items:
        cells.append(
            [
                Paragraph(_html(label), styles["label"]),
                Spacer(1, 1.5 * mm),
                Paragraph(f'<font color="{color}">{_html(value)}</font>', styles["value"]),
            ]
        )

    table = Table([cells], colWidths=[CONTENT_WIDTH / 3] * 3)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(PANEL_2)),
                ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor(BORDER)),
                ("INNERGRID", (0, 0), (-1, -1), 0.45, colors.HexColor(BORDER)),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return table


def _large_text_panel(text: str, styles: dict[str, ParagraphStyle]) -> Table:
    table = Table([[Paragraph(_html(text), styles["body"])]], colWidths=[CONTENT_WIDTH])
    table.setStyle(_panel_style(border=BRAND_PRIMARY))
    return table


def _notice_box(title: str, body: str, color: str, styles: dict[str, ParagraphStyle]) -> Table:
    table = Table(
        [
            [Paragraph(f'<font color="{color}">{_html(title)}</font>', styles["table_cell_bold"])],
            [Paragraph(_html(body), styles["table_cell"])],
        ],
        colWidths=[CONTENT_WIDTH],
    )
    table.setStyle(_panel_style(border=color))
    return table


def _insight_grid(items: list[tuple[str, str, str]], styles: dict[str, ParagraphStyle]) -> Table:
    rows = []

    for i in range(0, len(items), 2):
        row = []
        for title, body, color in items[i : i + 2]:
            row.append(_insight_card(title, body, color, styles))
        while len(row) < 2:
            row.append("")
        rows.append(row)

    table = Table(rows, colWidths=[CONTENT_WIDTH / 2, CONTENT_WIDTH / 2])
    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    return table


def _insight_card(title: str, body: str, color: str, styles: dict[str, ParagraphStyle]) -> Table:
    table = Table(
        [
            [Paragraph(f'<font color="{color}">{_html(title)}</font>', styles["table_cell_bold"])],
            [Paragraph(_html(body), styles["table_cell"])],
        ],
        colWidths=[CONTENT_WIDTH / 2 - 8],
    )
    table.setStyle(_panel_style(border=color))
    return table


def _detail_table(items: list[tuple[str, Any]], styles: dict[str, ParagraphStyle]) -> Table:
    rows = []

    for label, value in items:
        if _is_empty(value):
            continue
        rows.append(
            [
                Paragraph(_html(label), styles["table_header"]),
                Paragraph(_html(_compact_value(value)), styles["table_cell"]),
            ]
        )

    if not rows:
        rows = [
            [
                Paragraph("Data", styles["table_header"]),
                Paragraph("Not available", styles["table_cell"]),
            ]
        ]

    table = Table(rows, colWidths=[4.4 * cm, CONTENT_WIDTH - 4.4 * cm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#071225")),
                ("BACKGROUND", (1, 0), (1, -1), colors.HexColor(PANEL_2)),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor(BORDER)),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return table


def _modern_table(
    headers: list[str],
    rows: list[list[Any]] | list[tuple[Any, ...]],
    styles: dict[str, ParagraphStyle],
    col_widths: list[float],
) -> Table:
    table_rows = [[Paragraph(_html(header), styles["table_header"]) for header in headers]]

    for row in rows:
        table_rows.append([Paragraph(_html(_compact_value(cell)), styles["table_cell"]) for cell in row])

    table = Table(table_rows, colWidths=col_widths, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#071225")),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor(PANEL_2)),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor(PANEL_2), colors.HexColor(PANEL_3)]),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor(BORDER)),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return table


def _bullet_panel(items: list[str], color: str, styles: dict[str, ParagraphStyle]) -> Table:
    rows = []

    for item in items:
        if not safe_text(item, "").strip():
            continue
        rows.append(
            [
                Paragraph(f'<font color="{color}">●</font>', styles["table_cell_bold"]),
                Paragraph(_html(item), styles["table_cell"]),
            ]
        )

    if not rows:
        rows = [[Paragraph("", styles["table_cell"]), Paragraph("Not available", styles["table_cell"])]]

    table = Table(rows, colWidths=[0.7 * cm, CONTENT_WIDTH - 0.7 * cm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(PANEL_2)),
                ("BOX", (0, 0), (-1, -1), 0.65, colors.HexColor(BORDER)),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#172A44")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return table


def _panel_style(border: str = BORDER) -> TableStyle:
    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(PANEL_2)),
            ("BOX", (0, 0), (-1, -1), 0.7, colors.HexColor(border)),
            ("LEFTPADDING", (0, 0), (-1, -1), 9),
            ("RIGHTPADDING", (0, 0), (-1, -1), 9),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]
    )


def _normalize_mapping(value: Any) -> dict[str, Any]:
    if value is None:
        return {}

    if isinstance(value, dict):
        return {str(key): _normalize_value(item) for key, item in value.items()}

    try:
        return {str(key): _normalize_value(item) for key, item in dict(value).items()}
    except Exception:
        return {}


def _normalize_value(value: Any) -> Any:
    if isinstance(value, str):
        parsed = _parse_json(value)
        return parsed if parsed is not value else value

    if isinstance(value, dict):
        return {str(key): _normalize_value(item) for key, item in value.items()}

    if isinstance(value, list):
        return [_normalize_value(item) for item in value]

    return value


def _parse_json(value: str) -> Any:
    text = value.strip()

    if not text:
        return value

    if not ((text.startswith("{") and text.endswith("}")) or (text.startswith("[") and text.endswith("]"))):
        return value

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return value



def _normalize_risk_label_for_pdf(value: Any) -> str:
    """
    Normalize risk labels for PDF rendering.

    The risk engine uses:
    Minimal, Low, Moderate, High, Critical.

    Older PDF code may still expect:
    Low, Medium, High, Critical.

    This function keeps Minimal visible as Minimal while making lookups safe.
    """
    text_value = str(value or "").strip()

    if not text_value:
        return "Unknown"

    normalized = text_value.lower()

    if normalized == "minimal":
        return "Minimal"
    if normalized == "low":
        return "Low"
    if normalized in {"moderate", "medium"}:
        return "Moderate"
    if normalized == "high":
        return "High"
    if normalized == "critical":
        return "Critical"

    return text_value.title()


def _as_dict(value: Any) -> dict[str, Any]:
    normalized = _normalize_value(value)
    return normalized if isinstance(normalized, dict) else {}



def _assessment_scope(scan: dict[str, Any]) -> dict[str, Any]:
    metadata = _as_dict(scan.get("metadata"))
    scope = scan.get("assessment_scope") or scan.get("scope") or metadata.get("assessment_scope")

    if isinstance(scope, dict) and scope:
        return scope

    return {
        "profile": "basic",
        "profile_label": "Basic",
        "assessment_type": "Basic External Website Security Posture Assessment",
        "coverage": [
            "Website availability and HTTP response status",
            "HTTPS usage and TLS certificate validity",
            "Core browser security headers",
            "DNS and email-security records including SPF, DMARC, and CAA",
            "Basic technology evidence from response headers",
            "Explainable risk scoring and PDF reporting",
        ],
        "limitations": [
            "No exploitation or intrusive vulnerability testing",
            "No authenticated application testing",
            "No deep crawling of all pages",
            "No port or service scanning",
            "No subdomain enumeration",
            "No full penetration test",
            "No full vulnerability assessment",
        ],
    }


def _scope_list_text(scope: dict[str, Any], key: str, fallback: str) -> str:
    value = scope.get(key)

    if isinstance(value, list):
        cleaned = [safe_text(item, "").strip() for item in value if safe_text(item, "").strip()]
        if cleaned:
            return "; ".join(cleaned)

    if isinstance(value, str) and value.strip():
        return value.strip()

    return fallback


def _pretty(value: Any) -> str:
    text = safe_text(value, "Unknown")
    return text.replace("_", " ").lower().title()


def _yes_no(value: Any) -> str:
    if isinstance(value, bool):
        return "Yes" if value else "No"

    text = str(value).strip().lower()

    if text in {"true", "1", "yes", "present", "enabled", "valid"}:
        return "Yes"

    if text in {"false", "0", "no", "missing", "disabled", "invalid"}:
        return "No"

    return safe_text(value)


def _format_datetime(value: Any) -> str:
    if value is None:
        return "Not available"

    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M UTC")

    text = str(value).strip()

    if not text:
        return "Not available"

    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed.strftime("%Y-%m-%d %H:%M UTC")
    except ValueError:
        return text


def _format_response_time(value: Any) -> str:
    if _is_empty(value):
        return "Not available"

    try:
        return f"{float(value):.0f} ms"
    except (TypeError, ValueError):
        return safe_text(value)


def _compact_value(value: Any) -> str:
    if isinstance(value, dict):
        return ", ".join(f"{clean_key(k)}: {safe_text(v)}" for k, v in value.items()) or "Not available"

    if isinstance(value, list):
        return ", ".join(safe_text(item) for item in value if not _is_empty(item)) or "Not available"

    return safe_text(value)


def _is_empty(value: Any) -> bool:
    if value is None:
        return True

    if isinstance(value, str) and not value.strip():
        return True

    if isinstance(value, (list, tuple, set, dict)) and len(value) == 0:
        return True

    return False


def _html(value: Any) -> str:
    return escape(safe_text(value, ""))


def clean_key(value: Any) -> str:
    text = str(value or "Unknown").replace("_", " ").replace("-", " ").strip()
    return text.title() if text else "Unknown"


def _display_rating(scan: dict[str, Any]) -> str:
    value = scan.get("security_rating") or scan.get("grade")
    if value:
        return _pretty(value)
    return security_rating_from_score(scan.get("security_score"))



def _display_risk(scan: dict[str, Any]) -> str:
    value = scan.get("risk_level")

    if value:
        normalized = str(value).strip().lower()

        if normalized == "minimal":
            return "Minimal"
        if normalized == "low":
            return "Low"
        if normalized in {"moderate", "medium"}:
            return "Moderate"
        if normalized == "high":
            return "High"
        if normalized == "critical":
            return "Critical"

        return _pretty(value)

    return risk_level_from_score(scan.get("security_score"))

def _score_color(score: Any) -> str:
    try:
        value = int(score)
    except (TypeError, ValueError):
        return MUTED

    if value >= 70:
        return BRAND_SUCCESS
    if value >= 50:
        return BRAND_WARNING
    return BRAND_DANGER


def _rating_color(rating: str) -> str:
    normalized = rating.lower()

    if normalized in {"excellent", "strong"}:
        return BRAND_SUCCESS
    if normalized == "moderate":
        return BRAND_WARNING
    if normalized in {"weak", "critical"}:
        return BRAND_DANGER

    return MUTED



def _risk_color(risk: str) -> str:
    normalized = str(risk or "").strip().lower()

    if normalized in {"minimal", "low"}:
        return BRAND_SUCCESS
    if normalized in {"moderate", "medium"}:
        return BRAND_WARNING
    if normalized in {"high", "critical"}:
        return BRAND_DANGER

    return MUTED

def _extract_executive_summary(scan: dict[str, Any], website_check: dict[str, Any]) -> str:
    for source in (
        scan,
        _as_dict(website_check.get("risk_assessment")),
        _as_dict(website_check.get("metadata")),
    ):
        for key in ("executive_summary", "risk_engine_summary", "summary"):
            value = source.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

    return ""



def _posture_sentence(score: Any) -> str:
    rating = security_rating_from_score(score)

    if rating == "Excellent":
        return "The website demonstrates an excellent observable security posture with strong baseline controls."
    if rating == "Strong":
        return "The website demonstrates a strong observable security posture with limited improvements recommended."
    if rating == "Moderate":
        return "The website has a moderate security posture. Several improvements are recommended to reduce exposure and strengthen the baseline."
    if rating == "Weak":
        return "The website shows a weak security posture. Remediation should be prioritized before the asset is considered client-ready."
    if rating == "Critical":
        return "The website shows a critical security posture. Urgent review and remediation are recommended."

    return "The scan did not provide enough score data to determine a complete security posture."

def _main_risk_sentence(scan: dict[str, Any], website_check: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    report_findings = _collect_report_findings(scan, website_check, findings)

    if report_findings:
        titles = [safe_text(item.get("title")) for item in report_findings[:2]]
        return "Primary concerns include: " + "; ".join(titles) + "."

    return "No detailed risk findings were recorded by the scanner for this scan."


def _positive_signal_sentence(website_check: dict[str, Any]) -> str:
    signals = _collect_positive_signals(website_check)

    if signals:
        return "Observed positive controls include: " + "; ".join(signals[:2]) + "."

    return "No positive security signals were recorded by the scanner for this scan."


def _recommendation_sentence(scan: dict[str, Any], website_check: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    recommendations = _collect_priority_recommendations(scan, website_check, findings)

    if recommendations:
        return recommendations[0]

    return "No scanner-generated priority recommendation was recorded for this scan."


def _collect_report_findings(scan: dict[str, Any], website_check: dict[str, Any], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []

    for finding in findings:
        collected.append(
            {
                "title": finding.get("title") or finding.get("name") or finding.get("finding_type") or "Security finding",
                "risk": finding.get("severity") or finding.get("risk_level") or finding.get("risk") or _display_risk(scan),
                "why": finding.get("description") or finding.get("why_it_matters") or finding.get("summary") or "This item may affect the target security posture.",
                "recommendation": finding.get("recommendation") or finding.get("remediation") or finding.get("action") or "Review and remediate according to security best practices.",
                "evidence": finding.get("evidence") or finding.get("evidence_summary") or finding.get("technical_evidence") or "Scan evidence available in technical section.",
            }
        )

    risk_assessment = _as_dict(website_check.get("risk_assessment"))
    priority_actions = risk_assessment.get("priority_actions") or risk_assessment.get("priority_recommendations")

    if isinstance(priority_actions, list):
        for action in priority_actions:
            if isinstance(action, dict):
                collected.append(
                    {
                        "title": action.get("title") or action.get("action") or "Priority action",
                        "risk": action.get("severity") or action.get("risk") or _display_risk(scan),
                        "why": action.get("why_it_matters") or action.get("summary") or "This action can improve the target security posture.",
                        "recommendation": action.get("recommendation") or action.get("action") or "Review this priority action.",
                        "evidence": action.get("evidence") or "Generated from SecureSight360 risk analysis.",
                    }
                )
            else:
                collected.append(
                    {
                        "title": "Priority action",
                        "risk": _display_risk(scan),
                        "why": "This action can improve the target security posture.",
                        "recommendation": safe_text(action),
                        "evidence": "Generated from SecureSight360 risk analysis.",
                    }
                )

    return collected


def _collect_positive_signals(website_check: dict[str, Any]) -> list[str]:
    signals: list[str] = []

    ssl = _as_dict(website_check.get("ssl") or website_check.get("tls"))
    dns = _as_dict(website_check.get("dns"))
    headers = _as_dict(website_check.get("headers") or website_check.get("security_headers"))
    availability = _as_dict(website_check.get("availability"))

    if _yes_no(ssl.get("https_enabled")) == "Yes":
        signals.append("HTTPS is enabled")

    if _yes_no(ssl.get("certificate_valid")) == "Yes":
        signals.append("SSL/TLS certificate appears valid")

    if _yes_no(dns.get("spf_present")) == "Yes":
        signals.append("SPF email security record is present")

    if _yes_no(dns.get("dmarc_present")) == "Yes":
        signals.append("DMARC email security record is present")

    if not _is_empty(availability.get("status_code")):
        signals.append("Website availability evidence was captured")

    checked_headers = headers.get("checked_headers")
    if isinstance(checked_headers, dict):
        present = [
            str(header)
            for header, info in checked_headers.items()
            if isinstance(info, dict) and str(info.get("status", "")).lower() in {"present", "configured"}
        ]

        if present:
            signals.append(f"Security headers present: {', '.join(present[:3])}")

    risk_assessment = _as_dict(website_check.get("risk_assessment"))
    engine_signals = risk_assessment.get("positive_security_signals") or risk_assessment.get("positive_signals")

    if isinstance(engine_signals, list):
        for item in engine_signals:
            if isinstance(item, dict):
                text = item.get("title") or item.get("summary") or item.get("signal")
                if text:
                    signals.append(safe_text(text))
            elif item:
                signals.append(safe_text(item))

    return _deduplicate(signals)


def _collect_priority_recommendations(scan: dict[str, Any], website_check: dict[str, Any], findings: list[dict[str, Any]]) -> list[str]:
    recommendations: list[str] = []

    for finding in _collect_report_findings(scan, website_check, findings):
        recommendation = safe_text(finding.get("recommendation"), "")
        if recommendation:
            recommendations.append(recommendation)

    risk_assessment = _as_dict(website_check.get("risk_assessment"))
    priority_actions = risk_assessment.get("priority_actions") or risk_assessment.get("priority_recommendations")

    if isinstance(priority_actions, list):
        for action in priority_actions:
            if isinstance(action, dict):
                recommendations.append(safe_text(action.get("recommendation") or action.get("action"), ""))
            else:
                recommendations.append(safe_text(action, ""))

    return _deduplicate([item for item in recommendations if item])


def _risk_breakdown_rows(scan: dict[str, Any], website_check: dict[str, Any], findings: list[dict[str, Any]]) -> list[list[str]]:
    ssl = _as_dict(website_check.get("ssl") or website_check.get("tls"))
    dns = _as_dict(website_check.get("dns"))
    headers = _as_dict(website_check.get("headers") or website_check.get("security_headers"))

    return [
        [
            "Overall Risk",
            _display_risk(scan),
            "Derived from the security score and observable control gaps.",
        ],
        [
            "Transport Security",
            "HTTPS enabled" if _yes_no(ssl.get("https_enabled")) == "Yes" else "Needs review",
            "Valid HTTPS/TLS reduces interception and downgrade risks.",
        ],
        [
            "Security Headers",
            _headers_posture(headers),
            "Headers help reduce browser-based attacks such as clickjacking and cross-site scripting.",
        ],
        [
            "DNS / Email Security",
            _dns_posture(dns),
            "SPF and DMARC reduce spoofing and phishing abuse of the domain.",
        ],
        [
            "Findings",
            f"{len(_collect_report_findings(scan, website_check, findings))} finding(s)",
            "Findings should be prioritized based on impact and business criticality.",
        ],
    ]


def _headers_posture(headers: dict[str, Any]) -> str:
    checked_headers = headers.get("checked_headers")

    if isinstance(checked_headers, dict):
        missing = [
            str(header)
            for header, info in checked_headers.items()
            if isinstance(info, dict) and str(info.get("status", "")).lower() == "missing"
        ]

        if missing:
            return f"{len(missing)} missing header(s)"

        return "No missing headers observed"

    return "Not available"


def _dns_posture(dns: dict[str, Any]) -> str:
    spf = _yes_no(dns.get("spf_present"))
    dmarc = _yes_no(dns.get("dmarc_present"))

    if spf == "Yes" and dmarc == "Yes":
        return "SPF and DMARC present"
    if spf == "Yes" or dmarc == "Yes":
        return "Partially configured"
    if spf == "No" or dmarc == "No":
        return "Needs review"

    return "Not available"


def _headers_summary(headers: dict[str, Any]) -> list[tuple[str, Any]]:
    if not headers:
        return [("Security Headers", "Not available")]

    checked_headers = headers.get("checked_headers")

    if isinstance(checked_headers, dict):
        rows: list[tuple[str, Any]] = []

        for header_name, header_info in checked_headers.items():
            if isinstance(header_info, dict):
                rows.append((header_name, header_info.get("status") or header_info.get("value") or "Observed"))
            else:
                rows.append((header_name, header_info))

        return rows or [("Security Headers", "Not available")]

    important_headers = [
        "content_security_policy",
        "strict_transport_security",
        "x_frame_options",
        "x_content_type_options",
        "referrer_policy",
        "permissions_policy",
    ]

    rows = []

    for header in important_headers:
        if header in headers:
            rows.append((header.replace("_", "-").title(), headers.get(header)))

    if rows:
        return rows

    return [(clean_key(key), value) for key, value in headers.items()] or [("Security Headers", "Not available")]


def _deduplicate(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []

    for item in items:
        cleaned = safe_text(item, "").strip()
        key = cleaned.lower()

        if not cleaned or key in seen:
            continue

        seen.add(key)
        result.append(cleaned)

    return result
