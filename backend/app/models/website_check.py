from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, TimestampMixin


class WebsiteCheck(Base, TimestampMixin):
    """
    Stores detailed website security check results for one website scan.

    This model keeps structured evidence from the website scanner, including:
    - Website availability
    - HTTP response information
    - HTTPS status
    - SSL/TLS certificate details
    - Security headers
    - DNS records
    - Email security records such as SPF, DKIM, and DMARC
    - Basic technology detection from safe headers only

    Each WebsiteCheck belongs to exactly one Scan.
    """

    __tablename__ = "website_checks"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
        comment="One website check result belongs to one scan.",
    )

    original_url: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        comment="Original URL entered by the user.",
    )

    final_url: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
        comment="Final URL after redirects, if applicable.",
    )

    domain: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Extracted domain name from the target URL.",
    )

    is_available: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="True if the website responds successfully.",
    )

    http_status_code: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="HTTP response status code such as 200, 301, 403, or 500.",
    )

    response_time_ms: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Website response time in milliseconds.",
    )

    https_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="True if the website uses HTTPS.",
    )

    ssl_valid: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
        comment="True if SSL/TLS certificate is valid.",
    )

    ssl_issuer: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="SSL/TLS certificate issuer.",
    )

    ssl_subject: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="SSL/TLS certificate subject.",
    )

    ssl_expiry_date: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="SSL/TLS certificate expiry date.",
    )

    security_headers: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
        comment="Detected and missing security headers.",
    )

    dns_records: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
        comment="DNS records such as A, AAAA, MX, NS, and TXT.",
    )

    spf_found: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
        comment="True if SPF record is found.",
    )

    dmarc_found: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
        comment="True if DMARC record is found.",
    )

    dkim_guidance: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="DKIM guidance because DKIM selector discovery is not always reliable.",
    )

    technologies_detected: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
        comment="Basic technology information detected from safe headers only.",
    )

    raw_headers: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
        comment="Raw HTTP response headers collected during safe website checks.",
    )

    scan = relationship(
        "Scan",
        backref="website_check",
    )

    def __repr__(self) -> str:
        return (
            f"<WebsiteCheck id={self.id} scan_id={self.scan_id} "
            f"domain={self.domain!r} https_enabled={self.https_enabled}>"
        )