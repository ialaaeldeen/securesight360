from enum import Enum

from sqlalchemy import ForeignKey, Index, Integer, String, Text
from sqlalchemy import Enum as SqlEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, TimestampMixin
from app.models.scan import enum_values


class FindingSeverity(str, Enum):
    """
    Finding severity levels used across SecureSight360.

    These values will be used for:
    - Dashboard cards
    - Report severity tables
    - Risk scoring
    - Filtering findings
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(str, Enum):
    """
    Main finding categories.

    Categories help organize findings in the dashboard and reports.
    """

    WEBSITE_SECURITY = "website_security"
    SSL_TLS = "ssl_tls"
    SECURITY_HEADERS = "security_headers"
    DNS_SECURITY = "dns_security"
    EMAIL_SECURITY = "email_security"
    NETWORK_EXPOSURE = "network_exposure"
    SERVICE_EXPOSURE = "service_exposure"
    MISCONFIGURATION = "misconfiguration"
    COMPLIANCE = "compliance"
    GENERAL = "general"


class Finding(Base, TimestampMixin):
    """
    Stores one security finding discovered during a scan.

    A finding includes:
    - Title
    - Severity
    - Technical description
    - Evidence
    - Business impact
    - Recommendation
    - Compliance/framework mapping

    Example:
        Finding:
            title = "Missing Content-Security-Policy Header"
            severity = "medium"
            category = "security_headers"
            owasp_mapping = "A05: Security Misconfiguration"
    """

    __tablename__ = "findings"

    __table_args__ = (
        Index("ix_findings_scan_severity", "scan_id", "severity"),
        Index("ix_findings_scan_category", "scan_id", "category"),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Short finding title shown in dashboard and reports.",
    )

    severity: Mapped[FindingSeverity] = mapped_column(
        SqlEnum(
            FindingSeverity,
            values_callable=enum_values,
            native_enum=False,
            validate_strings=True,
            name="finding_severity_enum",
        ),
        nullable=False,
        index=True,
    )

    category: Mapped[FindingCategory] = mapped_column(
        SqlEnum(
            FindingCategory,
            values_callable=enum_values,
            native_enum=False,
            validate_strings=True,
            name="finding_category_enum",
        ),
        nullable=False,
        index=True,
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Technical explanation of the finding.",
    )

    evidence: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Observed technical evidence, such as missing header or open port.",
    )

    business_impact: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Business or operational impact of the finding.",
    )

    recommendation: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Recommended remediation steps.",
    )

    owasp_mapping: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="OWASP Top 10 mapping where applicable.",
    )

    nist_mapping: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="NIST Cybersecurity Framework mapping where applicable.",
    )

    mitre_mapping: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="MITRE ATT&CK mapping where applicable.",
    )

    scan = relationship(
        "Scan",
        backref="findings",
    )

    def __repr__(self) -> str:
        return (
            f"<Finding id={self.id} scan_id={self.scan_id} "
            f"severity={self.severity.value} title={self.title!r}>"
        )