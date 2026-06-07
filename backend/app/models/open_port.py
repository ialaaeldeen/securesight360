from enum import Enum

from sqlalchemy import CheckConstraint, ForeignKey, Index, Integer, String, Text
from sqlalchemy import Enum as SqlEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, TimestampMixin
from app.models.scan import enum_values


class PortRiskLevel(str, Enum):
    """
    Risk level assigned to an exposed/open port.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class NetworkProtocol(str, Enum):
    """
    Supported network protocols for port scan results.
    """

    TCP = "tcp"
    UDP = "udp"


class OpenPort(Base, TimestampMixin):
    """
    Stores one open port discovered during an authorized network scan.

    This model stores network exposure evidence from tools such as Nmap,
    including host, port number, protocol, detected service, service version,
    risk level, risk reason, and remediation recommendation.

    Example:
        host = "192.168.56.101"
        port = 22
        protocol = "tcp"
        service = "ssh"
        risk_level = "medium"
    """

    __tablename__ = "open_ports"

    __table_args__ = (
        CheckConstraint(
            "port >= 1 AND port <= 65535",
            name="ck_open_ports_port_range",
        ),
        Index("ix_open_ports_scan_host", "scan_id", "host"),
        Index("ix_open_ports_scan_risk", "scan_id", "risk_level"),
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
        comment="Related scan ID.",
    )

    host: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Scanned host IP address, hostname, or lab target.",
    )

    port: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        index=True,
        comment="Open port number from 1 to 65535.",
    )

    protocol: Mapped[NetworkProtocol] = mapped_column(
        SqlEnum(
            NetworkProtocol,
            values_callable=enum_values,
            native_enum=False,
            validate_strings=True,
            name="network_protocol_enum",
        ),
        nullable=False,
        default=NetworkProtocol.TCP,
        index=True,
        comment="Transport protocol, usually TCP or UDP.",
    )

    service: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        index=True,
        comment="Detected service name such as ssh, http, smb, mysql, or rdp.",
    )

    service_product: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Detected service product such as OpenSSH, Apache httpd, or Microsoft IIS.",
    )

    service_version: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Detected service version where available.",
    )

    risk_level: Mapped[PortRiskLevel] = mapped_column(
        SqlEnum(
            PortRiskLevel,
            values_callable=enum_values,
            native_enum=False,
            validate_strings=True,
            name="port_risk_level_enum",
        ),
        nullable=False,
        default=PortRiskLevel.INFO,
        index=True,
        comment="Risk level assigned to this exposed port.",
    )

    risk_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Explanation of why this port received its risk level.",
    )

    recommendation: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Recommended action to reduce exposure risk.",
    )

    scan = relationship(
        "Scan",
        backref="open_ports",
    )

    def __repr__(self) -> str:
        return (
            f"<OpenPort id={self.id} scan_id={self.scan_id} "
            f"host={self.host!r} port={self.port}/{self.protocol.value} "
            f"risk={self.risk_level.value}>"
        )