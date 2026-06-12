from datetime import datetime
from enum import Enum

from sqlalchemy import Boolean, CheckConstraint, DateTime, Enum as SqlEnum
from sqlalchemy import Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, TimestampMixin


class TargetType(str, Enum):
    """
    Supported target categories.
    """

    WEBSITE = "website"
    NETWORK = "network"


class ScanType(str, Enum):
    """
    Supported scan types.

    More scan types can be added later without changing
    the main scan table structure.
    """

    WEBSITE_BASIC = "website_basic"
    NETWORK_PORT_SCAN = "network_port_scan"
    COMBINED_ASSESSMENT = "combined_assessment"


class ScanStatus(str, Enum):
    """
    Scan lifecycle status.
    """

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


def enum_values(enum_class: type[Enum]) -> list[str]:
    """
    Store enum values in the database instead of enum names.

    Example:
        Store 'website' instead of 'WEBSITE'.
    """

    return [member.value for member in enum_class]


class Scan(Base, TimestampMixin):
    """
    Stores one CyberShield360 scan session.

    A scan represents one assessment request against an authorized target.
    Examples:
        - Website scan for https://example.com
        - Network scan for 192.168.56.101
        - Lab subnet scan for 192.168.56.0/24

    This table stores the scan metadata, authorization confirmation,
    status, score, timing, and error details.
    """

    __tablename__ = "scans"

    __table_args__ = (
        CheckConstraint(
            "security_score IS NULL OR security_score BETWEEN 0 AND 100",
            name="ck_scans_security_score_range",
        ),
        Index("ix_scans_target_type_status", "target_type", "status"),
        Index("ix_scans_scan_type_status", "scan_type", "status"),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    user_id: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        index=True,
        comment="Authenticated user ID that started this scan.",
    )

    user_email: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        index=True,
        comment="Snapshot of authenticated user email when the scan was started.",
    )

    user_full_name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Snapshot of authenticated user full name when the scan was started.",
    )
    target: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        index=True,
        comment="Website URL, IP address, hostname, or authorized subnet.",
    )

    target_type: Mapped[TargetType] = mapped_column(
        SqlEnum(
            TargetType,
            values_callable=enum_values,
            native_enum=False,
            validate_strings=True,
            name="target_type_enum",
        ),
        nullable=False,
        index=True,
    )

    scan_type: Mapped[ScanType] = mapped_column(
        SqlEnum(
            ScanType,
            values_callable=enum_values,
            native_enum=False,
            validate_strings=True,
            name="scan_type_enum",
        ),
        nullable=False,
        index=True,
    )

    status: Mapped[ScanStatus] = mapped_column(
        SqlEnum(
            ScanStatus,
            values_callable=enum_values,
            native_enum=False,
            validate_strings=True,
            name="scan_status_enum",
        ),
        nullable=False,
        default=ScanStatus.PENDING,
        index=True,
    )

    security_score: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Final calculated security score from 0 to 100.",
    )

    authorization_confirmed: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="True only when the user confirms ownership or permission.",
    )

    authorization_text: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Exact authorization disclaimer accepted by the user.",
    )

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Stores failure reason if the scan fails.",
    )

    def __repr__(self) -> str:
        return (
            f"<Scan id={self.id} target={self.target!r} "
            f"target_type={self.target_type.value} "
            f"scan_type={self.scan_type.value} "
            f"status={self.status.value}>"
        )
