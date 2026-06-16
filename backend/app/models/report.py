from enum import Enum

from sqlalchemy import Enum as SqlEnum
from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, TimestampMixin
from app.models.scan import enum_values


class ReportFormat(str, Enum):
    """
    Supported report output formats.
    """

    PDF = "pdf"
    HTML = "html"


class ReportStatus(str, Enum):
    """
    Report generation lifecycle status.
    """

    PENDING = "pending"
    GENERATED = "generated"
    FAILED = "failed"


class Report(Base, TimestampMixin):
    """
    Stores metadata for a generated SecureSight360 report.

    The actual report file will be stored in the reports directory.
    This table stores report metadata such as format, status,
    file path, file size, and error details.
    """

    __tablename__ = "reports"

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
        comment="Each scan can have one generated report for now.",
    )

    report_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Human-readable report name.",
    )

    report_format: Mapped[ReportFormat] = mapped_column(
        SqlEnum(
            ReportFormat,
            values_callable=enum_values,
            native_enum=False,
            validate_strings=True,
            name="report_format_enum",
        ),
        nullable=False,
        default=ReportFormat.PDF,
        comment="Generated report format.",
    )

    status: Mapped[ReportStatus] = mapped_column(
        SqlEnum(
            ReportStatus,
            values_callable=enum_values,
            native_enum=False,
            validate_strings=True,
            name="report_status_enum",
        ),
        nullable=False,
        default=ReportStatus.PENDING,
        index=True,
        comment="Report generation status.",
    )

    file_path: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
        comment="Local path of the generated report file.",
    )

    file_size_bytes: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Generated report file size in bytes.",
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Stores report generation failure reason if any.",
    )

    scan = relationship(
        "Scan",
        backref="report",
    )

    def __repr__(self) -> str:
        return (
            f"<Report id={self.id} scan_id={self.scan_id} "
            f"format={self.report_format.value} status={self.status.value}>"
        )