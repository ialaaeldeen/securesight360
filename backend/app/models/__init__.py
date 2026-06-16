"""
SecureSight360 database models.

This package imports all SQLAlchemy models so they are registered
with SQLAlchemy metadata and can be detected by Alembic migrations
or database initialization scripts.

Do not place business logic in this file.
Only import model classes and related enums here.
"""

from app.models.finding import Finding, FindingCategory, FindingSeverity
from app.models.open_port import NetworkProtocol, OpenPort, PortRiskLevel
from app.models.report import Report, ReportFormat, ReportStatus
from app.models.scan import Scan, ScanStatus, ScanType, TargetType
from app.models.website_check import WebsiteCheck

__all__ = [
    # Scan models
    "Scan",
    "ScanStatus",
    "ScanType",
    "TargetType",

    # Finding models
    "Finding",
    "FindingCategory",
    "FindingSeverity",

    # Website scan models
    "WebsiteCheck",

    # Network scan models
    "OpenPort",
    "NetworkProtocol",
    "PortRiskLevel",

    # Report models
    "Report",
    "ReportFormat",
    "ReportStatus",
]