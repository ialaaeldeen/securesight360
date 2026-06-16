from typing import Any


def safe_text(value: Any, default: str = "Not available") -> str:
    """
    Convert report values into safe, readable plain text.

    This helper intentionally does not HTML-escape text because the PDF builder
    already escapes text before placing it inside ReportLab Paragraph objects.
    """
    if value is None:
        return default

    if isinstance(value, (list, tuple, set)):
        text = ", ".join(str(item).strip() for item in value if item not in (None, ""))
    elif isinstance(value, dict):
        parts = []
        for key, item in value.items():
            if item not in (None, "", [], {}):
                parts.append(f"{key}: {item}")
        text = "; ".join(parts)
    else:
        text = str(value)

    text = " ".join(text.strip().split())

    return text if text else default


def security_rating_from_score(score: Any) -> str:
    try:
        value = int(score)
    except (TypeError, ValueError):
        return "Unrated"

    if value >= 90:
        return "Excellent"
    if value >= 80:
        return "Strong"
    if value >= 70:
        return "Moderate"
    if value >= 40:
        return "Weak"
    return "Critical"


def risk_level_from_score(score: Any) -> str:
    try:
        value = int(score)
    except (TypeError, ValueError):
        return "Unknown"

    if value >= 90:
        return "Minimal"
    if value >= 80:
        return "Low"
    if value >= 70:
        return "Moderate"
    if value >= 40:
        return "High"
    return "Critical"


def format_score(score: Any) -> str:
    try:
        value = int(score)
    except (TypeError, ValueError):
        return "Unrated"

    return f"{value}/100"
