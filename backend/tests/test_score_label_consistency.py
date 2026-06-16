from app.api.v1.website import _history_score_to_grade, _history_score_to_risk_level
from app.reports.report_helpers import risk_level_from_score, security_rating_from_score
from app.scoring.risk_engine import _grade_for_score, _risk_level_for_score


def test_score_label_thresholds_are_consistent_across_backend_layers():
    cases = [
        (100, "Excellent", "minimal"),
        (90, "Excellent", "minimal"),
        (89, "Strong", "low"),
        (80, "Strong", "low"),
        (79, "Moderate", "moderate"),
        (70, "Moderate", "moderate"),
        (69, "Weak", "high"),
        (40, "Weak", "high"),
        (39, "Critical", "critical"),
        (0, "Critical", "critical"),
    ]

    for score, expected_grade, expected_risk in cases:
        assert _grade_for_score(score) == expected_grade
        assert _risk_level_for_score(score).value == expected_risk

        assert security_rating_from_score(score) == expected_grade
        assert risk_level_from_score(score).lower() == expected_risk

        assert _history_score_to_grade(score) == expected_grade
        assert _history_score_to_risk_level(score) == expected_risk