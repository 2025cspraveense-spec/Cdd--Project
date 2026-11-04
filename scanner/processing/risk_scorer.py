"""
Risk Scoring Engine
Calculates CVSS-weighted numerical risk scores (0 to 100) and letter grades (A+ to F).
"""

from typing import Tuple
from scanner.models import ScanSummary


class RiskScorer:
    """Computes project risk metrics and security grading."""

    # Risk weights per finding severity
    WEIGHT_CRITICAL = 25.0
    WEIGHT_HIGH = 10.0
    WEIGHT_MEDIUM = 3.0
    WEIGHT_LOW = 1.0

    @classmethod
    def calculate_score_and_grade(cls, summary: ScanSummary) -> Tuple[float, str]:
        """
        Calculates numerical risk score (0 to 100) and corresponding letter grade.
        0.0 = Zero vulnerabilities detected (Grade A+)
        100.0 = Maximum risk exposure (Grade F)
        """
        raw_score = (
            (summary.critical * cls.WEIGHT_CRITICAL)
            + (summary.high * cls.WEIGHT_HIGH)
            + (summary.medium * cls.WEIGHT_MEDIUM)
            + (summary.low * cls.WEIGHT_LOW)
        )

        # Cap risk score at 100.0
        risk_score = min(100.0, round(raw_score, 1))

        # Determine letter grade
        if risk_score == 0.0:
            grade = "A+"
        elif risk_score <= 15.0:
            grade = "A"
        elif risk_score <= 35.0:
            grade = "B"
        elif risk_score <= 60.0:
            grade = "C"
        elif risk_score <= 80.0:
            grade = "D"
        else:
            grade = "F"

        return risk_score, grade
