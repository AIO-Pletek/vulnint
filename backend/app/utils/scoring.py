"""CVSS severity mapping and risk scoring."""
from __future__ import annotations

from typing import Optional

from app.models.vulnerability import Severity


def severity_from_cvss(score: Optional[float]) -> Severity:
    if score is None:
        return Severity.none
    if score >= 9.0:
        return Severity.critical
    if score >= 7.0:
        return Severity.high
    if score >= 4.0:
        return Severity.medium
    if score > 0.0:
        return Severity.low
    return Severity.none


def severity_rank(s: Severity | str) -> int:
    order = {
        Severity.none: 0,
        Severity.low: 1,
        Severity.medium: 2,
        Severity.high: 3,
        Severity.critical: 4,
    }
    if isinstance(s, str):
        try:
            s = Severity(s)
        except Exception:
            return 0
    return order.get(s, 0)


def compute_risk_score(
    cvss: Optional[float],
    kev: bool,
    exploit_available: bool,
    affected_servers: int = 0,
    production_affected: bool = False,
) -> float:
    """Composite risk score combining CVSS, exploitation, and exposure.

    Range: 0..100. Aligns roughly with CVSS but boosts KEV/exploit/production.
    This is a heuristic, not a substitute for EPSS/SSVC; it can be replaced
    by an ML model later (see ai_prioritization service).
    """
    base = (cvss or 0.0) * 8.0  # 0..80 from CVSS
    if kev:
        base += 15.0
    if exploit_available:
        base += 8.0
    if production_affected:
        base += 7.0
    if affected_servers > 0:
        # log-ish boost — many affected servers raise risk but cap at +10
        import math
        base += min(10.0, math.log10(affected_servers + 1) * 5.0)
    return round(min(100.0, base), 2)
