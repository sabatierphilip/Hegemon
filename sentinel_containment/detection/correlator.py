from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class CorrelatedAlert:
    summary: str
    severity: int
    tags: list[str]
    details: dict[str, Any]


class AlertCorrelator:
    def correlate(self, rule_alerts: list[Any], baseline_alerts: list[Any]) -> CorrelatedAlert | None:
        if not rule_alerts and not baseline_alerts:
            return None
        severity = 0
        tags = []
        for alert in rule_alerts:
            severity += alert.severity
            tags.append("rule")
        for alert in baseline_alerts:
            severity += alert.severity
            tags.append("anomaly")
        severity = min(100, severity // max(1, len(rule_alerts) + len(baseline_alerts)))
        summary = f"{len(rule_alerts)} rule alerts, {len(baseline_alerts)} baseline anomalies"
        return CorrelatedAlert(summary=summary, severity=severity, tags=sorted(set(tags)), details={
            "rule_alerts": [a.__dict__ for a in rule_alerts],
            "baseline_alerts": [a.__dict__ for a in baseline_alerts],
        })
