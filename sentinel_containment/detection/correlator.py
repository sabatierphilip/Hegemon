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
    def __init__(
        self,
        model_spike_weight: float = 1.0,
        egress_weight: float = 1.3,
        privilege_weight: float = 2.2,
        anomaly_weight: float = 0.9,
        correlation_bonus: int = 10,
    ):
        self.model_spike_weight = model_spike_weight
        self.egress_weight = egress_weight
        self.privilege_weight = privilege_weight
        self.anomaly_weight = anomaly_weight
        self.correlation_bonus = correlation_bonus

    def correlate(self, rule_alerts: list[Any], baseline_alerts: list[Any]) -> CorrelatedAlert | None:
        if not rule_alerts and not baseline_alerts:
            return None

        tags = []
        weighted_score = 0.0

        for alert in rule_alerts:
            tags.append("rule")
            rule_name = str(getattr(alert, "rule", "")).lower()
            weight = self.model_spike_weight
            if "egress" in rule_name or "external" in rule_name:
                weight = self.egress_weight
            if "iam" in rule_name or "privilege" in rule_name:
                weight = self.privilege_weight
            weighted_score += alert.severity * weight

        for alert in baseline_alerts:
            tags.append("anomaly")
            weighted_score += alert.severity * self.anomaly_weight

        if rule_alerts and baseline_alerts:
            weighted_score += self.correlation_bonus

        total_alerts = max(1, len(rule_alerts) + len(baseline_alerts))
        severity = min(100, int(weighted_score / total_alerts))
        summary = f"{len(rule_alerts)} rule alerts, {len(baseline_alerts)} baseline anomalies"

        compressed_rule_alerts = [a.__dict__ for a in rule_alerts]
        suppressed_events = sum(int(a.get("dedup_hits", 1)) - 1 for a in compressed_rule_alerts)

        return CorrelatedAlert(
            summary=summary,
            severity=severity,
            tags=sorted(set(tags)),
            details={
                "rule_alerts": compressed_rule_alerts,
                "baseline_alerts": [a.__dict__ for a in baseline_alerts],
                "risk_formula": {
                    "model_spike_weight": self.model_spike_weight,
                    "egress_weight": self.egress_weight,
                    "privilege_weight": self.privilege_weight,
                    "anomaly_weight": self.anomaly_weight,
                    "correlation_bonus": self.correlation_bonus,
                },
                "suppressed_rule_events": max(0, suppressed_events),
            },
        )
