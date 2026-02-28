from __future__ import annotations

from collections import defaultdict
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
        model_spike_weight: float = 0.25,
        egress_weight: float = 0.30,
        privilege_weight: float = 0.45,
        correlation_bonus: float = 10.0,
    ):
        self.model_spike_weight = model_spike_weight
        self.egress_weight = egress_weight
        self.privilege_weight = privilege_weight
        self.correlation_bonus = correlation_bonus

    def correlate(self, rule_alerts: list[Any], baseline_alerts: list[Any]) -> CorrelatedAlert | None:
        if not rule_alerts and not baseline_alerts:
            return None

        compressed: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for a in rule_alerts:
            host = str(a.event.get("host", "unknown"))
            compressed[host][a.rule] += 1

        max_api = 0.0
        max_egress = 0.0
        privilege_change = 0.0

        for a in rule_alerts:
            event = a.event
            max_api = max(max_api, float(event.get("api_call_count", 0) or 0))
            max_egress = max(max_egress, float(event.get("egress_mb", 0) or 0))
            if "IAM" in a.rule or "iam_" in str(event.get("action", "")):
                privilege_change = max(privilege_change, 100.0)

        for b in baseline_alerts:
            if b.metric == "api_call_rate":
                max_api = max(max_api, float(b.current))
            if b.metric == "network_egress":
                max_egress = max(max_egress, float(b.current))

        api_score = min(100.0, (max_api / 1000.0) * 100.0)
        egress_score = min(100.0, (max_egress / 1000.0) * 100.0)
        correlation = self.correlation_bonus if rule_alerts and baseline_alerts else 0.0

        risk_score = (
            self.model_spike_weight * api_score
            + self.egress_weight * egress_score
            + self.privilege_weight * privilege_change
            + correlation
        )

        severity = min(100, int(risk_score))
        summary = (
            f"{len(rule_alerts)} rule alerts, {len(baseline_alerts)} baseline anomalies, "
            f"{len(compressed)} hosts after compression"
        )

        tags = []
        if rule_alerts:
            tags.append("rule")
        if baseline_alerts:
            tags.append("anomaly")
        if privilege_change > 0:
            tags.append("iam_risk")

        return CorrelatedAlert(
            summary=summary,
            severity=severity,
            tags=sorted(set(tags)),
            details={
                "compressed_rule_alerts": {h: dict(r) for h, r in compressed.items()},
                "rule_alerts": [a.__dict__ for a in rule_alerts],
                "baseline_alerts": [a.__dict__ for a in baseline_alerts],
                "risk_components": {
                    "api_score": api_score,
                    "egress_score": egress_score,
                    "privilege_score": privilege_change,
                    "correlation_bonus": correlation,
                },
            },
        )
