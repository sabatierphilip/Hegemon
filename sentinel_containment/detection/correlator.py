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
            weighted_score += alert.severity * self._rule_weight(alert)

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
                "event_correlation": {
                    "rule_groups": self._group_rule_alerts(rule_alerts),
                    "baseline_groups": self._group_baseline_alerts(baseline_alerts),
                },
            },
        )

    def _rule_weight(self, alert: Any) -> float:
        rule_name = str(getattr(alert, "rule", "")).lower()
        reason = str(getattr(alert, "reason", "")).lower()
        event = getattr(alert, "event", {}) or {}
        action = str(event.get("action", "")).lower()

        tokens = f"{rule_name} {reason} {action}"
        if "iam" in tokens or "privilege" in tokens:
            return self.privilege_weight
        if "egress" in tokens or "external" in tokens or "exfil" in tokens:
            return self.egress_weight
        return self.model_spike_weight

    @staticmethod
    def _group_rule_alerts(rule_alerts: list[Any]) -> list[dict[str, Any]]:
        grouped: dict[tuple[str, str], dict[str, Any]] = defaultdict(lambda: {"hits": 0, "suppressed": 0})
        for alert in rule_alerts:
            host = str(getattr(alert, "event", {}).get("host", "unknown"))
            rule = str(getattr(alert, "rule", "unnamed_rule"))
            key = (host, rule)
            grouped[key]["host"] = host
            grouped[key]["rule"] = rule
            grouped[key]["hits"] += 1
            grouped[key]["suppressed"] += max(0, int(getattr(alert, "dedup_hits", 1)) - 1)
        return sorted(grouped.values(), key=lambda g: (g["host"], g["rule"]))

    @staticmethod
    def _group_baseline_alerts(baseline_alerts: list[Any]) -> list[dict[str, Any]]:
        grouped: dict[tuple[str, str], dict[str, Any]] = defaultdict(lambda: {"hits": 0, "max_severity": 0})
        for alert in baseline_alerts:
            host = str(getattr(alert, "host", "unknown"))
            metric = str(getattr(alert, "metric", "unknown_metric"))
            key = (host, metric)
            grouped[key]["host"] = host
            grouped[key]["metric"] = metric
            grouped[key]["hits"] += 1
            grouped[key]["max_severity"] = max(grouped[key]["max_severity"], int(getattr(alert, "severity", 0)))
        return sorted(grouped.values(), key=lambda g: (g["host"], g["metric"]))
