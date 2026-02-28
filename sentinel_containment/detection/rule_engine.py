from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml


@dataclass
class DetectionAlert:
    rule: str
    reason: str
    severity: int
    event: dict[str, Any]
    dedup_hits: int = 1


class RuleEngine:
    def __init__(self, rules_path: Path = Path("rules"), dedup_window_seconds: int = 300):
        self.rules_path = rules_path
        self.rules = self._load_rules()
        self.dedup_window = timedelta(seconds=dedup_window_seconds)
        self._last_alert_seen: dict[tuple[str, str], datetime] = {}
        self._suppressed_count: dict[tuple[str, str], int] = {}

    def _load_rules(self) -> list[dict[str, Any]]:
        loaded = []
        for file in sorted(self.rules_path.glob("*.yaml")):
            with file.open("r", encoding="utf-8") as f:
                loaded.append(yaml.safe_load(f) or {})
        return loaded

    def evaluate(self, event: dict[str, Any]) -> list[DetectionAlert]:
        alerts: list[DetectionAlert] = []
        event_time = self._event_timestamp(event)
        host = event.get("host", "unknown")
        for rule in self.rules:
            cond = rule.get("detection", {})
            matches = all(event.get(k) == v for k, v in cond.get("equals", {}).items())
            if "greater_than" in cond:
                for key, threshold in cond["greater_than"].items():
                    if float(event.get(key, 0)) <= float(threshold):
                        matches = False
            if matches:
                rule_name = rule.get("title", "unnamed_rule")
                key = (host, rule_name)
                last_seen = self._last_alert_seen.get(key)
                if last_seen and (event_time - last_seen) < self.dedup_window:
                    self._suppressed_count[key] = self._suppressed_count.get(key, 0) + 1
                    continue

                dedup_hits = self._suppressed_count.pop(key, 0) + 1
                self._last_alert_seen[key] = event_time
                alerts.append(
                    DetectionAlert(
                        rule=rule_name,
                        reason=rule.get("description", "Rule match"),
                        severity=int(rule.get("severity", 50)),
                        event=event,
                        dedup_hits=dedup_hits,
                    )
                )
        return alerts

    @staticmethod
    def _event_timestamp(event: dict[str, Any]) -> datetime:
        raw = event.get("@timestamp") or event.get("timestamp")
        if isinstance(raw, str):
            try:
                return datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                pass
        return datetime.now(timezone.utc)
