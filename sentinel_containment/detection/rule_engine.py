from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass
class DetectionAlert:
    rule: str
    reason: str
    severity: int
    event: dict[str, Any]


class RuleEngine:
    def __init__(self, rules_path: Path = Path("rules")):
        self.rules_path = rules_path
        self.rules = self._load_rules()

    def _load_rules(self) -> list[dict[str, Any]]:
        loaded = []
        for file in sorted(self.rules_path.glob("*.yaml")):
            with file.open("r", encoding="utf-8") as f:
                loaded.append(yaml.safe_load(f) or {})
        return loaded

    def evaluate(self, event: dict[str, Any]) -> list[DetectionAlert]:
        alerts: list[DetectionAlert] = []
        for rule in self.rules:
            cond = rule.get("detection", {})
            matches = all(event.get(k) == v for k, v in cond.get("equals", {}).items())
            if "greater_than" in cond:
                for key, threshold in cond["greater_than"].items():
                    if float(event.get(key, 0)) <= float(threshold):
                        matches = False
            if matches:
                alerts.append(
                    DetectionAlert(
                        rule=rule.get("title", "unnamed_rule"),
                        reason=rule.get("description", "Rule match"),
                        severity=int(rule.get("severity", 50)),
                        event=event,
                    )
                )
        return alerts
