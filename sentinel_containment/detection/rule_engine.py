from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


@dataclass
class DetectionAlert:
    rule: str
    reason: str
    severity: int
    event: dict[str, Any]
    deduped: bool = False


class RuleEngine:
    def __init__(
        self,
        rules_path: Path = Path("rules"),
        cooldown_seconds: int = 300,
        dedup_state_path: Path = Path("data/alert_dedup_state.json"),
    ):
        self.rules_path = rules_path
        self.cooldown_seconds = cooldown_seconds
        self.dedup_state_path = dedup_state_path
        self.rules = self._load_rules()
        self._dedup_state = self._load_dedup_state()

    def _load_rules(self) -> list[dict[str, Any]]:
        loaded = []
        for file in sorted(self.rules_path.glob("*.yaml")):
            with file.open("r", encoding="utf-8") as f:
                loaded.append(yaml.safe_load(f) or {})
        return loaded

    def _load_dedup_state(self) -> dict[str, float]:
        if not self.dedup_state_path.exists():
            return {}
        try:
            return json.loads(self.dedup_state_path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save_dedup_state(self) -> None:
        self.dedup_state_path.parent.mkdir(parents=True, exist_ok=True)
        self.dedup_state_path.write_text(json.dumps(self._dedup_state, indent=2), encoding="utf-8")

    def _event_epoch(self, event: dict[str, Any]) -> float:
        ts = event.get("@timestamp") or event.get("timestamp")
        if not ts:
            return datetime.now(timezone.utc).timestamp()
        try:
            return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
        except Exception:
            return datetime.now(timezone.utc).timestamp()

    def _is_deduped(self, rule_name: str, host: str, epoch: float) -> bool:
        key = f"{host}::{rule_name}"
        last = float(self._dedup_state.get(key, 0))
        if epoch - last < self.cooldown_seconds:
            return True
        self._dedup_state[key] = epoch
        return False

    def evaluate(self, event: dict[str, Any]) -> list[DetectionAlert]:
        alerts: list[DetectionAlert] = []
        host = str(event.get("host", "unknown"))
        event_epoch = self._event_epoch(event)
        for rule in self.rules:
            cond = rule.get("detection", {})
            matches = all(event.get(k) == v for k, v in cond.get("equals", {}).items())
            if "greater_than" in cond:
                for key, threshold in cond["greater_than"].items():
                    if float(event.get(key, 0)) <= float(threshold):
                        matches = False
            if matches:
                rule_name = rule.get("title", "unnamed_rule")
                deduped = self._is_deduped(rule_name, host, event_epoch)
                alerts.append(
                    DetectionAlert(
                        rule=rule_name,
                        reason=rule.get("description", "Rule match"),
                        severity=int(rule.get("severity", 50)),
                        event=event,
                        deduped=deduped,
                    )
                )
        self._save_dedup_state()
        return [a for a in alerts if not a.deduped]
