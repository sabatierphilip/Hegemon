from __future__ import annotations

import re
from collections import defaultdict, deque
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
        self._metric_history: dict[tuple[str, str, str], deque[tuple[datetime, float]]] = defaultdict(deque)
        self._recent_events: dict[str, deque[tuple[datetime, str, float]]] = defaultdict(deque)

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
            threshold_matches: list[bool] = []

            if "greater_than" in cond:
                threshold_matches.append(self._check_greater_than(cond.get("greater_than", {}), event))
            if "dynamic_velocity" in cond:
                threshold_matches.append(self._check_dynamic_velocity(rule, cond["dynamic_velocity"], event, event_time))
            if "distributed_burst" in cond:
                threshold_matches.append(self._check_distributed_burst(rule, cond["distributed_burst"], event, event_time))

            structured_match = self._evaluate_structured_conditions(cond, event)
            thresholds_ok = any(threshold_matches) if threshold_matches else True
            matches = structured_match and thresholds_ok

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

    def _evaluate_structured_conditions(self, cond: dict[str, Any], event: dict[str, Any]) -> bool:
        equals = cond.get("equals", {})
        if equals and not all(event.get(k) == v for k, v in equals.items()):
            return False

        regex = cond.get("regex", {})
        if regex:
            for field, pattern in regex.items():
                value = str(event.get(field, ""))
                if re.search(str(pattern), value) is None:
                    return False

        contains_any = cond.get("contains_any", {})
        if contains_any:
            for field, expected in contains_any.items():
                haystack = str(event.get(field, "")).lower()
                words = [str(item).lower() for item in expected] if isinstance(expected, list) else [str(expected).lower()]
                if not any(word in haystack for word in words):
                    return False

        yara_like = cond.get("yara_like", {})
        if yara_like and not self._evaluate_yara_like(yara_like, event):
            return False

        sigma = cond.get("sigma", {})
        if sigma and not self._evaluate_sigma_like(sigma, event):
            return False

        return True

    def _evaluate_yara_like(self, yara_like: dict[str, Any], event: dict[str, Any]) -> bool:
        fields = yara_like.get("fields", ["command_line", "metadata", "resource"])
        strings = yara_like.get("strings", [])
        min_hits = int(yara_like.get("min_hits", 1))

        haystack = " ".join(str(event.get(field, "")) for field in fields).lower()
        hits = 0
        for token in strings:
            if str(token).lower() in haystack:
                hits += 1
        return hits >= min_hits

    def _evaluate_sigma_like(self, sigma: dict[str, Any], event: dict[str, Any]) -> bool:
        all_of = sigma.get("all_of", [])
        any_of = sigma.get("any_of", [])
        not_block = sigma.get("not", [])

        if all_of and not all(self._match_selector(selector, event) for selector in all_of):
            return False
        if any_of and not any(self._match_selector(selector, event) for selector in any_of):
            return False
        if not_block and any(self._match_selector(selector, event) for selector in not_block):
            return False
        return True

    def _match_selector(self, selector: dict[str, Any], event: dict[str, Any]) -> bool:
        for field, expected in selector.items():
            value = event.get(field)
            if isinstance(expected, dict):
                for op, cond in expected.items():
                    if not self._match_operator(op, value, cond):
                        return False
            elif value != expected:
                return False
        return True

    def _match_operator(self, op: str, value: Any, cond: Any) -> bool:
        text = str(value or "")
        op = op.lower()
        if op == "contains":
            return str(cond).lower() in text.lower()
        if op == "regex":
            return re.search(str(cond), text) is not None
        if op == "startswith":
            return text.lower().startswith(str(cond).lower())
        if op == "endswith":
            return text.lower().endswith(str(cond).lower())
        if op == "in":
            if not isinstance(cond, list):
                return False
            return text in {str(item) for item in cond}
        return False

    def _check_greater_than(self, greater_than: dict[str, Any], event: dict[str, Any]) -> bool:
        for key, threshold in greater_than.items():
            event_value = self._safe_float(event.get(key), default=0.0)
            threshold_value = self._safe_float(threshold, default=0.0)
            if event_value <= threshold_value:
                return False
        return True

    def _check_dynamic_velocity(
        self,
        rule: dict[str, Any],
        condition: dict[str, Any],
        event: dict[str, Any],
        event_time: datetime,
    ) -> bool:
        metric = str(condition.get("metric", "api_call_count"))
        value = self._safe_float(event.get(metric), default=0.0)
        identity_fields = condition.get("identity_fields", ["user", "host"])
        identity = "|".join(str(event.get(field, "unknown")).strip().lower() for field in identity_fields)
        history_key = (rule.get("title", "unnamed_rule"), identity, metric)
        history = self._metric_history[history_key]

        baseline_window = timedelta(seconds=int(condition.get("baseline_window_seconds", 900)))
        while history and (event_time - history[0][0]) > baseline_window:
            history.popleft()

        values = [sample for _, sample in history]
        min_samples = int(condition.get("min_samples", 4))
        multiplier = float(condition.get("multiplier", 10.0))
        baseline = (sum(values) / len(values)) if values else 0.0
        is_burst = len(values) >= min_samples and baseline > 0 and value >= baseline * multiplier

        history.append((event_time, value))
        return is_burst

    def _check_distributed_burst(
        self,
        rule: dict[str, Any],
        condition: dict[str, Any],
        event: dict[str, Any],
        event_time: datetime,
    ) -> bool:
        metric = str(condition.get("metric", "api_call_count"))
        value = self._safe_float(event.get(metric), default=0.0)
        identity_field = str(condition.get("identity_field", "user"))
        identity = str(event.get(identity_field, "unknown")).strip().lower()
        rule_name = rule.get("title", "unnamed_rule")

        window = timedelta(seconds=int(condition.get("baseline_window_seconds", 900)))
        recent = self._recent_events[rule_name]
        while recent and (event_time - recent[0][0]) > window:
            recent.popleft()
        recent.append((event_time, identity, value))

        max_per_identity = float(condition.get("max_per_identity", 500))
        min_total = float(condition.get("min_total_api_calls", 1200))
        min_identities = int(condition.get("min_identities", 4))
        under_threshold = [(ident, api) for _, ident, api in recent if api <= max_per_identity]
        if not under_threshold:
            return False
        unique_identities = {ident for ident, _ in under_threshold}
        aggregate_velocity = sum(api for _, api in under_threshold)
        return len(unique_identities) >= min_identities and aggregate_velocity >= min_total

    @staticmethod
    def _safe_float(value: Any, default: float = 0.0) -> float:
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            return default
        return numeric

    @staticmethod
    def _event_timestamp(event: dict[str, Any]) -> datetime:
        raw = event.get("@timestamp") or event.get("timestamp")
        if isinstance(raw, str):
            try:
                return datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                pass
        return datetime.now(timezone.utc)
