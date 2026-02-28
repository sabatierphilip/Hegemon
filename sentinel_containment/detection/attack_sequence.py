from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sentinel_containment.detection.graph_anomaly import parse_event_time


@dataclass
class AttackChainAlert:
    host: str
    stages: list[str]
    severity: int
    confidence: float
    summary: str
    events: list[dict[str, Any]]


class AttackSequenceModel:
    """Models multi-step attack chains over time instead of isolated alerts."""

    def __init__(self, chain_window_minutes: int = 30):
        self.chain_window = timedelta(minutes=chain_window_minutes)
        self._history: dict[str, list[tuple[str, Any, dict[str, Any]]]] = defaultdict(list)

    def evaluate(self, events: list[dict[str, Any]]) -> list[AttackChainAlert]:
        for event in events:
            host = str(event.get("host", "unknown"))
            stage = self._event_stage(event)
            timestamp = parse_event_time(event)
            self._history[host].append((stage, timestamp, event))
            self._trim(host, timestamp)

        alerts: list[AttackChainAlert] = []
        for host, host_events in self._history.items():
            chain = self._extract_chain(host_events)
            if chain is None:
                continue
            stages, chain_events, confidence = chain
            severity = min(100, 60 + len(stages) * 9 + int(confidence * 15))
            alerts.append(
                AttackChainAlert(
                    host=host,
                    stages=stages,
                    severity=severity,
                    confidence=round(confidence, 3),
                    summary=f"{host}: detected {len(stages)}-stage attack chain",
                    events=chain_events,
                )
            )
        return alerts

    def _trim(self, host: str, now) -> None:
        self._history[host] = [
            entry for entry in self._history[host] if (now - entry[1]) <= self.chain_window
        ]

    @staticmethod
    def _event_stage(event: dict[str, Any]) -> str:
        action = str(event.get("action", "unknown")).lower()
        if "login" in action or "auth" in action:
            return "initial_access"
        if "iam_privilege" in action or "privilege" in action:
            return "privilege_escalation"
        if "container_spawn" in action or "process_start" in action:
            return "execution"
        if "model_invoke" in action:
            return "resource_abuse"
        if "egress" in action or float(event.get("egress_mb", 0) or 0) > 500:
            return "exfiltration"
        return "discovery"

    def _extract_chain(
        self,
        host_events: list[tuple[str, Any, dict[str, Any]]],
    ) -> tuple[list[str], list[dict[str, Any]], float] | None:
        if len(host_events) < 3:
            return None

        stage_order = {
            "initial_access": 1,
            "execution": 2,
            "privilege_escalation": 3,
            "discovery": 4,
            "resource_abuse": 5,
            "exfiltration": 6,
        }

        sorted_events = sorted(host_events, key=lambda item: item[1])
        chain_stages: list[str] = []
        chain_events: list[dict[str, Any]] = []
        last_rank = 0

        for stage, _, event in sorted_events:
            rank = stage_order.get(stage, 0)
            if rank >= last_rank and (not chain_stages or stage != chain_stages[-1]):
                chain_stages.append(stage)
                chain_events.append(event)
                last_rank = rank

        if len(chain_stages) < 3:
            return None

        max_stage = max(stage_order.get(s, 0) for s in chain_stages)
        coverage = max_stage / max(stage_order.values())
        progression = min(1.0, len(chain_stages) / 5)
        confidence = (coverage * 0.55) + (progression * 0.45)
        return chain_stages, chain_events, confidence
