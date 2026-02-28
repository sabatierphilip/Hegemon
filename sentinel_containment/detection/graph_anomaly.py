from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass
class GraphEdgeAnomaly:
    source: str
    target: str
    relation: str
    severity: int
    novelty_score: float
    reason: str
    event: dict[str, Any]


class GraphAnomalyDetector:
    """Detects novel graph edges (node-to-node relations) appearing in telemetry."""

    def __init__(self, warmup_events: int = 5, novelty_weight: float = 1.6):
        self.warmup_events = warmup_events
        self.novelty_weight = novelty_weight
        self._processed_events = 0
        self._known_edges: set[tuple[str, str, str]] = set()
        self._node_degree: dict[str, int] = {}

    def evaluate(self, event: dict[str, Any]) -> list[GraphEdgeAnomaly]:
        edge = self._event_edge(event)
        if edge is None:
            self._processed_events += 1
            return []

        source, target, relation = edge
        key = (source, target, relation)

        anomalies: list[GraphEdgeAnomaly] = []
        edge_known = key in self._known_edges
        warmed_up = self._processed_events >= self.warmup_events
        source_degree = self._node_degree.get(source, 0)
        target_degree = self._node_degree.get(target, 0)

        if warmed_up and not edge_known:
            novelty_score = min(1.0, (1.0 / (1 + source_degree + target_degree)) * self.novelty_weight)
            severity = min(95, 55 + int(40 * novelty_score))
            anomalies.append(
                GraphEdgeAnomaly(
                    source=source,
                    target=target,
                    relation=relation,
                    severity=severity,
                    novelty_score=round(novelty_score, 3),
                    reason=f"New graph edge detected: {source} -> {target} ({relation})",
                    event=event,
                )
            )

        self._known_edges.add(key)
        self._node_degree[source] = source_degree + 1
        self._node_degree[target] = target_degree + 1
        self._processed_events += 1
        return anomalies

    @staticmethod
    def _event_edge(event: dict[str, Any]) -> tuple[str, str, str] | None:
        host = str(event.get("host", "unknown"))
        user = str(event.get("user", "unknown"))
        process = str(event.get("process", "unknown"))
        action = str(event.get("action", "unknown"))
        resource = str(event.get("resource", "unknown"))

        if action == "unknown" and resource == "unknown":
            return None

        if user != "unknown" and host != "unknown":
            return (f"user:{user}", f"host:{host}", "accesses")
        if process != "unknown" and host != "unknown":
            return (f"process:{process}", f"host:{host}", "runs_on")

        return (f"host:{host}", f"resource:{resource}", action)


@dataclass
class TimelineEvent:
    stage: str
    timestamp: datetime
    event: dict[str, Any]


def parse_event_time(event: dict[str, Any]) -> datetime:
    raw = event.get("@timestamp") or event.get("timestamp")
    if isinstance(raw, str):
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.now(timezone.utc)
