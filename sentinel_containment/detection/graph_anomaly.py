from __future__ import annotations

import math
from collections import defaultdict
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
    """Learns graph edge behavior and flags temporal/structural outliers."""

    def __init__(self, warmup_events: int = 5, novelty_weight: float = 1.6):
        self.warmup_events = warmup_events
        self.novelty_weight = novelty_weight
        self._processed_events = 0
        self._known_edges: set[tuple[str, str, str]] = set()
        self._node_degree: dict[str, int] = {}
        self._neighbors: dict[str, set[str]] = defaultdict(set)
        self._relation_counts: dict[str, int] = defaultdict(int)
        self._embedding_mean = [0.0, 0.0, 0.0, 0.0]
        self._embedding_var = [1.0, 1.0, 1.0, 1.0]
        self._embedding_seen = 0
        self._relation_ewma: dict[str, float] = defaultdict(float)

    def evaluate(self, event: dict[str, Any]) -> list[GraphEdgeAnomaly]:
        edge = self._event_edge(event)
        if edge is None:
            self._processed_events += 1
            return []

        source, target, relation = edge
        key = (source, target, relation)
        source_degree = self._node_degree.get(source, 0)
        target_degree = self._node_degree.get(target, 0)

        embedding = self._edge_embedding(source, target, relation)
        embed_distance = self._embedding_distance(embedding)
        temporal_drift = self._temporal_drift(relation)
        structural_outlier = self._structural_outlier(source, target)
        first_seen_bonus = 1.0 if key not in self._known_edges else 0.15

        combined = (
            0.35 * min(1.0, embed_distance / 3.0)
            + 0.25 * temporal_drift
            + 0.20 * structural_outlier
            + 0.20 * first_seen_bonus
        ) * self.novelty_weight
        novelty_score = min(1.0, combined)

        anomalies: list[GraphEdgeAnomaly] = []
        warmed_up = self._processed_events >= self.warmup_events
        if warmed_up and novelty_score >= 0.55:
            severity = min(97, 52 + int(novelty_score * 45))
            reason = (
                f"Graph edge outlier: {source} -> {target} ({relation}); "
                f"embed={embed_distance:.2f}, drift={temporal_drift:.2f}, structural={structural_outlier:.2f}"
            )
            anomalies.append(
                GraphEdgeAnomaly(
                    source=source,
                    target=target,
                    relation=relation,
                    severity=severity,
                    novelty_score=round(novelty_score, 3),
                    reason=reason,
                    event=event,
                )
            )

        self._update_models(source, target, relation, key, embedding, source_degree, target_degree)
        self._processed_events += 1
        return anomalies

    def _update_models(
        self,
        source: str,
        target: str,
        relation: str,
        key: tuple[str, str, str],
        embedding: list[float],
        source_degree: int,
        target_degree: int,
    ) -> None:
        self._known_edges.add(key)
        self._node_degree[source] = source_degree + 1
        self._node_degree[target] = target_degree + 1
        self._neighbors[source].add(target)
        self._neighbors[target].add(source)
        self._relation_counts[relation] += 1

        alpha = 0.3
        self._relation_ewma[relation] = (
            alpha * self._relation_counts[relation] + (1.0 - alpha) * self._relation_ewma[relation]
        )

        self._embedding_seen += 1
        for i, value in enumerate(embedding):
            delta = value - self._embedding_mean[i]
            self._embedding_mean[i] += delta / self._embedding_seen
            self._embedding_var[i] = max(1e-6, ((self._embedding_seen - 1) * self._embedding_var[i] + delta * (value - self._embedding_mean[i])) / self._embedding_seen)

    def _edge_embedding(self, source: str, target: str, relation: str) -> list[float]:
        src_degree = float(self._node_degree.get(source, 0))
        tgt_degree = float(self._node_degree.get(target, 0))
        relation_freq = float(self._relation_counts.get(relation, 0))
        shared = len(self._neighbors.get(source, set()) & self._neighbors.get(target, set()))
        return [
            math.log1p(src_degree),
            math.log1p(tgt_degree),
            math.log1p(relation_freq),
            float(shared),
        ]

    def _embedding_distance(self, embedding: list[float]) -> float:
        zsum = 0.0
        for i, value in enumerate(embedding):
            std = math.sqrt(max(self._embedding_var[i], 1e-6))
            zsum += ((value - self._embedding_mean[i]) / std) ** 2
        return math.sqrt(zsum)

    def _temporal_drift(self, relation: str) -> float:
        baseline = self._relation_ewma.get(relation, 0.0)
        current = float(self._relation_counts.get(relation, 0))
        if baseline <= 0:
            return 0.6
        drift = abs(current - baseline) / max(1.0, baseline)
        return min(1.0, drift)

    def _structural_outlier(self, source: str, target: str) -> float:
        src_neighbors = self._neighbors.get(source, set())
        tgt_neighbors = self._neighbors.get(target, set())
        if not src_neighbors or not tgt_neighbors:
            return 1.0
        overlap = len(src_neighbors & tgt_neighbors)
        union = len(src_neighbors | tgt_neighbors)
        jaccard = overlap / max(1, union)
        return 1.0 - jaccard

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
