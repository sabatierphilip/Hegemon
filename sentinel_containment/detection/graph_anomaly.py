from __future__ import annotations

import math
from collections import defaultdict, deque
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

    def __init__(
        self,
        warmup_events: int = 5,
        novelty_weight: float = 1.6,
        warmup_min_distinct_sources: int = 2,
        warmup_min_relations: int = 1,
        max_tracked_edges: int = 20000,
    ):
        self.warmup_events = warmup_events
        self.novelty_weight = novelty_weight
        self.warmup_min_distinct_sources = max(1, warmup_min_distinct_sources)
        self.warmup_min_relations = max(1, warmup_min_relations)
        self.max_tracked_edges = max(1, int(max_tracked_edges))
        self._processed_events = 0
        self._known_edges: set[tuple[str, str, str]] = set()
        self._edge_order: deque[tuple[str, str, str]] = deque()
        self._known_edge_patterns: set[tuple[str, str]] = set()
        self._edge_pattern_counts: dict[tuple[str, str], int] = defaultdict(int)
        self._node_degree: dict[str, int] = {}
        self._neighbors: dict[str, set[str]] = defaultdict(set)
        self._pair_counts: dict[tuple[str, str], int] = defaultdict(int)
        self._relation_counts: dict[str, int] = defaultdict(int)
        self._embedding_mean = [0.0, 0.0, 0.0, 0.0]
        self._embedding_var = [1.0, 1.0, 1.0, 1.0]
        self._embedding_seen = 0
        self._relation_ewma: dict[str, float] = defaultdict(float)
        self._warmup_sources: set[str] = set()
        self._warmup_relations: set[str] = set()

    def evaluate(self, event: dict[str, Any]) -> list[GraphEdgeAnomaly]:
        edges = self._event_edges(event)
        if not edges:
            self._processed_events += 1
            return []
        anomalies: list[GraphEdgeAnomaly] = []
        for source, target, relation in edges:
            key = (source, target, relation)
            edge_pattern = (source, relation)
            source_degree = self._node_degree.get(source, 0)
            target_degree = self._node_degree.get(target, 0)
            known_pattern = edge_pattern in self._known_edge_patterns

            embedding = self._edge_embedding(source, target, relation)
            embed_distance = self._embedding_distance(embedding)
            temporal_drift = self._temporal_drift(relation)
            structural_outlier = self._structural_outlier(source, target)
            first_seen_bonus = 1.0 if key not in self._known_edges and not known_pattern else 0.15

            if known_pattern and key not in self._known_edges:
                embed_distance *= 0.6
                structural_outlier *= 0.35

            combined = (
                0.35 * min(1.0, embed_distance / 3.0)
                + 0.25 * temporal_drift
                + 0.20 * structural_outlier
                + 0.20 * first_seen_bonus
            ) * self.novelty_weight
            if known_pattern and key not in self._known_edges:
                combined *= 0.5
            novelty_score = min(1.0, combined)

            self._warmup_sources.add(source)
            self._warmup_relations.add(relation)
            warmed_up = self._is_warmed_up()
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

            self._update_models(source, target, relation, key, edge_pattern, embedding, source_degree, target_degree)
        self._processed_events += 1
        return anomalies

    def _is_warmed_up(self) -> bool:
        return (
            self._processed_events >= self.warmup_events
            and len(self._warmup_sources) >= self.warmup_min_distinct_sources
            and len(self._warmup_relations) >= self.warmup_min_relations
        )

    def _update_models(
        self,
        source: str,
        target: str,
        relation: str,
        key: tuple[str, str, str],
        edge_pattern: tuple[str, str],
        embedding: list[float],
        source_degree: int,
        target_degree: int,
    ) -> None:
        if key not in self._known_edges:
            self._known_edges.add(key)
            self._edge_order.append(key)

        self._known_edge_patterns.add(edge_pattern)
        self._edge_pattern_counts[edge_pattern] += 1
        self._node_degree[source] = source_degree + 1
        self._node_degree[target] = target_degree + 1
        self._neighbors[source].add(target)
        self._neighbors[target].add(source)
        pair = tuple(sorted((source, target)))
        self._pair_counts[pair] += 1
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

        self._evict_edges_if_needed()

    def _evict_edges_if_needed(self) -> None:
        while len(self._known_edges) > self.max_tracked_edges:
            old_source, old_target, old_relation = self._edge_order.popleft()
            old_key = (old_source, old_target, old_relation)
            if old_key not in self._known_edges:
                continue
            self._known_edges.remove(old_key)

            old_pattern = (old_source, old_relation)
            pattern_count = self._edge_pattern_counts.get(old_pattern, 0)
            if pattern_count <= 1:
                self._edge_pattern_counts.pop(old_pattern, None)
                self._known_edge_patterns.discard(old_pattern)
            else:
                self._edge_pattern_counts[old_pattern] = pattern_count - 1

            self._relation_counts[old_relation] = max(0, self._relation_counts.get(old_relation, 0) - 1)
            if self._relation_counts[old_relation] == 0:
                self._relation_counts.pop(old_relation, None)
                self._relation_ewma.pop(old_relation, None)

            self._node_degree[old_source] = max(0, self._node_degree.get(old_source, 0) - 1)
            self._node_degree[old_target] = max(0, self._node_degree.get(old_target, 0) - 1)
            if self._node_degree.get(old_source, 0) == 0:
                self._node_degree.pop(old_source, None)
                self._neighbors.pop(old_source, None)
            if self._node_degree.get(old_target, 0) == 0:
                self._node_degree.pop(old_target, None)
                self._neighbors.pop(old_target, None)

            pair = tuple(sorted((old_source, old_target)))
            pair_count = self._pair_counts.get(pair, 0)
            if pair_count <= 1:
                self._pair_counts.pop(pair, None)
                if old_source in self._neighbors:
                    self._neighbors[old_source].discard(old_target)
                if old_target in self._neighbors:
                    self._neighbors[old_target].discard(old_source)
            else:
                self._pair_counts[pair] = pair_count - 1

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
    def _event_edges(event: dict[str, Any]) -> list[tuple[str, str, str]]:
        host = str(event.get("host", "unknown"))
        user = str(event.get("user", "unknown"))
        process = str(event.get("process", "unknown"))
        action = str(event.get("action", "unknown"))
        resource = str(event.get("resource", "unknown"))

        if action == "unknown" and resource == "unknown":
            return [(f"host:{host}", "telemetry:null_event", "unknown_activity")]

        edges: list[tuple[str, str, str]] = []
        if user != "unknown" and host != "unknown":
            edges.append((f"user:{user}", f"host:{host}", "accesses"))
        if process != "unknown" and host != "unknown":
            edges.append((f"process:{process}", f"host:{host}", "runs_on"))
        if host != "unknown" and resource != "unknown":
            edges.append((f"host:{host}", f"resource:{resource}", action))
        if process != "unknown" and resource != "unknown":
            edges.append((f"process:{process}", f"resource:{resource}", f"{action}_resource"))

        deduped: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str, str]] = set()
        for edge in edges:
            if edge in seen:
                continue
            seen.add(edge)
            deduped.append(edge)
        return deduped


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
