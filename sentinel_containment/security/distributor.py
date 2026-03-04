from __future__ import annotations

import hashlib
import json
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


_READ_ACTIONS = {
    "read",
    "list",
    "open",
    "file_read",
    "query",
    "model_invoke",
    "dns_query",
}


@dataclass
class DistributionVerdict:
    score: float
    confidence: float
    reasons: list[str]


class SecurityDistributorEngine:
    """Cross-component distributor for peer trust + read-aware security context."""

    def __init__(
        self,
        *,
        risk_window_seconds: int = 900,
        max_events_per_component: int = 2000,
        sensitive_resource_markers: list[str] | None = None,
    ):
        self._risk_window_seconds = max(60, int(risk_window_seconds))
        self._max_events_per_component = max(50, int(max_events_per_component))
        self._sensitive_markers = [
            marker.lower()
            for marker in (sensitive_resource_markers or ["/etc", "credential", "token", "secret", "key", "kubelet", "iam"]) 
        ]
        self._component_reads: dict[str, deque[dict[str, Any]]] = defaultdict(deque)
        self._peer_scores: dict[str, float] = defaultdict(lambda: 1.0)
        self._peer_failures: dict[str, int] = defaultdict(int)

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    def _trim(self, component: str, now_ts: float) -> None:
        window_start = now_ts - self._risk_window_seconds
        bucket = self._component_reads[component]
        while bucket and float(bucket[0].get("ts_epoch", 0.0)) < window_start:
            bucket.popleft()
        if len(bucket) > self._max_events_per_component:
            while len(bucket) > self._max_events_per_component:
                bucket.popleft()

    def enrich_event(self, source_type: str, event: dict[str, Any]) -> dict[str, Any]:
        action = str(event.get("action", "")).strip().lower()
        resource = str(event.get("resource", "")).strip().lower()
        process = str(event.get("process", "unknown")).strip().lower() or "unknown"
        host = str(event.get("host", "unknown")).strip().lower() or "unknown"
        component = f"{host}:{process}"

        now = self._now()
        ts_epoch = now.timestamp()
        read_aware = action in _READ_ACTIONS or "read" in action
        sensitive_read = read_aware and any(marker in resource for marker in self._sensitive_markers)

        if read_aware:
            record = {
                "ts": now.isoformat(),
                "ts_epoch": ts_epoch,
                "source_type": source_type,
                "host": host,
                "process": process,
                "action": action,
                "resource": resource,
                "sensitive_read": sensitive_read,
            }
            self._component_reads[component].append(record)
            self._trim(component, ts_epoch)

        read_count = len(self._component_reads.get(component, ()))
        sensitive_count = sum(1 for e in self._component_reads.get(component, ()) if e.get("sensitive_read"))
        read_pressure = round(min(1.0, read_count / 50.0), 4)
        sensitive_pressure = round(min(1.0, sensitive_count / 20.0), 4)

        envelope = {
            "component": component,
            "read_aware": read_aware,
            "sensitive_read": sensitive_read,
            "read_pressure": read_pressure,
            "sensitive_read_pressure": sensitive_pressure,
            "peer_distributor_epoch": int(ts_epoch),
            "distributor_proof": hashlib.sha256(
                json.dumps(
                    {
                        "component": component,
                        "action": action,
                        "resource": resource,
                        "source_type": source_type,
                        "read_pressure": read_pressure,
                        "sensitive_read_pressure": sensitive_pressure,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()[:20],
        }
        return envelope

    def observe_peer_attestation(self, result: dict[str, Any]) -> None:
        failures = result.get("failures", [])
        mesh_size = max(1, int(result.get("mesh_size", 1)))
        for entry in failures:
            responder = str(entry.get("responder", "unknown")).strip()
            if responder:
                self._peer_failures[responder] += 1

        for peer in {str(p) for p in result.get("peers", []) if str(p).strip()}:
            self._peer_scores[peer] = max(0.05, 1.0 - (self._peer_failures.get(peer, 0) / (mesh_size * 4)))

    def current_snapshot(self) -> dict[str, Any]:
        now_ts = time.time()
        total_reads = 0
        sensitive_reads = 0
        hot_components: list[dict[str, Any]] = []
        for component in list(self._component_reads.keys()):
            self._trim(component, now_ts)
            events = self._component_reads.get(component, deque())
            if not events:
                continue
            reads = len(events)
            sens = sum(1 for e in events if e.get("sensitive_read"))
            total_reads += reads
            sensitive_reads += sens
            hot_components.append(
                {
                    "component": component,
                    "read_count": reads,
                    "sensitive_read_count": sens,
                    "pressure": round(min(1.0, reads / 50.0), 4),
                }
            )

        top = sorted(hot_components, key=lambda x: (x["sensitive_read_count"], x["read_count"]), reverse=True)[:5]
        avg_trust = round(sum(self._peer_scores.values()) / len(self._peer_scores), 4) if self._peer_scores else 1.0
        risk = round(min(1.0, (sensitive_reads / 40.0) + (1.0 - avg_trust)), 4)
        confidence = round(min(1.0, (total_reads / 100.0) + 0.2), 4)
        return {
            "risk_score": risk,
            "risk_confidence": confidence,
            "avg_peer_trust": avg_trust,
            "total_reads": total_reads,
            "sensitive_reads": sensitive_reads,
            "hot_components": top,
            "peer_failures": dict(self._peer_failures),
        }

    def verdict(self) -> DistributionVerdict:
        snapshot = self.current_snapshot()
        reasons: list[str] = []
        if snapshot["sensitive_reads"] > 0:
            reasons.append("sensitive_read_activity")
        if snapshot["avg_peer_trust"] < 0.75:
            reasons.append("peer_trust_degradation")
        if snapshot["risk_score"] > 0.6:
            reasons.append("distributed_risk_elevated")
        return DistributionVerdict(score=snapshot["risk_score"], confidence=snapshot["risk_confidence"], reasons=reasons)
