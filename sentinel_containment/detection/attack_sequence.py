from __future__ import annotations

import math
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
    mitre_techniques: list[str]


class AttackSequenceModel:
    """Probabilistic multi-step attack chain model with MITRE-aware transitions."""

    _stage_order = [
        "initial_access",
        "execution",
        "privilege_escalation",
        "discovery",
        "resource_abuse",
        "exfiltration",
    ]

    _stage_priors = {
        "initial_access": 0.16,
        "execution": 0.16,
        "privilege_escalation": 0.16,
        "discovery": 0.14,
        "resource_abuse": 0.18,
        "exfiltration": 0.20,
    }

    _token_weights = {
        "initial_access": {"login": 1.3, "auth": 1.1, "password": 1.0, "ssh": 0.8, "token": 0.5},
        "execution": {"process_start": 1.2, "container_spawn": 1.4, "exec": 1.0, "script": 0.9},
        "privilege_escalation": {"privilege": 1.5, "assume_role": 1.4, "iam": 1.2, "sudo": 1.0},
        "discovery": {"scan": 1.3, "list": 0.9, "describe": 0.8, "inventory": 1.0},
        "resource_abuse": {"model_invoke": 1.5, "api_call": 1.2, "gpu": 1.0, "automation": 0.8},
        "exfiltration": {"egress": 1.3, "network_send": 1.2, "upload": 1.1, "dump": 1.0, "exfil": 1.5},
    }

    _mitre_map = {
        "initial_access": "T1078",
        "execution": "T1059",
        "privilege_escalation": "T1068",
        "discovery": "T1087",
        "resource_abuse": "T1496",
        "exfiltration": "T1041",
    }

    def __init__(self, chain_window_minutes: int = 30):
        self.chain_window = timedelta(minutes=chain_window_minutes)
        self._history: dict[str, list[tuple[str, float, Any, dict[str, Any]]]] = defaultdict(list)
        self._transitions = self._build_transition_matrix()

    def evaluate(self, events: list[dict[str, Any]]) -> list[AttackChainAlert]:
        for event in events:
            host = str(event.get("host", "unknown"))
            stage, stage_confidence = self._infer_stage(event)
            timestamp = parse_event_time(event)
            self._history[host].append((stage, stage_confidence, timestamp, event))
            self._trim(host, timestamp)

        alerts: list[AttackChainAlert] = []
        for host, host_events in self._history.items():
            chain = self._extract_chain(host_events)
            if chain is None:
                continue
            stages, chain_events, confidence = chain
            severity = min(100, 58 + len(stages) * 8 + int(confidence * 18))
            mitre = [self._mitre_map[s] for s in stages if s in self._mitre_map]
            alerts.append(
                AttackChainAlert(
                    host=host,
                    stages=stages,
                    severity=severity,
                    confidence=round(confidence, 3),
                    summary=f"{host}: probabilistic {len(stages)}-stage MITRE chain detected",
                    events=chain_events,
                    mitre_techniques=mitre,
                )
            )
        return alerts

    def _trim(self, host: str, now) -> None:
        self._history[host] = [
            entry for entry in self._history[host] if (now - entry[2]) <= self.chain_window
        ]

    def _infer_stage(self, event: dict[str, Any]) -> tuple[str, float]:
        action = str(event.get("action", "unknown")).lower()
        resource = str(event.get("resource", "")).lower()
        payload = f"{action} {resource}"

        evidence = {stage: math.log(self._stage_priors[stage]) for stage in self._stage_order}
        for stage, weights in self._token_weights.items():
            for token, weight in weights.items():
                if token in payload:
                    evidence[stage] += weight

        if float(event.get("egress_mb", 0) or 0) > 500:
            evidence["exfiltration"] += 1.2
        if float(event.get("api_call_count", 0) or 0) > 600:
            evidence["resource_abuse"] += 1.0
        if "denied" in payload or "failed" in payload:
            evidence["initial_access"] += 0.7

        top_stage = max(evidence, key=evidence.get)
        sorted_scores = sorted(evidence.values(), reverse=True)
        margin = sorted_scores[0] - sorted_scores[1] if len(sorted_scores) > 1 else 1.0
        confidence = 1.0 / (1.0 + math.exp(-margin))
        return top_stage, confidence

    def _extract_chain(
        self,
        host_events: list[tuple[str, float, Any, dict[str, Any]]],
    ) -> tuple[list[str], list[dict[str, Any]], float] | None:
        if len(host_events) < 3:
            return None

        sorted_events = sorted(host_events, key=lambda item: item[2])
        num_states = len(self._stage_order)
        n = len(sorted_events)
        dp = [[-1e9] * num_states for _ in range(n)]
        parent = [[-1] * num_states for _ in range(n)]

        for i, (stage, stage_conf, _, _) in enumerate(sorted_events):
            for s, state in enumerate(self._stage_order):
                emission = math.log(1e-6 + (stage_conf if state == stage else (1.0 - stage_conf) / (num_states - 1)))
                if i == 0:
                    dp[i][s] = math.log(self._stage_priors[state]) + emission
                    continue
                best_prev_score = -1e9
                best_prev_idx = -1
                for ps, prev_state in enumerate(self._stage_order):
                    transition = self._transitions.get((prev_state, state), 1e-6)
                    score = dp[i - 1][ps] + math.log(transition) + emission
                    if score > best_prev_score:
                        best_prev_score = score
                        best_prev_idx = ps
                dp[i][s] = best_prev_score
                parent[i][s] = best_prev_idx

        end_state = max(range(num_states), key=lambda idx: dp[-1][idx])
        path = [end_state]
        for i in range(n - 1, 0, -1):
            path.append(parent[i][path[-1]])
        path.reverse()

        planned_stages = [self._stage_order[s] for s in path]
        chain_stages: list[str] = []
        chain_events: list[dict[str, Any]] = []
        for i, stage in enumerate(planned_stages):
            if not chain_stages or stage != chain_stages[-1]:
                chain_stages.append(stage)
                chain_events.append(sorted_events[i][3])

        if len(chain_stages) < 3:
            return None

        progression_bonus = len(set(chain_stages)) / len(self._stage_order)
        terminal_bonus = 0.2 if "exfiltration" in chain_stages else 0.0
        path_confidence = min(1.0, 0.55 + progression_bonus * 0.35 + terminal_bonus)
        if path_confidence < 0.62:
            return None
        return chain_stages, chain_events, path_confidence

    def _build_transition_matrix(self) -> dict[tuple[str, str], float]:
        transitions: dict[tuple[str, str], float] = {}
        for i, src in enumerate(self._stage_order):
            for j, dst in enumerate(self._stage_order):
                if i == j:
                    prob = 0.20
                elif j == i + 1:
                    prob = 0.45
                elif j > i:
                    prob = 0.25 / max(1, len(self._stage_order) - i - 2)
                else:
                    prob = 0.10 / max(1, i)
                transitions[(src, dst)] = prob
        return transitions
