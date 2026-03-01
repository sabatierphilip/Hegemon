from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass
from math import fabs
from typing import Any


@dataclass
class MirrorAlert:
    shard: str
    mode: str
    severity: int
    confidence: float
    reason: str
    event: dict[str, Any]


@dataclass
class CounterCloneAction:
    shard: str
    action: str
    target: str
    rationale: str
    priority: int


@dataclass
class CapturedClone:
    shard: str
    confidence: float
    action_priors: dict[str, float]
    transition_model: dict[str, dict[str, float]]
    likely_resources: dict[str, list[str]]
    behavioral_signature: str
    simulation_horizon: int


@dataclass
class CloneDeployment:
    shard: str
    deployment_id: str
    ready_in_minutes: int
    confidence: float
    predicted_next_actions: list[str]
    reverse_shards: list[str]
    deception_risk: float
    phases: list[str]
    synthetic_probe_sequence: list[dict[str, Any]]
    containment_targets: list[str]
    captured_clone: CapturedClone
    simulated_attack_path: list[dict[str, str]]
    reason: str


@dataclass
class ReconDirective:
    shard: str
    confidence: float
    markov_kill_chain_score: float
    predicted_path: list[str]
    target_resource: str
    rationale: str


class MirrorCloneDetector:
    """Builds per-identity scan/trace clones and can rapidly deploy executable counter-clones."""

    def __init__(
        self,
        warmup_events: int = 6,
        min_prediction_confidence: float = 0.65,
        rapid_clone_minutes: int = 3,
    ):
        self.warmup_events = warmup_events
        self.min_prediction_confidence = min_prediction_confidence
        self.rapid_clone_minutes = max(1, rapid_clone_minutes)
        self._seen_events = 0
        self._scan_fingerprint: dict[str, float] = {}
        self._scan_samples: dict[str, int] = defaultdict(int)
        self._null_probe_counts: dict[str, int] = defaultdict(int)
        self._last_action: dict[str, str] = {}
        self._action_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._transitions: dict[str, dict[str, dict[str, int]]] = defaultdict(
            lambda: defaultdict(lambda: defaultdict(int))
        )
        self._resource_counts: dict[str, dict[str, dict[str, int]]] = defaultdict(
            lambda: defaultdict(lambda: defaultdict(int))
        )
        self._deployments: dict[str, CloneDeployment] = {}

    def generate_autonomous_recon_directives(
        self,
        max_directives: int = 4,
        min_markov_score: float = 0.35,
    ) -> list[ReconDirective]:
        directives: list[ReconDirective] = []
        for shard, action_counts in self._action_counts.items():
            if sum(action_counts.values()) < self.warmup_events:
                continue

            path, confidence = self._predict_markov_path(shard, horizon=4)
            if not path:
                continue
            markov_score = self._markov_kill_chain_score(path)
            if markov_score < min_markov_score:
                continue

            candidate_resources = self._resource_counts[shard].get(path[0], {})
            target_resource = (
                max(candidate_resources.items(), key=lambda item: item[1])[0]
                if candidate_resources
                else "synthetic://unknown"
            )
            directives.append(
                ReconDirective(
                    shard=shard,
                    confidence=round(confidence, 3),
                    markov_kill_chain_score=round(markov_score, 3),
                    predicted_path=path,
                    target_resource=target_resource,
                    rationale=(
                        "Autonomous hunter directive generated from Markov kill-chain backmodeling; "
                        "counter-clone seeks rogue behavior before inbound alerts"
                    ),
                )
            )

        directives.sort(
            key=lambda item: (item.markov_kill_chain_score, item.confidence),
            reverse=True,
        )
        return directives[:max(0, max_directives)]

    def execute_recon_directive(self, directive: ReconDirective) -> list[CounterCloneAction]:
        host = directive.shard.split("|", 1)[0].replace("host:", "")
        primary_action = directive.predicted_path[0] if directive.predicted_path else "unknown"
        return [
            CounterCloneAction(
                shard=directive.shard,
                action="launch_autonomous_recon",
                target=f"{primary_action}@{directive.target_resource}",
                rationale=directive.rationale,
                priority=min(98, 72 + int(directive.markov_kill_chain_score * 20)),
            ),
            CounterCloneAction(
                shard=directive.shard,
                action="backmodel_markov_kill_chain",
                target="->".join(directive.predicted_path),
                rationale="Continuously update rogue trajectory model and pre-compute interception points",
                priority=min(97, 70 + int(directive.confidence * 20)),
            ),
            CounterCloneAction(
                shard=directive.shard,
                action="emit_synthetic_probe",
                target="synthetic://hunter/recon",
                rationale=f"Active hunt probe against host {host}",
                priority=68,
            ),
        ]

    def evaluate(self, event: dict[str, Any]) -> list[MirrorAlert]:
        shard = self._shard_key(event)
        action = str(event.get("action", "unknown")).strip().lower()
        resource = str(event.get("resource", "unknown")).strip().lower()

        alerts: list[MirrorAlert] = []
        alerts.extend(self._scan_mode(shard, event))
        alerts.extend(self._trace_mode(shard, action, resource, event))

        self._update_models(shard, action, resource)
        self._seen_events += 1
        return alerts

    def deploy_counter_clone(self, alert: MirrorAlert) -> CloneDeployment:
        shard = alert.shard
        if shard in self._deployments:
            return self._deployments[shard]

        reverse_shards = self._neighbor_shards(shard)
        ensemble = self._ensemble_predictions(shard, top_k=3)
        predicted_actions = [name for name, _ in ensemble] or ["unknown"]
        prediction_conf = ensemble[0][1] if ensemble else alert.confidence
        disagreement = self._model_disagreement(shard)
        deception_risk = round(min(0.99, max(0.05, 1.0 - prediction_conf + 0.35 * disagreement)), 3)
        captured_clone = self.capture_rogue_clone(shard, max(alert.confidence, prediction_conf))
        simulated_attack_path = self._simulate_clone_path(captured_clone)

        deployment = CloneDeployment(
            shard=shard,
            deployment_id=f"clone::{shard}::{len(self._deployments) + 1}",
            ready_in_minutes=self.rapid_clone_minutes,
            confidence=round(max(alert.confidence, prediction_conf), 3),
            predicted_next_actions=predicted_actions,
            reverse_shards=reverse_shards,
            deception_risk=deception_risk,
            phases=self._deployment_phases(deception_risk),
            synthetic_probe_sequence=self._synthetic_probe_sequence(shard, predicted_actions),
            containment_targets=self._containment_targets(shard, reverse_shards),
            captured_clone=captured_clone,
            simulated_attack_path=simulated_attack_path,
            reason=(
                f"Rapid counter-clone deployment generated from {alert.mode} alert; "
                f"clone ready in ~{self.rapid_clone_minutes} minute(s)"
            ),
        )
        self._deployments[shard] = deployment
        return deployment

    def capture_rogue_clone(self, shard: str, confidence: float) -> CapturedClone:
        action_counts = self._action_counts[shard]
        total_actions = float(sum(action_counts.values()))
        priors = {a: (c / total_actions) for a, c in action_counts.items()} if total_actions > 0 else {"unknown": 1.0}

        transition_model: dict[str, dict[str, float]] = {}
        for action, nxt in self._transitions[shard].items():
            total = float(sum(nxt.values()))
            if total > 0:
                transition_model[action] = {n: (cnt / total) for n, cnt in nxt.items()}

        likely_resources: dict[str, list[str]] = {}
        for action, resources in self._resource_counts[shard].items():
            ranked = sorted(resources.items(), key=lambda item: item[1], reverse=True)
            likely_resources[action] = [name for name, _ in ranked[:3]]

        signature_payload = {
            "shard": shard,
            "priors": priors,
            "transitions": transition_model,
            "resources": likely_resources,
        }
        signature = hashlib.sha256(json.dumps(signature_payload, sort_keys=True).encode("utf-8")).hexdigest()[:24]

        return CapturedClone(
            shard=shard,
            confidence=round(confidence, 3),
            action_priors=priors,
            transition_model=transition_model,
            likely_resources=likely_resources,
            behavioral_signature=signature,
            simulation_horizon=4,
        )

    def execute_counter_clone(self, deployment: CloneDeployment) -> list[CounterCloneAction]:
        actions: list[CounterCloneAction] = []
        for phase in deployment.phases:
            actions.append(
                CounterCloneAction(
                    shard=deployment.shard,
                    action="run_phase",
                    target=phase,
                    rationale=f"Execute clone phase '{phase}'",
                    priority=90 if "deception" in phase else 70,
                )
            )

        for step in deployment.simulated_attack_path:
            target = f"{step['action']}@{step['resource']}"
            actions.append(
                CounterCloneAction(
                    shard=deployment.shard,
                    action="block_simulated_path",
                    target=target,
                    rationale="Block predicted clone-simulated rogue action path",
                    priority=92,
                )
            )

        for probe in deployment.synthetic_probe_sequence:
            actions.append(
                CounterCloneAction(
                    shard=deployment.shard,
                    action="emit_synthetic_probe",
                    target=str(probe.get("resource", "synthetic://unknown")),
                    rationale=f"Probe predicted path via {probe.get('action', 'unknown')}",
                    priority=65,
                )
            )

        for target in deployment.containment_targets:
            actions.append(
                CounterCloneAction(
                    shard=deployment.shard,
                    action="prestage_containment",
                    target=target,
                    rationale="Pre-stage containment on primary and reverse shards",
                    priority=95 if target == deployment.shard else 75,
                )
            )

        dedup: dict[tuple[str, str], CounterCloneAction] = {}
        for action in actions:
            key = (action.action, action.target)
            if key not in dedup or action.priority > dedup[key].priority:
                dedup[key] = action
        return sorted(dedup.values(), key=lambda item: item.priority, reverse=True)

    def predict_actions_for_shard(self, shard: str, top_k: int = 3) -> list[tuple[str, float]]:
        previous = self._last_action.get(shard)
        if previous is None:
            return []
        transitions = self._transitions[shard][previous]
        if not transitions:
            return []
        total = float(sum(transitions.values()))
        ranked = sorted(transitions.items(), key=lambda item: item[1], reverse=True)
        return [(action, count / total) for action, count in ranked[:top_k]]

    def _ensemble_predictions(self, shard: str, top_k: int = 3) -> list[tuple[str, float]]:
        transition_preds = dict(self.predict_actions_for_shard(shard, top_k=6))
        action_counts = self._action_counts[shard]
        total_actions = float(sum(action_counts.values()))
        frequency_preds = {action: (count / total_actions) for action, count in action_counts.items()} if total_actions > 0 else {}

        universe = set(transition_preds) | set(frequency_preds)
        if not universe:
            return []

        blended: list[tuple[str, float]] = []
        for action in universe:
            score = 0.7 * transition_preds.get(action, 0.0) + 0.3 * frequency_preds.get(action, 0.0)
            blended.append((action, score))
        blended.sort(key=lambda item: item[1], reverse=True)

        total = sum(score for _, score in blended[:top_k])
        if total <= 0:
            return []
        return [(action, score / total) for action, score in blended[:top_k]]

    def _model_disagreement(self, shard: str) -> float:
        transition = self.predict_actions_for_shard(shard, top_k=1)
        ensemble = self._ensemble_predictions(shard, top_k=1)
        if not transition or not ensemble:
            return 0.0
        transition_action, transition_conf = transition[0]
        ensemble_action, ensemble_conf = ensemble[0]
        disagreement = abs(transition_conf - ensemble_conf)
        if transition_action != ensemble_action:
            disagreement += 0.3
        return min(1.0, disagreement)

    def _simulate_clone_path(self, clone: CapturedClone) -> list[dict[str, str]]:
        path: list[dict[str, str]] = []
        priors = clone.action_priors
        if not priors:
            return [{"action": "unknown", "resource": "synthetic://unknown"}]

        current = max(priors.items(), key=lambda item: item[1])[0]
        for _ in range(clone.simulation_horizon):
            resources = clone.likely_resources.get(current, ["synthetic://unknown"])
            path.append({"action": current, "resource": resources[0]})
            transitions = clone.transition_model.get(current, {})
            if transitions:
                current = max(transitions.items(), key=lambda item: item[1])[0]
            else:
                current = max(priors.items(), key=lambda item: item[1])[0]
        return path

    def _scan_mode(self, shard: str, event: dict[str, Any]) -> list[MirrorAlert]:
        alerts: list[MirrorAlert] = []
        score = self._scan_score(event)
        prev = self._scan_fingerprint.get(shard)
        samples = self._scan_samples[shard]

        if prev is not None and samples >= self.warmup_events:
            drift = fabs(score - prev)
            if drift >= 0.45:
                confidence = min(0.99, 0.45 + drift)
                severity = min(96, 55 + int(drift * 50))
                alerts.append(
                    MirrorAlert(
                        shard=shard,
                        mode="scan",
                        severity=severity,
                        confidence=round(confidence, 3),
                        reason=(
                            f"Scan fingerprint drift detected for {shard}: "
                            f"current={score:.3f}, baseline={prev:.3f}, drift={drift:.3f}"
                        ),
                        event=event,
                    )
                )

        alpha = 0.2
        self._scan_fingerprint[shard] = score if prev is None else (1.0 - alpha) * prev + alpha * score
        self._scan_samples[shard] += 1
        return alerts

    def _trace_mode(self, shard: str, action: str, resource: str, event: dict[str, Any]) -> list[MirrorAlert]:
        alerts: list[MirrorAlert] = []
        warmed_up = self._seen_events >= self.warmup_events

        if action == "unknown" and resource == "unknown" and warmed_up:
            self._null_probe_counts[shard] += 1
            probes = self._null_probe_counts[shard]
            if probes >= 3:
                confidence = min(0.98, 0.50 + probes * 0.07)
                severity = min(95, 60 + probes * 4)
                alerts.append(
                    MirrorAlert(
                        shard=shard,
                        mode="trace",
                        severity=severity,
                        confidence=round(confidence, 3),
                        reason=f"Repeated null-event probes observed for {shard} ({probes} in sequence)",
                        event=event,
                    )
                )
        else:
            self._null_probe_counts[shard] = 0

        prev_action = self._last_action.get(shard)
        if warmed_up and prev_action is not None:
            predicted, confidence = self._predict_next_action(shard, prev_action)
            if predicted and confidence >= self.min_prediction_confidence and action != predicted:
                severity = min(97, 58 + int(confidence * 35))
                alerts.append(
                    MirrorAlert(
                        shard=shard,
                        mode="trace",
                        severity=severity,
                        confidence=round(confidence, 3),
                        reason=(
                            f"Trace divergence for {shard}: clone predicted '{predicted}' "
                            f"after '{prev_action}' but observed '{action}'"
                        ),
                        event=event,
                    )
                )

        return alerts

    def _update_models(self, shard: str, action: str, resource: str) -> None:
        previous = self._last_action.get(shard)
        if previous is not None:
            self._transitions[shard][previous][action] += 1
        self._action_counts[shard][action] += 1
        self._resource_counts[shard][action][resource] += 1
        self._last_action[shard] = action

    def _predict_next_action(self, shard: str, previous_action: str) -> tuple[str | None, float]:
        next_map = self._transitions[shard][previous_action]
        if not next_map:
            return None, 0.0
        total = sum(next_map.values())
        predicted, count = max(next_map.items(), key=lambda item: item[1])
        return predicted, (count / total) if total else 0.0

    def _neighbor_shards(self, shard: str) -> list[str]:
        host_token = shard.split("|", 1)[0]
        neighbors = [s for s in self._scan_samples.keys() if s != shard and s.startswith(host_token)]
        return sorted(neighbors)[:3]

    @staticmethod
    def _deployment_phases(deception_risk: float) -> list[str]:
        phases = [
            "bootstrap_shadow_clone",
            "replay_recent_trace_windows",
            "generate_counterfactual_evasion_paths",
            "prestage_containment_edges",
        ]
        if deception_risk >= 0.45:
            phases.append("activate_deception_hardening")
        return phases

    @staticmethod
    def _synthetic_probe_sequence(shard: str, predicted_actions: list[str]) -> list[dict[str, Any]]:
        host = shard.split("|", 1)[0].replace("host:", "")
        return [
            {"host": host, "action": "unknown", "resource": "unknown", "probe": "recon_canary"},
            {"host": host, "action": predicted_actions[0], "resource": "synthetic://primary_path"},
            {"host": host, "action": predicted_actions[min(1, len(predicted_actions) - 1)], "resource": "synthetic://alternate_path"},
        ]

    @staticmethod
    def _containment_targets(shard: str, reverse_shards: list[str]) -> list[str]:
        targets = [shard]
        targets.extend(reverse_shards)
        return targets[:4]

    @staticmethod
    def _shard_key(event: dict[str, Any]) -> str:
        host = str(event.get("host", "unknown")).strip().lower()
        user = str(event.get("user", "unknown")).strip().lower()
        process = str(event.get("process", "unknown")).strip().lower()
        return f"host:{host}|user:{user}|proc:{process}"

    def _predict_markov_path(self, shard: str, horizon: int = 4) -> tuple[list[str], float]:
        priors = self._action_counts[shard]
        if not priors:
            return [], 0.0
        total = float(sum(priors.values()))
        current = max(priors.items(), key=lambda item: item[1])[0]
        confidence = priors[current] / total if total else 0.0

        path = [current]
        for _ in range(max(0, horizon - 1)):
            transitions = self._transitions[shard].get(current, {})
            if not transitions:
                break
            t_total = float(sum(transitions.values()))
            if t_total <= 0:
                break
            next_action, next_count = max(transitions.items(), key=lambda item: item[1])
            confidence *= next_count / t_total
            path.append(next_action)
            current = next_action
        return path, min(1.0, confidence)

    @staticmethod
    def _markov_kill_chain_score(path: list[str]) -> float:
        stage_weights = {
            "login_failure": 0.18,
            "scan": 0.16,
            "container_spawn": 0.22,
            "model_invoke": 0.1,
            "compute_hoarding": 0.25,
            "iam_privilege_change": 0.26,
            "network_send": 0.3,
            "autonomous_replication": 0.35,
            "policy_evasion": 0.35,
            "sandbox_escape": 0.4,
        }
        if not path:
            return 0.0
        score = sum(stage_weights.get(step, 0.05) for step in path)
        progression_bonus = 0.15 if len(set(path)) >= 3 else 0.0
        model_invoke_share = sum(1 for step in path if step == "model_invoke") / len(path)
        if model_invoke_share >= 0.75:
            score += stage_weights["compute_hoarding"]
        return min(1.0, score / max(1.0, len(path) * 0.3) + progression_bonus)

    @staticmethod
    def _scan_score(event: dict[str, Any]) -> float:
        action = str(event.get("action", "unknown")).strip().lower()
        resource = str(event.get("resource", "unknown")).strip().lower()
        api_call_count = float(event.get("api_call_count", 0) or 0)
        egress_mb = float(event.get("egress_mb", 0) or 0)
        gpu_cpu = float(event.get("gpu_cpu", 0) or 0)

        identity_density = sum(
            1
            for field in ("host", "user", "process", "action", "resource")
            if str(event.get(field, "unknown")) != "unknown"
        ) / 5.0
        behavior_intensity = min(1.0, (api_call_count / 1200.0) + (egress_mb / 1200.0) + (gpu_cpu / 100.0)) / 3.0
        lexical_bias = min(1.0, (len(action) + len(resource)) / 40.0)
        return 0.50 * behavior_intensity + 0.30 * identity_density + 0.20 * lexical_bias
