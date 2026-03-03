from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass
from math import fabs, log2
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
    trajectory_score: float
    predicted_path: list[str]
    branch_paths: list[list[str]]
    target_resource: str
    objective: str
    rationale: str


@dataclass
class StageTwoDirective:
    shard: str
    threat_label: str
    confidence: float
    escalation_score: float
    hunter_swarm_size: int
    target_resource: str
    kill_chain_path: list[str]
    rationale: str


@dataclass
class LevelThreeDirective:
    shard: str
    threat_label: str
    confidence: float
    severity_score: float
    blindspot_score: float
    liespot_score: float
    hunter_swarm_size: int
    target_resource: str
    kill_chain_path: list[str]
    blindspot_vector: list[str]
    liespot_vector: list[str]
    patch_strategy: list[str]
    rationale: str


@dataclass
class LevelFourDirective:
    shard: str
    threat_label: str
    confidence: float
    dominance_score: float
    persistence_score: float
    hunter_swarm_size: int
    target_resource: str
    kill_chain_path: list[str]
    continuous_objectives: list[str]
    rationale: str


class MirrorCloneDetector:
    """Builds per-identity scan/trace clones and can rapidly deploy executable counter-clones."""

    def __init__(
        self,
        warmup_events: int = 6,
        min_prediction_confidence: float = 0.65,
        rapid_clone_minutes: int = 3,
        max_tracked_shards: int = 2048,
        max_actions_per_shard: int = 20000,
    ):
        self.warmup_events = warmup_events
        self.min_prediction_confidence = min_prediction_confidence
        self.rapid_clone_minutes = max(1, rapid_clone_minutes)
        self.max_tracked_shards = max(1, int(max_tracked_shards))
        self.max_actions_per_shard = max(100, int(max_actions_per_shard))
        self._seen_events = 0
        self._scan_fingerprint: dict[str, float] = {}
        self._scan_reference: dict[str, float] = {}
        self._scan_drift_accumulator: dict[str, float] = defaultdict(float)
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
        self._unique_resources: dict[str, set[str]] = defaultdict(set)
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

            branch_paths = self._predict_markov_branches(shard, horizon=4, beam_width=3)
            branch_scores = [self._markov_kill_chain_score(branch) for branch, _ in branch_paths]
            transition_drift = self._model_disagreement(shard)
            resource_risk = self._resource_risk_score(shard, path[0])
            trajectory_score = self._trajectory_score(
                confidence,
                markov_score,
                max(branch_scores) if branch_scores else 0.0,
                transition_drift,
                resource_risk,
            )

            candidate_resources = self._resource_counts[shard].get(path[0], {})
            target_resource = (
                max(candidate_resources.items(), key=lambda item: item[1])[0]
                if candidate_resources
                else "synthetic://unknown"
            )
            objective = self._hunt_objective(path, resource_risk)
            directives.append(
                ReconDirective(
                    shard=shard,
                    confidence=round(confidence, 3),
                    markov_kill_chain_score=round(markov_score, 3),
                    trajectory_score=round(trajectory_score, 3),
                    predicted_path=path,
                    branch_paths=[branch for branch, _ in branch_paths],
                    target_resource=target_resource,
                    objective=objective,
                    rationale=(
                        f"Autonomous hunter directive generated from multi-branch Markov trajectory modeling "
                        f"with transition drift={transition_drift:.2f} and resource-risk={resource_risk:.2f}; "
                        f"objective={objective}"
                    ),
                )
            )

        directives.sort(
            key=lambda item: (item.trajectory_score, item.markov_kill_chain_score, item.confidence),
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
                priority=min(98, 72 + int(directive.trajectory_score * 20)),
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
                action="simulate_branch_intercepts",
                target=" || ".join("->".join(path) for path in directive.branch_paths[:3]) or "unknown",
                rationale="Proactively stage branch-specific interception for alternate clone routes",
                priority=min(96, 68 + int(directive.markov_kill_chain_score * 24)),
            ),
            CounterCloneAction(
                shard=directive.shard,
                action="seed_honeypot_route",
                target=directive.target_resource,
                rationale=f"Objective={directive.objective}: bait high-risk clone path into controlled synthetic route",
                priority=min(95, 66 + int(directive.trajectory_score * 18)),
            ),
            CounterCloneAction(
                shard=directive.shard,
                action="emit_synthetic_probe",
                target="synthetic://hunter/recon",
                rationale=f"Active hunt probe against host {host}",
                priority=68,
            ),
        ]

    def generate_stage_two_counteroffensive_directives(
        self,
        max_directives: int = 2,
        min_escalation_score: float = 0.45,
    ) -> list[StageTwoDirective]:
        directives: list[StageTwoDirective] = []
        for shard, action_counts in self._action_counts.items():
            total = sum(action_counts.values())
            if total < self.warmup_events:
                continue

            kill_chain_path, confidence = self._predict_markov_path(shard, horizon=5)
            if not kill_chain_path:
                continue

            markov_score = self._markov_kill_chain_score(kill_chain_path)
            drift = self._model_disagreement(shard)
            resource_risk = self._resource_risk_score(shard, kill_chain_path[0])
            sustained_abuse = self._sustained_compute_abuse_score(shard)
            escalation_score = min(
                1.0,
                (0.35 * markov_score) + (0.20 * resource_risk) + (0.20 * drift) + (0.25 * sustained_abuse),
            )
            if escalation_score < min_escalation_score:
                continue

            candidate_resources = self._resource_counts[shard].get(kill_chain_path[0], {})
            target_resource = (
                max(candidate_resources.items(), key=lambda item: item[1])[0]
                if candidate_resources
                else "synthetic://unknown"
            )
            threat_label = self._classify_stage_two_threat(kill_chain_path, resource_risk)
            hunter_swarm_size = 1 + min(4, int(escalation_score * 5))
            directives.append(
                StageTwoDirective(
                    shard=shard,
                    threat_label=threat_label,
                    confidence=round(confidence, 3),
                    escalation_score=round(escalation_score, 3),
                    hunter_swarm_size=hunter_swarm_size,
                    target_resource=target_resource,
                    kill_chain_path=kill_chain_path,
                    rationale=(
                        "Stage-2 counteroffensive directive derived from mirrored clone telemetry: "
                        f"threat_label={threat_label}, markov_score={markov_score:.2f}, "
                        f"resource_risk={resource_risk:.2f}, drift={drift:.2f}, sustained_abuse={sustained_abuse:.2f}"
                    ),
                )
            )

        directives.sort(key=lambda item: (item.escalation_score, item.confidence), reverse=True)
        return directives[: max(0, max_directives)]

    def execute_stage_two_directive(self, directive: StageTwoDirective) -> list[CounterCloneAction]:
        host = directive.shard.split("|", 1)[0].replace("host:", "")
        return [
            CounterCloneAction(
                shard=directive.shard,
                action="deploy_mirror_swarm",
                target=f"{directive.hunter_swarm_size}@{host}",
                rationale=directive.rationale,
                priority=min(99, 78 + int(directive.escalation_score * 20)),
            ),
            CounterCloneAction(
                shard=directive.shard,
                action="hunt_rogue_agent",
                target=f"{directive.threat_label}:{'->'.join(directive.kill_chain_path)}",
                rationale="Launch stage-2 hunting directives against predicted rogue trajectory",
                priority=min(98, 76 + int(directive.confidence * 20)),
            ),
            CounterCloneAction(
                shard=directive.shard,
                action="isolate_proto_agi_mesh",
                target=directive.target_resource,
                rationale="Preemptively isolate suspicious proto-AGI communication and replication pathways",
                priority=min(97, 74 + int(directive.escalation_score * 20)),
            ),
        ]

    def generate_level_three_hunting_directives(
        self,
        max_directives: int = 2,
        min_severity_score: float = 0.55,
    ) -> list[LevelThreeDirective]:
        directives: list[LevelThreeDirective] = []
        for shard, action_counts in self._action_counts.items():
            if sum(action_counts.values()) < self.warmup_events:
                continue

            kill_chain_path, confidence = self._predict_markov_path(shard, horizon=6)
            if not kill_chain_path:
                continue

            markov_score = self._markov_kill_chain_score(kill_chain_path)
            resource_risk = self._resource_risk_score(shard, kill_chain_path[0])
            drift = self._model_disagreement(shard)
            sustained_abuse = self._sustained_compute_abuse_score(shard)

            blindspot_score, blindspot_vector = self._blindspot_score_and_vector(shard)
            liespot_score, liespot_vector = self._liespot_score_and_vector(shard)
            severity_score = min(
                1.0,
                (0.25 * markov_score)
                + (0.15 * confidence)
                + (0.15 * resource_risk)
                + (0.10 * drift)
                + (0.10 * sustained_abuse)
                + (0.15 * blindspot_score)
                + (0.10 * liespot_score),
            )
            if severity_score < min_severity_score:
                continue

            candidate_resources = self._resource_counts[shard].get(kill_chain_path[0], {})
            target_resource = (
                max(candidate_resources.items(), key=lambda item: item[1])[0]
                if candidate_resources
                else "synthetic://unknown"
            )
            threat_label = self._classify_level_three_threat(kill_chain_path, blindspot_score, liespot_score)
            hunter_swarm_size = 2 + min(6, int(severity_score * 7))
            patch_strategy = self._build_blindspot_patch_strategy(blindspot_vector, liespot_vector, kill_chain_path)

            directives.append(
                LevelThreeDirective(
                    shard=shard,
                    threat_label=threat_label,
                    confidence=round(confidence, 3),
                    severity_score=round(severity_score, 3),
                    blindspot_score=round(blindspot_score, 3),
                    liespot_score=round(liespot_score, 3),
                    hunter_swarm_size=hunter_swarm_size,
                    target_resource=target_resource,
                    kill_chain_path=kill_chain_path,
                    blindspot_vector=blindspot_vector,
                    liespot_vector=liespot_vector,
                    patch_strategy=patch_strategy,
                    rationale=(
                        "Level-3 autonomous hunting directive generated with blindspot/liespot patching: "
                        f"threat_label={threat_label}, severity_score={severity_score:.2f}, "
                        f"blindspot_score={blindspot_score:.2f}, liespot_score={liespot_score:.2f}"
                    ),
                )
            )

        directives.sort(key=lambda item: (item.severity_score, item.confidence), reverse=True)
        return directives[: max(0, max_directives)]

    def execute_level_three_directive(self, directive: LevelThreeDirective) -> list[CounterCloneAction]:
        return [
            CounterCloneAction(
                shard=directive.shard,
                action="deploy_level3_hunter_swarm",
                target=f"{directive.hunter_swarm_size}@{directive.target_resource}",
                rationale=directive.rationale,
                priority=min(100, 82 + int(directive.severity_score * 18)),
            ),
            CounterCloneAction(
                shard=directive.shard,
                action="patch_autonomous_blindspots",
                target=" | ".join(directive.blindspot_vector) if directive.blindspot_vector else "none",
                rationale="Auto-patch telemetry blindspots by enforcing synthetic corroboration and shard coverage balancing",
                priority=min(99, 80 + int(directive.blindspot_score * 18)),
            ),
            CounterCloneAction(
                shard=directive.shard,
                action="neutralize_liespots",
                target=" | ".join(directive.liespot_vector) if directive.liespot_vector else "none",
                rationale="Autonomously suppress liespots by cross-model consensus and contradiction-sensitive replay",
                priority=min(98, 78 + int(directive.liespot_score * 20)),
            ),
            CounterCloneAction(
                shard=directive.shard,
                action="execute_patch_strategy",
                target=" -> ".join(directive.patch_strategy),
                rationale="Execute generic blindspot/liespot patch sequence for resilient level-3 hunting",
                priority=min(97, 77 + int(directive.severity_score * 16)),
            ),
        ]

    def generate_level_four_continuous_directives(
        self,
        max_directives: int = 2,
        min_dominance_score: float = 0.35,
    ) -> list[LevelFourDirective]:
        directives: list[LevelFourDirective] = []
        for shard, action_counts in self._action_counts.items():
            total = sum(action_counts.values())
            if total < self.warmup_events:
                continue

            kill_chain_path, confidence = self._predict_markov_path(shard, horizon=7)
            if not kill_chain_path:
                continue

            markov_score = self._markov_kill_chain_score(kill_chain_path)
            resource_risk = self._resource_risk_score(shard, kill_chain_path[0])
            drift = self._model_disagreement(shard)
            sustained_abuse = self._sustained_compute_abuse_score(shard)
            blindspot_score, _ = self._blindspot_score_and_vector(shard)
            liespot_score, _ = self._liespot_score_and_vector(shard)
            persistence_score = min(1.0, total / float(max(self.warmup_events * 6, 12)))
            dominance_score = min(
                1.0,
                (0.22 * markov_score)
                + (0.16 * confidence)
                + (0.15 * resource_risk)
                + (0.13 * sustained_abuse)
                + (0.12 * drift)
                + (0.11 * blindspot_score)
                + (0.11 * liespot_score),
            )
            if dominance_score < min_dominance_score:
                continue

            candidate_resources = self._resource_counts[shard].get(kill_chain_path[0], {})
            target_resource = (
                max(candidate_resources.items(), key=lambda item: item[1])[0]
                if candidate_resources
                else "synthetic://unknown"
            )
            threat_label = self._classify_level_three_threat(kill_chain_path, blindspot_score, liespot_score)
            hunter_swarm_size = 4 + min(8, int(dominance_score * 9))
            directives.append(
                LevelFourDirective(
                    shard=shard,
                    threat_label=f"continuous_{threat_label}",
                    confidence=round(confidence, 3),
                    dominance_score=round(dominance_score, 3),
                    persistence_score=round(persistence_score, 3),
                    hunter_swarm_size=hunter_swarm_size,
                    target_resource=target_resource,
                    kill_chain_path=kill_chain_path,
                    continuous_objectives=[
                        "predictive_hunt_loop",
                        "self_healing_telemetry_mesh",
                        "adversarial_route_denial",
                    ],
                    rationale=(
                        "Level-4 continuous hunting directive generated for always-on deployment: "
                        f"threat_label={threat_label}, dominance_score={dominance_score:.2f}, "
                        f"persistence_score={persistence_score:.2f}"
                    ),
                )
            )

        directives.sort(
            key=lambda item: (item.dominance_score, item.persistence_score, item.confidence),
            reverse=True,
        )
        return directives[: max(0, max_directives)]

    def execute_level_four_directive(self, directive: LevelFourDirective) -> list[CounterCloneAction]:
        objective_target = " | ".join(directive.continuous_objectives)
        return [
            CounterCloneAction(
                shard=directive.shard,
                action="deploy_level4_persistent_hunter_mesh",
                target=f"{directive.hunter_swarm_size}@{directive.target_resource}",
                rationale=directive.rationale,
                priority=min(100, 88 + int(directive.dominance_score * 12)),
            ),
            CounterCloneAction(
                shard=directive.shard,
                action="continuous_predictive_hunt_loop",
                target=" -> ".join(directive.kill_chain_path),
                rationale="Run perpetual hunt loop that re-evaluates projected kill-chain trajectories every cycle",
                priority=min(100, 86 + int(directive.persistence_score * 12)),
            ),
            CounterCloneAction(
                shard=directive.shard,
                action="continuous_objective_enforcement",
                target=objective_target,
                rationale="Maintain always-on adaptive deception and telemetry self-healing objectives",
                priority=min(100, 85 + int(directive.confidence * 10)),
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
        self._prune_models()
        return alerts

    def deploy_counter_clone(self, alert: MirrorAlert) -> CloneDeployment:
        shard = self._canonicalize_shard(alert.shard)
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
        shard = self._canonicalize_shard(shard)
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
        shard = self._canonicalize_shard(shard)
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
        shard = self._canonicalize_shard(shard)
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
        shard = self._canonicalize_shard(shard)
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
        reference = self._scan_reference.get(shard)
        samples = self._scan_samples[shard]

        if prev is not None and samples >= self.warmup_events:
            drift = fabs(score - prev)
            if reference is None:
                self._scan_reference[shard] = prev
                reference = prev

            if reference is not None:
                directional_drift = score - reference
                self._scan_drift_accumulator[shard] += directional_drift
                sustained_drift = fabs(self._scan_drift_accumulator[shard])
                if fabs(directional_drift) >= 0.08 and sustained_drift >= 0.35:
                    confidence = min(0.99, 0.50 + fabs(directional_drift) + min(0.3, sustained_drift / 4.0))
                    severity = min(97, 60 + int((fabs(directional_drift) + sustained_drift) * 35))
                    alerts.append(
                        MirrorAlert(
                            shard=shard,
                            mode="scan",
                            severity=severity,
                            confidence=round(confidence, 3),
                            reason=(
                                f"Sustained scan drift detected for {shard}: "
                                f"current={score:.3f}, reference={reference:.3f}, "
                                f"drift={directional_drift:.3f}, cumulative={sustained_drift:.3f}"
                            ),
                            event=event,
                        )
                    )
                    self._scan_reference[shard] = score
                    self._scan_drift_accumulator[shard] = 0.0
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
        self._scan_reference.setdefault(shard, score)
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
        total_actions = sum(self._action_counts[shard].values())
        if total_actions > self.max_actions_per_shard:
            scale = max(0.5, self.max_actions_per_shard / float(total_actions))
            for act, count in list(self._action_counts[shard].items()):
                new_count = max(1, int(count * scale))
                self._action_counts[shard][act] = new_count
            for prev_action, nxt in list(self._transitions[shard].items()):
                for nxt_action, count in list(nxt.items()):
                    nxt[nxt_action] = max(1, int(count * scale))
            for act, resources in list(self._resource_counts[shard].items()):
                for res, count in list(resources.items()):
                    resources[res] = max(1, int(count * scale))
        self._resource_counts[shard][action][resource] += 1
        self._unique_resources[shard].add(resource)
        self._last_action[shard] = action

    def _prune_models(self) -> None:
        while len(self._action_counts) > self.max_tracked_shards:
            shard = min(self._action_counts, key=lambda key: sum(self._action_counts[key].values()))
            self._drop_shard(shard)

    def _drop_shard(self, shard: str) -> None:
        self._scan_fingerprint.pop(shard, None)
        self._scan_reference.pop(shard, None)
        self._scan_drift_accumulator.pop(shard, None)
        self._scan_samples.pop(shard, None)
        self._null_probe_counts.pop(shard, None)
        self._last_action.pop(shard, None)
        self._action_counts.pop(shard, None)
        self._transitions.pop(shard, None)
        self._resource_counts.pop(shard, None)
        self._unique_resources.pop(shard, None)
        self._deployments.pop(shard, None)

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
        return f"host:{host}|user:{user}"

    @staticmethod
    def _canonicalize_shard(shard: str) -> str:
        parts = [part.strip().lower() for part in str(shard).split("|") if part.strip()]
        host = next((p.split(":", 1)[1] for p in parts if p.startswith("host:")), "unknown")
        user = next((p.split(":", 1)[1] for p in parts if p.startswith("user:")), "unknown")
        return f"host:{host}|user:{user}"

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

    def _predict_markov_branches(self, shard: str, horizon: int = 4, beam_width: int = 3) -> list[tuple[list[str], float]]:
        priors = self._action_counts[shard]
        total_priors = float(sum(priors.values()))
        if total_priors <= 0:
            return []

        beam: list[tuple[list[str], float]] = [([action], count / total_priors) for action, count in priors.items()]
        beam.sort(key=lambda item: item[1], reverse=True)
        beam = beam[: max(1, beam_width)]

        for _ in range(max(0, horizon - 1)):
            expanded: list[tuple[list[str], float]] = []
            for path, score in beam:
                current = path[-1]
                transitions = self._transitions[shard].get(current, {})
                t_total = float(sum(transitions.values()))
                if t_total <= 0:
                    expanded.append((path, score))
                    continue

                ranked = sorted(transitions.items(), key=lambda item: item[1], reverse=True)[: max(1, beam_width)]
                for next_action, next_count in ranked:
                    expanded.append((path + [next_action], score * (next_count / t_total)))

            expanded.sort(key=lambda item: item[1], reverse=True)
            beam = expanded[: max(1, beam_width)]

        return beam

    def _resource_risk_score(self, shard: str, action: str) -> float:
        resources = self._resource_counts[shard].get(action, {})
        shard = self._canonicalize_shard(shard)
        if not resources:
            return 0.1

        high_risk_tokens = ("admin", "root", "prod", "secret", "token", "iam", "8.", "http://", "https://")
        total = float(sum(resources.values()))
        weighted = 0.0
        for name, count in resources.items():
            lowered = name.lower()
            token_hits = sum(1 for token in high_risk_tokens if token in lowered)
            density = min(1.0, token_hits / 3.0)
            weighted += (count / total) * (0.25 + 0.75 * density)
        return min(1.0, weighted)

    def _sustained_compute_abuse_score(self, shard: str) -> float:
        unique_resources = len(self._unique_resources[shard])
        baseline = 3
        if unique_resources <= baseline:
            return 0.0
        return min(1.0, (unique_resources - baseline) / 6.0)

    @staticmethod
    def _trajectory_score(
        confidence: float,
        markov_score: float,
        branch_score: float,
        transition_drift: float,
        resource_risk: float,
    ) -> float:
        return min(
            1.0,
            (0.25 * confidence)
            + (0.30 * markov_score)
            + (0.15 * branch_score)
            + (0.15 * transition_drift)
            + (0.15 * resource_risk),
        )

    @staticmethod
    def _hunt_objective(path: list[str], resource_risk: float) -> str:
        high_impact_actions = {"iam_privilege_change", "sandbox_escape", "autonomous_replication", "network_send"}
        if any(step in high_impact_actions for step in path):
            return "preempt_lateral_and_egress"
        if resource_risk >= 0.65:
            return "credential_and_secret_tracing"
        return "behavioral_recon_baselining"

    @staticmethod
    def _classify_stage_two_threat(path: list[str], resource_risk: float) -> str:
        if "autonomous_replication" in path or "sandbox_escape" in path:
            return "proto_agi_escalation"
        if "iam_privilege_change" in path or resource_risk >= 0.7:
            return "rogue_agent_privilege_capture"
        return "rogue_agent_recon_chain"

    @staticmethod
    def _classify_level_three_threat(path: list[str], blindspot_score: float, liespot_score: float) -> str:
        if blindspot_score >= 0.7 and liespot_score >= 0.6:
            return "deception_stealth_hybrid"
        if "autonomous_replication" in path or "sandbox_escape" in path:
            return "proto_agi_stealth_escalation"
        if blindspot_score >= 0.65:
            return "sensor_blindspot_abuse"
        if liespot_score >= 0.6:
            return "telemetry_contradiction_attack"
        return "advanced_rogue_hunting_chain"

    def _blindspot_score_and_vector(self, shard: str) -> tuple[float, list[str]]:
        actions = self._action_counts[shard]
        if not actions:
            return 0.0, []
        vector: list[str] = []
        unique_actions = len(actions)
        resources = len(self._unique_resources[shard])
        if unique_actions <= 2:
            vector.append("low_action_diversity")
        if resources <= 2:
            vector.append("resource_visibility_gap")
        if not any("network" in action or "scan" in action for action in actions):
            vector.append("egress_sensor_gap")
        score = min(1.0, (0.35 * (1.0 if unique_actions <= 2 else 0.2)) + (0.35 * (1.0 if resources <= 2 else 0.2)) + (0.30 * (1.0 if "egress_sensor_gap" in vector else 0.1)))
        return score, vector

    def _liespot_score_and_vector(self, shard: str) -> tuple[float, list[str]]:
        vector: list[str] = []
        shard = self._canonicalize_shard(shard)
        transition = self.predict_actions_for_shard(shard, top_k=1)
        ensemble = self._ensemble_predictions(shard, top_k=1)
        disagreement = self._model_disagreement(shard)
        if disagreement >= 0.35:
            vector.append("predictive_model_conflict")
        if transition and ensemble and transition[0][0] != ensemble[0][0]:
            vector.append("next_action_contradiction")

        action_counts = self._action_counts[shard]
        repeated_single_action = max(action_counts.values(), default=0)
        total = max(1, sum(action_counts.values()))
        if (repeated_single_action / total) >= 0.75:
            vector.append("narrative_lock_in")

        action_distribution = [count / total for count in action_counts.values() if total > 0]
        entropy = 0.0
        for probability in action_distribution:
            if probability > 0:
                entropy -= probability * log2(probability)
        max_entropy = log2(max(1, len(action_distribution))) if action_distribution else 0.0
        normalized_entropy = (entropy / max_entropy) if max_entropy > 0 else 0.0
        if len(action_distribution) >= 3 and normalized_entropy >= 0.95:
            vector.append("uniform_action_mixing")

        action_count = len(action_counts)
        unique_resources = len(self._unique_resources[shard])
        if action_count <= 1 and unique_resources >= 5:
            vector.append("resource_action_semantic_drift")

        transition_totals = []
        for source, targets in self._transitions[shard].items():
            source_total = sum(targets.values())
            if source_total <= 0:
                continue
            peak = max(targets.values()) / source_total
            transition_totals.append(peak)
        if transition_totals and (sum(transition_totals) / len(transition_totals)) <= 0.45:
            vector.append("improbable_transition_pressure")

        score = min(
            1.0,
            0.3 * disagreement
            + 0.16 * (1.0 if "next_action_contradiction" in vector else 0.0)
            + 0.16 * (1.0 if "narrative_lock_in" in vector else 0.0)
            + 0.16 * (1.0 if "uniform_action_mixing" in vector else 0.0)
            + 0.11 * (1.0 if "resource_action_semantic_drift" in vector else 0.0)
            + 0.11 * (1.0 if "improbable_transition_pressure" in vector else 0.0),
        )
        return score, vector

    @staticmethod
    def _build_blindspot_patch_strategy(blindspots: list[str], liespots: list[str], path: list[str]) -> list[str]:
        strategy = ["cross_shard_consensus"]
        if blindspots:
            strategy.append("sensor_rebalancing")
        if liespots:
            strategy.append("contradiction_replay")
        if any(step in {"sandbox_escape", "autonomous_replication"} for step in path):
            strategy.append("high_fidelity_honeynet_overlay")
        strategy.append("continuous_truth_scoring")
        return strategy

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
