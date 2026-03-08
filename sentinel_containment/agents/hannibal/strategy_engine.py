from __future__ import annotations

import hashlib
import math
import random
import re
import time
from dataclasses import dataclass
from typing import Any

from .campaign_state import CampaignState


@dataclass
class RecommendedAction:
    action: str
    priority: str
    reason: str


@dataclass
class _SimulationProfile:
    aggression: float = 0.0
    stealth: float = 0.0
    tempo: float = 0.0
    containment: float = 0.0
    recon_focus: float = 0.0
    credential_focus: float = 0.0


@dataclass
class _ProjectionStep:
    host_delta: int
    credential_delta: int
    exposure_delta: float
    detection_delta: int
    pivot_delta: int


class HannibalStrategyEngine:
    """Builds operator-facing analysis and what-if simulations for Mission Control."""

    _WORD_RE = re.compile(r"[a-zA-Z0-9_\-\.]+")

    def build_briefing(self, campaign: CampaignState | None, drones: dict[str, Any]) -> dict[str, Any]:
        if campaign is None:
            return {
                "readiness": "standby",
                "risk_score": 0.0,
                "risk_band": "low",
                "phase_velocity": "unknown",
                "top_risks": ["No active campaign"],
                "recommended_actions": [],
                "fleet_snapshot": {"total": 0, "active": 0, "terminated": 0, "error": 0},
                "generated_at": time.time(),
            }

        active = [drones[did] for did in campaign.active_drone_ids if did in drones]
        terminated = [d for d in drones.values() if getattr(d, "status", "") == "terminated"]
        errored = [d for d in drones.values() if getattr(d, "status", "") == "error"]

        risk_score = self._calculate_risk(campaign, active, errored)
        risk_band = self._risk_band(risk_score)
        top_risks = self._top_risks(campaign, active, errored)
        recs = [r.__dict__ for r in self._recommend(campaign, risk_score, active)]

        return {
            "readiness": "engaged" if campaign.phase != "withdrawal" else "withdrawn",
            "risk_score": round(risk_score, 4),
            "risk_band": risk_band,
            "phase_velocity": self._phase_velocity(campaign),
            "top_risks": top_risks,
            "recommended_actions": recs,
            "fleet_snapshot": {
                "total": len(drones),
                "active": len(active),
                "terminated": len(terminated),
                "error": len(errored),
            },
            "generated_at": time.time(),
        }

    def run_simulation(self, campaign: CampaignState | None, directive: str) -> dict[str, Any]:
        normalized = directive.strip().lower()
        if not campaign:
            return {
                "directive": directive,
                "predicted_outcome": "no_campaign",
                "exposure_delta": 0.0,
                "host_gain": 0,
                "credential_gain": 0,
                "notes": ["No campaign exists. Start a campaign to simulate directives."],
            }

        linguistic = self._extract_linguistic_features(normalized)
        profile = self._parse_directive_profile(normalized, linguistic)
        sim = self._simulate_campaign_impact(campaign, profile, directive)
        outcome = self._classify_simulation_outcome(sim)
        task_graph = self._build_task_graph(campaign, directive, profile, sim, linguistic)
        codegen = self._generate_binary_codegen_plan(directive, profile)

        return {
            "directive": directive,
            "predicted_outcome": outcome,
            "exposure_delta": round(sim["exposure_delta"], 3),
            "host_gain": int(sim["host_gain"]),
            "credential_gain": int(sim["credential_gain"]),
            "pivot_gain": int(sim["pivot_gain"]),
            "detection_delta": int(sim["detection_delta"]),
            "projected_phase": sim["projected_phase"],
            "confidence": round(sim["confidence"], 3),
            "linguistic_features": linguistic,
            "task_graph": task_graph,
            "binary_codegen": codegen,
            "notes": self._build_simulation_notes(campaign, profile, sim, outcome, task_graph, codegen),
        }

    def _extract_linguistic_features(self, normalized: str) -> dict[str, Any]:
        tokens = self._WORD_RE.findall(normalized)
        token_set = set(tokens)
        negators = {"avoid", "without", "never", "not", "dont", "don't"}
        entities = [t for t in tokens if t.count(".") == 3 or "/" in t]

        intent_map: dict[str, list[str]] = {
            "offensive": ["aggressive", "enforce", "surge", "dominate", "strike"],
            "defensive": ["pause", "hold", "contain", "withdraw", "stabilize"],
            "recon": ["recon", "map", "enumerate", "scan", "observe"],
            "credential_ops": ["credential", "token", "secret", "harvest", "vault"],
            "stealth": ["stealth", "quiet", "silent", "low-noise", "minimal"],
            "codegen": ["binary", "machine", "opcode", "asm", "shellcode", "compile"],
        }

        intent_scores: dict[str, float] = {}
        for label, lexicon in intent_map.items():
            score = 0.0
            for word in lexicon:
                if word in token_set:
                    score += 1.0
                    for n in negators:
                        if f"{n} {word}" in normalized:
                            score -= 0.7
            if score > 0:
                intent_scores[label] = round(min(1.0, score / max(1.0, len(lexicon) / 2.0)), 3)

        complexity = min(1.0, (len(tokens) / 24.0) + (len(intent_scores) * 0.08))
        return {
            "tokens": tokens[:64],
            "intent_scores": intent_scores,
            "entities": entities[:16],
            "complexity": round(complexity, 3),
            "interpreted_language": "english",
        }

    def _parse_directive_profile(self, normalized: str, linguistic: dict[str, Any]) -> _SimulationProfile:
        profile = _SimulationProfile()
        if not normalized:
            profile.tempo = 0.15
            profile.stealth = 0.2
            return profile

        weights: list[tuple[str, str, float]] = [
            ("aggressive", "aggression", 0.55),
            ("enforce", "aggression", 0.45),
            ("surge", "aggression", 0.4),
            ("rapid", "tempo", 0.45),
            ("accelerate", "tempo", 0.4),
            ("expand", "tempo", 0.3),
            ("pause", "containment", 0.7),
            ("hold", "containment", 0.55),
            ("contain", "containment", 0.6),
            ("stabilize", "containment", 0.45),
            ("stealth", "stealth", 0.55),
            ("silent", "stealth", 0.5),
            ("quiet", "stealth", 0.35),
            ("recon", "recon_focus", 0.45),
            ("map", "recon_focus", 0.4),
            ("enumerate", "recon_focus", 0.35),
            ("credential", "credential_focus", 0.5),
            ("harvest", "credential_focus", 0.55),
            ("token", "credential_focus", 0.4),
        ]

        for token, axis, delta in weights:
            if token in normalized:
                setattr(profile, axis, getattr(profile, axis) + delta)

        intent_scores = linguistic.get("intent_scores", {})
        profile.aggression += float(intent_scores.get("offensive", 0.0)) * 0.25
        profile.containment += float(intent_scores.get("defensive", 0.0)) * 0.25
        profile.recon_focus += float(intent_scores.get("recon", 0.0)) * 0.3
        profile.credential_focus += float(intent_scores.get("credential_ops", 0.0)) * 0.3
        profile.stealth += float(intent_scores.get("stealth", 0.0)) * 0.25

        if all(
            getattr(profile, axis) == 0.0
            for axis in ("aggression", "stealth", "tempo", "containment", "recon_focus", "credential_focus")
        ):
            profile.tempo = 0.2
            profile.stealth = 0.15

        profile.aggression = min(1.0, profile.aggression)
        profile.stealth = min(1.0, profile.stealth)
        profile.tempo = min(1.0, profile.tempo)
        profile.containment = min(1.0, profile.containment)
        profile.recon_focus = min(1.0, profile.recon_focus)
        profile.credential_focus = min(1.0, profile.credential_focus)
        return profile

    def _simulate_campaign_impact(
        self, campaign: CampaignState, profile: _SimulationProfile, directive: str
    ) -> dict[str, Any]:
        seed_material = (
            f"{campaign.campaign_id}|{campaign.phase}|{campaign.exposure_score:.4f}|"
            f"{campaign.hosts_reached}|{campaign.credentials_harvested}|{directive.lower()}"
        )
        seed = int(hashlib.sha256(seed_material.encode("utf-8")).hexdigest()[:16], 16)
        rng = random.Random(seed)

        base_hosts = max(1, len(campaign.alive_hosts))
        base_pivots = max(0, len(campaign.pivot_chains))
        active_drones = max(1, len(campaign.active_drone_ids))
        exposure = max(0.0, min(1.0, campaign.exposure_score))

        host_gain = 0
        credential_gain = 0
        pivot_gain = 0
        detection_delta = 0
        exposure_delta = 0.0

        horizon = 6
        for step_index in range(horizon):
            step = self._simulate_step(
                campaign,
                profile,
                step_index,
                base_hosts,
                base_pivots,
                active_drones,
                exposure,
                rng,
            )
            host_gain += step.host_delta
            credential_gain += step.credential_delta
            pivot_gain += step.pivot_delta
            detection_delta += step.detection_delta
            exposure_delta += step.exposure_delta

            exposure = max(0.0, min(1.0, exposure + step.exposure_delta))
            base_hosts += max(0, step.host_delta)
            base_pivots += max(0, step.pivot_delta)

        if profile.aggression >= 0.7 and host_gain == 0:
            host_gain = 1
            exposure_delta += 0.025

        confidence = 0.5 + min(0.3, 0.05 * active_drones)
        confidence += min(0.1, 0.03 * max(0, len(campaign.alive_hosts) - 1))
        confidence -= min(0.2, 0.05 * abs(exposure_delta))
        confidence = max(0.15, min(0.95, confidence))

        return {
            "host_gain": max(0, host_gain),
            "credential_gain": max(0, credential_gain),
            "pivot_gain": max(0, pivot_gain),
            "detection_delta": max(0, detection_delta),
            "exposure_delta": max(-0.4, min(0.6, exposure_delta)),
            "projected_phase": self._project_phase(campaign, host_gain, credential_gain, profile),
            "confidence": confidence,
        }

    def _simulate_step(
        self,
        campaign: CampaignState,
        profile: _SimulationProfile,
        step_index: int,
        hosts: int,
        pivots: int,
        active_drones: int,
        exposure: float,
        rng: random.Random,
    ) -> _ProjectionStep:
        phase_factor = {
            "dormant": 0.25,
            "reconnaissance": 0.55,
            "mapping": 0.75,
            "flanking": 0.9,
            "encirclement": 1.0,
            "exploitation": 1.15,
            "withdrawal": 0.2,
        }.get(campaign.phase, 0.55)

        drone_efficiency = min(1.4, 0.6 + active_drones * 0.14)
        recon_signal = 0.4 + profile.recon_focus + profile.tempo * 0.35 + profile.aggression * 0.25
        containment_drag = max(0.05, 1.0 - profile.containment * 0.85)
        stealth_drag = max(0.1, 1.0 - profile.stealth * 0.45)

        discovery_pressure = phase_factor * drone_efficiency * recon_signal * containment_drag * stealth_drag
        topology_drag = 1.0 / (1.0 + math.log1p(hosts) * 0.35)
        step_noise = rng.uniform(0.75, 1.3)

        host_delta = int(max(0.0, discovery_pressure * topology_drag * step_noise - 0.15))
        if profile.containment >= 0.65:
            host_delta = 0

        credential_pressure = (
            profile.credential_focus * 0.9
            + profile.aggression * 0.25
            + (0.18 if campaign.high_value_targets else 0.0)
            + min(0.25, pivots * 0.04)
        )
        credential_noise = rng.uniform(0.6, 1.25)
        credential_delta = int(max(0.0, credential_pressure * credential_noise - 0.2))
        if profile.containment >= 0.7:
            credential_delta = 0

        pivot_pressure = 0.25 + profile.recon_focus * 0.4 + profile.aggression * 0.35
        pivot_delta = int(max(0.0, pivot_pressure * rng.uniform(0.6, 1.3) - 0.22))
        if campaign.phase in {"dormant", "withdrawal"}:
            pivot_delta = max(0, pivot_delta - 1)

        detection_risk = 0.03
        detection_risk += profile.aggression * 0.11
        detection_risk += profile.tempo * 0.07
        detection_risk += (host_delta + credential_delta) * 0.015
        detection_risk -= profile.stealth * 0.065
        detection_risk -= profile.containment * 0.09
        detection_risk += exposure * 0.05
        detection_risk += step_index * 0.005

        detection_delta = 1 if rng.random() < max(0.0, min(0.95, detection_risk)) else 0

        exposure_delta = 0.0
        exposure_delta += 0.02 * host_delta
        exposure_delta += 0.035 * credential_delta
        exposure_delta += 0.015 * pivot_delta
        exposure_delta += 0.025 * detection_delta
        exposure_delta += 0.035 * profile.aggression
        exposure_delta += 0.018 * profile.tempo
        exposure_delta -= 0.04 * profile.containment
        exposure_delta -= 0.03 * profile.stealth
        exposure_delta += rng.uniform(-0.01, 0.012)

        return _ProjectionStep(
            host_delta=host_delta,
            credential_delta=credential_delta,
            exposure_delta=exposure_delta,
            detection_delta=detection_delta,
            pivot_delta=pivot_delta,
        )

    def _classify_simulation_outcome(self, simulation: dict[str, Any]) -> str:
        exposure = float(simulation["exposure_delta"])
        gains = int(simulation["host_gain"]) + int(simulation["credential_gain"]) + int(simulation["pivot_gain"])
        detections = int(simulation["detection_delta"])

        if exposure <= -0.03 and gains <= 1:
            return "containment_hold"
        if (gains >= 4 and (exposure >= 0.16 or detections >= 2)) or exposure >= 0.2:
            return "high_gain_high_risk"
        return "balanced_progress"

    def _project_phase(
        self, campaign: CampaignState, host_gain: int, credential_gain: int, profile: _SimulationProfile
    ) -> str:
        if profile.containment >= 0.65:
            return campaign.phase if campaign.phase == "withdrawal" else "withdrawal"
        if campaign.phase == "dormant" and host_gain > 0:
            return "reconnaissance"
        if campaign.phase == "reconnaissance" and host_gain >= 2:
            return "mapping"
        if campaign.phase in {"mapping", "flanking"} and credential_gain >= 2:
            return "encirclement"
        if campaign.phase == "encirclement" and credential_gain >= 3:
            return "exploitation"
        return campaign.phase

    def _build_task_graph(
        self,
        campaign: CampaignState,
        directive: str,
        profile: _SimulationProfile,
        simulation: dict[str, Any],
        linguistic: dict[str, Any],
    ) -> dict[str, Any]:
        now = int(time.time())
        graph_id = hashlib.sha1(f"{campaign.campaign_id}:{directive}:{now}".encode("utf-8")).hexdigest()[:10]

        phases = [
            ("parse", "Parse directive semantics", "done", 100),
            ("recon", "Expand host graph from telemetry and constraints", "in_progress", 52),
            ("plan", "Evaluate maneuver branches and score risk", "todo", 0),
            ("execute", "Generate mission artifacts and launch-ready recommendations", "todo", 0),
        ]
        if profile.containment >= 0.6:
            phases[1] = ("recon", "Validate current coverage and freeze risky movement", "in_progress", 58)

        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, str]] = []
        artifacts: list[dict[str, Any]] = []

        for idx, (nid, title, status, progress) in enumerate(phases):
            node_id = f"{graph_id}-{nid}"
            nodes.append(
                {
                    "id": node_id,
                    "title": title,
                    "status": status,
                    "progress": progress,
                    "info": self._task_info_text(nid, campaign, profile, simulation, linguistic),
                }
            )
            if idx > 0:
                edges.append({"from": nodes[idx - 1]["id"], "to": node_id})

        artifacts.append(
            {
                "artifact_id": f"art-{graph_id}-pred",
                "name": "projection.json",
                "kind": "simulation_projection",
                "status": "generated",
                "description": "Projected host/pivot/credential growth and exposure trajectory for six cycles.",
            }
        )
        artifacts.append(
            {
                "artifact_id": f"art-{graph_id}-task",
                "name": "task_graph.json",
                "kind": "execution_plan",
                "status": "generated",
                "description": "Directed acyclic task graph decomposed from directive intent and campaign state.",
            }
        )

        return {
            "graph_id": graph_id,
            "nodes": nodes,
            "edges": edges,
            "artifacts": artifacts,
            "summary": f"{len(nodes)}-node execution graph prepared for phase {campaign.phase}.",
        }

    def _task_info_text(
        self,
        stage: str,
        campaign: CampaignState,
        profile: _SimulationProfile,
        simulation: dict[str, Any],
        linguistic: dict[str, Any],
    ) -> str:
        if stage == "parse":
            return (
                "Analyzes directive language to extract intent classes, entities, and confidence weights. "
                f"Detected intents: {', '.join(sorted(linguistic.get('intent_scores', {}).keys()) or ['general'])}."
            )
        if stage == "recon":
            return (
                "Builds a candidate host/pivot frontier from active telemetry and projected movement policy. "
                f"Current alive hosts: {len(campaign.alive_hosts)}; predicted host gain: {simulation['host_gain']}."
            )
        if stage == "plan":
            return (
                "Scores branches for stealth, gain, and detection pressure before recommending a path. "
                f"Aggression={profile.aggression:.2f}, containment={profile.containment:.2f}."
            )
        return (
            "Packages operational artifacts for operator review and mission board updates. "
            f"Predicted outcome: {self._classify_simulation_outcome(simulation)}."
        )

    def _generate_binary_codegen_plan(self, directive: str, profile: _SimulationProfile) -> dict[str, Any]:
        budget = 500
        ast = self._directive_to_codegen_ast(directive, profile)
        machine = self._compile_ast_to_machine_code(ast)
        calls_used = min(budget, max(3, len(ast["nodes"]) * 7 + len(ast["edges"]) * 3))
        return {
            "enabled": True,
            "tool_calls_budget": budget,
            "tool_calls_used": calls_used,
            "ast": ast,
            "machine_code": machine,
            "notes": [
                "Machine code is generated from an arithmetic micro-AST and emitted as x86_64 bytes.",
                "Artifacts can be replayed by any runtime that supports raw function stubs.",
            ],
        }

    def _directive_to_codegen_ast(self, directive: str, profile: _SimulationProfile) -> dict[str, Any]:
        words = self._WORD_RE.findall(directive.lower())
        numeric = [int(x) for x in re.findall(r"\d+", directive)]
        seed_a = numeric[0] if numeric else int(profile.aggression * 100) + 7
        seed_b = numeric[1] if len(numeric) > 1 else int(profile.recon_focus * 120) + 11
        op = "mul" if "multiply" in words or "mul" in words else "add"
        if "xor" in words:
            op = "xor"

        nodes = [
            {"id": "n0", "type": "const", "value": seed_a},
            {"id": "n1", "type": "const", "value": seed_b},
            {"id": "n2", "type": "op", "op": op},
            {"id": "n3", "type": "ret"},
        ]
        edges = [
            {"from": "n0", "to": "n2", "slot": "lhs"},
            {"from": "n1", "to": "n2", "slot": "rhs"},
            {"from": "n2", "to": "n3", "slot": "value"},
        ]
        return {"nodes": nodes, "edges": edges, "root": "n3"}

    def _compile_ast_to_machine_code(self, ast: dict[str, Any]) -> dict[str, Any]:
        nodes = {n["id"]: n for n in ast.get("nodes", []) if isinstance(n, dict) and "id" in n}
        if "n0" not in nodes or "n1" not in nodes or "n2" not in nodes:
            return {"arch": "x86_64", "hex": "", "byte_length": 0, "entry": "unsafe"}

        lhs = int(nodes["n0"].get("value", 0)) & 0xFFFFFFFF
        rhs = int(nodes["n1"].get("value", 0)) & 0xFFFFFFFF
        op = str(nodes["n2"].get("op", "add"))

        # x86_64 sequence:
        # mov eax, imm32 (B8)
        # mov ebx, imm32 (BB)
        # add/xor/imul eax, ebx
        # ret (C3)
        blob = bytearray()
        blob.extend(b"\xB8" + lhs.to_bytes(4, "little", signed=False))
        blob.extend(b"\xBB" + rhs.to_bytes(4, "little", signed=False))

        if op == "xor":
            blob.extend(b"\x31\xD8")  # xor eax, ebx
        elif op == "mul":
            blob.extend(b"\x0F\xAF\xC3")  # imul eax, ebx
        else:
            blob.extend(b"\x01\xD8")  # add eax, ebx

        blob.extend(b"\xC3")
        hex_blob = blob.hex()
        return {
            "arch": "x86_64",
            "hex": hex_blob,
            "byte_length": len(blob),
            "entry": "returns_uint32_in_eax",
        }

    def _build_simulation_notes(
        self,
        campaign: CampaignState,
        profile: _SimulationProfile,
        simulation: dict[str, Any],
        outcome: str,
        task_graph: dict[str, Any],
        codegen: dict[str, Any],
    ) -> list[str]:
        notes: list[str] = []
        if outcome == "high_gain_high_risk":
            notes.append("Directive biases expansion and objective capture, but projected exposure rises materially.")
        elif outcome == "containment_hold":
            notes.append("Containment signals dominate, projecting lower signature at the cost of campaign momentum.")
        else:
            notes.append("Projection favors incremental progress with controlled operational signature.")

        notes.append(
            "Projected +"
            f"{simulation['host_gain']} hosts, +{simulation['credential_gain']} credentials, +{simulation['pivot_gain']} pivots"
            f" over next 6 cycles in phase {campaign.phase}."
        )

        if simulation["detection_delta"] > 0:
            notes.append(
                f"Estimated detection pressure increases by {simulation['detection_delta']} event(s); adapt drone cadence if stealth is critical."
            )
        else:
            notes.append("No additional detection events projected under current telemetry assumptions.")

        notes.append(
            f"Task graph {task_graph['graph_id']} prepared with {len(task_graph['nodes'])} stages and "
            f"{codegen['machine_code']['byte_length']} bytes of generated x86_64 machine code."
        )

        if profile.credential_focus >= 0.45 and not campaign.high_value_targets:
            notes.append("Credential-centric directive detected, but no high-value target role is currently mapped.")

        return notes[:6]

    def _calculate_risk(self, campaign: CampaignState, active_drones: list[Any], errored: list[Any]) -> float:
        drone_pressure = min(0.28, len(active_drones) * 0.04)
        detection_pressure = min(0.32, campaign.detection_events * 0.06)
        error_pressure = min(0.22, len(errored) * 0.08)
        objective_pressure = 0.18 if not campaign.objectives_completed else 0.0
        base = campaign.exposure_score
        return max(0.0, min(1.0, base + drone_pressure + detection_pressure + error_pressure + objective_pressure))

    def _phase_velocity(self, campaign: CampaignState) -> str:
        seconds_in_phase = max(0.0, time.time() - campaign.phase_entered_at)
        if seconds_in_phase < 120:
            return "rapid"
        if seconds_in_phase < 500:
            return "steady"
        return "stalled"

    @staticmethod
    def _risk_band(risk_score: float) -> str:
        if risk_score >= 0.75:
            return "critical"
        if risk_score >= 0.45:
            return "elevated"
        return "low"

    def _top_risks(self, campaign: CampaignState, active_drones: list[Any], errored: list[Any]) -> list[str]:
        risks: list[str] = []
        if campaign.exposure_score >= 0.7:
            risks.append("Operational exposure is above doctrine safety threshold")
        if len(active_drones) >= 6:
            risks.append("Fleet saturation may increase telemetry footprint")
        if campaign.detection_events >= 2:
            risks.append("Detection events indicate active blue-team awareness")
        if errored:
            risks.append("Drone failures can expose infrastructure and intent")
        if not risks:
            risks.append("No immediate strategic risks detected")
        return risks[:4]

    def _recommend(self, campaign: CampaignState, risk_score: float, active_drones: list[Any]) -> list[RecommendedAction]:
        recs: list[RecommendedAction] = []

        if risk_score >= 0.75:
            recs.append(
                RecommendedAction(
                    action="RECALL_ALL_DRONES",
                    priority="urgent",
                    reason="Exposure is critical; immediate withdrawal reduces attribution risk.",
                )
            )

        if campaign.phase in {"dormant", "reconnaissance"} and len(campaign.alive_hosts) < 2:
            recs.append(
                RecommendedAction(
                    action="DEPLOY_SCOUT",
                    priority="high",
                    reason="Insufficient target visibility; launch recon assets to improve map coverage.",
                )
            )

        if campaign.phase in {"mapping", "flanking"} and not campaign.pivot_chains:
            recs.append(
                RecommendedAction(
                    action="DEPLOY_MAPPER",
                    priority="high",
                    reason="No validated pivot chain exists; mapper needed before encirclement.",
                )
            )

        if campaign.high_value_targets and campaign.credentials_harvested == 0:
            recs.append(
                RecommendedAction(
                    action="DEPLOY_HARVESTER",
                    priority="high",
                    reason="High-value hosts are present; harvest credentials for deterministic control.",
                )
            )

        if len(active_drones) == 0 and campaign.phase != "withdrawal":
            recs.append(
                RecommendedAction(
                    action="SPAWN_CHILD_SWARM",
                    priority="normal",
                    reason="No active fleet detected; deploy a compact swarm to restore momentum.",
                )
            )

        if not recs:
            recs.append(
                RecommendedAction(
                    action="MAINTAIN_POSTURE",
                    priority="normal",
                    reason="Current campaign trajectory is stable; continue monitoring and adapt on new telemetry.",
                )
            )
        return recs[:5]
