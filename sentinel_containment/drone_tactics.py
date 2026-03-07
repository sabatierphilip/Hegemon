from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import math
import random
from typing import Any, Iterable, Literal


PivotMethod = Literal["tcp_probe", "smb_pivot", "rdp_trace", "ssh_hop", "winrm"]
CountermeasureStrategy = Literal[
    "bidirectional_block",
    "counter-lateral-quarantine",
    "active-containment",
    "sinkhole",
]


@dataclass(slots=True)
class HostSignal:
    host: str
    role: str = "unknown"
    criticality: float = 0.5
    trust: float = 0.5
    anomaly_score: float = 0.0
    services: dict[int, str] = field(default_factory=dict)
    reachable: bool = False
    tags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class PivotEdge:
    src: str
    dst: str
    method: PivotMethod
    candidate_ports: list[int]
    open_ports: list[int]
    banner_intel: dict[int, str]
    confidence: float
    travel_risk: float
    stealth: float
    explanation: str


@dataclass(slots=True)
class PivotPlan:
    target: str
    method: PivotMethod
    selected_chain: list[str]
    edges: list[PivotEdge]
    confidence: float
    detection_risk: float
    resilience: float
    opportunities: list[str]
    blockers: list[str]
    recommendations: list[str]
    telemetry: dict[str, Any]


@dataclass(slots=True)
class CountermeasureAction:
    action_id: str
    name: str
    domain: Literal["network", "identity", "process", "forensics", "deception", "coordination"]
    description: str
    priority: int
    prerequisites: list[str]
    expected_effect: str
    reversibility: float
    blast_radius: float
    execution_hint: str


@dataclass(slots=True)
class CountermeasurePlan:
    target: str
    strategy: CountermeasureStrategy
    risk_score: float
    confidence: float
    containment_strength: float
    latency_budget_seconds: int
    phases: dict[str, list[CountermeasureAction]]
    rollback_steps: list[str]
    operator_brief: list[str]
    telemetry: dict[str, Any]


class LateralMovementDesigner:
    """Designs protocol-aware pivot plans with confidence and risk estimates."""

    _METHOD_PORTS: dict[PivotMethod, list[int]] = {
        "tcp_probe": [80, 443, 8080, 8443],
        "smb_pivot": [445, 139, 135],
        "rdp_trace": [3389, 3390],
        "ssh_hop": [22, 2222],
        "winrm": [5985, 5986, 47001],
    }

    _METHOD_STEALTH: dict[PivotMethod, float] = {
        "tcp_probe": 0.62,
        "smb_pivot": 0.45,
        "rdp_trace": 0.38,
        "ssh_hop": 0.71,
        "winrm": 0.58,
    }

    _SERVICE_WEIGHTS: dict[str, float] = {
        "http": 0.55,
        "https": 0.64,
        "ssh": 0.76,
        "rdp": 0.43,
        "smb": 0.48,
        "winrm": 0.51,
        "kerberos": 0.67,
        "ldap": 0.61,
        "mssql": 0.58,
        "postgres": 0.57,
        "redis": 0.49,
        "unknown": 0.4,
    }

    def build_candidate_ports(self, method: PivotMethod, seed_port: int | None) -> list[int]:
        base = list(self._METHOD_PORTS.get(method, []))
        if seed_port is not None:
            seed = max(1, min(65535, int(seed_port)))
            if seed in base:
                base.remove(seed)
            base.insert(0, seed)
        out: list[int] = []
        for port in base:
            if port not in out:
                out.append(port)
        return out[:8]

    def _normalize_service(self, banner: str, port: int) -> str:
        b = banner.lower()
        if "ssh" in b or port == 22:
            return "ssh"
        if "rdp" in b or "mstshash" in b or port == 3389:
            return "rdp"
        if "smb" in b or "microsoft-ds" in b or port in {139, 445}:
            return "smb"
        if "http" in b or port in {80, 8080, 8000}:
            return "http"
        if "tls" in b or "https" in b or port in {443, 8443}:
            return "https"
        if "winrm" in b or port in {5985, 5986, 47001}:
            return "winrm"
        if port == 88:
            return "kerberos"
        if port in {389, 636}:
            return "ldap"
        return "unknown"

    def infer_services(self, open_ports: Iterable[int], banners: dict[int, str]) -> dict[int, str]:
        services: dict[int, str] = {}
        for port in open_ports:
            services[int(port)] = self._normalize_service(banners.get(int(port), ""), int(port))
        return services

    def score_host_opportunity(self, signal: HostSignal) -> float:
        service_score = 0.0
        if signal.services:
            ws = [self._SERVICE_WEIGHTS.get(v, self._SERVICE_WEIGHTS["unknown"]) for v in signal.services.values()]
            service_score = sum(ws) / len(ws)
        trust_factor = max(0.0, min(1.0, 1.0 - signal.trust))
        anomaly_factor = max(0.0, min(1.0, signal.anomaly_score))
        criticality = max(0.0, min(1.0, signal.criticality))
        role_bonus = {
            "domain_controller": 0.18,
            "db": 0.12,
            "jump_host": 0.14,
            "workstation": 0.05,
            "unknown": 0.0,
        }.get(signal.role, 0.0)
        reachable = 0.12 if signal.reachable else -0.2
        score = 0.22 + (0.36 * service_score) + (0.16 * trust_factor) + (0.12 * anomaly_factor) + (0.1 * criticality) + role_bonus + reachable
        return max(0.0, min(1.0, score))

    def _travel_risk(self, method: PivotMethod, open_ports: list[int], anomaly_score: float) -> float:
        base = {
            "tcp_probe": 0.28,
            "smb_pivot": 0.55,
            "rdp_trace": 0.62,
            "ssh_hop": 0.35,
            "winrm": 0.46,
        }[method]
        if not open_ports:
            base += 0.18
        elif len(open_ports) >= 2:
            base -= 0.05
        base += max(0.0, min(1.0, anomaly_score)) * 0.2
        return max(0.0, min(1.0, base))

    def _explain_edge(self, src: str, dst: str, method: PivotMethod, services: dict[int, str], confidence: float, risk: float) -> str:
        top_services = ", ".join(sorted(set(services.values()))[:3]) if services else "none"
        return (
            f"Pivot {src}->{dst} via {method}: services={top_services}, "
            f"confidence={confidence:.2f}, risk={risk:.2f}"
        )

    def build_edge(
        self,
        src: str,
        dst: str,
        method: PivotMethod,
        seed_port: int | None,
        observed_open_ports: Iterable[int] | None,
        observed_banners: dict[int, str] | None,
        anomaly_score: float,
    ) -> PivotEdge:
        candidate_ports = self.build_candidate_ports(method, seed_port)
        observed_set = {int(p) for p in (observed_open_ports or [])}
        open_ports = [p for p in candidate_ports if p in observed_set]
        if not observed_set and seed_port:
            # deterministic synthetic fallback for offline planning
            if int(seed_port) % 2 == 0:
                open_ports = [candidate_ports[0]]
        banners = {int(k): str(v)[:120] for k, v in (observed_banners or {}).items() if int(k) in open_ports}
        services = self.infer_services(open_ports, banners)
        opportunity = 0.35
        if services:
            opportunity += sum(self._SERVICE_WEIGHTS.get(s, 0.4) for s in services.values()) / (2.5 * len(services))
        confidence = max(0.05, min(0.99, opportunity + (0.08 * len(open_ports))))
        risk = self._travel_risk(method, open_ports, anomaly_score)
        stealth = self._METHOD_STEALTH[method] - (risk * 0.18)
        explanation = self._explain_edge(src, dst, method, services, confidence, risk)
        return PivotEdge(
            src=src,
            dst=dst,
            method=method,
            candidate_ports=candidate_ports,
            open_ports=open_ports,
            banner_intel=banners,
            confidence=round(confidence, 4),
            travel_risk=round(risk, 4),
            stealth=round(max(0.0, min(1.0, stealth)), 4),
            explanation=explanation,
        )

    def build_signal(self, host: str, role: str, trust: float, anomaly: float, open_ports: list[int], banners: dict[int, str]) -> HostSignal:
        services = self.infer_services(open_ports, banners)
        criticality = {
            "domain_controller": 0.95,
            "db": 0.83,
            "jump_host": 0.78,
            "workstation": 0.56,
            "unknown": 0.52,
        }.get(role, 0.5)
        return HostSignal(
            host=host,
            role=role,
            criticality=criticality,
            trust=max(0.0, min(1.0, trust)),
            anomaly_score=max(0.0, min(1.0, anomaly)),
            services=services,
            reachable=bool(open_ports),
            tags=["observed" if open_ports else "cold"],
        )

    def _node_score(self, signal: HostSignal) -> float:
        return self.score_host_opportunity(signal)

    def _chain_score(self, edges: list[PivotEdge], signals: dict[str, HostSignal]) -> tuple[float, float, float]:
        if not edges:
            return (0.0, 1.0, 0.0)
        confidences = [e.confidence for e in edges]
        risks = [e.travel_risk for e in edges]
        stealths = [e.stealth for e in edges]
        endpoint_bonus = 0.0
        dst = edges[-1].dst
        if dst in signals:
            endpoint_bonus = 0.15 * self._node_score(signals[dst])
        conf = max(0.0, min(1.0, (sum(confidences) / len(confidences)) + endpoint_bonus))
        risk = max(0.0, min(1.0, sum(risks) / len(risks)))
        resilience = max(0.0, min(1.0, (sum(stealths) / len(stealths)) + (0.12 if len(edges) > 1 else 0.0)))
        return (round(conf, 4), round(risk, 4), round(resilience, 4))

    def _recommendations(self, chain: list[PivotEdge], risk: float, confidence: float) -> list[str]:
        recs: list[str] = []
        if not chain:
            return ["No viable pivot chain. Increase telemetry depth and validate host exposure map."]
        if risk > 0.65:
            recs.append("Throttle scan cadence and route through low-noise relay host before active pivot.")
            recs.append("Enable packet timing jitter and opportunistic backoff per failed transport attempt.")
        if confidence < 0.5:
            recs.append("Collect additional service banners and credential context before remote action.")
        methods = {edge.method for edge in chain}
        if "smb_pivot" in methods:
            recs.append("Pre-stage SMB signing checks and fallback to WinRM if integrity controls fail.")
        if "rdp_trace" in methods:
            recs.append("Capture session fingerprints and terminate immediately on unknown certificate chain.")
        if "ssh_hop" in methods:
            recs.append("Use ephemeral keys and disable agent forwarding during chained SSH pivots.")
        if not recs:
            recs.append("Chain is stable; execute with adaptive wait intervals and signed telemetry checkpoints.")
        return recs

    def _blockers(self, chain: list[PivotEdge]) -> list[str]:
        blockers: list[str] = []
        for edge in chain:
            if not edge.open_ports:
                blockers.append(f"{edge.dst}: no responsive transport for {edge.method}")
            if edge.travel_risk > 0.8:
                blockers.append(f"{edge.dst}: excessive detection risk ({edge.travel_risk:.2f})")
        return blockers

    def _opportunities(self, chain: list[PivotEdge], signals: dict[str, HostSignal]) -> list[str]:
        out: list[str] = []
        for edge in chain:
            signal = signals.get(edge.dst)
            if not signal:
                continue
            if signal.role in {"domain_controller", "db", "jump_host"}:
                out.append(f"{edge.dst}: high-value role={signal.role} with opportunity={self._node_score(signal):.2f}")
            if "ssh" in signal.services.values() and edge.method != "ssh_hop":
                out.append(f"{edge.dst}: SSH surfaced; optional stealth upgrade path available")
        return out[:10]

    def _enumerate_paths(self, graph: dict[str, list[PivotEdge]], start: str, target: str, max_depth: int = 4) -> list[list[PivotEdge]]:
        paths: list[list[PivotEdge]] = []

        def dfs(node: str, visited: set[str], stack: list[PivotEdge]) -> None:
            if len(stack) > max_depth:
                return
            if node == target and stack:
                paths.append(list(stack))
                return
            for edge in graph.get(node, []):
                if edge.dst in visited:
                    continue
                visited.add(edge.dst)
                stack.append(edge)
                dfs(edge.dst, visited, stack)
                stack.pop()
                visited.remove(edge.dst)

        dfs(start, {start}, [])
        return paths

    def select_best_chain(self, graph: dict[str, list[PivotEdge]], signals: dict[str, HostSignal], start: str, target: str) -> tuple[list[PivotEdge], float, float, float]:
        candidates = self._enumerate_paths(graph, start, target, max_depth=5)
        if not candidates and start == target:
            return ([], 0.0, 1.0, 0.0)
        if not candidates:
            return ([], 0.0, 1.0, 0.0)
        best_chain = candidates[0]
        best_metric = -10.0
        best_tuple = (0.0, 1.0, 0.0)
        for chain in candidates:
            conf, risk, resilience = self._chain_score(chain, signals)
            metric = (1.8 * conf) + (1.2 * resilience) - (1.4 * risk) + (0.05 * len(chain))
            if metric > best_metric:
                best_metric = metric
                best_chain = chain
                best_tuple = (conf, risk, resilience)
        return (best_chain, best_tuple[0], best_tuple[1], best_tuple[2])

    def design_plan(
        self,
        source_host: str,
        target_host: str,
        method: PivotMethod,
        seed_port: int | None,
        observed_open_ports: list[int],
        observed_banners: dict[int, str],
        mesh_hosts: list[str] | None = None,
        host_roles: dict[str, str] | None = None,
        host_trust: dict[str, float] | None = None,
        host_anomaly: dict[str, float] | None = None,
        random_seed: int = 7,
    ) -> PivotPlan:
        rng = random.Random(random_seed)
        mesh = [source_host] + [h for h in (mesh_hosts or []) if h not in {source_host, target_host}] + [target_host]
        roles = host_roles or {}
        trust = host_trust or {}
        anomaly = host_anomaly or {}

        signals: dict[str, HostSignal] = {}
        signals[source_host] = self.build_signal(
            source_host,
            roles.get(source_host, "jump_host"),
            trust.get(source_host, 0.35),
            anomaly.get(source_host, 0.1),
            observed_open_ports,
            observed_banners,
        )
        signals[target_host] = self.build_signal(
            target_host,
            roles.get(target_host, "unknown"),
            trust.get(target_host, 0.52),
            anomaly.get(target_host, 0.24),
            observed_open_ports,
            observed_banners,
        )

        graph: dict[str, list[PivotEdge]] = {h: [] for h in mesh}

        for idx, src in enumerate(mesh):
            for dst in mesh[idx + 1 :]:
                if src == dst:
                    continue
                variant_method: PivotMethod = method
                if src != source_host and dst != target_host:
                    variant_method = rng.choice(["ssh_hop", "tcp_probe", "winrm"])
                synthetic_open = list(observed_open_ports)
                if src != source_host or dst != target_host:
                    base_candidates = self.build_candidate_ports(variant_method, seed_port)
                    synthetic_open = [p for p in base_candidates if (p + len(src) + len(dst)) % 3 == 0][:2]
                edge = self.build_edge(
                    src,
                    dst,
                    variant_method,
                    seed_port,
                    synthetic_open,
                    observed_banners,
                    anomaly.get(dst, 0.2),
                )
                graph[src].append(edge)

                reverse_edge = self.build_edge(
                    dst,
                    src,
                    variant_method,
                    seed_port,
                    synthetic_open,
                    observed_banners,
                    anomaly.get(src, 0.15),
                )
                graph[dst].append(reverse_edge)

                if dst not in signals:
                    signals[dst] = self.build_signal(
                        dst,
                        roles.get(dst, "workstation"),
                        trust.get(dst, 0.5),
                        anomaly.get(dst, 0.2),
                        synthetic_open,
                        observed_banners,
                    )
                if src not in signals:
                    signals[src] = self.build_signal(
                        src,
                        roles.get(src, "workstation"),
                        trust.get(src, 0.5),
                        anomaly.get(src, 0.2),
                        synthetic_open,
                        observed_banners,
                    )

        chain, confidence, risk, resilience = self.select_best_chain(graph, signals, source_host, target_host)
        selected_hosts = [source_host] + [edge.dst for edge in chain]
        opportunities = self._opportunities(chain, signals)
        blockers = self._blockers(chain)
        recommendations = self._recommendations(chain, risk, confidence)

        telemetry = {
            "source": source_host,
            "target": target_host,
            "method": method,
            "candidate_paths": max(1, len(self._enumerate_paths(graph, source_host, target_host, max_depth=5))),
            "selected_chain": [
                {
                    "src": e.src,
                    "dst": e.dst,
                    "method": e.method,
                    "open_ports": e.open_ports,
                    "confidence": e.confidence,
                    "risk": e.travel_risk,
                    "stealth": e.stealth,
                    "explanation": e.explanation,
                }
                for e in chain
            ],
            "host_opportunities": {h: round(self._node_score(s), 3) for h, s in signals.items()},
            "blockers": blockers,
            "recommendations": recommendations,
        }

        return PivotPlan(
            target=target_host,
            method=method,
            selected_chain=selected_hosts,
            edges=chain,
            confidence=confidence,
            detection_risk=risk,
            resilience=resilience,
            opportunities=opportunities,
            blockers=blockers,
            recommendations=recommendations,
            telemetry=telemetry,
        )


class IntruderConfrontationDesigner:
    """Produces multi-phase containment plans with rollback and operator briefing."""

    _STRATEGY_LATENCY: dict[CountermeasureStrategy, int] = {
        "bidirectional_block": 20,
        "counter-lateral-quarantine": 45,
        "active-containment": 60,
        "sinkhole": 55,
    }

    def _risk_model(
        self,
        intruder_score: float,
        lateral_pressure: float,
        endpoint_criticality: float,
        confidence: float,
        active_sessions: int,
    ) -> float:
        s = max(0.0, min(1.0, intruder_score))
        l = max(0.0, min(1.0, lateral_pressure))
        c = max(0.0, min(1.0, endpoint_criticality))
        conf = max(0.0, min(1.0, confidence))
        session_factor = max(0.0, min(1.0, active_sessions / 12.0))
        risk = (0.32 * s) + (0.23 * l) + (0.19 * c) + (0.14 * (1 - conf)) + (0.12 * session_factor)
        return round(max(0.0, min(1.0, risk)), 4)

    def _containment_strength(self, strategy: CountermeasureStrategy, risk: float, confidence: float) -> float:
        base = {
            "bidirectional_block": 0.66,
            "counter-lateral-quarantine": 0.79,
            "active-containment": 0.86,
            "sinkhole": 0.74,
        }[strategy]
        base += 0.1 * confidence
        base -= 0.08 * risk
        return round(max(0.0, min(1.0, base)), 4)

    def _mk_action(
        self,
        aid: str,
        name: str,
        domain: Literal["network", "identity", "process", "forensics", "deception", "coordination"],
        description: str,
        priority: int,
        prerequisites: list[str],
        expected_effect: str,
        reversibility: float,
        blast_radius: float,
        execution_hint: str,
    ) -> CountermeasureAction:
        return CountermeasureAction(
            action_id=aid,
            name=name,
            domain=domain,
            description=description,
            priority=priority,
            prerequisites=prerequisites,
            expected_effect=expected_effect,
            reversibility=round(max(0.0, min(1.0, reversibility)), 4),
            blast_radius=round(max(0.0, min(1.0, blast_radius)), 4),
            execution_hint=execution_hint,
        )

    def _strategy_actions(self, strategy: CountermeasureStrategy, target: str, risk: float) -> dict[str, list[CountermeasureAction]]:
        prep: list[CountermeasureAction] = [
            self._mk_action(
                "prep-telemetry-freeze",
                "Freeze signed telemetry lane",
                "coordination",
                "Force high-fidelity signed telemetry mode before active intervention.",
                1,
                ["drone_online"],
                "Improves evidentiary quality and chain-of-custody.",
                0.95,
                0.05,
                "append signed marker + increase check-in frequency",
            ),
            self._mk_action(
                "prep-snapshot",
                "Capture volatile process and network snapshot",
                "forensics",
                "Collect memory/process/netflow triage before isolation to avoid losing TTP evidence.",
                2,
                ["local_sensor_ready"],
                "Preserves initial compromise context.",
                0.99,
                0.08,
                "trigger lightweight memory map + connection table export",
            ),
        ]

        contain: list[CountermeasureAction]
        recover: list[CountermeasureAction]

        if strategy == "bidirectional_block":
            contain = [
                self._mk_action(
                    "contain-ingress-egress-deny",
                    "Apply ingress/egress deny tuple",
                    "network",
                    f"Install paired deny rules around {target} to halt inbound and outbound command channels.",
                    1,
                    ["prep-telemetry-freeze"],
                    "Severs direct C2 communication lines.",
                    0.92,
                    0.24,
                    "iptables/nftables deny target both directions",
                ),
                self._mk_action(
                    "contain-reset-sessions",
                    "Reset suspicious sessions",
                    "process",
                    "Terminate suspicious interactive sessions without full host isolation.",
                    2,
                    ["contain-ingress-egress-deny"],
                    "Interrupts active operator foothold.",
                    0.81,
                    0.18,
                    "kill high-risk tty/session tokens",
                ),
            ]
            recover = [
                self._mk_action(
                    "recover-gradual-unblock",
                    "Gradual connectivity restore",
                    "coordination",
                    "Restore safe traffic segments while maintaining deny policies on high-risk flows.",
                    1,
                    ["contain-reset-sessions"],
                    "Minimizes business disruption.",
                    0.96,
                    0.3,
                    "stepwise ACL rollback with observation gates",
                )
            ]
        elif strategy == "counter-lateral-quarantine":
            contain = [
                self._mk_action(
                    "contain-microsegment",
                    "Microsegment host",
                    "network",
                    "Move target into restrictive microsegment with explicit allow-list for SOC tooling.",
                    1,
                    ["prep-snapshot"],
                    "Blocks lateral propagation while keeping forensic channel alive.",
                    0.78,
                    0.36,
                    "switch endpoint VLAN/SDN segment profile",
                ),
                self._mk_action(
                    "contain-revoke-eastwest",
                    "Revoke east-west credentials",
                    "identity",
                    "Revoke service tickets and temporary credentials used for east-west movement.",
                    2,
                    ["contain-microsegment"],
                    "Reduces replay and pass-the-ticket opportunities.",
                    0.73,
                    0.42,
                    "invalidate kerberos TGT/TGS + rotate local admin secrets",
                ),
                self._mk_action(
                    "contain-force-mfa",
                    "Force MFA re-challenge",
                    "identity",
                    "Require fresh MFA for identities with active sessions on adjacent hosts.",
                    3,
                    ["contain-revoke-eastwest"],
                    "Raises attacker operating cost and blocks stale sessions.",
                    0.89,
                    0.27,
                    "trigger conditional access policy + token revocation",
                ),
            ]
            recover = [
                self._mk_action(
                    "recover-trust-rebuild",
                    "Rebuild trust graph",
                    "coordination",
                    "Gradually reintroduce inter-host trust edges after identity hygiene checks.",
                    1,
                    ["contain-force-mfa"],
                    "Restores operations with reduced reinfection probability.",
                    0.84,
                    0.41,
                    "automated canary auth checks before each trust-edge restore",
                )
            ]
        elif strategy == "active-containment":
            contain = [
                self._mk_action(
                    "contain-sinkhole-c2",
                    "Sinkhole command channel",
                    "deception",
                    "Rewrite C2 egress routes to controlled sinkhole infrastructure.",
                    1,
                    ["prep-telemetry-freeze"],
                    "Allows adversary observation and controlled disruption.",
                    0.65,
                    0.49,
                    "dns/routing override to sinkhole collectors",
                ),
                self._mk_action(
                    "contain-memory-capture",
                    "Capture memory snapshots",
                    "forensics",
                    "Capture targeted process memory for IOC/YARA extraction.",
                    2,
                    ["contain-sinkhole-c2"],
                    "Improves attribution and eradication confidence.",
                    0.97,
                    0.22,
                    "snapshot suspicious process set and memory pages",
                ),
                self._mk_action(
                    "contain-kill-sessions",
                    "Kill suspicious sessions",
                    "process",
                    "Terminate suspicious shells, service sessions, and remote exec channels.",
                    3,
                    ["contain-memory-capture"],
                    "Eliminates active attacker execution context.",
                    0.83,
                    0.34,
                    "terminate session tree by risk score",
                ),
            ]
            recover = [
                self._mk_action(
                    "recover-reimage-candidate",
                    "Reimage persistence candidate",
                    "coordination",
                    "Queue reimage/remediation workflow for hosts with persistence indicators.",
                    1,
                    ["contain-kill-sessions"],
                    "Ensures long-term eradication.",
                    0.71,
                    0.58,
                    "handoff to patching + golden image pipeline",
                )
            ]
        else:  # sinkhole
            contain = [
                self._mk_action(
                    "contain-route-rewrite",
                    "Rewrite malicious route",
                    "network",
                    "Rewrite suspicious destination route into controlled sinkhole.",
                    1,
                    ["prep-snapshot"],
                    "Neutralizes outbound data exfil path.",
                    0.68,
                    0.31,
                    "update route maps + verify asymmetric paths",
                ),
                self._mk_action(
                    "contain-dns-sinkhole",
                    "DNS sinkhole known indicators",
                    "deception",
                    "Override IOC domains to sinkhole responder.",
                    2,
                    ["contain-route-rewrite"],
                    "Prevents callback and enables request capture.",
                    0.74,
                    0.29,
                    "update dns policy zones and caching rules",
                ),
                self._mk_action(
                    "contain-capture-indicators",
                    "Capture residual indicators",
                    "forensics",
                    "Collect residual C2 metadata and suspicious payload fragments.",
                    3,
                    ["contain-dns-sinkhole"],
                    "Improves threat intel enrichment.",
                    0.92,
                    0.19,
                    "capture sinkhole logs + packet metadata",
                ),
            ]
            recover = [
                self._mk_action(
                    "recover-clean-route",
                    "Restore clean route",
                    "network",
                    "Restore original route after indicators stop and confidence threshold met.",
                    1,
                    ["contain-capture-indicators"],
                    "Returns network to steady-state posture.",
                    0.87,
                    0.33,
                    "progressive route rollback with canary traffic",
                )
            ]

        if risk > 0.72:
            contain.insert(
                0,
                self._mk_action(
                    "contain-emergency-lockdown",
                    "Emergency transport lockdown",
                    "network",
                    "Immediate lock-down on high-risk transport lanes while preserving SOC out-of-band access.",
                    0,
                    ["prep-telemetry-freeze"],
                    "Rapidly suppresses escalating compromise blast radius.",
                    0.54,
                    0.63,
                    "apply emergency ACL profile with SOC exception list",
                ),
            )

        return {"prepare": prep, "contain": contain, "recover": recover}

    def _rollback_steps(self, phases: dict[str, list[CountermeasureAction]], strategy: CountermeasureStrategy) -> list[str]:
        ordered = [*phases.get("recover", []), *reversed(phases.get("contain", [])), *reversed(phases.get("prepare", []))]
        steps = [f"Rollback {a.name}: verify prerequisite reversal and audit state." for a in ordered]
        if strategy in {"active-containment", "sinkhole"}:
            steps.append("Revoke sinkhole redirections only after 2 clean detection windows.")
        steps.append("Finalize with signed incident closure record and postmortem seed tasks.")
        return steps

    def _brief(
        self,
        strategy: CountermeasureStrategy,
        target: str,
        risk: float,
        confidence: float,
        containment_strength: float,
    ) -> list[str]:
        posture = "aggressive" if strategy in {"active-containment", "counter-lateral-quarantine"} else "targeted"
        brief = [
            f"Strategy={strategy} posture={posture} target={target}.",
            f"Estimated incident risk {risk:.2f}, confidence {confidence:.2f}, projected containment strength {containment_strength:.2f}.",
            "Run prepare phase to preserve forensic quality before disruptive controls.",
            "Gate each contain action on telemetry signature health and control-plane quorum where applicable.",
        ]
        if risk > 0.7:
            brief.append("Risk is elevated: consider human-in-the-loop approval before irreversible identity controls.")
        if confidence < 0.45:
            brief.append("Confidence is limited: prioritize additional host attestations before high-blast-radius operations.")
        brief.append("Execute rollback steps in reverse order if mission objective shifts or collateral risk grows.")
        return brief

    def design_plan(
        self,
        target: str,
        strategy: CountermeasureStrategy,
        intruder_score: float,
        lateral_pressure: float,
        endpoint_criticality: float,
        confidence: float,
        active_sessions: int,
    ) -> CountermeasurePlan:
        risk = self._risk_model(intruder_score, lateral_pressure, endpoint_criticality, confidence, active_sessions)
        strength = self._containment_strength(strategy, risk, confidence)
        phases = self._strategy_actions(strategy, target, risk)
        latency_budget = self._STRATEGY_LATENCY[strategy] + int(math.ceil(risk * 25))
        rollback_steps = self._rollback_steps(phases, strategy)
        brief = self._brief(strategy, target, risk, confidence, strength)

        phase_stats = {
            k: {
                "count": len(v),
                "max_priority": max((a.priority for a in v), default=0),
                "avg_blast_radius": round(sum((a.blast_radius for a in v), 0.0) / max(1, len(v)), 4),
            }
            for k, v in phases.items()
        }

        telemetry = {
            "target": target,
            "strategy": strategy,
            "risk_score": risk,
            "confidence": confidence,
            "containment_strength": strength,
            "latency_budget_seconds": latency_budget,
            "phase_stats": phase_stats,
            "phase_actions": {
                k: [
                    {
                        "id": a.action_id,
                        "name": a.name,
                        "domain": a.domain,
                        "priority": a.priority,
                        "prerequisites": a.prerequisites,
                        "blast_radius": a.blast_radius,
                        "reversibility": a.reversibility,
                        "expected_effect": a.expected_effect,
                    }
                    for a in actions
                ]
                for k, actions in phases.items()
            },
            "rollback_steps": rollback_steps,
            "operator_brief": brief,
        }

        return CountermeasurePlan(
            target=target,
            strategy=strategy,
            risk_score=risk,
            confidence=confidence,
            containment_strength=strength,
            latency_budget_seconds=latency_budget,
            phases=phases,
            rollback_steps=rollback_steps,
            operator_brief=brief,
            telemetry=telemetry,
        )


def normalize_target_host(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return "127.0.0.1"
    if raw.lower() in {"localhost", "loopback"}:
        return "127.0.0.1"
    return raw


def normalize_ip(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return "unknown"
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return raw


def clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))


__all__ = [
    "PivotMethod",
    "CountermeasureStrategy",
    "HostSignal",
    "PivotEdge",
    "PivotPlan",
    "CountermeasureAction",
    "CountermeasurePlan",
    "LateralMovementDesigner",
    "IntruderConfrontationDesigner",
    "normalize_target_host",
    "normalize_ip",
    "clamp",
]
