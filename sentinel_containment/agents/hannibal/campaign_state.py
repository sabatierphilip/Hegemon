from __future__ import annotations

from dataclasses import asdict, dataclass, field
import re
import time
from typing import Any, Literal

Phase = Literal[
    "dormant",
    "reconnaissance",
    "mapping",
    "flanking",
    "encirclement",
    "exploitation",
    "withdrawal",
]

_PHASE_ORDER: dict[Phase, int] = {
    "dormant": 0,
    "reconnaissance": 1,
    "mapping": 2,
    "flanking": 3,
    "encirclement": 4,
    "exploitation": 4,
    "withdrawal": 4,
}

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class CampaignState:
    campaign_id: str
    agent_id: str
    mission_objective: str
    phase: Phase = "dormant"

    # optional campaign-level directives (used by agent loop)
    target_host: str | None = None
    target_network: str | None = None
    autonomy_override: str | None = None

    # Network picture
    alive_hosts: list[str] = field(default_factory=list)
    mapped_hosts: dict[str, dict[str, Any]] = field(default_factory=dict)
    credential_findings: list[dict[str, Any]] = field(default_factory=list)
    pivot_chains: list[dict[str, Any]] = field(default_factory=list)
    high_value_targets: list[str] = field(default_factory=list)

    # Fleet state
    active_drone_ids: list[str] = field(default_factory=list)
    terminated_drone_ids: list[str] = field(default_factory=list)
    failed_drone_ids: list[str] = field(default_factory=list)
    drone_orders: list[dict[str, Any]] = field(default_factory=list)

    # Progress metrics
    hosts_reached: int = 0
    credentials_harvested: int = 0
    pivot_paths_confirmed: int = 0
    countermeasures_executed: int = 0
    objectives_completed: list[str] = field(default_factory=list)

    # Operational security
    detection_events: int = 0
    exposure_score: float = 0.0

    # Timing
    started_at: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)
    phase_entered_at: float = field(default_factory=time.time)

    @staticmethod
    def _safe_string(value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"')

    def to_clips_facts(self) -> list[str]:
        """Serialize CampaignState into CLIPS assert-string facts."""
        return [
            (
                "(campaign-state "
                f"(phase {self.phase}) "
                f"(alive-hosts {len(self.alive_hosts)}) "
                f"(mapped-hosts {len(self.mapped_hosts)}) "
                f"(high-value-targets {len(self.high_value_targets)}) "
                f"(active-drones {len(self.active_drone_ids)}) "
                f"(pivot-paths {self.pivot_paths_confirmed}) "
                f"(credentials-harvested {self.credentials_harvested}) "
                f"(exposure-score {float(self.exposure_score):.3f}) "
                f"(objectives-complete {len(self.objectives_completed)}) "
                f"(mission-objective \"{self._safe_string(self.mission_objective)}\"))"
            )
        ]

    @staticmethod
    def _bucket_int(value: float, cuts: tuple[float, float, float, float]) -> int:
        if value <= cuts[0]:
            return 0
        if value <= cuts[1]:
            return 1
        if value <= cuts[2]:
            return 2
        if value <= cuts[3]:
            return 3
        return 4

    def to_q_vector(self) -> tuple[int, int, int, int, int]:
        """
        Discrete Q-state bucket:
        (phase, alive_hosts, exposure, high_value_targets, active_drones)
        """
        phase_bucket = _PHASE_ORDER.get(self.phase, 0)
        alive_bucket = self._bucket_int(len(self.alive_hosts), (0, 2, 5, 10))
        exposure_bucket = self._bucket_int(self.exposure_score, (0.05, 0.25, 0.50, 0.75))
        hvt_bucket = self._bucket_int(len(self.high_value_targets), (0, 1, 2, 4))
        active_bucket = self._bucket_int(len(self.active_drone_ids), (0, 1, 3, 5))
        return (phase_bucket, alive_bucket, exposure_bucket, hvt_bucket, active_bucket)

    @staticmethod
    def _extract_ip_candidates(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return _IP_RE.findall(value)
        if isinstance(value, (list, tuple, set)):
            out: list[str] = []
            for item in value:
                out.extend(CampaignState._extract_ip_candidates(item))
            return out
        if isinstance(value, dict):
            out = []
            for v in value.values():
                out.extend(CampaignState._extract_ip_candidates(v))
            return out
        return []

    def _ensure_host_map(self, host: str) -> dict[str, Any]:
        return self.mapped_hosts.setdefault(
            host,
            {
                "role": "",
                "services": [],
                "open_ports": [],
                "banners": [],
                "sources": [],
            },
        )

    def _is_hvt_role(self, role: str) -> bool:
        return role in {
            "dc",
            "domain_controller",
            "domain controller",
            "db",
            "database",
            "sql",
            "jump_host",
            "jump host",
        }

    def update_from_drone_telemetry(self, drone_id: str, telemetry: list[dict], findings: list[str]) -> None:
        """
        Ingest telemetry/findings from a drone execution cycle.

        Extracts hosts/credentials/pivot-chains/HVTs and updates metrics + exposure.
        """
        known_alive = set(self.alive_hosts)
        known_hvts = set(self.high_value_targets)
        creds_before = len(self.credential_findings)
        pivots_before = len(self.pivot_chains)

        new_detections = 0
        new_countermeasures = 0

        for entry in telemetry or []:
            if not isinstance(entry, dict):
                continue
            kind = str(entry.get("kind", "")).lower().strip()
            source_host = str(entry.get("source_host") or entry.get("source") or "").strip()
            target_host = str(entry.get("target_host") or entry.get("target") or entry.get("host") or "").strip()

            # Host liveness from lateral movement/ping/topology style records
            if kind in {
                "lateral_move",
                "lateral",
                "host_reachable",
                "reachable",
                "subnet_scan",
                "ping_host",
            }:
                for ip in [source_host, target_host, *self._extract_ip_candidates(entry)]:
                    if ip and ip not in known_alive:
                        self.alive_hosts.append(ip)
                        known_alive.add(ip)

            # Build host map details
            for host in [source_host, target_host]:
                if not host:
                    continue
                host_map = self._ensure_host_map(host)
                role = str(entry.get("role") or host_map.get("role") or "").strip().lower()
                if role:
                    host_map["role"] = role
                if drone_id not in host_map["sources"]:
                    host_map["sources"].append(drone_id)
                for key in ("services", "open_ports", "banners"):
                    values = entry.get(key)
                    if isinstance(values, list):
                        for value in values:
                            if value not in host_map[key]:
                                host_map[key].append(value)

                if role and self._is_hvt_role(role) and host not in known_hvts:
                    self.high_value_targets.append(host)
                    known_hvts.add(host)

            # pivot chain extraction
            if kind in {"pivot_plan", "pivot", "pivot_chain", "lateral_move"}:
                src = source_host or "unknown"
                dst = target_host or "unknown"
                chain = {
                    "source": src,
                    "target": dst,
                    "method": str(entry.get("method", "unknown")),
                    "confidence": float(entry.get("confidence", 0.5) or 0.5),
                    "drone_id": drone_id,
                    "ts": float(entry.get("ts", time.time())),
                }
                if not any(c.get("source") == chain["source"] and c.get("target") == chain["target"] and c.get("method") == chain["method"] for c in self.pivot_chains):
                    self.pivot_chains.append(chain)

            # credential telemetry extraction
            if kind in {"credential_probe", "credential", "secrets_scan", "harvest"}:
                cred_entry = {
                    "source": "telemetry",
                    "drone_id": drone_id,
                    "kind": kind,
                    "host": target_host or source_host or "",
                    "key": entry.get("key") or entry.get("name") or entry.get("path") or "unknown",
                    "value_preview": str(entry.get("value") or "")[:64],
                    "path": entry.get("path"),
                    "raw": entry,
                    "ts": float(entry.get("ts", time.time())),
                }
                self.credential_findings.append(cred_entry)

            # countermeasure telemetry extraction
            if kind in {"confront_intruder", "deploy_honeypot", "rotate_credentials", "sinkhole_clone"}:
                new_countermeasures += 1

        for finding in findings or []:
            # findings can be text or dict-like represented as str
            text = str(finding)
            text_l = text.lower()

            if "credential" in text_l or "secret" in text_l or "token" in text_l:
                self.credential_findings.append(
                    {
                        "source": "finding",
                        "drone_id": drone_id,
                        "key": "unstructured",
                        "raw": text,
                        "ts": time.time(),
                    }
                )

            # simple exposure / detection signals
            if any(token in text_l for token in ("detection", "alert", "blocked", "denied", "siem")):
                new_detections += 1

            # pull potential hosts from finding text
            for ip in self._extract_ip_candidates(text):
                if ip not in known_alive:
                    self.alive_hosts.append(ip)
                    known_alive.add(ip)

        self.detection_events += new_detections
        self.countermeasures_executed += new_countermeasures

        self.hosts_reached = len(self.alive_hosts)
        self.credentials_harvested = len(self.credential_findings)
        self.pivot_paths_confirmed = len(self.pivot_chains)

        if self.hosts_reached >= 1 and "host_discovery" not in self.objectives_completed:
            self.objectives_completed.append("host_discovery")
        if self.pivot_paths_confirmed >= 1 and "pivot_path_confirmed" not in self.objectives_completed:
            self.objectives_completed.append("pivot_path_confirmed")
        if self.credentials_harvested >= 1 and "credential_harvest" not in self.objectives_completed:
            self.objectives_completed.append("credential_harvest")

        delta_creds = len(self.credential_findings) - creds_before
        delta_pivots = len(self.pivot_chains) - pivots_before
        exposure_delta = (0.045 * new_detections) + (0.008 * max(delta_pivots, 0)) - (0.004 * max(delta_creds, 0))
        self.exposure_score = max(0.0, min(1.0, self.exposure_score + exposure_delta))

        self.last_updated = time.time()

    def advance_phase(self, new_phase: Phase) -> None:
        self.phase = new_phase
        now = time.time()
        self.phase_entered_at = now
        self.last_updated = now

    def serialize(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def deserialize(cls, d: dict[str, Any]) -> CampaignState:
        return cls(**d)
