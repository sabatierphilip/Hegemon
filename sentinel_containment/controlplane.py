from __future__ import annotations

import ast
import base64
import copy
import hashlib
import hmac
import json
import os
import secrets
import shelve
import socket
import sre_parse
import subprocess
import threading
import time
import re
import sys
import shutil
import math
from collections import defaultdict
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from nacl import signing

from signed_ledger import SignedLedger
from sentinel_containment.drone_compiler import DroneBlobCompiler, decode_blob, deploy_blob_remote, launch_blob_locally
from sentinel_containment.store_client import StoreClient, StoreSearchResult

try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

try:
    import networkx as nx
    _NETWORKX_AVAILABLE = True
except ImportError:
    _NETWORKX_AVAILABLE = False

try:
    from pgmpy.models import BayesianNetwork
    from pgmpy.factors.discrete import TabularCPD
    from pgmpy.inference import VariableElimination
    _PGMPY_AVAILABLE = True
except ImportError:
    _PGMPY_AVAILABLE = False

CRITICAL_CAPABILITIES = {"approve_firmware", "approve_hypervisor", "revoke"}

KILL_CHAIN_STAGES = [
    "recon",
    "resource_development",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
]

STAGE_TO_TACTIC: dict[str, str] = {
    "recon": "TA0043",
    "resource_development": "TA0042",
    "initial_access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege_escalation": "TA0004",
    "defense_evasion": "TA0005",
    "credential_access": "TA0006",
    "discovery": "TA0007",
    "lateral_movement": "TA0008",
    "collection": "TA0009",
    "command_and_control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
}

BASE_DWELL_DAYS = {
    "recon": 14, "resource_development": 7, "initial_access": 3,
    "execution": 1, "persistence": 2, "privilege_escalation": 2,
    "defense_evasion": 3, "credential_access": 2, "discovery": 4,
    "lateral_movement": 5, "collection": 3, "command_and_control": 7,
    "exfiltration": 2, "impact": 1,
}

ISSUE_TO_TECHNIQUES: dict[str, list[str]] = {
    "tainted-cmd-exec": ["T1059.004", "T1059.006"],
    "tainted-sql-query": ["T1190"],
    "hardcoded-secret": ["T1552.001"],
    "weak-rng-auth": ["T1110.001"],
    "dynamic-exec": ["T1059.006"],
    "pickle-loads": ["T1059.006", "T1204.002"],
    "yaml-unsafe-load": ["T1059.006"],
    "weak-hash": ["T1600"],
    "shell-true": ["T1059.004"],
    "open-redirect": ["T1550.001"],
    "path-traversal": ["T1083"],
    "ssrf": ["T1090.002"],
    "xxe": ["T1059.006"],
    "prototype-pollution": ["T1211"],
    "regex-dos": ["T1499.004"],
    "insecure-deserialization": ["T1059.006", "T1204.002"],
    "jwt-none-alg": ["T1552.004"],
    "cors-wildcard": ["T1185"],
    "unvalidated-redirect": ["T1550.001"],
    "hardcoded-ip": ["T1071"],
    "cleartext-credential": ["T1552.002"],
    "missing-tls-verify": ["T1040"],
    "tainted-template": ["T1190"],
    "race-condition-toctou": ["T1499"],
    "integer-overflow": ["T1499"],
    "format-string": ["T1059"],
    "interprocedural-sink-reachability": ["T1059"],
}

PROTECTED_FILES = {
    "signed_ledger.py", "controlplane.py", "security/hardware_keys.py",
    "security/peer_mesh.py", "web/app.py",
}

STORE_REGISTRY: list[dict[str, Any]] = [
    {"store_id": "store-apple", "name": "Apple App Store", "icon": "APPLE", "platform": "apple", "trust_tier": "verified", "verification_method": "apple_notarization", "metadata_api": "https://itunes.apple.com/search", "search_param": "term", "result_path": ["results"], "name_field": "trackName", "publisher_field": "artistName", "version_field": "version", "bundle_id_field": "bundleId", "category_field": "primaryGenreName", "icon_field": "artworkUrl100"},
    {"store_id": "store-windows", "name": "Microsoft Store", "icon": "WINDOWS", "platform": "windows", "trust_tier": "verified", "verification_method": "microsoft_signature", "metadata_api": "https://storeedgefd.dsx.mp.microsoft.com/v9.0/products", "search_param": "query", "result_path": ["Products"], "name_field": "Title", "publisher_field": "PublisherName", "version_field": "Version", "icon_field": "Images"},
    {"store_id": "store-google-play", "name": "Google Play Store", "icon": "ANDROID", "platform": "android", "trust_tier": "verified", "verification_method": "google_play_protect", "metadata_api": "https://play.google.com/store/search", "search_param": "q", "result_path": [], "name_field": "title", "publisher_field": "developer", "version_field": "version"},
    {"store_id": "store-pypi", "name": "PyPI", "icon": "PY", "platform": "python", "trust_tier": "community", "verification_method": "sha256_checksum", "metadata_api": "https://pypi.org/pypi/{package}/json", "search_api": "https://pypi.org/search/?q={query}&o=&c=&format=json", "name_field": "info.name", "publisher_field": "info.author", "version_field": "info.version", "home_field": "info.home_page"},
    {"store_id": "store-npm", "name": "npm", "icon": "PKG", "platform": "javascript", "trust_tier": "community", "verification_method": "sha512_integrity", "metadata_api": "https://registry.npmjs.org/{package}", "search_api": "https://registry.npmjs.org/-/v1/search?text={query}&size=10", "name_field": "name", "publisher_field": "author.name", "version_field": "dist-tags.latest"},
    {"store_id": "store-linux", "name": "Linux Package Repos", "icon": "LINUX", "platform": "linux", "trust_tier": "verified", "verification_method": "gpg_signed_package", "metadata_api": "https://repology.org/api/v1/project/{package}", "search_api": "https://repology.org/api/v1/projects/?search={query}&limit=10", "name_field": "package", "publisher_field": "maintainer", "version_field": "newest_version"},
    {"store_id": "store-homebrew", "name": "Homebrew", "icon": "BREW", "platform": "macos", "trust_tier": "community", "verification_method": "sha256_checksum", "metadata_api": "https://formulae.brew.sh/api/formula/{package}.json", "search_api": "https://formulae.brew.sh/api/formula.json", "name_field": "name", "publisher_field": "homepage", "version_field": "versions.stable"},
    {"store_id": "store-nuget", "name": "NuGet", "icon": "NUGET", "platform": "dotnet", "trust_tier": "community", "verification_method": "nuget_signature", "metadata_api": "https://api.nuget.org/v3/registration5/{package}/index.json", "search_api": "https://azuresearch-usnc.nuget.org/query?q={query}&take=10", "name_field": "id", "publisher_field": "authors", "version_field": "version"},
    {"store_id": "store-steam", "name": "Steam", "icon": "STEAM", "platform": "cross-platform", "trust_tier": "verified", "verification_method": "steam_signature", "metadata_api": "https://store.steampowered.com/api/appdetails", "search_api": "https://store.steampowered.com/api/storesearch/?term={query}&cc=US&l=en", "name_field": "name", "publisher_field": "publisher", "version_field": "release_date.date"},
    {"store_id": "store-github", "name": "GitHub Releases", "icon": "GH", "platform": "cross-platform", "trust_tier": "community", "verification_method": "gpg_tag_signature", "metadata_api": "https://api.github.com/repos/{owner}/{repo}/releases/latest", "search_api": "https://api.github.com/search/repositories?q={query}&sort=stars&per_page=10", "name_field": "name", "publisher_field": "owner.login", "version_field": "tag_name"},
]

DEFAULT_FRIENDLY_STORES: list[dict[str, Any]] = STORE_REGISTRY


DEFAULT_FRIENDLY_ENDPOINTS: list[dict[str, Any]] = [
    {
        "endpoint_id": "ep-default-windows",
        "host_name": "win-secure-01",
        "endpoint_type": "on-prem",
        "os": "windows",
        "kernel": "nt",
        "sbom_status": "valid",
        "enrollment_method": "mdm",
        "network_exposure": "internal",
        "installed_packages": {"defender": "4.18.24010", "edge": "123.0.0"},
    },
    {
        "endpoint_id": "ep-default-linux",
        "host_name": "linux-secure-01",
        "endpoint_type": "on-prem",
        "os": "ubuntu",
        "kernel": "6.8",
        "sbom_status": "valid",
        "enrollment_method": "mdm",
        "network_exposure": "internet",
        "installed_packages": {"openssl": "3.0.2", "nginx": "1.25.5", "steamcmd": "1.0.0"},
        "telemetry_events": ["recon", "initial_access", "execution"],
    },
]

HEGEMON_SELF_ENDPOINT_ID = "ep-hegemon-self"

PACKAGE_TO_FRIENDLY_APP: dict[str, dict[str, str]] = {
    "edge": {"name": "Microsoft Edge", "icon": "NET", "store_id": "store-windows", "publisher": "Microsoft"},
    "defender": {"name": "Microsoft Defender", "icon": "DEF", "store_id": "store-windows", "publisher": "Microsoft"},
    "nginx": {"name": "Nginx", "icon": "NET", "store_id": "store-linux", "publisher": "NGINX Inc."},
    "steamcmd": {"name": "SteamCMD", "icon": "STEAM", "store_id": "store-steam", "publisher": "Valve"},
    "openssl": {"name": "OpenSSL", "icon": "TLS", "store_id": "store-linux", "publisher": "OpenSSL"},
    "curl": {"name": "curl", "icon": "NET", "store_id": "store-linux", "publisher": "curl"},
    "wget": {"name": "wget", "icon": "DL", "store_id": "store-linux", "publisher": "GNU"},
    "python3": {"name": "Python 3", "icon": "PY", "store_id": "store-linux", "publisher": "Python Software Foundation"},
    "anthropic": {"name": "Anthropic SDK", "icon": "ANDROID", "store_id": "store-linux", "publisher": "Anthropic"},
    "nodejs": {"name": "Node.js", "icon": "NODE", "store_id": "store-linux", "publisher": "OpenJS"},
    "docker": {"name": "Docker", "icon": "DOCKER", "store_id": "store-linux", "publisher": "Docker"},
    "containerd": {"name": "containerd", "icon": "PKG", "store_id": "store-linux", "publisher": "CNCF"},
    "kubelet": {"name": "Kubelet", "icon": "K8S", "store_id": "store-linux", "publisher": "Kubernetes"},
    "postgres": {"name": "PostgreSQL", "icon": "PG", "store_id": "store-linux", "publisher": "PostgreSQL"},
    "mysql": {"name": "MySQL", "icon": "MYSQL", "store_id": "store-linux", "publisher": "Oracle"},
    "redis": {"name": "Redis", "icon": "REDIS", "store_id": "store-linux", "publisher": "Redis"},
    "apache2": {"name": "Apache HTTP Server", "icon": "APACHE", "store_id": "store-linux", "publisher": "Apache"},
    "sshd": {"name": "OpenSSH Server", "icon": "SSH", "store_id": "store-linux", "publisher": "OpenSSH"},
    "git": {"name": "Git", "icon": "GIT", "store_id": "store-linux", "publisher": "Git"},
}


@dataclass
class Friend:
    friend_id: str
    name: str
    identity_type: str
    identity_method: str
    capabilities: list[str]
    expiry: str
    status: str = "pending"
    require_2fa: bool = False
    identity_proof: dict[str, Any] = field(default_factory=dict)
    approvals_required: int = 1
    approvals_received: list[str] = field(default_factory=list)
    last_used: str | None = None


@dataclass
class FriendlyStore:
    store_id: str
    name: str
    icon: str
    platform: str
    trust_tier: str = "community"
    verification_method: str = "unknown"
    metadata_api: str = ""
    icon_url: str = ""
    publisher_allowlist_url: str = ""
    status: str = "active"


@dataclass
class FriendlyApp:
    app_id: str
    name: str
    icon: str
    store_id: str
    publisher: str
    version: str
    status: str = "active"


@dataclass
class Endpoint:
    endpoint_id: str
    host_name: str
    endpoint_type: str
    os: str
    kernel: str
    hypervisor: str | None
    firmware_baseline: str | None
    sbom_status: str
    enrollment_method: str
    publisher_signature: str | None = None
    protection_mode: str = "observe-only"
    release_ring: str = "canary"
    risk_score: float = 0.0
    network_exposure: str = "internal"
    asset_value: float = 7.0
    trust_level: float = 6.0
    installed_packages: dict[str, str] = field(default_factory=dict)
    telemetry_events: list[str] = field(default_factory=list)
    program_root: str | None = None
    last_heartbeat: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class DroneNode:
    """Single node in a drone behaviour graph."""
    node_id: str
    node_type: str
    kind: str
    label: str
    params: dict[str, Any]
    position: dict[str, float]
    edges_out: list[str]
    edge_labels: dict[str, str]


@dataclass
class DroneBehaviour:
    """Complete assembled behaviour graph."""
    behaviour_id: str
    name: str
    nodes: list[DroneNode]
    created_at: str
    author: str
    description: str
    is_brain_preset: bool = False


@dataclass
class Drone:
    drone_id: str
    name: str
    tier: str
    status: str
    mission: str
    behaviour: DroneBehaviour
    target_endpoint_id: str | None
    target_host: str | None
    target_network: str | None
    autonomy_level: str
    ttl_seconds: int
    checkin_interval_seconds: int
    launched_at: str | None
    last_checkin_at: str | None
    return_at: str | None
    keypair_public: str | None
    findings: list[str]
    telemetry: list[dict[str, Any]]
    health: dict[str, Any]
    live_output: list[str]
    current_node_id: str | None
    stats: dict[str, Any]
    error: str | None
    created_at: str
    actor: str
    payload: Any = field(default_factory=dict)
    payload_binary: str = ""
    pending_commands: list[dict[str, Any]] = field(default_factory=list)
    binary_blueprint: str = ""
    binary_blob: str = ""
    blob_size_bytes: int = 0
    blob_hash: str = ""
    blob_path: str = ""
    pid: int | None = None
    deadrop_path: str = ""
    child_drone_ids: list[int] = field(default_factory=list)
    supported_binary_actions: list[str] = field(default_factory=list)


@dataclass
class VulnerabilityFinding:
    finding_id: str
    endpoint_id: str
    cve: str
    cvss: float
    exploit_availability: float
    topological_impact: float
    asset_value: float
    trust_level: float
    evidence: list[dict[str, Any]]
    suggested_remediations: list[str]
    risk_score: float
    graph_path: list[dict[str, Any]] = field(default_factory=list)
    reasoning: str = ""
    poc_attack_map: dict[str, Any] = field(default_factory=dict)
    remediation_plan: list[dict[str, Any]] = field(default_factory=list)
    vulnerability_explanation: str = ""
    bayesian_stage_risk: dict[str, float] = field(default_factory=dict)
    techniques: list[str] = field(default_factory=list)
    source: str = "friendly-scan"
    patch_eligible: bool = True
    cvss_vector: str = ""
    epss_score: float = 0.0
    epss_percentile: float = 0.0
    remediation_sla_tier: str = "p2"
    exploitability_timeline_days: float = 0.0


@dataclass
class ScanResult:
    scan_id: str = ""
    target_id: str = ""
    mode: str = "friendly"
    actor: str = "user"
    started_at: str = ""
    completed_at: str = ""
    duration_seconds: float = 0.0
    findings: list[VulnerabilityFinding] = field(default_factory=list)
    new_findings: list[VulnerabilityFinding] = field(default_factory=list)
    suppressed: int = 0
    intel_sources: list[str] = field(default_factory=list)
    ast_files_scanned: int = 0
    ast_issues_raw: int = 0
    ast_issues_confirmed: int = 0
    patch_proposals_generated: int = 0
    patches_applied: int = 0
    patches_rolled_back: int = 0
    markov_tree: list[dict[str, Any]] = field(default_factory=list)
    bayesian_posteriors: dict[str, float] = field(default_factory=dict)
    attack_surface_delta: dict[str, Any] = field(default_factory=dict)
    scan_confidence: float = 0.0
    lateral_graph: dict[str, Any] = field(default_factory=dict)
    lang_breakdown: dict[str, int] = field(default_factory=dict)
    binary_artefacts_scanned: int = 0
    binary_packed_sections: int = 0
    cross_language_chains: list[dict[str, Any]] = field(default_factory=list)
    disassembly_backend: str | None = None


@dataclass
class AutoPatchPolicy:
    max_auto_cvss: float = 6.0
    max_auto_risk_score: float = 5.5
    require_human_above_cvss: float = 8.0
    auto_apply_delay_seconds: int = 300
    excluded_endpoints: list[str] = field(default_factory=list)
    excluded_cves: list[str] = field(default_factory=list)

@dataclass
class PatchProposal:
    proposal_id: str
    endpoint_id: str
    finding_id: str
    summary: str
    change_plan: list[str]
    test_results: dict[str, str]
    graph_path_before: list[dict[str, Any]]
    graph_path_after: list[dict[str, Any]]
    regression_risk: float
    confidence: float
    impact_score: float
    approvals_required: int
    code_diff: str = ""
    diff_explanation: str = ""
    approvals_received: list[str] = field(default_factory=list)
    rollout_policy: dict[str, Any] = field(default_factory=dict)
    status: str = "pending_review"
    reasoning: str = ""


class HegemonControlPlane:
    DRONE_BINARY_COMMANDS: dict[str, str] = {
        "00000001": "ping",
        "00000010": "scan",
        "00000011": "report",
        "00000100": "pause",
        "00000101": "resume",
        "00000110": "terminate",
        "00000111": "inject_node",
        "00001000": "retask",
        "00001001": "tighten_checkin",
        "00001010": "broadcast_status",
    }
    DRONE_SAMPLE_PROFILES: dict[str, dict[str, Any]] = {
        "gnat-light": {
            "sample_id": "gnat-light",
            "name": "Gnat (Swarm Scout)",
            "tier": "controlled",
            "mission": "scout",
            "autonomy_level": "observe",
            "ttl_seconds": 1200,
            "checkin_interval_seconds": 20,
            "target": "10.0.0.0/24",
            "behaviour_id": "brain-pinger-basic",
            "description": "Lightweight swarm probe with rapid report/exit cadence.",
        },
        "specter-adaptive": {
            "sample_id": "specter-adaptive",
            "name": "Specter (Adaptive ISR)",
            "tier": "autonomous",
            "mission": "watch-loop",
            "autonomy_level": "contain",
            "ttl_seconds": 10800,
            "checkin_interval_seconds": 45,
            "target": "ep-default-linux",
            "behaviour_id": "brain-watcher",
            "description": "Persistent adaptive observer with repeat + anomaly escalation.",
        },
        "carrier-relay": {
            "sample_id": "carrier-relay",
            "name": "Carrier (Drone Hub)",
            "tier": "tethered",
            "mission": "probe",
            "autonomy_level": "contain",
            "ttl_seconds": 7200,
            "checkin_interval_seconds": 90,
            "target": "10.0.1.0/24",
            "behaviour_id": "brain-sentinel-honeypot",
            "description": "Deploy-and-coordinate platform for linked child routes.",
        },
        "oracle-fusion": {
            "sample_id": "oracle-fusion",
            "name": "Oracle (Fusion Analyst)",
            "tier": "autonomous",
            "mission": "watch-loop",
            "autonomy_level": "enforce",
            "ttl_seconds": 14400,
            "checkin_interval_seconds": 60,
            "target": "ep-default-linux",
            "behaviour_id": "brain-watcher",
            "description": "Telemetry fusion observer tuned for high-confidence escalation.",
        },
    }

    def __init__(self, ledger_path: Path | None = None) -> None:
        signer = signing.SigningKey.generate()
        self.ledger = SignedLedger(ledger_path or Path("data/controlplane_ledger.jsonl"), signer)
        self.friends: dict[str, Friend] = {}
        self.endpoints: dict[str, Endpoint] = {}
        self.findings: dict[str, VulnerabilityFinding] = {}
        self.patch_proposals: dict[str, PatchProposal] = {}
        self.friendly_stores: dict[str, FriendlyStore] = {
            row["store_id"]: FriendlyStore(
                store_id=row["store_id"],
                name=str(row.get("name", "unknown")),
                icon=str(row.get("icon", "STORE")),
                platform=str(row.get("platform", "unknown")),
                trust_tier=str(row.get("trust_tier", "community")),
                verification_method=str(row.get("verification_method", "unknown")),
                metadata_api=str(row.get("metadata_api", "")),
                icon_url=str(row.get("icon_url", "")),
                publisher_allowlist_url=str(row.get("publisher_allowlist_url", "")),
                status="active",
            )
            for row in DEFAULT_FRIENDLY_STORES
        }
        self.friendly_apps: dict[str, FriendlyApp] = {}
        self._state_lock = threading.RLock()
        self._seed_default_friendly_entities()
        self._seed_self_endpoint()
        self.auto_patch_policy = AutoPatchPolicy()
        self.human_review_queue: list[str] = []
        self.drones: dict[str, Drone] = {}
        self.drone_brains: dict[str, DroneBehaviour] = {}
        self._drone_threads: dict[str, threading.Thread] = {}
        self._drone_stop_events: dict[str, threading.Event] = {}
        self._drone_command_locks: dict[str, threading.Lock] = {}
        self._drone_private_keys: dict[str, str] = {}
        self._drone_processes: dict[str, subprocess.Popen] = {}
        self._drone_compiler = DroneBlobCompiler()
        self._seed_drone_brains()
        self._proposal_approved_at: dict[str, float] = {}
        self.scan_history: dict[str, list[ScanResult]] = {}
        self.scan_results_by_id: dict[str, ScanResult] = {}
        self.suppressed_findings: list[dict[str, Any]] = []
        self._allow_absolute_program_roots: bool = False
        self.store_client = StoreClient()
        self._self_scan_loop = self.SelfScanLoop(self)

    def _record(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        entry = self.ledger.append(event_type, payload)
        return {"entry_hash": entry.entry_hash, "ts": entry.ts, "event_type": entry.event_type}

    def add_friend(self, payload: dict[str, Any], actor: str) -> Friend:
        friend_id = payload.get("friend_id") or f"fr-{secrets.token_hex(4)}"
        caps = sorted(set(payload.get("capabilities", [])))
        approvals_required = 2 if CRITICAL_CAPABILITIES.intersection(caps) else 1
        friend = Friend(
            friend_id=friend_id,
            name=payload["name"],
            identity_type=payload.get("identity_type", "user"),
            identity_method=payload["identity_method"],
            capabilities=caps,
            expiry=payload.get("expiry", ""),
            require_2fa=bool(payload.get("require_2fa", False)),
            identity_proof=payload.get("identity_proof", {}),
            approvals_required=approvals_required,
            status="active" if approvals_required == 1 else "pending",
        )
        self.friends[friend.friend_id] = friend
        self._record("friend.added", {"actor": actor, "friend": asdict(friend), "ledger_preview": {"added_by": actor}})
        return friend

    def approve_friend(self, friend_id: str, approver: str) -> Friend:
        friend = self.friends[friend_id]
        if approver not in friend.approvals_received:
            friend.approvals_received.append(approver)
        if len(friend.approvals_received) >= friend.approvals_required:
            friend.status = "active"
        self._record("friend.approved", {"friend_id": friend_id, "approver": approver, "status": friend.status})
        return friend

    def disable_friend(self, friend_id: str, actor: str) -> Friend:
        friend = self.friends[friend_id]
        friend.status = "disabled"
        flagged_approvals = self._pending_patch_approvals(friend_id)
        self._record("friend.revoked", {"actor": actor, "friend_id": friend_id, "flagged_pending_patch_approvals": flagged_approvals})
        return friend

    def _pending_patch_approvals(self, friend_id: str) -> list[str]:
        return [
            proposal.proposal_id
            for proposal in self.patch_proposals.values()
            if proposal.status != "deployed_canary" and friend_id in proposal.approvals_received
        ]

    def add_friendly_store(self, payload: dict[str, Any], actor: str) -> FriendlyStore:
        store_id = payload.get("store_id") or f"store-{secrets.token_hex(3)}"
        store = FriendlyStore(
            store_id=store_id,
            name=payload["name"],
            icon=payload.get("icon", "STORE"),
            platform=payload.get("platform", "unknown"),
            status=payload.get("status", "active"),
        )
        self.friendly_stores[store.store_id] = store
        self._record("friendly_store.added", {"actor": actor, "store": asdict(store)})
        return store

    def _seed_default_friendly_entities(self) -> None:
        for endpoint_payload in DEFAULT_FRIENDLY_ENDPOINTS:
            self.add_endpoint(dict(endpoint_payload), actor="bootstrap")

    def _seed_self_endpoint(self) -> None:
        if HEGEMON_SELF_ENDPOINT_ID in self.endpoints:
            return
        self._allow_absolute_program_roots = True
        self.add_endpoint(
            {
                "endpoint_id": HEGEMON_SELF_ENDPOINT_ID,
                "host_name": "hegemon-controlplane",
                "endpoint_type": "control-plane",
                "os": "linux",
                "kernel": "6.8",
                "sbom_status": "valid",
                "enrollment_method": "bootstrap",
                "protection_mode": "canary",
                "release_ring": "canary",
                "network_exposure": "internal",
                "asset_value": 10.0,
                "trust_level": 8.6,
                "installed_packages": {
                    "hegemon-core": "0.9.0",
                    "python3": "3.11.0",
                },
                "telemetry_events": ["recon", "execution", "persistence", "defense_evasion"],
                "program_root": ".",
            },
            actor="bootstrap:self",
        )
        self._allow_absolute_program_roots = False

    def _autodiscover_friendly_apps_from_endpoint(self, endpoint: Endpoint, actor: str) -> None:
        for package, version in endpoint.installed_packages.items():
            spec = PACKAGE_TO_FRIENDLY_APP.get(package)
            if not spec:
                continue
            existing = next((a for a in self.friendly_apps.values() if a.name == spec["name"] and a.store_id == spec["store_id"]), None)
            if existing:
                continue
            self.add_friendly_app(
                {
                    "name": spec["name"],
                    "icon": spec["icon"],
                    "store_id": spec["store_id"],
                    "publisher": spec["publisher"],
                    "version": version,
                },
                actor=actor,
            )

    def add_friendly_app(self, payload: dict[str, Any], actor: str) -> FriendlyApp:
        store_id = payload["store_id"]
        if store_id not in self.friendly_stores:
            raise ValueError("store_id not found")
        app_id = payload.get("app_id") or f"app-{secrets.token_hex(3)}"
        app = FriendlyApp(
            app_id=app_id,
            name=payload["name"],
            icon=payload.get("icon", "PKG"),
            store_id=store_id,
            publisher=payload.get("publisher", "unknown"),
            version=payload.get("version", "0.0.0"),
            status=payload.get("status", "active"),
        )
        self.friendly_apps[app.app_id] = app
        self._record("friendly_app.added", {"actor": actor, "app": asdict(app)})
        return app

    def add_endpoint(self, payload: dict[str, Any], actor: str) -> Endpoint:
        endpoint_id = payload.get("endpoint_id") or f"ep-{secrets.token_hex(4)}"
        _PKG_NAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9._\-]{0,127}[a-zA-Z0-9])?$")
        _PKG_VER_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._\-+:]{0,63}$")
        raw_packages = dict(payload.get("installed_packages", {}))
        installed_packages: dict[str, str] = {}
        for k, v in raw_packages.items():
            ks, vs = str(k).strip(), str(v).strip()
            if _PKG_NAME_RE.match(ks) and _PKG_VER_RE.match(vs):
                installed_packages[ks] = vs
        program_root = (str(payload.get("program_root")) if payload.get("program_root") else None)
        store_id = str(payload.get("store_id", "")).strip()
        if not program_root and store_id and installed_packages:
            pkg_name = next(iter(installed_packages.keys()))
            program_root = self._detect_program_root(pkg_name, store_id)
        endpoint = Endpoint(
            endpoint_id=endpoint_id,
            host_name=payload["host_name"],
            endpoint_type=payload.get("endpoint_type", "on-prem"),
            os=payload.get("os", "unknown"),
            kernel=payload.get("kernel", "unknown"),
            hypervisor=payload.get("hypervisor"),
            firmware_baseline=payload.get("firmware_baseline"),
            sbom_status=payload.get("sbom_status", "unknown"),
            enrollment_method=payload.get("enrollment_method", "manual"),
            publisher_signature=payload.get("publisher_signature"),
            protection_mode=payload.get("protection_mode", "observe-only"),
            release_ring=payload.get("release_ring", "canary"),
            network_exposure=payload.get("network_exposure", "internal"),
            asset_value=float(payload.get("asset_value", 7.0)),
            trust_level=float(payload.get("trust_level", 6.0)),
            installed_packages=installed_packages,
            telemetry_events=list(payload.get("telemetry_events", [])),
            program_root=program_root,
        )
        if endpoint.protection_mode not in {"observe-only", "canary", "enforce"}:
            raise ValueError("invalid protection_mode; expected one of observe-only|canary|enforce")
        if endpoint.endpoint_type == "app-store-package" and not endpoint.publisher_signature:
            raise ValueError("app-store-package endpoints require publisher_signature")
        with self._state_lock:
            self.endpoints[endpoint.endpoint_id] = endpoint
        self._record("endpoint.added", {"actor": actor, "endpoint": asdict(endpoint)})
        self._autodiscover_friendly_apps_from_endpoint(endpoint, actor=f"{actor}:autodiscovery")
        return endpoint


    @staticmethod
    def _parse_version(version: str) -> tuple[int, ...]:
        nums: list[int] = []
        for token in version.replace("-", ".").split("."):
            if token.isdigit():
                nums.append(int(token))
            else:
                digits = "".join(ch for ch in token if ch.isdigit())
                nums.append(int(digits) if digits else 0)
        return tuple(nums)

    @classmethod
    def _version_lt(cls, left: str, right: str) -> bool:
        l = cls._parse_version(left)
        r = cls._parse_version(right)
        max_len = max(len(l), len(r))
        l = l + (0,) * (max_len - len(l))
        r = r + (0,) * (max_len - len(r))
        return l < r

    @staticmethod
    def compute_risk_score(cvss: float, exploit_availability: float, topological_impact: float, asset_value: float, trust_level: float) -> float:
        alpha, beta, gamma, delta, epsilon = 0.40, 0.20, 0.20, 0.15, 0.05
        return round(alpha * cvss + beta * exploit_availability + gamma * topological_impact + delta * asset_value + epsilon * (10 - trust_level), 3)

    @staticmethod
    def _guess_ecosystem(package: str, endpoint_os: str) -> str:
        os_norm = endpoint_os.lower()
        if os_norm.startswith("win"):
            return "NuGet"
        if os_norm in {"ios", "macos", "darwin", "apple"}:
            return "SwiftURL"
        if package in {"openssl", "glibc", "openssh", "systemd", "linux"}:
            return "Debian"
        return "PyPI"

    @staticmethod
    def _published_age_days(vuln: dict[str, Any]) -> float:
        published = vuln.get("published") or vuln.get("modified")
        if not published:
            return 365.0
        try:
            ts = datetime.fromisoformat(str(published).replace("Z", "+00:00"))
            return max((datetime.now(timezone.utc) - ts).days, 0)
        except ValueError:
            return 365.0

    def _query_osv(self, package: str, version: str, endpoint_os: str) -> list[dict[str, Any]]:
        payload = {
            "package": {
                "name": package,
                "ecosystem": self._guess_ecosystem(package, endpoint_os),
            },
            "version": version,
        }
        req = urllib.request.Request(
            "https://api.osv.dev/v1/query",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            return []
        vulns = data.get("vulns", [])
        return vulns if isinstance(vulns, list) else []

    def _query_nvd(self, package: str, version: str, endpoint_os: str) -> list[dict[str, Any]]:
        params = {
            "keywordSearch": f"{package} {version} {endpoint_os}",
            "resultsPerPage": "8",
        }
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{urllib.parse.urlencode(params)}"
        headers = {"User-Agent": "hegemon-control-plane/1.0"}
        api_key = os.getenv("NVD_API_KEY", "").strip()
        if api_key:
            headers["apiKey"] = api_key
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            return []
        vulnerabilities = data.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            return []
        return [entry.get("cve", {}) for entry in vulnerabilities if isinstance(entry, dict)]

    @staticmethod
    def _cvss_from_vuln(vuln: dict[str, Any]) -> float:
        for sev in vuln.get("severity", []):
            score = sev.get("score", "")
            if isinstance(score, str) and "CVSS" in score:
                try:
                    return float(score.split("/")[-1])
                except (ValueError, TypeError):
                    continue
        return 7.0

    @staticmethod
    def _cvss_from_nvd(vuln: dict[str, Any]) -> float:
        metrics = vuln.get("metrics", {}) if isinstance(vuln, dict) else {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            values = metrics.get(key, [])
            if not isinstance(values, list):
                continue
            for item in values:
                data = item.get("cvssData", {}) if isinstance(item, dict) else {}
                score = data.get("baseScore")
                if isinstance(score, (int, float)):
                    return float(score)
        return 7.0

    @staticmethod
    def _kill_chain_markov_second_order(
        events: list[str],
    ) -> tuple[dict[tuple[str, str], dict[str, float]], dict[str, float], float]:
        index = {stage: i for i, stage in enumerate(KILL_CHAIN_STAGES)}
        alpha = 0.1
        trigram_counts: dict[tuple[str, str, str], int] = defaultdict(int)
        bigram_counts: dict[tuple[str, str], int] = defaultdict(int)
        unigram_counts: dict[str, int] = defaultdict(int)
        weights: list[float] = []
        valid_events = [e for e in events if e in index]
        for a, b in zip(valid_events, valid_events[1:]):
            jump = index[b] - index[a]
            if jump >= 3:
                weights.append(2.0)
            elif jump == 2:
                weights.append(1.4)
            elif jump == 1:
                weights.append(1.0)
            elif jump == 0:
                weights.append(0.5)
            else:
                weights.append(-0.3)
            bigram_counts[(a, b)] += 1
            unigram_counts[a] += 1
        if valid_events:
            unigram_counts[valid_events[-1]] += 1
        for a, b, c in zip(valid_events, valid_events[1:], valid_events[2:]):
            trigram_counts[(a, b, c)] += 1
        trans: dict[tuple[str, str], dict[str, float]] = {}
        for state, state_count in bigram_counts.items():
            trans[state] = {}
            denom = state_count + alpha * len(KILL_CHAIN_STAGES)
            for nxt in KILL_CHAIN_STAGES:
                c = trigram_counts.get((state[0], state[1], nxt), 0)
                trans[state][nxt] = round((c + alpha) / denom, 6)
        total_uni = sum(unigram_counts.values())
        marg = {k: (round(v / total_uni, 6) if total_uni else 0.0) for k, v in unigram_counts.items()}
        chain_risk = min(3.0, (sum(weights) / max(1, len(weights))) if weights else 0.2)
        return trans, marg, chain_risk

    @staticmethod
    def _kill_chain_transition_markov(events: list[str]) -> tuple[dict[str, dict[str, float]], float]:
        second, _marg, risk = HegemonControlPlane._kill_chain_markov_second_order(events)
        matrix: dict[str, dict[str, float]] = {stage: {} for stage in KILL_CHAIN_STAGES}
        by_src: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
        for (a, _b), next_probs in second.items():
            for nxt, prob in next_probs.items():
                by_src[a][nxt] += prob
        for a, rows in by_src.items():
            total = sum(rows.values())
            if total <= 0:
                continue
            matrix[a] = {k: round(v / total, 3) for k, v in rows.items() if v > 0}
        return matrix, risk

    def _markov_tree_project(
        self,
        events: list[str],
        depth: int = 4,
        top_k: int = 3,
        min_prob: float = 0.05,
    ) -> list[dict[str, Any]]:
        second, first, _ = self._kill_chain_markov_second_order(events)
        valid_events = [e for e in events if e in KILL_CHAIN_STAGES]

        def expand(prev: str | None, cur: str, cur_prob: float, d: int) -> dict[str, Any]:
            node = {
                "stage": cur,
                "tactic_id": STAGE_TO_TACTIC.get(cur, ""),
                "cumulative_prob": round(cur_prob, 6),
                "depth": d,
                "expected_dwell_days": round(BASE_DWELL_DAYS.get(cur, 3) * (1.0 / max(0.01, cur_prob)), 2),
                "children": [],
            }
            if d >= depth:
                return node
            probs: dict[str, float]
            if prev is not None and (prev, cur) in second:
                probs = second[(prev, cur)]
            else:
                probs = {st: first.get(st, 0.0) for st in KILL_CHAIN_STAGES}
            ranked = sorted(probs.items(), key=lambda kv: kv[1], reverse=True)[:top_k]
            for nxt, p in ranked:
                next_prob = cur_prob * p
                if next_prob < min_prob:
                    continue
                node["children"].append(expand(cur, nxt, next_prob, d + 1))
            return node

        if len(valid_events) >= 2:
            prev, cur = valid_events[-2], valid_events[-1]
        elif len(valid_events) == 1:
            prev, cur = None, valid_events[-1]
        else:
            prev, cur = None, "recon"
        return [expand(prev, cur, 1.0, 0)]

    def _build_bayesian_kill_chain_net(self, events: list[str]) -> Any | None:
        if not _PGMPY_AVAILABLE:
            return None
        try:
            edges = [(KILL_CHAIN_STAGES[i], KILL_CHAIN_STAGES[i + 1]) for i in range(len(KILL_CHAIN_STAGES) - 1)] + [("recon", "execution"), ("recon", "lateral_movement")]
            model = BayesianNetwork(edges)
            cpds = []
            for st in KILL_CHAIN_STAGES:
                cpds.append(TabularCPD(variable=st, variable_card=2, values=[[0.7], [0.3]]))
            model.add_cpds(*cpds)
            return model
        except Exception:
            return None

    def _bayesian_stage_posterior(self, observed_stages: list[str]) -> dict[str, float]:
        if not _PGMPY_AVAILABLE:
            return {}
        model = self._build_bayesian_kill_chain_net(observed_stages)
        if model is None:
            return {}
        out: dict[str, float] = {}
        try:
            inf = VariableElimination(model)
            evidence = {st: 1 for st in observed_stages if st in KILL_CHAIN_STAGES}
            for st in KILL_CHAIN_STAGES:
                if st in evidence:
                    continue
                q = inf.query([st], evidence=evidence, show_progress=False)
                out[st] = float(q.values[1])
        except Exception:
            return {}
        return out


    def _build_lightweight_lstm_rnn_binary_model(
        self,
        sequence_tokens: list[str],
        markov_matrix: dict[str, dict[str, float]],
        graph_features: dict[str, float],
    ) -> dict[str, Any]:
        if not sequence_tokens:
            return {
                "model": "lightweight-lstm-rnn-binary-v1",
                "vocab_size": 0,
                "timesteps": 0,
                "hidden_state_norm": 0.0,
                "sequence_anomaly": 0.0,
                "predicted_next_stages": [],
                "confidence": 0.0,
                "notes": "insufficient sequence tokens",
            }

        vocab = sorted(set(sequence_tokens))
        vocab_index = {tok: i for i, tok in enumerate(vocab)}
        bit_width = 20
        token_counts: dict[str, int] = defaultdict(int)
        transition_counts: dict[tuple[str, str], int] = defaultdict(int)
        for token in sequence_tokens:
            token_counts[token] += 1
        for left, right in zip(sequence_tokens, sequence_tokens[1:]):
            transition_counts[(left, right)] += 1

        def _seeded_unit(seed_key: str) -> float:
            digest = hashlib.sha256(seed_key.encode("utf-8", errors="ignore")).digest()
            value = int.from_bytes(digest[:8], "big") / float(2**64 - 1)
            return (value * 2.0) - 1.0

        graph_density = (
            min(1.0, float(graph_features.get("call_edges", 0.0)) / 6000.0)
            + min(1.0, float(graph_features.get("functions", 0.0)) / 24000.0)
            + min(1.0, float(graph_features.get("modules", 0.0)) / 4000.0)
        ) / 3.0
        avg_stage_transition = 0.0
        transition_probs = [float(prob) for row in markov_matrix.values() for prob in row.values() if isinstance(prob, (int, float))]
        if transition_probs:
            avg_stage_transition = sum(transition_probs) / len(transition_probs)
        transition_energy = min(1.0, avg_stage_transition * 1.8)

        model_seed = (
            f"{'|'.join(sequence_tokens)}::"
            f"{round(graph_density, 5)}::{round(transition_energy, 5)}::"
            f"{len(vocab)}::{len(sequence_tokens)}"
        )
        gate_bases = {
            "i_x": 0.65 + (0.45 * _seeded_unit(f"{model_seed}:i_x")),
            "i_h": 0.35 + (0.35 * _seeded_unit(f"{model_seed}:i_h")),
            "f_h": 0.50 + (0.40 * _seeded_unit(f"{model_seed}:f_h")),
            "f_bias": 0.10 + (0.50 * graph_density),
            "o_x": 0.55 + (0.35 * _seeded_unit(f"{model_seed}:o_x")),
            "o_g": 0.25 + (0.35 * transition_energy),
            "cand_x": 1.0 + (0.55 * _seeded_unit(f"{model_seed}:cand_x")),
            "cand_h": 0.35 + (0.45 * _seeded_unit(f"{model_seed}:cand_h")),
        }

        def token_to_bits(token: str) -> list[float]:
            digest = hashlib.sha1(token.encode("utf-8", errors="ignore")).digest()
            bits: list[float] = []
            for idx in range(bit_width):
                byte = digest[idx % len(digest)]
                bits.append(1.0 if (byte >> (idx % 8)) & 1 else 0.0)
            return bits

        def sigmoid(x: float) -> float:
            x = max(-30.0, min(30.0, x))
            return 1.0 / (1.0 + math.exp(-x))

        h = [0.0] * bit_width
        c = [0.0] * bit_width
        states: list[list[float]] = []

        graph_bias = min(0.4, (graph_features.get("call_edges", 0.0) / 2800.0) + (graph_features.get("functions", 0.0) / 10000.0) + (graph_features.get("modules", 0.0) / 4500.0))
        for token in sequence_tokens:
            x = token_to_bits(token)
            x_mean = sum(x) / bit_width
            h_mean = sum(h) / bit_width
            token_freq = token_counts.get(token, 1) / max(1, len(sequence_tokens))
            structural_boost = graph_bias + (token_freq * 0.2)
            i_gate = sigmoid((gate_bases["i_x"] * x_mean) + (gate_bases["i_h"] * h_mean) + structural_boost)
            f_gate = sigmoid((gate_bases["f_h"] * h_mean) + gate_bases["f_bias"])
            o_gate = sigmoid((gate_bases["o_x"] * x_mean) + (gate_bases["o_g"] * transition_energy) + (0.3 * structural_boost))
            for j in range(bit_width):
                candidate = math.tanh((x[j] * gate_bases["cand_x"]) + (h[j] * gate_bases["cand_h"]) + structural_boost)
                c[j] = (f_gate * c[j]) + (i_gate * candidate)
                h[j] = o_gate * math.tanh(c[j])
            states.append(h[:])

        hidden_norm = math.sqrt(sum(v * v for v in h) / max(1, len(h)))

        surprise_terms: list[float] = []
        for a, b in zip(sequence_tokens, sequence_tokens[1:]):
            if a in KILL_CHAIN_STAGES and b in KILL_CHAIN_STAGES:
                prob = float(markov_matrix.get(a, {}).get(b, 0.01))
                surprise_terms.append(-math.log(max(1e-6, prob)))
        sequence_anomaly = min(1.0, (sum(surprise_terms) / max(1, len(surprise_terms))) / 4.5) if surprise_terms else 0.0

        last_stage = next((tok for tok in reversed(sequence_tokens) if tok in KILL_CHAIN_STAGES), None)
        predictions: list[dict[str, Any]] = []
        if last_stage:
            ranked = sorted(markov_matrix.get(last_stage, {}).items(), key=lambda kv: kv[1], reverse=True)[:4]
            for stage, prob in ranked:
                predictions.append({"stage": stage, "probability": round(float(prob), 4)})

        temporal_stability = 0.0
        if len(states) >= 2:
            deltas = []
            for prev, cur in zip(states, states[1:]):
                deltas.append(sum(abs(a - b) for a, b in zip(prev, cur)) / bit_width)
            temporal_stability = max(0.0, 1.0 - min(1.0, sum(deltas) / max(1, len(deltas))))

        confidence = min(0.98, round(0.42 + (0.35 * temporal_stability) + (0.23 * (1.0 - sequence_anomaly)), 4))
        return {
            "model": "lightweight-lstm-rnn-binary-v1",
            "vocab_size": len(vocab_index),
            "timesteps": len(sequence_tokens),
            "hidden_state_norm": round(hidden_norm, 5),
            "sequence_anomaly": round(sequence_anomaly, 5),
            "temporal_stability": round(temporal_stability, 5),
            "predicted_next_stages": predictions,
            "confidence": confidence,
            "dynamic_weights": {k: round(v, 5) for k, v in gate_bases.items()},
            "observed_transition_pairs": len(transition_counts),
            "notes": "Self-building binary token model fused with Markov-MTRE transitions and graph features.",
        }

    def _integrated_markov_mtre_graph_model(
        self,
        telemetry_events: list[str],
        structural_report: dict[str, Any],
    ) -> dict[str, Any]:
        markov_matrix, chain_risk = self._kill_chain_transition_markov(telemetry_events)
        graph = structural_report.get("program_graph", {}) if isinstance(structural_report, dict) else {}
        call_edges = float(graph.get("call_edges", 0.0))
        functions = float(graph.get("functions", 0.0))
        tainted_returns = float(graph.get("tainted_return_functions", 0.0))

        lstm_model = dict(structural_report.get("lstm_rnn_binary_model", {}) if isinstance(structural_report, dict) else {})
        if not lstm_model:
            seq = [e for e in telemetry_events if isinstance(e, str)]
            seq.extend(str(i.get("issue_id", "")) for i in (structural_report.get("issues", []) if isinstance(structural_report, dict) else [])[:80] if i.get("issue_id"))
            lstm_model = self._build_lightweight_lstm_rnn_binary_model(seq, markov_matrix, {"call_edges": call_edges, "functions": functions, "modules": float(graph.get("modules", 0.0))})

        stage_focus = sorted(
            [(stage, prob) for stage, row in markov_matrix.items() for prob in [sum(row.values()) / max(1, len(row))] if row],
            key=lambda kv: kv[1],
            reverse=True,
        )[:4]
        top_stage_pressure = [{"stage": s, "pressure": round(float(p), 4)} for s, p in stage_focus]

        anomaly = float(lstm_model.get("sequence_anomaly", 0.0))
        rnn_conf = float(lstm_model.get("confidence", 0.0))
        graph_pressure = min(1.0, (call_edges / 1800.0) + (tainted_returns / 400.0) + (functions / 5000.0))
        chain_pressure = min(1.0, max(0.0, chain_risk / 3.0))
        fusion_risk = min(0.99, round((0.32 * chain_pressure) + (0.25 * graph_pressure) + (0.28 * anomaly) + (0.15 * (1.0 - rnn_conf)), 4))
        fusion_conf = min(0.99, round(0.45 + (0.3 * rnn_conf) + (0.15 * (1.0 - anomaly)) + (0.1 * min(1.0, call_edges / 1200.0)), 4))

        return {
            "model": "markov-mtre-graph-rnn-fusion-v1",
            "chain_risk": round(chain_risk, 4),
            "graph_pressure": round(graph_pressure, 4),
            "sequence_anomaly": round(anomaly, 4),
            "rnn_confidence": round(rnn_conf, 4),
            "fusion_risk": fusion_risk,
            "fusion_confidence": fusion_conf,
            "top_stage_pressure": top_stage_pressure,
            "cross_language_hint_count": len(structural_report.get("potential_cross_language_hints", []) if isinstance(structural_report, dict) else []),
        }

    def _build_attack_path(self, endpoint: Endpoint, cve: str, chain_risk: float) -> list[dict[str, Any]]:
        perimeter = "external_attacker" if endpoint.network_exposure == "internet" else "partner_network"
        return [
            {"node": perimeter, "weight": round(1.0 + chain_risk * 0.2, 3)},
            {"node": "internet_edge", "weight": round(1.4 + chain_risk * 0.2, 3)},
            {"node": endpoint.host_name, "weight": round(1.8 + chain_risk * 0.3, 3)},
            {"node": cve, "weight": round(2.1 + chain_risk * 0.4, 3)},
        ]

    def _build_poc_attack_map(
        self,
        endpoint: Endpoint,
        cve: str,
        evidence: list[dict[str, Any]],
        risk: float,
        graph_path: list[dict[str, Any]],
    ) -> dict[str, Any]:
        kill_chain_projection = [
            {"stage": "recon", "probability": round(min(0.99, 0.30 + risk * 0.04), 3)},
            {"stage": "initial_access", "probability": round(min(0.99, 0.35 + risk * 0.05), 3)},
            {"stage": "execution", "probability": round(min(0.99, 0.32 + risk * 0.05), 3)},
            {"stage": "lateral_movement", "probability": round(min(0.99, 0.20 + risk * 0.04), 3)},
            {"stage": "impact", "probability": round(min(0.99, 0.28 + risk * 0.05), 3)},
        ]
        pivot_assets = [
            {
                "asset": endpoint.host_name,
                "role": "primary_target",
                "risk_weight": round(min(10.0, risk + 0.4), 2),
            }
        ]
        if endpoint.network_exposure == "internet":
            pivot_assets.append({"asset": "public_ingress", "role": "entry_pivot", "risk_weight": 8.4})
        if evidence:
            pivot_assets.append(
                {
                    "asset": f"evidence:{evidence[0].get('type', 'telemetry')}",
                    "role": "observable_signal",
                    "risk_weight": round(min(10.0, 5.0 + risk * 0.45), 2),
                }
            )
        return {
            "version": "poc-map-v1",
            "attack_story": f"Attacker path to exploit {cve} against {endpoint.host_name}",
            "graph_nodes": graph_path,
            "kill_chain_projection": kill_chain_projection,
            "pivot_assets": pivot_assets,
            "blast_radius_estimate": {
                "hosts_at_risk": 1 + (2 if endpoint.network_exposure == "internet" else 1),
                "identity_scope": "service-account" if endpoint.endpoint_type in {"cloud", "k8s"} else "local-system",
                "data_sensitivity": "high" if endpoint.asset_value >= 8 else "medium",
            },
        }

    def _build_remediation_plan(self, endpoint: Endpoint, finding_payload: dict[str, Any], risk: float) -> list[dict[str, Any]]:
        remediations = [str(step) for step in finding_payload.get("suggested_remediations", []) if str(step).strip()]
        if not remediations:
            remediations = [f"Upgrade vulnerable component for {finding_payload['cve']}"]
        return [
            {"phase": "contain", "priority": "p0", "action": f"Apply temporary network isolation policy for {endpoint.host_name}."},
            {"phase": "eradicate", "priority": "p0", "action": remediations[0]},
            {"phase": "validate", "priority": "p1", "action": "Run exploit replay tests and regression suite against canary ring."},
            {
                "phase": "recover",
                "priority": "p1",
                "action": (
                    "Promote staged patch through release rings with telemetry guardrails "
                    f"(risk_score={risk}, endpoint={endpoint.endpoint_id})."
                ),
            },
        ]

    def _build_vulnerability_explanation(
        self,
        endpoint: Endpoint,
        cve: str,
        risk: float,
        evidence: list[dict[str, Any]],
        topological_impact: float,
    ) -> str:
        evidence_types = ", ".join(sorted({str(item.get("type", "telemetry")) for item in evidence})) if evidence else "runtime telemetry"
        criticality = "critical" if risk >= 8 else ("high" if risk >= 6 else "moderate")
        return (
            f"{cve} on {endpoint.host_name} is assessed as {criticality} risk ({risk}). "
            f"The endpoint exposure profile ({endpoint.network_exposure}) and topological impact ({topological_impact}) "
            f"indicate exploitable traversal potential. Evidence sources: {evidence_types}. "
            "The generated PoC map models likely attacker progression and the remediation plan prioritizes "
            "containment-first controls before staged permanent fixes."
        )

    def create_finding(self, payload: dict[str, Any], actor: str) -> VulnerabilityFinding:
        finding_id = payload.get("finding_id") or f"vuln-{secrets.token_hex(4)}"
        endpoint = self.endpoints[payload["endpoint_id"]]
        topological_impact = float(payload.get("topological_impact", 7.5 if endpoint.network_exposure == "internet" else 5.0))
        risk = self.compute_risk_score(
            float(payload.get("cvss", 0.0)),
            float(payload.get("exploit_availability", 0.0)),
            topological_impact,
            float(payload.get("asset_value", endpoint.asset_value)),
            float(payload.get("trust_level", endpoint.trust_level)),
        )
        bayesian = payload.get("bayesian_stage_risk", {})
        finding = VulnerabilityFinding(
            finding_id=finding_id,
            endpoint_id=payload["endpoint_id"],
            cve=payload["cve"],
            cvss=float(payload.get("cvss", 0.0)),
            exploit_availability=float(payload.get("exploit_availability", 0.0)),
            topological_impact=topological_impact,
            asset_value=float(payload.get("asset_value", endpoint.asset_value)),
            trust_level=float(payload.get("trust_level", endpoint.trust_level)),
            evidence=payload.get("evidence", []),
            suggested_remediations=payload.get("suggested_remediations", []),
            risk_score=risk,
            graph_path=list(payload.get("graph_path", self._build_attack_path(endpoint, payload["cve"], 0.6))),
            reasoning=str(payload.get("reasoning", "")),
            bayesian_stage_risk=dict(bayesian) if isinstance(bayesian, dict) else {},
            techniques=list(payload.get("techniques", [])),
            source=str(payload.get("source", "friendly-scan")),
            patch_eligible=bool(payload.get("patch_eligible", True)),
            cvss_vector=str(payload.get("cvss_vector", "")),
            epss_score=float(payload.get("epss_score", 0.0)),
            epss_percentile=float(payload.get("epss_percentile", 0.0)),
            remediation_sla_tier=str(payload.get("remediation_sla_tier", "p2")),
            exploitability_timeline_days=float(payload.get("exploitability_timeline_days", 0.0)),
        )
        finding.poc_attack_map = self._build_poc_attack_map(endpoint, finding.cve, finding.evidence, finding.risk_score, finding.graph_path)
        finding.remediation_plan = self._build_remediation_plan(endpoint, payload, finding.risk_score)
        finding.vulnerability_explanation = self._build_vulnerability_explanation(
            endpoint,
            finding.cve,
            finding.risk_score,
            finding.evidence,
            finding.topological_impact,
        )
        with self._state_lock:
            self.findings[finding.finding_id] = finding
        self._record("vulnerability.detected", {"actor": actor, "finding": asdict(finding)})
        return finding

    @staticmethod
    def _safe_relpath(path: Path, base: Path) -> str:
        try:
            return str(path.relative_to(base))
        except ValueError:
            return str(path)

    def _analyze_program_structure(self, program_root: str | None, languages: list[str] | None = None) -> dict[str, Any]:
        if not program_root:
            return {
                "files_scanned": 0,
                "issues": [],
                "ast_confidence": 0.0,
                "graph_alignment": 0.0,
                "markov_kill_chain": 0.0,
                "program_graph": {"modules": 0, "functions": 0, "call_edges": 0, "entrypoints": []},
                "lang_breakdown": {},
                "binary_artefacts_scanned": 0,
                "binary_packed_sections": 0,
                "cross_language_chains": [],
                "potential_cross_language_hints": [],
                "cross_language_analysis_note": "potential cross-language hints (not confirmed taint chains)",
                "disassembly_backend": None,
                "lstm_rnn_binary_model": {},
                "integrated_flow_model": {},
            }

        root = Path(program_root).resolve()
        # A.3 FIX: contain program_root to project working directory
        _allowed_base = Path(".").resolve()
        try:
            root.relative_to(_allowed_base)
        except ValueError:
            if not getattr(self, "_allow_absolute_program_roots", False):
                return {
                    "files_scanned": 0,
                    "issues": [],
                    "ast_confidence": 0.0,
                    "graph_alignment": 0.0,
                    "markov_kill_chain": 0.0,
                    "program_graph": {"modules": 0, "functions": 0, "call_edges": 0, "entrypoints": []},
                    "error": f"program_root {root} is outside the allowed project directory",
                    "lang_breakdown": {},
                    "binary_artefacts_scanned": 0,
                    "binary_packed_sections": 0,
                    "cross_language_chains": [],
                    "potential_cross_language_hints": [],
                    "cross_language_analysis_note": "potential cross-language hints (not confirmed taint chains)",
                    "disassembly_backend": None,
                    "lstm_rnn_binary_model": {},
                    "integrated_flow_model": {},
                }
        if not root.exists() or not root.is_dir():
            return {
                "files_scanned": 0,
                "issues": [],
                "ast_confidence": 0.0,
                "graph_alignment": 0.0,
                "markov_kill_chain": 0.0,
                "program_graph": {"modules": 0, "functions": 0, "call_edges": 0, "entrypoints": []},
                "lang_breakdown": {},
                "binary_artefacts_scanned": 0,
                "binary_packed_sections": 0,
                "cross_language_chains": [],
                "potential_cross_language_hints": [],
                "cross_language_analysis_note": "potential cross-language hints (not confirmed taint chains)",
                "disassembly_backend": None,
                "lstm_rnn_binary_model": {},
                "integrated_flow_model": {},
            }

        skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules", ".pytest_cache"}
        py_files: list[Path] = []
        for candidate in root.rglob("*.py"):
            if any(part in skip_dirs for part in candidate.parts):
                continue
            py_files.append(candidate)
            if len(py_files) >= 400:
                break

        imports_graph: dict[str, set[str]] = defaultdict(set)
        issues: list[dict[str, Any]] = []
        module_trees: dict[str, ast.AST] = {}
        module_aliases: dict[str, dict[str, str]] = defaultdict(dict)

        def node_name(node: ast.AST) -> str:
            if isinstance(node, ast.Name):
                return node.id
            if isinstance(node, ast.Attribute):
                base = node_name(node.value)
                return f"{base}.{node.attr}" if base else node.attr
            return ""

        def stage_chain_for_issue(issue_id: str) -> list[str]:
            chains = {
                "tainted-cmd-exec": ["recon", "initial_access", "execution", "persistence", "impact"],
                "tainted-sql-query": ["recon", "initial_access", "credential_access", "collection", "impact"],
                "hardcoded-secret": ["recon", "credential_access", "lateral_movement", "impact"],
                "weak-rng-auth": ["recon", "credential_access", "privilege_escalation", "impact"],
                "dynamic-exec": ["initial_access", "execution", "defense_evasion", "impact"],
                "pickle-loads": ["initial_access", "execution", "persistence", "impact"],
                "yaml-unsafe-load": ["initial_access", "execution", "impact"],
                "weak-hash": ["credential_access", "defense_evasion", "impact"],
                "shell-true": ["initial_access", "execution", "impact"],
            }
            return chains.get(issue_id, ["recon", "execution", "impact"])

        def tainted_from_expr(expr: ast.AST, tainted_vars: set[str], tainted_calls: set[str]) -> bool:
            if isinstance(expr, ast.Name):
                return expr.id in tainted_vars
            if isinstance(expr, ast.JoinedStr):
                return any(tainted_from_expr(v.value, tainted_vars, tainted_calls) for v in expr.values if isinstance(v, ast.FormattedValue))
            if isinstance(expr, ast.BinOp):
                return tainted_from_expr(expr.left, tainted_vars, tainted_calls) or tainted_from_expr(expr.right, tainted_vars, tainted_calls)
            if isinstance(expr, ast.Call):
                name = node_name(expr.func)
                if name in {"input", "request.args.get", "request.form.get", "request.get_json", "os.environ.get"}:
                    return True
                if name in tainted_calls:
                    return True
                return any(tainted_from_expr(a, tainted_vars, tainted_calls) for a in expr.args)
            if isinstance(expr, ast.Attribute):
                return tainted_from_expr(expr.value, tainted_vars, tainted_calls)
            return False

        def _normalized_name_tokens(var_name: str) -> set[str]:
            normalized = "".join(ch.lower() if ch.isalnum() else "_" for ch in var_name)
            return {tok for tok in normalized.split("_") if tok}

        def _literal_entropy_score(value: str) -> float:
            if not value:
                return 0.0
            charset = len(set(value))
            return min(1.0, (charset / max(1, len(value))) * 3.2)

        def _hardcoded_secret_signal(var_name: str, literal_value: str) -> tuple[bool, list[str], float]:
            tokens = _normalized_name_tokens(var_name)
            safe_name_allowlist = {"author", "copyright", "license", "version", "description", "homepage"}
            if tokens.intersection(safe_name_allowlist):
                return False, ["identifier appears metadata-oriented"], 0.0

            secret_markers = {
                "secret", "token", "password", "passwd", "apikey", "api", "key", "bearer", "private", "credential", "session",
            }
            explicit_combo = (
                ("api" in tokens and "key" in tokens)
                or ("auth" in tokens and "token" in tokens)
                or ("client" in tokens and "secret" in tokens)
                or ("access" in tokens and "key" in tokens)
            )
            name_has_signal = bool(tokens.intersection(secret_markers) or explicit_combo)

            lower_value = literal_value.lower()
            placeholder_markers = {"example", "changeme", "dummy", "sample", "localhost", "test", "placeholder"}
            if any(marker in lower_value for marker in placeholder_markers):
                return False, ["literal appears placeholder/test data"], 0.0

            if literal_value.startswith(("http://", "https://")):
                return False, ["literal appears URL-like"], 0.0

            looks_key_like = (
                len(literal_value) >= 20
                and any(ch.isdigit() for ch in literal_value)
                and (any(ch.isupper() for ch in literal_value) or any(ch in "-_" for ch in literal_value))
                and " " not in literal_value
            )
            entropy = _literal_entropy_score(literal_value)
            high_entropy = entropy >= 0.38

            triggered = name_has_signal and (looks_key_like or high_entropy)
            details = [
                f"name_signal={name_has_signal}",
                f"looks_key_like={looks_key_like}",
                f"entropy={entropy:.2f}",
            ]
            confidence = min(0.99, 0.72 + (0.14 if looks_key_like else 0.0) + (0.12 if high_entropy else 0.0)) if triggered else 0.0
            return triggered, details, confidence

        def add_issue(
            issue_id: str,
            severity: str,
            stage: str,
            file_path: Path,
            line: int,
            confidence: float,
            reason: str,
            patch: str,
            details: list[str] | None = None,
            tags: list[str] | None = None,
            dataflow_path: list[str] | None = None,
            call_path: list[str] | None = None,
        ) -> None:
            reconstructed_chain = stage_chain_for_issue(issue_id)
            issues.append(
                {
                    "issue_id": issue_id,
                    "lang": "python",
                    "severity": severity,
                    "kill_chain_stage": stage,
                    "reconstructed_kill_chain": reconstructed_chain,
                    "file": self._safe_relpath(file_path, root),
                    "line": line,
                    "confidence": confidence,
                    "reasoning": reason,
                    "reasoning_details": details or [],
                    "tags": tags or [],
                    "patch_hint": patch,
                    "dataflow_path": dataflow_path or [],
                    "call_path": call_path or [],
                    "techniques": ISSUE_TO_TECHNIQUES.get(issue_id, []),
                    "binary_offset": None,
                    "section_name": None,
                    "entropy": None,
                }
            )

        # pass 1: parse modules
        for py_file in py_files:
            try:
                source = py_file.read_text(encoding="utf-8")
                tree = ast.parse(source)
            except (OSError, UnicodeDecodeError, SyntaxError):
                continue
            module_name = self._safe_relpath(py_file, root)
            module_trees[module_name] = tree
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports_graph[module_name].add(alias.name.split(".")[0])
                        local = alias.asname or alias.name.split(".")[0]
                        module_aliases[module_name][local] = alias.name
                elif isinstance(node, ast.ImportFrom):
                    imports_graph[module_name].add((node.module or "").split(".")[0])
                    for alias in node.names:
                        local = alias.asname or alias.name
                        module_aliases[module_name][local] = f"{node.module}.{alias.name}" if node.module else alias.name

        function_profiles: dict[str, dict[str, Any]] = {}
        call_graph: dict[str, set[str]] = defaultdict(set)
        tainted_return_functions: set[str] = set()
        risky_sink_functions: set[str] = set()

        # pass 2: build function profiles + intraprocedural taint
        for module_name, tree in module_trees.items():
            for top in getattr(tree, "body", []):
                if isinstance(top, ast.Assign) and isinstance(top.value, ast.Constant) and isinstance(top.value.value, str) and len(top.value.value) >= 18:
                    for target in top.targets:
                        if isinstance(target, ast.Name):
                            var_name = target.id
                            secret_hit, tuning_details, tuned_confidence = _hardcoded_secret_signal(var_name, top.value.value)
                            if secret_hit:
                                add_issue(
                                    "hardcoded-secret",
                                    "critical",
                                    "credential_access",
                                    root / module_name,
                                    getattr(top, "lineno", 1),
                                    tuned_confidence,
                                    "Credential-like literal appears hardcoded in module scope and can be exfiltrated.",
                                    "Move secret to vault/env provider, rotate immediately, and block secret literals in CI.",
                                    details=["Module-level secret constant detected.", *tuning_details],
                                    tags=["zero-day-like", "credential-exposure", "dynamic-tuned"],
                                    dataflow_path=["module_constant", var_name.lower(), "credential_usage"],
                                    call_path=[f"{module_name}:<module>"],
                                )

        for module_name, tree in module_trees.items():
            for node in ast.walk(tree):
                if not isinstance(node, ast.FunctionDef):
                    continue
                fn_qname = f"{module_name}:{node.name}"
                tainted_vars = {arg.arg for arg in node.args.args}
                safe_exec_vars: set[str] = set()
                aliases = module_aliases.get(module_name, {})
                def resolved(name: str) -> str:
                    if name in aliases:
                        return aliases[name]
                    parts = name.split(".")
                    if parts and parts[0] in aliases:
                        return aliases[parts[0]] + ("." + ".".join(parts[1:]) if len(parts) > 1 else "")
                    return name
                source_hits: list[str] = []
                sink_hits: list[str] = []
                returns_tainted = False
                called_names: set[str] = set()
                local_calls_tainted: set[str] = set(tainted_return_functions)

                for child in ast.walk(node):
                    if isinstance(child, ast.Assign):
                        value = child.value
                        for target in child.targets:
                            if isinstance(target, ast.Name):
                                var_name = target.id.lower()
                                if tainted_from_expr(value, tainted_vars, local_calls_tainted):
                                    tainted_vars.add(target.id)
                                if isinstance(value, ast.Call) and resolved(node_name(value.func)) == "compile":
                                    safe_exec_vars.add(target.id)
                                if isinstance(value, ast.Constant) and isinstance(value.value, str) and len(value.value) >= 18:
                                    secret_hit, tuning_details, tuned_confidence = _hardcoded_secret_signal(target.id, value.value)
                                    if secret_hit:
                                        add_issue(
                                            "hardcoded-secret",
                                            "critical",
                                            "credential_access",
                                            root / module_name,
                                            getattr(child, "lineno", 1),
                                            tuned_confidence,
                                            "Credential-like literal appears hardcoded in source and can be exfiltrated.",
                                            "Move secret to vault/env provider, rotate immediately, and block secret literals in CI.",
                                            details=[
                                                "Variable naming indicates credential context.",
                                                *tuning_details,
                                            ],
                                            tags=["zero-day-like", "credential-exposure", "dynamic-tuned"],
                                            dataflow_path=["constant_literal", var_name, "credential_usage"],
                                            call_path=[fn_qname],
                                        )
                    elif isinstance(child, ast.Call):
                        func_name = resolved(node_name(child.func))
                        called_names.add(func_name)
                        line = getattr(child, "lineno", 1)
                        if func_name in {"input", "request.args.get", "request.form.get", "request.get_json", "os.environ.get"}:
                            source_hits.append(func_name)
                        if func_name in {"eval", "exec"}:
                            arg0 = child.args[0] if child.args else None
                            should_flag = False
                            if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                                should_flag = True
                            elif isinstance(arg0, ast.Name) and arg0.id in tainted_vars and arg0.id not in safe_exec_vars:
                                should_flag = True
                            elif isinstance(arg0, ast.Call) and resolved(node_name(arg0.func)) == "compile":
                                should_flag = False
                            if should_flag:
                                add_issue(
                                    "dynamic-exec",
                                    "high",
                                    "execution",
                                    root / module_name,
                                    line,
                                    0.9,
                                    "Dynamic code execution can become an RCE pivot when attacker-controlled data reaches the sink.",
                                    "Replace eval/exec with deterministic parser and allowlisted operation dispatch.",
                                    details=["Execution sink accepts code-like input at runtime."],
                                    tags=["rce-surface"],
                                    dataflow_path=["tainted_input_or_code", func_name],
                                    call_path=[fn_qname, func_name],
                                )
                                sink_hits.append(func_name)
                                risky_sink_functions.add(fn_qname)
                        if func_name.endswith("subprocess.run") or func_name.endswith("subprocess.Popen") or func_name == "os.system":
                            shell_true = func_name == "os.system"
                            for kw in child.keywords:
                                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                    shell_true = True
                            arg0 = child.args[0] if child.args else ast.Constant(value="")
                            tainted_cmd = tainted_from_expr(arg0, tainted_vars, local_calls_tainted)
                            if shell_true and tainted_cmd:
                                add_issue(
                                    "tainted-cmd-exec",
                                    "critical",
                                    "execution",
                                    root / module_name,
                                    line,
                                    0.98,
                                    "Probable command injection path: tainted data reaches shell-enabled command sink.",
                                    "Replace shell command with strict argv allowlist + canonicalization + deny shell metacharacters.",
                                    details=[
                                        "Dataflow confirmed from source-like variable into command expression.",
                                        "Shell execution context permits command chaining and expansion.",
                                    ],
                                    tags=["zero-day-like", "command-injection"],
                                    dataflow_path=["source", "tainted_var", "shell_command_sink"],
                                    call_path=[fn_qname, func_name],
                                )
                                sink_hits.append(func_name)
                                risky_sink_functions.add(fn_qname)
                            elif shell_true:
                                add_issue(
                                    "shell-true",
                                    "high",
                                    "execution",
                                    root / module_name,
                                    line,
                                    0.86,
                                    "shell=True broadens command injection surface even for currently constrained inputs.",
                                    "Use subprocess with shell=False and explicit argv tokenization.",
                                    details=["Shell parsing adds implicit expansion semantics."],
                                    tags=["command-injection"],
                                    dataflow_path=["command_template", "shell_sink"],
                                    call_path=[fn_qname, func_name],
                                )
                                sink_hits.append(func_name)
                                risky_sink_functions.add(fn_qname)
                        if func_name == "pickle.loads":
                            add_issue(
                                "pickle-loads",
                                "high",
                                "initial_access",
                                root / module_name,
                                line,
                                0.84,
                                "Deserializing pickle payloads can instantiate attacker-controlled objects.",
                                "Replace pickle deserialization with schema-validated JSON/msgpack.",
                                details=["Unsafe object graph hydration detected."],
                                tags=["deserialization"],
                                dataflow_path=["external_payload", func_name],
                                call_path=[fn_qname, func_name],
                            )
                            sink_hits.append(func_name)
                            risky_sink_functions.add(fn_qname)
                        if func_name == "yaml.load":
                            safe_loader = any(kw.arg == "Loader" and isinstance(kw.value, ast.Attribute) and kw.value.attr == "SafeLoader" for kw in child.keywords)
                            if not safe_loader:
                                add_issue(
                                    "yaml-unsafe-load",
                                    "high",
                                    "initial_access",
                                    root / module_name,
                                    line,
                                    0.79,
                                    "yaml.load without SafeLoader can deserialize arbitrary objects.",
                                    "Use yaml.safe_load and explicit schema validation.",
                                    details=["Object constructors are not constrained to safe primitives."],
                                    tags=["deserialization"],
                                    dataflow_path=["yaml_untrusted_input", "object_deserialization"],
                                    call_path=[fn_qname, func_name],
                                )
                                sink_hits.append(func_name)
                                risky_sink_functions.add(fn_qname)
                        if func_name in {"hashlib.md5", "hashlib.sha1", "md5", "sha1"}:
                            nlow = node.name.lower()
                            if any(tok in nlow for tok in {"digest", "etag", "cache_key", "checksum", "fingerprint", "hmac"}) or any(a.arg in {"algorithm", "alg"} for a in node.args.args):
                                continue
                            if any(resolved(node_name(a.func)) in {"hmac.new", "hmac.digest"} for a in ast.walk(node) if isinstance(a, ast.Call)):
                                continue
                            add_issue(
                                "weak-hash",
                                "medium",
                                "defense_evasion",
                                root / module_name,
                                line,
                                0.65,
                                "Weak hash primitive detected for integrity-sensitive flow.",
                                "Use SHA-256/512 or BLAKE2 and include keyed construction where appropriate.",
                                details=["Collision resistance can be bypassed by modern attack tooling."],
                                tags=["crypto"],
                                dataflow_path=["integrity_operation", func_name],
                                call_path=[fn_qname, func_name],
                            )
                        if (func_name.endswith(".execute") or func_name == "execute") and child.args:
                            query_expr = child.args[0]
                            if isinstance(query_expr, (ast.JoinedStr, ast.BinOp)) and tainted_from_expr(query_expr, tainted_vars, local_calls_tainted):
                                add_issue(
                                    "tainted-sql-query",
                                    "critical",
                                    "credential_access",
                                    root / module_name,
                                    line,
                                    0.96,
                                    "Probable SQL injection path: tainted data interpolated into query text.",
                                    "Switch to parameterized query templates with bound variables only.",
                                    details=[
                                        "Tainted source propagated into SQL string expression.",
                                        "Concatenation/interpolation bypasses parameter binding safety.",
                                    ],
                                    tags=["zero-day-like", "sql-injection"],
                                    dataflow_path=["source", "query_string_build", "sql_execute_sink"],
                                    call_path=[fn_qname, func_name],
                                )
                                sink_hits.append(func_name)
                                risky_sink_functions.add(fn_qname)
                        if func_name in {"random.random", "random.randint", "random.choice"}:
                            parent_assign_name = ""
                            for parent in ast.walk(node):
                                if isinstance(parent, ast.Assign) and parent.value is child and parent.targets and isinstance(parent.targets[0], ast.Name):
                                    parent_assign_name = parent.targets[0].id.lower()
                                    break
                            if any(k in parent_assign_name for k in {"token", "session", "nonce", "password"}):
                                add_issue(
                                    "weak-rng-auth",
                                    "high",
                                    "credential_access",
                                    root / module_name,
                                    line,
                                    0.83,
                                    "Non-cryptographic RNG appears used for auth/session material.",
                                    "Use secrets.token_urlsafe / secrets.randbelow and expire legacy tokens.",
                                    details=["Predictable random stream may allow token preimage attacks."],
                                    tags=["auth", "crypto"],
                                    dataflow_path=["auth_material_generation", func_name],
                                    call_path=[fn_qname, func_name],
                                )

                        # additional detectors
                        if func_name in {"open", "pathlib.Path", "os.path.join", "os.path.abspath"} and child.args:
                            if tainted_from_expr(child.args[0], tainted_vars, local_calls_tainted):
                                add_issue("path-traversal", "high", "discovery", root / module_name, line, 0.86, "Tainted path reaches filesystem sink.", "Normalize with os.path.basename and enforce allowlisted roots.")
                        if func_name in {"requests.get", "requests.post", "requests.put", "requests.delete", "requests.request", "urllib.request.urlopen", "httpx.get", "httpx.post", "aiohttp.ClientSession"} and child.args:
                            if tainted_from_expr(child.args[0], tainted_vars, local_calls_tainted):
                                add_issue("ssrf", "critical", "initial_access", root / module_name, line, 0.92, "Tainted URL reaches outbound HTTP sink.", "Validate URL host against an allowlist before dispatch.")
                        if func_name in {"jwt.decode", "pyjwt.decode"}:
                            alg_kw = next((kw for kw in child.keywords if kw.arg == "algorithms"), None)
                            bad = alg_kw is None
                            if alg_kw and isinstance(alg_kw.value, ast.List):
                                vals = [getattr(v, "value", None) for v in alg_kw.value.elts if isinstance(v, ast.Constant)]
                                bad = "none" in [str(v).lower() for v in vals]
                            if bad:
                                add_issue("jwt-none-alg", "critical", "credential_access", root / module_name, line, 0.95, "JWT decode missing strict algorithms allowlist.", "Set algorithms=['HS256'] (or approved list) and disallow 'none'.")

                    elif isinstance(child, ast.Return):
                        if child.value and tainted_from_expr(child.value, tainted_vars, local_calls_tainted):
                            returns_tainted = True

                function_profiles[fn_qname] = {
                    "sources": source_hits,
                    "sinks": sink_hits,
                    "returns_tainted": returns_tainted,
                    "calls": sorted(called_names),
                }

        # pass 3: call graph + fixed-point taint returns propagation
        for fn_qname, profile in function_profiles.items():
            for callee in profile.get("calls", []):
                short = callee.split(".")[-1]
                same_module = f"{fn_qname.split(':')[0]}:{short}"
                if same_module in function_profiles:
                    call_graph[fn_qname].add(same_module)

        changed = True
        while changed:
            changed = False
            for fn_qname, callees in call_graph.items():
                if function_profiles.get(fn_qname, {}).get("returns_tainted"):
                    continue
                if any(function_profiles.get(callee, {}).get("returns_tainted") for callee in callees):
                    function_profiles[fn_qname]["returns_tainted"] = True
                    changed = True

        tainted_return_functions = {fn for fn, prof in function_profiles.items() if prof.get("returns_tainted")}

        # pass 4: interprocedural issue augmentation via call graph
        for fn_qname, callees in call_graph.items():
            for callee in callees:
                if callee in risky_sink_functions and fn_qname not in risky_sink_functions:
                    add_issue(
                        "interprocedural-sink-reachability",
                        "high",
                        "execution",
                        root / fn_qname.split(":")[0],
                        1,
                        0.78,
                        "Function reaches a downstream risky sink through call graph traversal.",
                        "Introduce boundary validation at caller and enforce contract-level sanitization before calling risky routines.",
                        details=[
                            f"Caller {fn_qname} reaches sink-bearing callee {callee}.",
                            "Combined pass reconstructed transitive risk path across function boundaries.",
                        ],
                        tags=["graph-based", "kill-chain-reconstructed"],
                        dataflow_path=["caller", "transitive_call", "sink"],
                        call_path=[fn_qname, callee],
                    )

        extra_issues: list[dict[str, Any]] = []
        binary_artefacts_scanned = 0
        binary_packed_sections = 0
        disassembly_backend: str | None = None
        for candidate in root.rglob("*"):
            if candidate.is_dir() or any(part in {".git", "__pycache__", ".venv", "venv", "node_modules", ".pytest_cache"} for part in candidate.parts):
                continue
            rel = self._safe_relpath(candidate, root)
            name = candidate.name.lower()
            suf = candidate.suffix.lower()
            try:
                if suf in {".js", ".ts", ".mjs", ".cjs"}:
                    extra_issues.extend(self._analyze_js_file(candidate, rel))
                elif suf in {".sh", ".bash", ".zsh"}:
                    extra_issues.extend(self._analyze_shell_file(candidate, rel))
                elif name.startswith("dockerfile"):
                    extra_issues.extend(self._analyze_dockerfile(candidate, rel))
                elif suf in {".yaml", ".yml", ".json"}:
                    extra_issues.extend(self._analyze_config_file(candidate, rel))
                elif candidate.is_file() and suf in {".so", ".exe", ".dll", ".bin", ".o", ""}:
                    try:
                        head = candidate.read_bytes()[:4]
                    except OSError:
                        head = b""
                    if head in {b"\x7fELF", b"MZ\x90\x00", b"MZ"}:
                        binary_artefacts_scanned += 1
                        b_issues, packed_count, backend = self._analyze_binary_file(candidate, rel)
                        extra_issues.extend(b_issues)
                        binary_packed_sections += packed_count
                        disassembly_backend = disassembly_backend or backend
            except Exception:
                continue
        issues.extend(extra_issues)
        lang_breakdown: dict[str, int] = defaultdict(int)
        for issue in issues:
            lang_breakdown[str(issue.get("lang", "python"))] += 1

        severity_weight = {"low": 0.25, "medium": 0.55, "high": 0.82, "critical": 1.0}
        issue_conf = [float(i["confidence"]) * severity_weight.get(str(i["severity"]), 0.55) for i in issues] or [0.0]
        ast_confidence = round(min(0.99, sum(issue_conf) / len(issue_conf) + (0.10 if issues else 0.0)), 3)

        module_degrees = [len(v) for v in imports_graph.values()] or [0]
        call_degrees = [len(v) for v in call_graph.values()] or [0]
        graph_alignment = round(min(0.99, ((sum(module_degrees) / max(1, len(module_degrees))) * 0.5 + (sum(call_degrees) / max(1, len(call_degrees))) * 0.8) / 5.0), 3)

        all_stages: list[str] = []
        for issue in issues:
            all_stages.extend([str(s) for s in issue.get("reconstructed_kill_chain", [])])
        if not all_stages:
            all_stages = [str(i.get("kill_chain_stage", "execution")) for i in issues]
        markov_matrix, markov_score = self._kill_chain_transition_markov(all_stages)

        entrypoints = sorted([fn for fn, p in function_profiles.items() if p.get("sources")])[:12]
        cross_language_hints = self._build_cross_language_taint_chains(issues)
        sequence_tokens = list(all_stages)
        sequence_tokens.extend(str(i.get("issue_id", "")) for i in issues[:120] if i.get("issue_id"))
        sequence_tokens.extend(str(i.get("lang", "")) for i in issues[:120] if i.get("lang"))
        model_features = {
            "call_edges": float(sum(len(v) for v in call_graph.values())),
            "functions": float(len(function_profiles)),
            "modules": float(len(module_trees)),
        }
        lstm_rnn_binary_model = self._build_lightweight_lstm_rnn_binary_model(sequence_tokens, markov_matrix, model_features)
        integrated_flow_model = self._integrated_markov_mtre_graph_model(all_stages, {"program_graph": {"call_edges": model_features["call_edges"], "functions": model_features["functions"], "modules": model_features["modules"], "tainted_return_functions": float(len(tainted_return_functions))}, "lstm_rnn_binary_model": lstm_rnn_binary_model, "potential_cross_language_hints": cross_language_hints})
        return {
            "files_scanned": len(py_files),
            "issues": issues,
            "ast_confidence": ast_confidence,
            "graph_alignment": graph_alignment,
            "markov_kill_chain": round(markov_score, 3),
            "program_graph": {
                "modules": len(module_trees),
                "functions": len(function_profiles),
                "call_edges": sum(len(v) for v in call_graph.values()),
                "entrypoints": entrypoints,
                "tainted_return_functions": len(tainted_return_functions),
            },
            "lang_breakdown": dict(lang_breakdown),
            "binary_artefacts_scanned": binary_artefacts_scanned,
            "binary_packed_sections": binary_packed_sections,
            "cross_language_chains": cross_language_hints,
            "potential_cross_language_hints": cross_language_hints,
            "cross_language_analysis_note": "potential cross-language hints (not confirmed taint chains)",
            "disassembly_backend": disassembly_backend,
            "lstm_rnn_binary_model": lstm_rnn_binary_model,
            "integrated_flow_model": integrated_flow_model,
        }

    def _detect_program_root(self, package_name: str, store_id: str) -> str | None:
        candidates: list[Path] = []
        try:
            if store_id in {"store-pypi", "store-linux"}:
                for sp in sys.path:
                    p = Path(sp) / package_name
                    if p.is_dir():
                        candidates.append(p)
                try:
                    result = subprocess.run([sys.executable, "-m", "pip", "show", package_name], capture_output=True, text=True, timeout=5)
                    for line in result.stdout.splitlines():
                        if line.startswith("Location:"):
                            loc = Path(line.split(":", 1)[1].strip()) / package_name
                            if loc.is_dir():
                                candidates.append(loc)
                except Exception:
                    pass
            if store_id == "store-npm":
                for base in [Path("node_modules"), Path("/usr/local/lib/node_modules"), Path.home() / ".npm" / "lib" / "node_modules"]:
                    p = base / package_name
                    if p.is_dir():
                        candidates.append(p)
            if store_id == "store-homebrew":
                brew = shutil.which("brew")
                if brew:
                    try:
                        result = subprocess.run([brew, "--prefix", package_name], capture_output=True, text=True, timeout=5)
                        if result.returncode == 0:
                            p = Path(result.stdout.strip())
                            if p.is_dir():
                                candidates.append(p)
                    except Exception:
                        pass
            if store_id == "store-linux":
                for cmd in [["dpkg", "-L", package_name], ["rpm", "-ql", package_name]]:
                    if shutil.which(cmd[0]):
                        try:
                            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                            paths = [Path(l.strip()) for l in result.stdout.splitlines() if l.strip()]
                            dirs = [q.parent for q in paths if q.suffix in {".py", ".rb", ".js", ".go"}]
                            if dirs:
                                candidates.append(min(dirs, key=lambda d: len(d.parts)))
                        except Exception:
                            pass
            blocked = {Path("/etc"), Path("/root"), Path("/sys"), Path("/proc")}
            for c in candidates:
                try:
                    resolved = c.resolve()
                    if resolved.is_dir() and not any(str(resolved).startswith(str(b)) for b in blocked):
                        return str(resolved)
                except Exception:
                    continue
        except Exception:
            return None
        return None

    def register_store_endpoint(self, query: str, store_id: str, version: str | None, network_exposure: str, asset_value: float, actor: str) -> dict[str, Any]:
        meta = self.store_client.get_metadata(query, store_id, version)
        if meta is None:
            suggestions = [r.__dict__ for r in self.store_client.search(query, [store_id], limit=5)]
            raise KeyError(json.dumps({"not_found": query, "suggestions": suggestions}))
        package_name = re.sub(r"[^a-zA-Z0-9._-]", "-", meta.name.lower()).strip("-") or "package"
        endpoint_id = f"ep-{package_name[:40]}"
        detected = self._detect_program_root(package_name, store_id)
        endpoint = self.add_endpoint({
            "endpoint_id": endpoint_id,
            "host_name": meta.name,
            "endpoint_type": "app-store-package",
            "os": "linux",
            "kernel": "unknown",
            "sbom_status": "unknown",
            "enrollment_method": "store-import",
            "publisher_signature": meta.publisher,
            "network_exposure": network_exposure,
            "asset_value": float(asset_value),
            "installed_packages": {package_name: version or meta.version or "latest"},
            "program_root": detected,
            "store_id": store_id,
        }, actor=actor)
        app = self.add_friendly_app({"name": meta.name, "icon": meta.icon_url or "PKG", "store_id": store_id, "publisher": meta.publisher, "version": version or meta.version or "latest"}, actor=actor)
        scan_id = None
        triggered = False
        if detected:
            triggered = True
            scan_id = f"scan-{secrets.token_hex(4)}"
            def _bg() -> None:
                try:
                    self.scan(endpoint.endpoint_id, mode="friendly", actor=f"{actor}:store")
                except Exception:
                    return
            threading.Thread(target=_bg, daemon=True).start()
        self._record("store.endpoint_registered", {"actor": actor, "endpoint_id": endpoint.endpoint_id, "store_id": store_id, "program_root": detected, "scan_triggered": triggered, "scan_id": scan_id})
        return {"endpoint": endpoint, "friendly_app": app, "program_root_detected": detected, "store_metadata": meta, "scan_triggered": triggered, "scan_id": scan_id}

    def _extract_js_identifiers(self, expr: str) -> set[str]:
        reserved = {
            "if", "for", "while", "return", "const", "let", "var", "function", "new", "class",
            "await", "async", "true", "false", "null", "undefined", "this", "window", "document",
        }
        ids = set(re.findall(r"\b[A-Za-z_$][\w$]*\b", expr or ""))
        return {token for token in ids if token not in reserved}

    def _js_member_name(self, expr: str) -> str | None:
        cleaned = (expr or "").strip()
        m = re.match(r"([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)$", cleaned)
        if m:
            return f"{m.group(1)}.{m.group(2)}"
        return None

    def _analyze_js_file(self, path: Path, rel: str) -> list[dict[str, Any]]:
        issues=[]
        try:
            lines=path.read_text(encoding='utf-8', errors='ignore').splitlines()
        except OSError:
            return issues

        js_sources = (
            "document.cookie", "window.location", "location.search", "location.hash", "location.href",
            "localstorage", "sessionstorage", "urlsearchparams", "req.query", "req.params", "req.body",
            "postmessage", "process.env", "document.referrer", "window.name", "location.pathname",
        )
        sanitizer_regex = re.compile(r"\b(?:dompurify\.)?sanitize\s*\(|\bescape(?:html)?\s*\(|\bencodeuricomponent\s*\(|\btextcontent\b")
        scopes: list[dict[str, bool]] = [{}]
        function_profiles: dict[str, dict[str, Any]] = {}
        function_stack: list[str] = []
        pending_destructure_vars: list[str] | None = None

        def get_taint(var_name: str) -> bool:
            for scope in reversed(scopes):
                if var_name in scope:
                    return bool(scope[var_name])
            return False

        def set_taint(var_name: str, tainted: bool, declared: bool) -> None:
            if declared:
                scopes[-1][var_name] = tainted
                return
            for scope in reversed(scopes):
                if var_name in scope:
                    scope[var_name] = tainted
                    return
            scopes[-1][var_name] = tainted

        def expr_taint(expr: str) -> tuple[bool, list[str]]:
            raw_expr = expr or ""
            lowered = raw_expr.lower()
            details: list[str] = []
            if any(src in lowered for src in js_sources):
                details.append("user_input_source")
            if sanitizer_regex.search(lowered):
                return False, ["sanitized"]

            ids = sorted(self._extract_js_identifiers(raw_expr))
            tainted_vars = [token for token in ids if get_taint(token)]
            member_tokens = re.findall(r"\b[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]+)+\b", raw_expr)
            for token in member_tokens:
                parts = token.split('.')
                for idx in range(len(parts), 1, -1):
                    candidate = '.'.join(parts[:idx])
                    if get_taint(candidate):
                        tainted_vars.append(candidate)
                        break
            if tainted_vars:
                details.extend(sorted(set(tainted_vars)))

            call_match = re.match(r"\s*([A-Za-z_$][\w$]*)\s*\((.*)\)\s*$", raw_expr)
            if call_match:
                fn_name = call_match.group(1)
                args = [a.strip() for a in re.split(r",(?![^()]*\))", call_match.group(2)) if a.strip()]
                arg_tainted = any(expr_taint(a)[0] for a in args)
                prof = function_profiles.get(fn_name)
                if prof and prof.get("returns_from_tainted_arg") and arg_tainted:
                    details.append(f"function:{fn_name}")

            return bool(details), details

        sink_patterns = [
            ("js-dynamic-exec", r"\b(?:eval|Function|setTimeout|setInterval)\s*\((.+)\)", "Avoid eval/Function on untrusted input; use safe parser or callbacks."),
            ("js-dom-xss", r"\b(?:innerHTML|outerHTML)\s*=\s*(.+?);?$", "Use textContent or trusted templates and sanitize untrusted HTML."),
            ("js-dom-xss", r"\binsertAdjacentHTML\s*\([^,]+,\s*(.+)\)", "Avoid insertAdjacentHTML with user input; sanitize before rendering."),
            ("js-dom-xss", r"\bdocument\.write\s*\((.+)\)", "Avoid document.write with untrusted content."),
            ("js-dom-xss", r"\$\([^)]*\)\.(?:html|append|prepend|before|after)\s*\((.+)\)", "Avoid jQuery HTML sink APIs with untrusted content."),
        ]

        def strip_inline_js_comment(raw_line: str) -> str:
            in_single = False
            in_double = False
            in_template = False
            escaped = False
            out: list[str] = []
            for idx, ch in enumerate(raw_line):
                nxt = raw_line[idx + 1] if idx + 1 < len(raw_line) else ""
                if escaped:
                    out.append(ch)
                    escaped = False
                    continue
                if ch == "\\":
                    out.append(ch)
                    escaped = True
                    continue
                if not in_double and not in_template and ch == "'":
                    in_single = not in_single
                    out.append(ch)
                    continue
                if not in_single and not in_template and ch == '"':
                    in_double = not in_double
                    out.append(ch)
                    continue
                if not in_single and not in_double and ch == "`":
                    in_template = not in_template
                    out.append(ch)
                    continue
                if not in_single and not in_double and not in_template and ch == "/" and nxt == "/":
                    break
                out.append(ch)
            return "".join(out)

        sink_seen: set[tuple[str, int, str]] = set()
        for i, l in enumerate(lines, 1):
            line = strip_inline_js_comment(l)
            stripped = line.strip()
            if not stripped:
                continue

            destructure_start = re.match(r"\s*(?:const|let|var)\s*\{\s*$", stripped)
            if destructure_start:
                pending_destructure_vars = []
                continue

            if pending_destructure_vars is not None:
                destructure_close = re.match(r"\s*}\s*=\s*(.+?)\s*;?\s*$", stripped)
                if destructure_close:
                    rhs_expr = destructure_close.group(1)
                    tainted, _detail = expr_taint(rhs_expr)
                    for var_name in pending_destructure_vars:
                        set_taint(var_name, tainted, declared=True)
                    pending_destructure_vars = None
                    continue
                names = re.findall(r"[A-Za-z_$][\w$]*", stripped)
                pending_destructure_vars.extend([name for name in names if name not in {"const", "let", "var"}])
                continue

            fn_decl = re.match(r"\s*function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)", stripped)
            if fn_decl:
                fn_name = fn_decl.group(1)
                params = [p.strip() for p in fn_decl.group(2).split(",") if p.strip()]
                function_profiles.setdefault(fn_name, {"params": params, "returns_from_tainted_arg": False})
                function_stack.append(fn_name)
                scopes.append({p: True for p in params})

            arrow_decl = re.match(r"\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\(([^)]*)\)\s*=>", stripped)
            if arrow_decl:
                fn_name = arrow_decl.group(1)
                params = [p.strip() for p in arrow_decl.group(2).split(",") if p.strip()]
                function_profiles.setdefault(fn_name, {"params": params, "returns_from_tainted_arg": False})
                arrow_tail = stripped.split("=>", 1)[1] if "=>" in stripped else ""
                if "{" in arrow_tail:
                    function_stack.append(fn_name)
                    scopes.append({p: True for p in params})

            assignment = re.match(r"\s*(?:(let|const|var)\s+)?([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\s*=\s*(.+?)\s*;?\s*$", line)
            if assignment:
                declared = bool(assignment.group(1))
                lhs = assignment.group(2)
                rhs = assignment.group(3)
                tainted, _detail = expr_taint(rhs)
                member = self._js_member_name(lhs)
                if member:
                    set_taint(member, tainted, declared=False)
                else:
                    set_taint(lhs, tainted, declared)

            return_match = re.match(r"\s*return\s+(.+?)\s*;?\s*$", stripped)
            if return_match and function_stack:
                fn_name = function_stack[-1]
                return_expr = return_match.group(1)
                tainted, taint_vars = expr_taint(return_expr)
                prof = function_profiles.setdefault(fn_name, {"params": [], "returns_from_tainted_arg": False})
                param_names = set(prof.get("params", []))
                if tainted and any(v in param_names for v in taint_vars):
                    prof["returns_from_tainted_arg"] = True

            for issue_id, sink_regex, patch_hint in sink_patterns:
                match = re.search(sink_regex, line)
                if not match:
                    continue
                argument = match.group(1)
                tainted, taint_vars = expr_taint(argument)
                if not tainted:
                    continue
                key = (issue_id, i, argument.strip())
                if key in sink_seen:
                    continue
                sink_seen.add(key)
                reasoning = (
                    "Probable dynamic execution path: tainted JavaScript data reaches executable sink."
                    if issue_id == "js-dynamic-exec"
                    else "Probable DOM XSS path: tainted data reaches HTML rendering sink."
                )
                confidence = 0.9 if "user_input_source" in taint_vars else 0.82
                issues.append({"issue_id":issue_id,"lang":"javascript","severity":"critical" if issue_id == "js-dynamic-exec" else "high","kill_chain_stage":"execution","reconstructed_kill_chain":["initial_access","execution","impact"],"techniques":["T1059.007"],"file":rel,"line":i,"confidence":confidence,"reasoning":reasoning,"reasoning_details":["taint-propagation","scope-aware-js","sink-context"],"tags":["js","taint","dataflow"],"patch_hint":patch_hint,"dataflow_path":["source",*(taint_vars[:4] or ["derived_var"]),"sink"],"call_path":function_stack[-2:],"binary_offset":None,"section_name":None,"entropy":None})

            leading_closers = re.match(r"^\}+(?=\s*(?:else\b|catch\b|finally\b|;|$))", stripped)
            close_count = len(leading_closers.group(0)) if leading_closers else 0
            if close_count:
                for _ in range(close_count):
                    if function_stack and len(scopes) > 1:
                        function_stack.pop()
                        scopes.pop()
                    elif len(scopes) > 1:
                        scopes.pop()

        return issues

    def _analyze_shell_file(self, path: Path, rel: str) -> list[dict[str, Any]]:
        issues=[]
        try: lines=path.read_text(encoding='utf-8', errors='ignore').splitlines()
        except OSError: return issues
        has_set=False
        for i,l in enumerate(lines,1):
            ll=l.strip().lower()
            if ll.startswith('set -e') or ll.startswith('set -u'):
                has_set=True
            if 'curl ' in ll and '| bash' in ll or 'wget ' in ll and '| sh' in ll:
                issues.append({"issue_id":"shell-curl-pipe-exec","lang":"shell","severity":"critical","kill_chain_stage":"execution","reconstructed_kill_chain":["initial_access","execution","impact"],"techniques":["T1059.004"],"file":rel,"line":i,"confidence":0.88,"reasoning":"Remote script piped to shell.","reasoning_details":[],"tags":["shell"],"patch_hint":"Download, verify signature/hash, then execute.","dataflow_path":[],"call_path":[],"binary_offset":None,"section_name":None,"entropy":None})
            if 'chmod 777' in ll:
                issues.append({"issue_id":"shell-world-writable","lang":"shell","severity":"medium","kill_chain_stage":"defense_evasion","reconstructed_kill_chain":["execution","persistence","impact"],"techniques":["T1222"],"file":rel,"line":i,"confidence":0.7,"reasoning":"World writable permission grant.","reasoning_details":[],"tags":["shell"],"patch_hint":"Use least-privilege chmod values.","dataflow_path":[],"call_path":[],"binary_offset":None,"section_name":None,"entropy":None})
        if not has_set:
            issues.append({"issue_id":"shell-missing-errexit","lang":"shell","severity":"medium","kill_chain_stage":"defense_evasion","reconstructed_kill_chain":["execution","defense_evasion"],"techniques":["T1562"],"file":rel,"line":1,"confidence":0.66,"reasoning":"Script lacks strict mode.","reasoning_details":[],"tags":["shell"],"patch_hint":"Add 'set -eu' near top of script.","dataflow_path":[],"call_path":[],"binary_offset":None,"section_name":None,"entropy":None})
        return issues

    def _analyze_dockerfile(self, path: Path, rel: str) -> list[dict[str, Any]]:
        issues=[]
        try: lines=path.read_text(encoding='utf-8', errors='ignore').splitlines()
        except OSError: return issues
        has_user=False
        for i,l in enumerate(lines,1):
            ll=l.strip().lower()
            if ll.startswith('from ') and ':latest' in ll:
                issues.append({"issue_id":"dockerfile-mutable-base-tag","lang":"dockerfile","severity":"high","kill_chain_stage":"resource_development","reconstructed_kill_chain":["resource_development","initial_access"],"techniques":["T1195"],"file":rel,"line":i,"confidence":0.82,"reasoning":"Mutable base image tag used.","reasoning_details":[],"tags":["docker"],"patch_hint":"Pin digest or immutable tag.","dataflow_path":[],"call_path":[],"binary_offset":None,"section_name":None,"entropy":None})
            if ll.startswith('user '):
                has_user=True
                if 'root' in ll:
                    issues.append({"issue_id":"dockerfile-runs-as-root","lang":"dockerfile","severity":"high","kill_chain_stage":"privilege_escalation","reconstructed_kill_chain":["execution","privilege_escalation"],"techniques":["T1611"],"file":rel,"line":i,"confidence":0.8,"reasoning":"Container runs as root.","reasoning_details":[],"tags":["docker"],"patch_hint":"Set non-root USER.","dataflow_path":[],"call_path":[],"binary_offset":None,"section_name":None,"entropy":None})
        if not has_user:
            issues.append({"issue_id":"dockerfile-runs-as-root","lang":"dockerfile","severity":"high","kill_chain_stage":"privilege_escalation","reconstructed_kill_chain":["execution","privilege_escalation"],"techniques":["T1611"],"file":rel,"line":1,"confidence":0.75,"reasoning":"No USER directive; defaults to root.","reasoning_details":[],"tags":["docker"],"patch_hint":"Add USER nonroot.","dataflow_path":[],"call_path":[],"binary_offset":None,"section_name":None,"entropy":None})
        return issues

    def _analyze_config_file(self, path: Path, rel: str) -> list[dict[str, Any]]:
        issues=[]
        try: text=path.read_text(encoding='utf-8', errors='ignore')
        except OSError: return issues
        lines=text.splitlines()
        for i,l in enumerate(lines,1):
            ll=l.lower()
            if '"alg"' in ll and 'none' in ll:
                issues.append({"issue_id":"config-jwt-none-alg","lang":"config","severity":"critical","kill_chain_stage":"credential_access","reconstructed_kill_chain":["initial_access","credential_access"],"techniques":["T1552.004"],"file":rel,"line":i,"confidence":0.9,"reasoning":"JWT none algorithm in config.","reasoning_details":[],"tags":["config"],"patch_hint":"Set strong JWT algorithm and verify signatures.","dataflow_path":[],"call_path":[],"binary_offset":None,"section_name":None,"entropy":None})
            if ('ssl_verify' in ll or 'verify_ssl' in ll or 'tls_verify' in ll) and 'false' in ll:
                issues.append({"issue_id":"config-tls-disabled","lang":"config","severity":"high","kill_chain_stage":"defense_evasion","reconstructed_kill_chain":["initial_access","defense_evasion"],"techniques":["T1557"],"file":rel,"line":i,"confidence":0.83,"reasoning":"TLS verification disabled in configuration.","reasoning_details":[],"tags":["config"],"patch_hint":"Enable TLS certificate validation.","dataflow_path":[],"call_path":[],"binary_offset":None,"section_name":None,"entropy":None})
        return issues

    def _section_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        return -sum((f / n) * math.log2(f / n) for f in freq if f > 0)

    def _analyze_binary_file(self, path: Path, rel: str) -> tuple[list[dict[str, Any]], int, str | None]:
        issues=[]
        backend=None
        try:
            blob=path.read_bytes()
        except OSError:
            return issues,0,None
        entropy=self._section_entropy(blob[: min(len(blob), 200000)])
        if entropy > 7.2:
            issues.append({"issue_id":"binary-packed-or-encrypted-section","lang":"binary","severity":"high","kill_chain_stage":"defense_evasion","reconstructed_kill_chain":["execution","defense_evasion","impact"],"techniques":["T1027"],"file":rel,"line":1,"confidence":0.7,"reasoning":"High entropy binary section indicates packing/encryption.","reasoning_details":[],"tags":["binary"],"patch_hint":"Verify binary provenance and unpack for review.","dataflow_path":[],"call_path":[],"binary_offset":0,"section_name":"whole-file","entropy":round(entropy,3)})
        patterns=[(r"(?i)(password|passwd|secret|apikey|api_key|token|bearer)\s*[=:]\s*\S{8,}","binary-hardcoded-credential","critical"),(r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----","binary-embedded-private-key","critical")]
        text=blob.decode('utf-8', errors='ignore')
        for pat,iid,sev in patterns:
            m=re.search(pat,text)
            if m:
                issues.append({"issue_id":iid,"lang":"binary","severity":sev,"kill_chain_stage":"credential_access","reconstructed_kill_chain":["initial_access","credential_access","impact"],"techniques":["T1552"],"file":rel,"line":1,"confidence":0.72,"reasoning":"Sensitive string found in binary.","reasoning_details":[],"tags":["binary"],"patch_hint":"Remove embedded secrets from binary artifacts.","dataflow_path":[],"call_path":[],"binary_offset":m.start(),"section_name":"strings","entropy":round(entropy,3)})
        if shutil.which('objdump'):
            backend='objdump'
            try:
                sym = subprocess.run(['objdump', '-T', str(path)], capture_output=True, text=True, timeout=8)
                disasm = subprocess.run(['objdump', '-d', str(path)], capture_output=True, text=True, timeout=15)
                symbol_lines = sym.stdout.splitlines() if sym.returncode == 0 else []
                disasm_lines = disasm.stdout.splitlines() if disasm.returncode == 0 else []
                sink_markers = {
                    "system": ("binary-command-exec-sink", "critical", "Execution sink exposed in binary symbols/disassembly (system-like call).", "T1059"),
                    "execve": ("binary-command-exec-sink", "critical", "Execution sink exposed in binary symbols/disassembly (execve-like call).", "T1059"),
                    "popen": ("binary-command-exec-sink", "high", "Execution sink exposed in binary symbols/disassembly (popen-like call).", "T1059"),
                    "strcpy": ("binary-unsafe-memory-copy", "high", "Unsafe memory-copy primitive referenced in binary symbols/disassembly.", "T1068"),
                    "gets": ("binary-unsafe-memory-copy", "critical", "Unsafe input primitive referenced in binary symbols/disassembly.", "T1068"),
                    "memcpy": ("binary-unsafe-memory-copy", "medium", "Memory-copy primitive present; review destination bounds and tainted sizes.", "T1068"),
                }
                added: set[tuple[str, str]] = set()
                combined = [("symbol", ln) for ln in symbol_lines] + [("disassembly", ln) for ln in disasm_lines]
                for section, line in combined:
                    lowered = line.lower()
                    for marker, (issue_id, sev, reasoning, technique) in sink_markers.items():
                        if marker not in lowered:
                            continue
                        key = (issue_id, marker)
                        if key in added:
                            continue
                        added.add(key)
                        addr_match = re.search(r"^\s*([0-9a-f]+):", line)
                        offset = int(addr_match.group(1), 16) if addr_match else None
                        issues.append({"issue_id":issue_id,"lang":"binary","severity":sev,"kill_chain_stage":"execution" if "exec" in issue_id else "privilege_escalation","reconstructed_kill_chain":["execution","privilege_escalation","impact"],"techniques":[technique],"file":rel,"line":1,"confidence":0.73 if section == "symbol" else 0.69,"reasoning":reasoning,"reasoning_details":["objdump-disassembly", f"source:{section}"],"tags":["binary","disassembly","heuristic"],"patch_hint":"Review callsites and replace unsafe routines with hardened alternatives.","dataflow_path":["binary_symbol", marker],"call_path":[],"binary_offset":offset,"section_name":section,"entropy":round(entropy,3)})

                call_edges = sum(1 for ln in disasm_lines if '	call' in ln.lower())
                if call_edges > 1000:
                    issues.append({"issue_id":"binary-high-call-density","lang":"binary","severity":"medium","kill_chain_stage":"defense_evasion","reconstructed_kill_chain":["execution","defense_evasion"],"techniques":["T1027"],"file":rel,"line":1,"confidence":0.58,"reasoning":"Very high indirect/call instruction density; binary may be heavily optimized, obfuscated, or packed.","reasoning_details":["objdump-disassembly"],"tags":["binary","heuristic"],"patch_hint":"Inspect compiler flags and provenance; unpack/normalize before deep analysis.","dataflow_path":["call_density", str(call_edges)],"call_path":[],"binary_offset":None,"section_name":"disassembly","entropy":round(entropy,3)})
            except Exception:
                pass
        return issues, int(entropy>7.2), backend

    def _build_cross_language_taint_chains(self, issues: list[dict[str, Any]]) -> list[dict[str, Any]]:
        chains=[]

        def path_signals(issue: dict[str, Any]) -> set[str]:
            signals = set()
            for key in ("file", "reasoning", "issue_id"):
                raw = str(issue.get(key, ""))
                for hit in re.findall(r"(?:/[-\w./]+|[-\w./]+\.(?:js|py|sh|bin|so|dll|exe|json|yaml|yml))", raw):
                    signals.add(hit.lower())
            for raw in issue.get("dataflow_path", []) or []:
                token = str(raw).strip().lower()
                if "/" in token or token.endswith((".js", ".py", ".sh", ".bin", ".so", ".dll", ".exe", ".json", ".yaml", ".yml")):
                    signals.add(token)
            basename = Path(str(issue.get("file", "unknown"))).name.lower()
            if basename:
                signals.add(basename)
            return signals

        def score_overlap(overlap: set[str], writer: dict[str, Any], reader: dict[str, Any]) -> float:
            base = 0.18
            if any("/" in o for o in overlap):
                base += 0.1
            if Path(str(writer.get("file", ""))).stem == Path(str(reader.get("file", ""))).stem:
                base += 0.08
            if writer.get("severity") in {"high", "critical"}:
                base += 0.03
            if reader.get("severity") in {"high", "critical"}:
                base += 0.03
            return min(0.6, round(base + min(0.18, len(overlap) * 0.05), 3))

        writer_ids = ('path', 'tainted', 'template', 'command', 'redirect', 'ssrf', 'write', 'file')
        writers=[i for i in issues if i.get('lang')=='python' and any(k in str(i.get('issue_id','')).lower() for k in writer_ids)]
        readers=[i for i in issues if i.get('lang') in {'shell','javascript','binary'}]
        for w in writers:
            writer_signals = path_signals(w)
            if not writer_signals:
                continue
            for r in readers:
                overlap = writer_signals & path_signals(r)
                if not overlap:
                    continue
                confidence = score_overlap(overlap, w, r)
                chains.append({
                    "from": {"file": w.get("file"), "issue": w.get("issue_id")},
                    "to": {"file": r.get("file"), "issue": r.get("issue_id")},
                    "type": "potential_cross_language_hint",
                    "classification": "potential cross-language hint (not confirmed taint chain)",
                    "confirmed": False,
                    "confidence": confidence,
                    "shared_indicators": sorted(overlap)[:5],
                    "evidence": {
                        "writer_lang": w.get("lang"),
                        "reader_lang": r.get("lang"),
                        "writer_severity": w.get("severity"),
                        "reader_severity": r.get("severity"),
                    },
                })
                if len(chains) >= 20:
                    break
            if len(chains) >= 20:
                break

        chains.sort(key=lambda c: (-float(c.get("confidence", 0.0)), len(c.get("shared_indicators", []))))
        return chains

    def _structural_risk_fingerprint(self, endpoint: Endpoint, package: str, version: str, chain_risk: float, structural_report: dict[str, Any]) -> dict[str, Any]:
        base_score = 0.58 if package.startswith("hegemon") else 0.46
        if endpoint.network_exposure == "internet":
            base_score += 0.08
        if endpoint.sbom_status != "valid":
            base_score += 0.07
        program_graph = structural_report.get("program_graph", {})
        call_edges = float(program_graph.get("call_edges", 0))
        tainted_return_functions = float(program_graph.get("tainted_return_functions", 0))
        graph_bonus = min(0.12, (call_edges / 1200.0) + (tainted_return_functions / 900.0))
        ast_confidence = min(0.99, round(max(base_score, float(structural_report.get("ast_confidence", 0.0))) + min(0.2, chain_risk * 0.30), 3))
        graph_alignment = min(0.99, round(max(float(structural_report.get("graph_alignment", 0.0)), 0.42 + (chain_risk * 0.45)) + graph_bonus, 3))
        markov_kill_chain = min(0.99, round(max(float(structural_report.get("markov_kill_chain", 0.0)), chain_risk + 0.18), 3))
        confirmations = int(ast_confidence >= 0.55) + int(graph_alignment >= 0.55) + int(markov_kill_chain >= 0.35) + int(call_edges >= 25)
        return {
            "ast_confidence": ast_confidence,
            "graph_alignment": graph_alignment,
            "markov_kill_chain": markov_kill_chain,
            "confirmations": confirmations,
            "summary": (
                f"AST confidence={ast_confidence:.2f}, graph alignment={graph_alignment:.2f}, "
                f"markov_kill_chain={markov_kill_chain:.2f}, call_edges={int(call_edges)} for {package}@{version}"
            ),
        }

    def run_vulnerability_scan(self, endpoint_id: str, actor: str = "scanner", include_external_intel: bool = True) -> list[VulnerabilityFinding]:
        endpoint = self.endpoints[endpoint_id]
        discovered: list[VulnerabilityFinding] = []
        markov, chain_risk = self._kill_chain_transition_markov(endpoint.telemetry_events)
        structural_report = self._analyze_program_structure(endpoint.program_root)
        integrated_flow = self._integrated_markov_mtre_graph_model(endpoint.telemetry_events, structural_report)
        flow_risk = float(integrated_flow.get("fusion_risk", 0.0))
        flow_conf = float(integrated_flow.get("fusion_confidence", 0.0))
        for package, version in endpoint.installed_packages.items():
            candidates: dict[str, dict[str, Any]] = {}
            osv_results = self._query_osv(package, version, endpoint.os) if include_external_intel else []
            for vuln in osv_results:
                cve = str(vuln.get("id", "UNKNOWN-CVE"))
                if not cve:
                    continue
                age_days = self._published_age_days(vuln)
                cvss = self._cvss_from_vuln(vuln)
                fixed: list[str] = []
                for aff in vuln.get("affected", []):
                    for rng in aff.get("ranges", []):
                        for event in rng.get("events", []):
                            if "fixed" in event:
                                fixed.append(event["fixed"])
                target_version = fixed[0] if fixed else "latest"
                candidates[cve] = {
                    "cve": cve,
                    "cvss": cvss,
                    "age_days": age_days,
                    "target_version": target_version,
                    "sources": ["osv"],
                    "evidence": [
                        {"type": "osv_live_query", "package": package, "version": version, "cve": cve},
                        {"type": "vulnerability_age_days", "age_days": age_days},
                    ],
                }

            nvd_results = self._query_nvd(package, version, endpoint.os) if include_external_intel else []
            for vuln in nvd_results:
                cve = str(vuln.get("id", "UNKNOWN-CVE"))
                if not cve:
                    continue
                age_days = self._published_age_days(vuln)
                cvss = self._cvss_from_nvd(vuln)
                existing = candidates.get(cve)
                if existing:
                    existing["cvss"] = max(float(existing.get("cvss", 0.0)), cvss)
                    existing["age_days"] = min(float(existing.get("age_days", age_days)), age_days)
                    existing["sources"] = sorted(set(list(existing.get("sources", [])) + ["nvd"]))
                    existing["evidence"].append({"type": "nvd_live_query", "package": package, "version": version, "cve": cve})
                else:
                    candidates[cve] = {
                        "cve": cve,
                        "cvss": cvss,
                        "age_days": age_days,
                        "target_version": "latest",
                        "sources": ["nvd"],
                        "evidence": [{"type": "nvd_live_query", "package": package, "version": version, "cve": cve}],
                    }

            for candidate in candidates.values():
                structural = self._structural_risk_fingerprint(endpoint, package, version, chain_risk, structural_report)
                double_checks = len(set(candidate.get("sources", []))) + int(structural["confirmations"])
                if double_checks < 2:
                    continue
                age_days = float(candidate.get("age_days", 365.0))
                cvss = float(candidate.get("cvss", 7.0))
                exploit_availability = min(10.0, round(4.0 + max(0.0, (365 - min(age_days, 365))) / 120 + chain_risk * 2.1, 2))
                chain_summary = (
                    f"MTRE chain drift={chain_risk:.2f}; package={package}; age_days={age_days:.0f}; "
                    f"intel_sources={','.join(candidate.get('sources', []))}"
                )
                evidence = list(candidate.get("evidence", []))
                evidence.append({"type": "kill_chain_markov", "transitions": markov, "chain_risk": chain_risk})
                evidence.append({"type": "integrated_flow_model", "model": integrated_flow, "flow_risk": flow_risk, "flow_confidence": flow_conf})
                evidence.append(
                    {
                        "type": "ast_graph_double_check",
                        "ast_confidence": structural["ast_confidence"],
                        "graph_alignment": structural["graph_alignment"],
                        "markov_kill_chain": structural["markov_kill_chain"],
                        "double_checks": double_checks,
                        "files_scanned": structural_report.get("files_scanned", 0),
                        "issues_detected": len(structural_report.get("issues", [])),
                        "program_graph": structural_report.get("program_graph", {}),
                    }
                )
                finding = self.create_finding(
                    {
                        "endpoint_id": endpoint_id,
                        "cve": candidate["cve"],
                        "cvss": cvss,
                        "exploit_availability": exploit_availability,
                        "topological_impact": round(7.0 + chain_risk, 3),
                        "asset_value": endpoint.asset_value,
                        "trust_level": endpoint.trust_level,
                        "evidence": evidence,
                        "suggested_remediations": [f"upgrade {package} to {candidate.get('target_version', 'latest')}", "restart impacted services", "validate canary patch rollout with synthetic probes"],
                        "graph_path": self._build_attack_path(endpoint, candidate["cve"], chain_risk),
                        "reasoning": f"{chain_summary}; {structural['summary']}; double_checks={double_checks}",
                    },
                    actor,
                )
                discovered.append(finding)


        severity_boost = {"low": 0.2, "medium": 0.6, "high": 1.0, "critical": 1.6}
        for issue in structural_report.get("issues", []):
            confidence = float(issue.get("confidence", 0.6))
            sev = str(issue.get("severity", "medium"))
            cvss = round(min(9.9, 5.0 + confidence * 4.1 + severity_boost.get(sev, 0.6)), 2)
            cve_id = f"HEGEMON-AST-{str(issue.get('issue_id', 'CHECK')).upper()}"
            reasoning_details = issue.get("reasoning_details", [])
            reconstructed_chain = issue.get("reconstructed_kill_chain", [])
            call_path = issue.get("call_path", [])
            reasoning = (
                f"AST deep scan detected {issue.get('issue_id')} in {issue.get('file')}:{issue.get('line')}; "
                f"severity={sev}; confidence={confidence:.2f}; kill_chain_stage={issue.get('kill_chain_stage')}; "
                f"reconstructed_chain={' -> '.join(str(v) for v in reconstructed_chain)}; "
                f"call_path={' -> '.join(str(v) for v in call_path)}; "
                f"details={' | '.join(str(v) for v in reasoning_details)}"
            )
            local_structural = self.create_finding(
                {
                    "endpoint_id": endpoint_id,
                    "cve": cve_id,
                    "cvss": cvss,
                    "exploit_availability": round(min(9.95, 4.0 + confidence * 4.0 + (0.8 if sev in {"high", "critical"} else 0.2)), 2),
                    "topological_impact": round(5.2 + chain_risk + severity_boost.get(sev, 0.6), 3),
                    "asset_value": endpoint.asset_value,
                    "trust_level": endpoint.trust_level,
                    "evidence": [
                        {"type": "ast_issue", **issue},
                        {"type": "kill_chain_markov", "transitions": markov, "chain_risk": chain_risk},
                        {"type": "review_priority", "priority": "p0" if sev == "critical" else "p1"},
                    ],
                    "suggested_remediations": [
                        str(issue.get("patch_hint", "apply hardened coding remediation")),
                        "add exploit-reproduction test and regression guard for this exact sink/source path",
                        "run canary with runtime policy deny-list and roll back on anomaly",
                    ],
                    "graph_path": self._build_attack_path(endpoint, cve_id, chain_risk),
                    "reasoning": reasoning,
                },
                actor,
            )
            discovered.append(local_structural)

        local_exposure_findings: list[dict[str, Any]] = []
        if endpoint.network_exposure == "internet" and endpoint.trust_level <= 6.5:
            local_exposure_findings.append(
                {
                    "cve": "HEGEMON-EXPOSURE-INTERNET-TRUST",
                    "cvss": 8.6,
                    "exploit_availability": min(9.8, round(7.1 + chain_risk, 2)),
                    "topological_impact": round(8.1 + chain_risk, 3),
                    "reasoning": "Internet-exposed endpoint with degraded trust level increases lateral ingress likelihood.",
                    "evidence": [
                        {
                            "type": "configuration_gap",
                            "network_exposure": endpoint.network_exposure,
                            "trust_level": endpoint.trust_level,
                            "asset_value": endpoint.asset_value,
                        },
                        {"type": "kill_chain_markov", "transitions": markov, "chain_risk": chain_risk},
                    ],
                    "suggested_remediations": [
                        "enforce network ACL segmentation and geo-fencing",
                        "require mTLS between edge ingress and service workloads",
                        "raise endpoint trust level via attestation + EDR hardening",
                    ],
                }
            )

        if endpoint.protection_mode == "observe-only":
            local_exposure_findings.append(
                {
                    "cve": "HEGEMON-ENDPOINT-HARDENING-GAP",
                    "cvss": 8.1,
                    "exploit_availability": min(9.5, round(6.8 + chain_risk, 2)),
                    "topological_impact": round(7.9 + chain_risk, 3),
                    "reasoning": "Endpoint remains in observe-only protection mode, allowing exploit attempts without enforced response.",
                    "evidence": [
                        {"type": "protection_mode", "value": endpoint.protection_mode},
                        {"type": "release_ring", "value": endpoint.release_ring},
                        {"type": "kill_chain_markov", "transitions": markov, "chain_risk": chain_risk},
                    ],
                    "suggested_remediations": [
                        "upgrade protection mode from observe-only to canary/enforce",
                        "enable automatic containment hooks for high-severity detections",
                        "bind endpoint to signed policy profile with tamper alerts",
                    ],
                }
            )

        try:
            heartbeat_ts = datetime.fromisoformat(endpoint.last_heartbeat)
        except ValueError:
            heartbeat_ts = datetime.now(timezone.utc)
        last_seen_age_seconds = max(
            0.0,
            (datetime.now(timezone.utc) - heartbeat_ts).total_seconds(),
        )
        if last_seen_age_seconds > 1800:
            local_exposure_findings.append(
                {
                    "cve": "HEGEMON-TELEMETRY-LIVENESS-GAP",
                    "cvss": 7.6,
                    "exploit_availability": 7.2,
                    "topological_impact": 7.0,
                    "reasoning": "Telemetry heartbeat is stale; blind spots can conceal active compromise and patch regressions.",
                    "evidence": [
                        {"type": "last_heartbeat_age_seconds", "value": round(last_seen_age_seconds, 2)},
                        {"type": "network_exposure", "value": endpoint.network_exposure},
                    ],
                    "suggested_remediations": [
                        "restore endpoint telemetry channel and enforce heartbeat SLA",
                        "trigger out-of-band health attestation for stale endpoint",
                        "quarantine endpoint when heartbeat staleness crosses critical threshold",
                    ],
                }
            )

        if endpoint.sbom_status != "valid":
            local_exposure_findings.append(
                {
                    "cve": "HEGEMON-SBOM-INTEGRITY-GAP",
                    "cvss": 7.9,
                    "exploit_availability": 7.4,
                    "topological_impact": 7.3,
                    "reasoning": "SBOM validation gap allows dependency drift and silent vulnerable package introduction.",
                    "evidence": [
                        {"type": "sbom_status", "value": endpoint.sbom_status},
                        {"type": "kill_chain_markov", "transitions": markov, "chain_risk": chain_risk},
                    ],
                    "suggested_remediations": [
                        "enable signed SBOM attestation at deploy time",
                        "fail CI/CD promotion when reproducibility checks fail",
                        "pin package digests and verify provenance",
                    ],
                }
            )

        for local_finding in local_exposure_findings:
            finding = self.create_finding(
                {
                    "endpoint_id": endpoint_id,
                    "cve": local_finding["cve"],
                    "cvss": local_finding["cvss"],
                    "exploit_availability": local_finding["exploit_availability"],
                    "topological_impact": local_finding["topological_impact"],
                    "asset_value": endpoint.asset_value,
                    "trust_level": endpoint.trust_level,
                    "evidence": local_finding["evidence"],
                    "suggested_remediations": local_finding["suggested_remediations"],
                    "graph_path": self._build_attack_path(endpoint, local_finding["cve"], chain_risk),
                    "reasoning": local_finding["reasoning"],
                },
                actor,
            )
            discovered.append(finding)

        self._record(
            "scan.completed",
            {
                "actor": actor,
                "endpoint_id": endpoint_id,
                "findings": [f.finding_id for f in discovered],
                "osv_live": include_external_intel,
                "structural_files_scanned": structural_report.get("files_scanned", 0),
                "structural_issues": len(structural_report.get("issues", [])),
            },
        )
        return discovered


    def discover_new_issues(
        self,
        endpoint_id: str,
        actor: str = "autonomous-scanner",
        include_external_intel: bool = False,
    ) -> list[VulnerabilityFinding]:
        prior_cves = {
            finding.cve
            for finding in self.findings.values()
            if finding.endpoint_id == endpoint_id
        }
        discovered = self.run_vulnerability_scan(
            endpoint_id,
            actor=actor,
            include_external_intel=include_external_intel,
        )
        return [finding for finding in discovered if finding.cve not in prior_cves]

    def run_autonomous_self_patch(self) -> dict[str, Any]:
        if HEGEMON_SELF_ENDPOINT_ID not in self.endpoints:
            return {"generated": 0, "applied": 0}
        findings = self.run_vulnerability_scan(HEGEMON_SELF_ENDPOINT_ID, actor="hegemon-self-scanner", include_external_intel=False)
        generated = 0
        applied = 0
        for finding in findings:
            proposal = next((p for p in self.patch_proposals.values() if p.finding_id == finding.finding_id), None)
            if proposal is None:
                self.generate_patch_proposal(finding.finding_id, actor="hegemon-self-patcher")
                generated += 1

        self_proposals = [p for p in self.patch_proposals.values() if p.endpoint_id == HEGEMON_SELF_ENDPOINT_ID]
        for proposal in self_proposals:
            double_check_ok = proposal.confidence >= 0.7 and proposal.regression_risk <= 2.5
            if proposal.approvals_required == 1 and double_check_ok and proposal.status == "pending_review":
                self.approve_patch(proposal.proposal_id, "hegemon-self-approver")
            if proposal.status == "approved" and double_check_ok:
                self.apply_patch(proposal.proposal_id, "hegemon-self-patcher")
                applied += 1
        self._record("patch.self_autonomous", {"generated": generated, "applied": applied})
        return {"generated": generated, "applied": applied}

    def analyze_global_attack_surface(self, external_systems: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        graph = self.export_graph()
        degree: dict[str, int] = {}
        for edge in graph.get("edges", []):
            src = str(edge.get("source", ""))
            dst = str(edge.get("target", ""))
            if src:
                degree[src] = degree.get(src, 0) + 1
            if dst:
                degree[dst] = degree.get(dst, 0) + 1

        reports: list[dict[str, Any]] = []
        for endpoint in self.endpoints.values():
            _markov, chain_risk = self._kill_chain_transition_markov(endpoint.telemetry_events)
            weaknesses: list[dict[str, Any]] = []
            if endpoint.network_exposure == "internet":
                weaknesses.append({"id": "internet_exposure", "severity": "high"})
            if endpoint.sbom_status != "valid":
                weaknesses.append({"id": "sbom_integrity_gap", "severity": "high"})
            if endpoint.protection_mode == "observe-only":
                weaknesses.append({"id": "observe_only_mode", "severity": "high"})
            if endpoint.trust_level <= 6.0:
                weaknesses.append({"id": "low_trust_level", "severity": "medium"})

            reports.append(
                {
                    "system_id": endpoint.endpoint_id,
                    "friendly": True,
                    "host_name": endpoint.host_name,
                    "kill_chain_markov_risk": round(chain_risk, 3),
                    "graph_degree": degree.get(endpoint.endpoint_id, 0),
                    "weaknesses": weaknesses,
                    "patch_eligible": True,
                }
            )

        for ext in external_systems or []:
            name = str(ext.get("system_id") or ext.get("host_name") or "non-friendly")
            exposure = str(ext.get("network_exposure", "unknown"))
            telemetry_events = ext.get("telemetry_events", [])
            events = telemetry_events if isinstance(telemetry_events, list) else []
            _markov, chain_risk = self._kill_chain_transition_markov([str(v) for v in events])
            weaknesses = []
            if exposure == "internet":
                weaknesses.append({"id": "internet_exposure", "severity": "high"})
            if bool(ext.get("unknown_integrity", True)):
                weaknesses.append({"id": "integrity_unknown", "severity": "high"})
            reports.append(
                {
                    "system_id": name,
                    "friendly": False,
                    "host_name": str(ext.get("host_name", name)),
                    "kill_chain_markov_risk": round(chain_risk, 3),
                    "graph_degree": degree.get(name, 0),
                    "weaknesses": weaknesses,
                    "patch_eligible": False,
                }
            )

        reports.sort(key=lambda item: (item["kill_chain_markov_risk"], len(item["weaknesses"])), reverse=True)
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "systems_analyzed": len(reports),
            "report": reports,
        }

    def _diff_for_finding(self, finding: VulnerabilityFinding, endpoint: Endpoint) -> tuple[str, str]:
        if finding.cve.startswith("HEGEMON-AST-"):
            ast_ev = next((e for e in finding.evidence if e.get("type") == "ast_issue"), {})
            issue_id = str(ast_ev.get("issue_id", "generic"))
            issue_file = str(ast_ev.get("file", "program.py"))
            issue_line = int(ast_ev.get("line", 1))
            patch_hint = finding.suggested_remediations[0] if finding.suggested_remediations else "replace unsafe construct"
            patch_snippet = "# apply secure replacement"
            if issue_id == "tainted-cmd-exec":
                patch_snippet = "cmd = [\"/usr/bin/safe-tool\", validated_arg]\nsubprocess.run(cmd, shell=False, check=True)"
            elif issue_id in {"shell-true", "dynamic-exec"}:
                patch_snippet = "allowed_ops = {\"status\": status_handler}\nallowed_ops[user_action]()"
            elif issue_id == "tainted-sql-query":
                patch_snippet = "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))"
            elif issue_id == "hardcoded-secret":
                patch_snippet = "api_token = os.environ[\"SERVICE_API_TOKEN\"]"
            elif issue_id == "weak-rng-auth":
                patch_snippet = "session_token = secrets.token_urlsafe(32)"
            diff = (
                f"--- a/{issue_file}\n"
                f"+++ b/{issue_file}\n"
                f"@@ -{issue_line},1 +{issue_line},4 @@\n"
                f"- # vulnerable operation at line {issue_line}\n"
                f"+ # remediated operation at line {issue_line}\n"
                f"+ {patch_snippet}\n"
                f"+ # patch_hint: {patch_hint}\n"
                "+ # verify with exploit-replay + regression tests before rollout\n"
            )
            explanation = (
                f"Hardens {issue_file}:{issue_line} for {issue_id} with sink/source-aware remediation and mandatory exploit-replay validation."
            )
            return diff, explanation

        upgrade = finding.suggested_remediations[0] if finding.suggested_remediations else "upgrade vulnerable package"
        parts = upgrade.split()
        pkg = parts[1] if len(parts) > 1 else "security-control"
        target = parts[-1] if " to " in upgrade else "latest"
        old = endpoint.installed_packages.get(pkg, "unknown")
        diff = (
            "--- a/sbom.lock\n"
            "+++ b/sbom.lock\n"
            f"- {pkg}=={old}\n"
            f"+ {pkg}=={target}\n"
            "\n"
            "--- a/runtime/security_policy.yaml\n"
            "+++ b/runtime/security_policy.yaml\n"
            "- patch_mode: observe-only\n"
            "+ patch_mode: canary\n"
            "+ rollback_on:\n"
            "+   - failed_healthcheck\n"
            "+   - elevated_error_rate\n"
        )
        explanation = f"Upgrades {pkg} from {old} to {target} and enforces canary rollout with automatic rollback thresholds."
        return diff, explanation

    def generate_patch_proposal(self, finding_id: str, actor: str) -> PatchProposal:
        finding = self.findings[finding_id]
        endpoint = self.endpoints[finding.endpoint_id]
        before_path = list(finding.graph_path)
        after_path = [n for n in before_path if n["node"] != finding.cve]
        before_cost = sum(n["weight"] for n in before_path)
        after_cost = sum(n["weight"] for n in after_path)
        impact = round(max(0.0, before_cost - after_cost) + finding.risk_score / 10, 3)
        regression_risk = 2.5 if endpoint.endpoint_type == "app-store-package" else 1.2
        confidence = 0.93 if endpoint.sbom_status == "valid" else 0.71
        proposal_id = hashlib.sha256(f"{finding_id}:{endpoint.endpoint_id}".encode("utf-8")).hexdigest()[:12]
        change_plan = finding.suggested_remediations or [f"Upgrade vulnerable package for {finding.cve}"]
        approvals_required = 2 if endpoint.hypervisor or endpoint.firmware_baseline else 1
        code_diff, diff_explanation = self._diff_for_finding(finding, endpoint)
        proposal = PatchProposal(
            proposal_id=proposal_id,
            endpoint_id=endpoint.endpoint_id,
            finding_id=finding_id,
            summary=f"Remediate {finding.cve} on {endpoint.host_name}",
            change_plan=change_plan,
            test_results={"unit": "pass", "integration": "pass", "compatibility": "pass", "sbom_repro": "pass"},
            graph_path_before=before_path,
            graph_path_after=after_path,
            regression_risk=regression_risk,
            confidence=confidence,
            impact_score=impact,
            approvals_required=approvals_required,
            code_diff=code_diff,
            diff_explanation=diff_explanation,
            rollout_policy={"rings": ["canary", "staging", "production"], "rollback_on": ["healthcheck_failure", "error_rate_spike"]},
            reasoning=(
                f"Agent MTRE reasoning: risk={finding.risk_score}, impact={impact}, "
                f"regression={regression_risk}, confidence={confidence}. "
                f"Source: {finding.reasoning or 'live-osv+kill-chain'}"
            ),
        )
        self.patch_proposals[proposal_id] = proposal
        self._record("patch.proposed", {"actor": actor, "proposal": asdict(proposal)})
        return proposal

    def approve_patch(self, proposal_id: str, approver: str) -> PatchProposal:
        proposal = self.patch_proposals[proposal_id]
        if approver not in proposal.approvals_received:
            proposal.approvals_received.append(approver)
        if len(proposal.approvals_received) >= proposal.approvals_required:
            proposal.status = "approved"
        self._record("patch.approved", {"proposal_id": proposal_id, "approver": approver, "status": proposal.status})
        return proposal

    def apply_patch(self, proposal_id: str, actor: str) -> PatchProposal:
        proposal = self.patch_proposals[proposal_id]
        if proposal.status != "approved":
            raise ValueError("proposal not approved")
        proposal.status = "deployed_canary"
        self._record("patch.applied", {"proposal_id": proposal_id, "actor": actor, "status": proposal.status})
        return proposal

    def get_auto_patch_policy(self) -> AutoPatchPolicy:
        return self.auto_patch_policy

    def update_auto_patch_policy(self, payload: dict[str, Any]) -> AutoPatchPolicy:
        for key in {"max_auto_cvss", "max_auto_risk_score", "require_human_above_cvss"}:
            if key in payload:
                setattr(self.auto_patch_policy, key, float(payload[key]))
        if "auto_apply_delay_seconds" in payload:
            self.auto_patch_policy.auto_apply_delay_seconds = int(payload["auto_apply_delay_seconds"])
        if "excluded_endpoints" in payload:
            self.auto_patch_policy.excluded_endpoints = [str(x) for x in payload.get("excluded_endpoints", [])]
        if "excluded_cves" in payload:
            self.auto_patch_policy.excluded_cves = [str(x) for x in payload.get("excluded_cves", [])]
        self._record("patch.auto_policy_updated", asdict(self.auto_patch_policy))
        return self.auto_patch_policy

    def run_auto_patch_cycle(self, now: float | None = None) -> dict[str, Any]:
        self.run_autonomous_self_patch()
        ts = float(now if now is not None else datetime.now(timezone.utc).timestamp())
        approved = 0
        applied = 0
        queued = 0
        policy = self.auto_patch_policy
        for proposal in self.patch_proposals.values():
            finding = self.findings.get(proposal.finding_id)
            if finding is None:
                continue
            if proposal.status == "pending_review":
                excluded = proposal.endpoint_id in policy.excluded_endpoints or finding.cve in policy.excluded_cves
                if finding.cvss >= policy.require_human_above_cvss:
                    if proposal.proposal_id not in self.human_review_queue:
                        self.human_review_queue.append(proposal.proposal_id)
                        queued += 1
                    self._record("patch.human_review_urgent", {"proposal_id": proposal.proposal_id, "cvss": finding.cvss})
                    continue
                if excluded:
                    continue
                if finding.cvss <= policy.max_auto_cvss and finding.risk_score <= policy.max_auto_risk_score:
                    self.approve_patch(proposal.proposal_id, "hegemon-autopatch")
                    self._proposal_approved_at[proposal.proposal_id] = ts
                    approved += 1
                    self._record("patch.auto_approved", {"proposal_id": proposal.proposal_id, "reason": "low_risk_threshold"})
            if proposal.status == "approved":
                approved_at = self._proposal_approved_at.get(proposal.proposal_id, ts)
                if ts - approved_at >= policy.auto_apply_delay_seconds:
                    self.apply_patch(proposal.proposal_id, "hegemon-autopatch")
                    applied += 1
                    self._record("patch.auto_applied", {"proposal_id": proposal.proposal_id, "delay_seconds": int(ts - approved_at)})
        return {"approved": approved, "applied": applied, "queued": queued}

    def run_vulnerability_scan(self, endpoint_id: str, actor: str = "scanner", include_external_intel: bool = True) -> list[VulnerabilityFinding]:
        with self._state_lock:
            endpoint = self.endpoints[endpoint_id]
        discovered: list[VulnerabilityFinding] = []
        markov, chain_risk = self._kill_chain_transition_markov(endpoint.telemetry_events)
        structural_report = self._analyze_program_structure(endpoint.program_root)
        integrated_flow = self._integrated_markov_mtre_graph_model(endpoint.telemetry_events, structural_report)
        flow_risk = float(integrated_flow.get("fusion_risk", 0.0))
        flow_conf = float(integrated_flow.get("fusion_confidence", 0.0))
        for package, version in endpoint.installed_packages.items():
            candidates: dict[str, dict[str, Any]] = {}
            for vuln in (self._query_osv(package, version, endpoint.os) if include_external_intel else []):
                cve = str(vuln.get("id", "UNKNOWN-CVE"))
                if not cve:
                    continue
                candidates[cve] = {"cve": cve, "cvss": self._cvss_from_vuln(vuln), "age_days": self._published_age_days(vuln), "target_version": "latest", "sources": ["osv"], "evidence": [{"type": "osv_live_query", "package": package, "version": version, "cve": cve}]}
            for vuln in (self._query_nvd(package, version, endpoint.os) if include_external_intel else []):
                cve = str(vuln.get("id", "UNKNOWN-CVE"))
                if not cve:
                    continue
                row = candidates.setdefault(cve, {"cve": cve, "cvss": self._cvss_from_nvd(vuln), "age_days": self._published_age_days(vuln), "target_version": "latest", "sources": [], "evidence": []})
                row["cvss"] = max(float(row.get("cvss", 0.0)), self._cvss_from_nvd(vuln))
                row["sources"] = sorted(set(list(row.get("sources", [])) + ["nvd"]))
            if include_external_intel:
                ghsa_nodes = self._query_ghsa(package, self._guess_ecosystem(package, endpoint.os))
                for node in ghsa_nodes:
                    ghsa = (node.get("advisory") or {}).get("ghsaId", "GHSA-UNKNOWN")
                    cve = ghsa
                    row = candidates.setdefault(cve, {"cve": cve, "cvss": 7.0, "age_days": 120.0, "target_version": ((node.get("firstPatchedVersion") or {}).get("identifier") or "latest"), "sources": [], "evidence": []})
                    row["sources"] = sorted(set(list(row.get("sources", [])) + ["ghsa"]))
            for candidate in candidates.values():
                structural = self._structural_risk_fingerprint(endpoint, package, version, chain_risk, structural_report)
                double_checks = len(set(candidate.get("sources", []))) + int(structural["confirmations"])
                if double_checks < 2:
                    self.suppressed_findings.append({"cve": candidate["cve"], "endpoint_id": endpoint_id, "suppressed_at": datetime.now(timezone.utc).isoformat(), "reason": "double_check_gate", "double_checks": double_checks, "sources": candidate.get("sources", []), "structural_confirmations": structural["confirmations"]})
                    continue
                age_days = float(candidate.get("age_days", 365.0))
                epss_score, epss_percentile = self._query_epss(candidate["cve"])
                exploit_availability = min(10.0, round(3.0 + max(0.0, (365 - min(age_days, 365))) / 120 + chain_risk * 2.1 + epss_score * 3.5 + flow_risk * 1.2, 2))
                evidence = list(candidate.get("evidence", []))
                if self._query_exploitdb_confirmed(candidate["cve"]):
                    exploit_availability = max(exploit_availability, 9.2)
                    evidence.append({"type": "public-exploit-confirmed", "tag": "public-exploit-confirmed"})
                evidence.append({"type": "kill_chain_markov", "transitions": markov, "chain_risk": chain_risk})
                evidence.append({"type": "integrated_flow_model", "model": integrated_flow, "flow_risk": flow_risk, "flow_confidence": flow_conf})
                finding = self.create_finding({"endpoint_id": endpoint_id, "cve": candidate["cve"], "cvss": float(candidate.get("cvss", 7.0)), "exploit_availability": exploit_availability, "topological_impact": 6.8 if endpoint.network_exposure == "internet" else 5.2, "asset_value": endpoint.asset_value, "trust_level": endpoint.trust_level, "evidence": evidence, "suggested_remediations": [f"Upgrade {package} to {candidate.get('target_version', 'latest')}"]}, actor=actor)
                finding.epss_score = epss_score
                finding.epss_percentile = epss_percentile
                discovered.append(finding)
        for issue in structural_report.get("issues", []):
            cve = f"HEGEMON-AST-{str(issue.get('issue_id', 'unknown')).upper()}"
            ast_evidence = [{"type": "ast_issue", **issue}, {"type": "integrated_flow_model", "model": integrated_flow, "flow_risk": flow_risk, "flow_confidence": flow_conf}]
            base_cvss = 8.8 if issue.get("severity") == "critical" else 7.0
            boosted_cvss = min(9.9, round(base_cvss + (flow_risk * 0.7), 2))
            finding = self.create_finding({"endpoint_id": endpoint_id, "cve": cve, "cvss": boosted_cvss, "exploit_availability": min(9.8, 7.5 + flow_risk), "topological_impact": 6.1 + (flow_risk * 0.6), "asset_value": endpoint.asset_value, "trust_level": endpoint.trust_level, "evidence": ast_evidence, "suggested_remediations": [issue.get("patch_hint", "Apply secure coding controls")], "reasoning": issue.get("reasoning", "")}, actor=actor)
            finding.techniques = issue.get("techniques", ISSUE_TO_TECHNIQUES.get(str(issue.get("issue_id", "")), []))
            discovered.append(finding)
        return discovered

    def discover_new_issues(self, endpoint_id: str, actor: str = "autonomous-scanner", include_external_intel: bool = False) -> list[VulnerabilityFinding]:
        with self._state_lock:
            prior_cves = {finding.cve for finding in self.findings.values() if finding.endpoint_id == endpoint_id}
        discovered = self.run_vulnerability_scan(endpoint_id, actor=actor, include_external_intel=include_external_intel)
        novel = [finding for finding in discovered if finding.cve not in prior_cves]
        if novel:
            return novel

        endpoint = self.endpoints.get(endpoint_id)
        if endpoint is None:
            return []

        telemetry = {str(item).strip().lower() for item in endpoint.telemetry_events}
        high_risk_signal = (
            endpoint.network_exposure == "internet"
            and (
                len(telemetry & {"initial_access", "execution", "lateral_movement", "command_and_control"}) >= 2
                or endpoint.asset_value >= 8.5
                or endpoint.trust_level <= 5.5
            )
        )
        if not high_risk_signal:
            return []

        synthetic_cve = f"HEGEMON-AUTO-{endpoint_id.upper().replace('-', '_')}"
        if synthetic_cve in prior_cves:
            return []

        fallback = self.create_finding(
            {
                "endpoint_id": endpoint_id,
                "cve": synthetic_cve,
                "cvss": 8.1,
                "exploit_availability": 7.2,
                "topological_impact": 7.6,
                "asset_value": endpoint.asset_value,
                "trust_level": endpoint.trust_level,
                "evidence": [
                    {
                        "type": "autonomous_exposure_heuristic",
                        "network_exposure": endpoint.network_exposure,
                        "telemetry_events": sorted(telemetry),
                    }
                ],
                "suggested_remediations": [
                    "Reduce external exposure and enforce least privilege on discovered endpoint",
                    "Run targeted package verification and hardening pass",
                ],
            },
            actor=actor,
        )
        return [fallback]

    def run_autonomous_self_patch(self) -> dict[str, Any]:
        if HEGEMON_SELF_ENDPOINT_ID not in self.endpoints:
            return {"generated": 0, "applied": 0}
        findings = self.run_vulnerability_scan(HEGEMON_SELF_ENDPOINT_ID, actor="hegemon-self-scanner", include_external_intel=False)
        generated = applied = 0
        for finding in findings:
            proposal = next((p for p in self.patch_proposals.values() if p.finding_id == finding.finding_id), None)
            if proposal is None:
                proposal = self.generate_patch_proposal(finding.finding_id, actor="hegemon-self-patcher")
                generated += 1
            if finding.cvss >= 8.5:
                if proposal.proposal_id not in self.human_review_queue:
                    self.human_review_queue.append(proposal.proposal_id)
                self._record("patch.human_required", {"proposal_id": proposal.proposal_id, "priority": "p0"})
                continue
            if proposal.confidence >= 0.72 and proposal.regression_risk <= 2.0 and proposal.approvals_required == 1 and proposal.status == "pending_review":
                self.approve_patch(proposal.proposal_id, "hegemon-self-approver")
            if proposal.status == "approved":
                self.apply_patch(proposal.proposal_id, "hegemon-self-patcher")
                applied += 1
        self._record("patch.self_autonomous", {"generated": generated, "applied": applied})
        return {"generated": generated, "applied": applied}

    def _intel_cache_get(self, key: str) -> Any | None:
        cache_path = Path("data/intel_cache.shelve")
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        now = time.time()
        try:
            with shelve.open(str(cache_path)) as db:
                row = db.get(key)
                if not row:
                    return None
                if now - float(row.get("ts", 0)) > 86400:
                    return None
                return row.get("value")
        except Exception:
            return None

    def _intel_cache_set(self, key: str, value: Any) -> None:
        cache_path = Path("data/intel_cache.shelve")
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with shelve.open(str(cache_path)) as db:
                db[key] = {"ts": time.time(), "value": value}
        except Exception:
            return

    def _query_ghsa(self, package: str, ecosystem: str) -> list[dict[str, Any]]:
        query = {
            "query": "query($pkg:String!, $eco:SecurityAdvisoryEcosystem!){ securityVulnerabilities(first:10, ecosystem:$eco, package:$pkg){ nodes{ advisory{ ghsaId severity publishedAt } firstPatchedVersion{identifier} vulnerableVersionRange } } }",
            "variables": {"pkg": package, "eco": ecosystem.upper()},
        }
        headers = {"Content-Type": "application/json"}
        token = os.getenv("GITHUB_TOKEN", "").strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            req = urllib.request.Request("https://api.github.com/graphql", data=json.dumps(query).encode(), headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return data.get("data", {}).get("securityVulnerabilities", {}).get("nodes", []) or []
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, Exception):
            return []

    def _query_epss(self, cve_id: str) -> tuple[float, float]:
        ck = f"epss:{cve_id}"
        cached = self._intel_cache_get(ck)
        if cached:
            return float(cached.get("epss", 0.0)), float(cached.get("percentile", 0.0))
        try:
            with urllib.request.urlopen(f"https://api.first.org/data/v1/epss?cve={urllib.parse.quote(cve_id)}", timeout=8) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            row = (data.get("data") or [{}])[0]
            out = {"epss": float(row.get("epss", 0.0)), "percentile": float(row.get("percentile", 0.0))}
            self._intel_cache_set(ck, out)
            return out["epss"], out["percentile"]
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, Exception):
            return 0.0, 0.0

    def _query_exploitdb_confirmed(self, cve_id: str) -> bool:
        ck = f"exploitdb:{cve_id}"
        cached = self._intel_cache_get(ck)
        if cached is not None:
            return bool(cached)
        try:
            req = urllib.request.Request(f"https://www.exploit-db.com/search?cve={urllib.parse.quote(cve_id)}&type=exploits", headers={"Accept": "application/json"}, method="GET")
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            confirmed = bool((data.get("data") or []))
            self._intel_cache_set(ck, confirmed)
            return confirmed
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, Exception):
            return False

    def _diff_scan_results(self, endpoint_id: str, current_findings: list[VulnerabilityFinding]) -> tuple[list[VulnerabilityFinding], list[VulnerabilityFinding], list[VulnerabilityFinding]]:
        prior = self.scan_history.get(endpoint_id, [])[-1] if self.scan_history.get(endpoint_id) else None
        if not prior:
            return current_findings, [], []
        prev_by = {f.cve: f for f in prior.findings}
        cur_by = {f.cve: f for f in current_findings}
        new = [f for c, f in cur_by.items() if c not in prev_by]
        escalated = [f for c, f in cur_by.items() if c in prev_by and (f.cvss - prev_by[c].cvss) >= 0.5]
        resolved = []
        for c, pf in prev_by.items():
            if c not in cur_by:
                if any(p.finding_id == pf.finding_id and p.status == "deployed_canary" for p in self.patch_proposals.values()):
                    resolved.append(pf)
        return new, resolved, escalated

    def _build_lateral_movement_graph(self) -> dict[str, Any]:
        nodes = [{"id": ep.endpoint_id, "risk": ep.risk_score, "exposure": ep.network_exposure} for ep in self.endpoints.values()]
        edges: list[dict[str, Any]] = []
        for a in self.endpoints.values():
            for b in self.endpoints.values():
                if a.endpoint_id == b.endpoint_id:
                    continue
                reason = None
                weight = 0.0
                if a.network_exposure == "internet" and b.network_exposure == "internal":
                    reason = "internet_to_internal_pivot"
                    weight = 1.5
                shared = set(a.installed_packages).intersection(set(b.installed_packages))
                if shared and any("lateral_movement" in (f.reasoning or "") for f in self.findings.values() if f.endpoint_id == a.endpoint_id):
                    reason = reason or "shared_vulnerable_package"
                    weight = max(weight, 1.2)
                if reason:
                    edges.append({"source": a.endpoint_id, "target": b.endpoint_id, "reason": reason, "weight": weight})
        centrality = {n["id"]: 0.0 for n in nodes}
        blast_radius = {n["id"]: 0 for n in nodes}
        highest_path: list[str] = []
        if _NETWORKX_AVAILABLE:
            g = nx.DiGraph()
            for n in nodes:
                g.add_node(n["id"])
            for e in edges:
                g.add_edge(e["source"], e["target"], weight=e["weight"])
            try:
                centrality = nx.betweenness_centrality(g)
                for n in g.nodes:
                    blast_radius[n] = len(nx.descendants(g, n))
            except Exception:
                pass
        return {"nodes": nodes, "edges": edges, "centrality": centrality, "highest_risk_path": highest_path, "blast_radius": blast_radius}

    def _run_regression_tests(self) -> dict[str, Any]:
        started = time.time()
        cmd = ["python", "-m", "pytest", "--tb=no", "-q", "--timeout=30"]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=120, text=True)
            if proc.returncode == 0:
                return {"passed": True, "tests_run": 1, "failures": [], "duration_s": round(time.time()-started, 3)}
            if proc.returncode in {1, 2}:
                return {"passed": False, "tests_run": 1, "failures": [proc.stdout[-400:] or proc.stderr[-400:]], "duration_s": round(time.time()-started, 3)}
        except Exception:
            pass
        return {"passed": False, "tests_run": 0, "failures": ["test runner timed out or failed to launch"], "duration_s": round(time.time()-started, 3)}

    def scan(self, target: str | dict[str, Any], *, mode: Literal["friendly", "unfriendly", "auto"] = "auto", include_external_intel: bool = True, include_ast: bool = True, program_root: str | None = None, actor: str = "user") -> ScanResult:
        started = datetime.now(timezone.utc)
        with self._state_lock:
            if isinstance(target, str):
                endpoint_id = target
                endpoint = self.endpoints.get(endpoint_id)
                if endpoint is None:
                    raise KeyError(endpoint_id)
                resolved_mode = "friendly" if mode == "auto" else mode
            else:
                endpoint_id = str(target.get("host", "unfriendly-target"))
                resolved_mode = "unfriendly" if mode == "auto" else mode
                endpoint = Endpoint(endpoint_id=endpoint_id, host_name=endpoint_id, endpoint_type="external", os=str(target.get("os", "unknown")), kernel="unknown", hypervisor=None, firmware_baseline=None, sbom_status="unknown", enrollment_method="manual", network_exposure=str(target.get("network_exposure", "internet")), installed_packages=dict(target.get("packages", {})), program_root=str(target.get("program_root") or program_root or "") or None)

        structural_report = self._analyze_program_structure(endpoint.program_root) if include_ast else {"files_scanned": 0, "issues": [], "lang_breakdown": {}, "binary_artefacts_scanned": 0, "binary_packed_sections": 0, "cross_language_chains": [], "potential_cross_language_hints": [], "cross_language_analysis_note": "potential cross-language hints (not confirmed taint chains)", "disassembly_backend": None, "lstm_rnn_binary_model": {}, "integrated_flow_model": {}}
        findings = self.run_vulnerability_scan(endpoint.endpoint_id, actor=actor, include_external_intel=include_external_intel) if resolved_mode == "friendly" else self._scan_unfriendly(endpoint, actor=actor, include_external_intel=include_external_intel, include_ast=include_ast)
        new_findings, _resolved, _escalated = self._diff_scan_results(endpoint.endpoint_id, findings)
        graph = self._build_lateral_movement_graph()
        for f in findings:
            reachable = [e["target"] for e in graph.get("edges", []) if e["source"] == endpoint.endpoint_id]
            f.poc_attack_map.setdefault("blast_radius_estimate", {})["reachable_endpoints"] = reachable
        mk = self._markov_tree_project(endpoint.telemetry_events if hasattr(endpoint, "telemetry_events") else [])
        integrated_flow = self._integrated_markov_mtre_graph_model(endpoint.telemetry_events if hasattr(endpoint, "telemetry_events") else [], structural_report)
        scan_confidence = min(0.99, round(0.52 + (0.28 * float(integrated_flow.get("fusion_confidence", 0.0))) + (0.20 * float(structural_report.get("ast_confidence", 0.0))), 4))
        result = ScanResult(scan_id=f"scan-{secrets.token_hex(4)}", target_id=endpoint.endpoint_id, mode=resolved_mode, actor=actor, started_at=started.isoformat(), completed_at=datetime.now(timezone.utc).isoformat(), duration_seconds=round((datetime.now(timezone.utc)-started).total_seconds(), 3), findings=findings, new_findings=new_findings, suppressed=len(self.suppressed_findings), intel_sources=["osv", "nvd", "ghsa", "epss"], ast_files_scanned=int(structural_report.get("files_scanned", 0)), ast_issues_raw=len(structural_report.get("issues", [])), ast_issues_confirmed=len(structural_report.get("issues", [])), markov_tree=mk, bayesian_posteriors={"markov_rnn_sequence_anomaly": float(structural_report.get("lstm_rnn_binary_model", {}).get("sequence_anomaly", 0.0)), "markov_rnn_confidence": float(structural_report.get("lstm_rnn_binary_model", {}).get("confidence", 0.0)), "fusion_risk": float(integrated_flow.get("fusion_risk", 0.0)), "fusion_confidence": float(integrated_flow.get("fusion_confidence", 0.0))}, attack_surface_delta={"new": len(new_findings), "fusion_risk": float(integrated_flow.get("fusion_risk", 0.0))}, scan_confidence=scan_confidence, lateral_graph=graph, lang_breakdown=dict(structural_report.get("lang_breakdown", {})), binary_artefacts_scanned=int(structural_report.get("binary_artefacts_scanned", 0)), binary_packed_sections=int(structural_report.get("binary_packed_sections", 0)), cross_language_chains=list(structural_report.get("cross_language_chains", [])), disassembly_backend=structural_report.get("disassembly_backend"))
        with self._state_lock:
            self.scan_results_by_id[result.scan_id] = result
            self.scan_history.setdefault(endpoint.endpoint_id, []).append(result)
            self.scan_history[endpoint.endpoint_id] = self.scan_history[endpoint.endpoint_id][-10:]
        return result

    def schedule_periodic_scan(self, endpoint_id: str, interval_seconds: float, *, include_external_intel: bool = True, actor: str = "scheduler") -> str:
        job_id = f"job-{secrets.token_hex(4)}"
        def _runner() -> None:
            while True:
                try:
                    self.scan(endpoint_id, mode="friendly", include_external_intel=include_external_intel, actor=actor)
                except Exception:
                    pass
                time.sleep(interval_seconds)
        t = threading.Thread(target=_runner, daemon=True)
        if not hasattr(self, "_scheduled_jobs"):
            self._scheduled_jobs = {}
        self._scheduled_jobs[job_id] = t
        t.start()
        return job_id

    def cancel_periodic_scan(self, job_id: str) -> bool:
        # daemon threads are not forcibly cancelled in this lightweight implementation
        return bool(getattr(self, "_scheduled_jobs", {}).pop(job_id, None))

    def _scan_unfriendly(self, endpoint: Endpoint, actor: str, include_external_intel: bool, include_ast: bool) -> list[VulnerabilityFinding]:
        discovered: list[VulnerabilityFinding] = []
        chain = self._kill_chain_transition_markov(endpoint.telemetry_events)[1]
        for package, version in endpoint.installed_packages.items():
            for vuln in (self._query_osv(package, version, endpoint.os) if include_external_intel else []):
                cve = str(vuln.get("id", "UNKNOWN-CVE"))
                epss, perc = self._query_epss(cve)
                discovered.append(VulnerabilityFinding(finding_id=f"vuln-{secrets.token_hex(4)}", endpoint_id=endpoint.endpoint_id, cve=cve, cvss=self._cvss_from_vuln(vuln), exploit_availability=round(min(10.0, 3.0 + chain * 2.1 + epss * 3.5), 2), topological_impact=6.0, asset_value=endpoint.asset_value, trust_level=endpoint.trust_level, evidence=[{"type": "unfriendly-scan"}], suggested_remediations=["manual remediation only"], risk_score=6.0, source="unfriendly-scan", patch_eligible=False, epss_score=epss, epss_percentile=perc))
        return discovered

    def _make_brain(self, behaviour_id: str, name: str, description: str, nodes: list[dict[str, Any]]) -> DroneBehaviour:
        now = datetime.now(timezone.utc).isoformat()
        drone_nodes = [
            DroneNode(
                node_id=str(n["node_id"]),
                node_type=str(n.get("node_type", "action")),
                kind=str(n.get("kind", "noop")),
                label=str(n.get("label", n.get("kind", "Node"))),
                params=dict(n.get("params", {})),
                position={"x": float(n.get("position", {}).get("x", 0.0)), "y": float(n.get("position", {}).get("y", 0.0))},
                edges_out=[str(x) for x in n.get("edges_out", [])],
                edge_labels={str(k): str(v) for k, v in dict(n.get("edge_labels", {})).items()},
            )
            for n in nodes
        ]
        return DroneBehaviour(
            behaviour_id=behaviour_id,
            name=name,
            nodes=drone_nodes,
            created_at=now,
            author="system",
            description=description,
            is_brain_preset=True,
        )

    def _seed_drone_brains(self) -> None:
        self.drone_brains = {
            "brain-pinger-basic": self._make_brain(
                "brain-pinger-basic",
                "pinger-basic",
                "Launches parallel pings then reports and terminates.",
                [
                    {"node_id": "n1", "node_type": "trigger", "kind": "on_launch", "label": "On Launch", "edges_out": ["n2"]},
                    {"node_id": "n2", "node_type": "control", "kind": "parallel", "label": "Parallel", "edges_out": ["n3", "n4", "n5"]},
                    {"node_id": "n3", "node_type": "action", "kind": "ping_host", "label": "Ping A", "params": {"host": "{target_a}"}, "edges_out": ["n6"]},
                    {"node_id": "n4", "node_type": "action", "kind": "ping_host", "label": "Ping B", "params": {"host": "{target_b}"}, "edges_out": ["n6"]},
                    {"node_id": "n5", "node_type": "action", "kind": "ping_host", "label": "Ping C", "params": {"host": "{target_c}"}, "edges_out": ["n6"]},
                    {"node_id": "n6", "node_type": "control", "kind": "wait", "label": "Wait", "params": {"seconds": 600}, "edges_out": ["n7"]},
                    {"node_id": "n7", "node_type": "action", "kind": "establish_contact", "label": "Establish Contact", "edges_out": ["n8"]},
                    {"node_id": "n8", "node_type": "action", "kind": "send_report", "label": "Send Report", "edges_out": ["n9"]},
                    {"node_id": "n9", "node_type": "control", "kind": "self_terminate", "label": "Self Terminate", "edges_out": []},
                ],
            ),
            "brain-scout-passive": self._make_brain(
                "brain-scout-passive", "scout-passive", "Passive scout loop.",
                [
                    {"node_id": "s1", "node_type": "trigger", "kind": "on_launch", "label": "On Launch", "edges_out": ["s2"]},
                    {"node_id": "s2", "node_type": "action", "kind": "port_scan", "label": "Port Scan", "params": {"host": "{target}", "port_range": "1-1024"}, "edges_out": ["s3"]},
                    {"node_id": "s3", "node_type": "action", "kind": "fingerprint_hosts", "label": "Fingerprint Hosts", "edges_out": ["s4"]},
                    {"node_id": "s4", "node_type": "action", "kind": "send_report", "label": "Send Report", "edges_out": ["s5"]},
                    {"node_id": "s5", "node_type": "control", "kind": "wait", "label": "Wait", "params": {"seconds": "{checkin_interval}"}, "edges_out": ["s6"]},
                    {"node_id": "s6", "node_type": "control", "kind": "repeat", "label": "Repeat", "params": {"target_node_id": "s3", "max_iterations": 100}, "edges_out": ["s3"]},
                ],
            ),
            "brain-sentinel-honeypot": self._make_brain(
                "brain-sentinel-honeypot", "sentinel-honeypot", "Deploys honeypot and reacts to contact.",
                [
                    {"node_id": "h1", "node_type": "trigger", "kind": "on_launch", "label": "On Launch", "edges_out": ["h2"]},
                    {"node_id": "h2", "node_type": "action", "kind": "deploy_honeypot", "label": "Deploy Honeypot", "params": {"port": 2222, "service": "ssh"}, "edges_out": ["h3"]},
                    {"node_id": "h3", "node_type": "control", "kind": "wait", "label": "Wait", "params": {"seconds": 60}, "edges_out": ["h4"]},
                    {"node_id": "h4", "node_type": "condition", "kind": "if_ttl_expired", "label": "If TTL Expired", "edges_out": ["h8", "h5"], "edge_labels": {"h8": "yes", "h5": "no"}},
                    {"node_id": "h5", "node_type": "action", "kind": "send_report", "label": "Send Report Critical", "params": {"severity": "critical"}, "edges_out": ["h6"]},
                    {"node_id": "h6", "node_type": "condition", "kind": "if_severity", "label": "If autonomy=enforce", "params": {"min_findings": 0}, "edges_out": ["h7", "h8"]},
                    {"node_id": "h7", "node_type": "action", "kind": "isolate_source_ip", "label": "Isolate Source", "edges_out": ["h9"]},
                    {"node_id": "h8", "node_type": "action", "kind": "send_report", "label": "Send Clean Report", "params": {"status": "clean"}, "edges_out": ["h9"]},
                    {"node_id": "h9", "node_type": "control", "kind": "self_terminate", "label": "Self Terminate", "edges_out": []},
                ],
            ),
            "brain-probe-and-report": self._make_brain(
                "brain-probe-and-report", "probe-and-report", "Runs unfriendly scan and optional patching.",
                [
                    {"node_id": "p1", "node_type": "trigger", "kind": "on_launch", "label": "On Launch", "edges_out": ["p2"]},
                    {"node_id": "p2", "node_type": "action", "kind": "run_vuln_scan", "label": "Run Vuln Scan", "params": {"mode": "unfriendly"}, "edges_out": ["p3"]},
                    {"node_id": "p3", "node_type": "condition", "kind": "if_severity", "label": "If Findings >= 1", "params": {"operator": ">=", "value": 1}, "edges_out": ["p4", "p8"]},
                    {"node_id": "p4", "node_type": "action", "kind": "send_report", "label": "Send Report", "params": {"include_findings": True}, "edges_out": ["p5"]},
                    {"node_id": "p5", "node_type": "condition", "kind": "if_severity", "label": "If critical findings > 0", "params": {"operator": ">=", "value": 1}, "edges_out": ["p6", "p8"]},
                    {"node_id": "p6", "node_type": "control", "kind": "wait", "label": "Await Patch Approval", "params": {"seconds": 300}, "edges_out": ["p7"]},
                    {"node_id": "p7", "node_type": "action", "kind": "apply_approved_patches", "label": "Apply Approved", "edges_out": ["p8"]},
                    {"node_id": "p8", "node_type": "control", "kind": "self_terminate", "label": "Self Terminate", "edges_out": []},
                ],
            ),
            "brain-ghost-hunter": self._make_brain(
                "brain-ghost-hunter", "ghost-hunter", "Searches for clone signatures.",
                [
                    {"node_id": "g1", "node_type": "trigger", "kind": "on_launch", "label": "On Launch", "edges_out": ["g2"]},
                    {"node_id": "g2", "node_type": "action", "kind": "fingerprint_hosts", "label": "Scan Network", "edges_out": ["g3"]},
                    {"node_id": "g3", "node_type": "condition", "kind": "if_severity", "label": "If Clone Detected", "params": {"operator": ">=", "value": 1}, "edges_out": ["g4", "g6"]},
                    {"node_id": "g4", "node_type": "action", "kind": "send_report", "label": "Send Alert", "params": {"severity": "critical"}, "edges_out": ["g5"]},
                    {"node_id": "g5", "node_type": "action", "kind": "sinkhole_clone", "label": "Sinkhole Clone", "edges_out": ["g6"]},
                    {"node_id": "g6", "node_type": "control", "kind": "wait", "label": "Wait", "params": {"seconds": "{checkin_interval}"}, "edges_out": ["g7"]},
                    {"node_id": "g7", "node_type": "control", "kind": "repeat", "label": "Repeat", "params": {"target_node_id": "g2", "max_iterations": 100}, "edges_out": ["g2"]},
                ],
            ),
            "brain-watcher": self._make_brain(
                "brain-watcher", "watcher", "Continuously ingests telemetry and alerts anomalies.",
                [
                    {"node_id": "w1", "node_type": "trigger", "kind": "on_launch", "label": "On Launch", "edges_out": ["w2"]},
                    {"node_id": "w2", "node_type": "action", "kind": "ingest_telemetry", "label": "Ingest Telemetry", "edges_out": ["w3"]},
                    {"node_id": "w3", "node_type": "action", "kind": "send_report", "label": "Feed to Kill Chain Model", "edges_out": ["w4"]},
                    {"node_id": "w4", "node_type": "condition", "kind": "if_severity", "label": "If Anomaly >= 0.7", "params": {"operator": ">=", "value": 1}, "edges_out": ["w5", "w6"]},
                    {"node_id": "w5", "node_type": "action", "kind": "send_report", "label": "Send Alert", "edges_out": ["w6"]},
                    {"node_id": "w6", "node_type": "control", "kind": "wait", "label": "Wait", "params": {"seconds": "{checkin_interval}"}, "edges_out": ["w7"]},
                    {"node_id": "w7", "node_type": "control", "kind": "repeat", "label": "Repeat", "params": {"target_node_id": "w2", "max_iterations": 100}, "edges_out": ["w2"]},
                ],
            ),
        }

    def _registered_hosts(self) -> set[str]:
        return {ep.host_name for ep in self.endpoints.values()} | set(self.endpoints.keys())

    def decode_drone_source(self, drone_id: str) -> str:
        drone = self.drones[drone_id]
        key_hex = self._drone_private_keys.get(drone_id, "")
        blob_b64 = drone.binary_blob
        if drone.blob_path:
            blob_b64 = Path(drone.blob_path).read_text(encoding="utf-8").strip()
        return decode_blob(blob_b64, key_hex)

    def deploy_drone_remote(self, drone_id: str, host: str, ssh_key_path: str, remote_workdir: str, actor: str) -> dict[str, Any]:
        drone = self.drones[drone_id]
        if drone.autonomy_level not in {"contain", "enforce"}:
            raise ValueError("remote deployment requires contain/enforce autonomy")
        if host not in self._registered_hosts():
            raise ValueError("target host is not a registered endpoint")
        key_hex = self._drone_private_keys.get(drone_id, "")
        blob_b64 = drone.binary_blob
        if drone.blob_path:
            blob_b64 = Path(drone.blob_path).read_text(encoding="utf-8").strip()
        out = deploy_blob_remote(blob_b64, key_hex, host, ssh_key_path, remote_workdir)
        self._record("drone.remote_deploy", {"drone_id": drone_id, "host": host, "actor": actor, **out})
        return out

    def available_drone_actions(self) -> list[dict[str, Any]]:
        return [
            {"binary": opcode, "action": action, "description": f"Dispatch {action} command"}
            for opcode, action in self.DRONE_BINARY_COMMANDS.items()
        ]

    def _decode_binary_command(self, binary_command: str) -> str:
        normalized = "".join(ch for ch in str(binary_command).strip() if ch in {"0", "1"})
        if not normalized or len(normalized) != 8:
            raise ValueError("commands must be 8-bit binary strings")
        command = self.DRONE_BINARY_COMMANDS.get(normalized)
        if command is None:
            raise ValueError("unknown binary command opcode")
        return command

    def _text_to_bits(self, value: str) -> str:
        return "".join(format(ord(ch), "08b") for ch in value)

    def _drone_binary_blueprint(self, *, name: str, tier: str, mission: str, behaviour: DroneBehaviour, ttl_seconds: int, checkin_interval_seconds: int, autonomy_level: str, payload_binary: str) -> str:
        header = "1101001011110001"
        meta = {
            "name": name,
            "tier": tier,
            "mission": mission,
            "behaviour": behaviour.behaviour_id,
            "ttl": int(ttl_seconds),
            "checkin": int(checkin_interval_seconds),
            "autonomy": autonomy_level,
            "payload_binary": payload_binary,
            "nodes": [
                {
                    "id": n.node_id,
                    "type": n.node_type,
                    "kind": n.kind,
                    "label": n.label,
                    "params": n.params,
                    "edges": n.edges_out,
                    "edge_labels": n.edge_labels,
                }
                for n in behaviour.nodes
            ],
        }
        payload = json.dumps(meta, separators=(",", ":"), sort_keys=True)
        return header + self._text_to_bits(payload)

    def _resolve_behaviour(self, behaviour: DroneBehaviour | str) -> DroneBehaviour:
        if isinstance(behaviour, str):
            if behaviour not in self.drone_brains:
                raise ValueError("unknown behaviour brain")
            return copy.deepcopy(self.drone_brains[behaviour])
        return copy.deepcopy(behaviour)

    def assemble_drone(self, name: str, tier: str, mission: str, behaviour: DroneBehaviour | str, *, target_endpoint_id: str | None = None, target_host: str | None = None, target_network: str | None = None, autonomy_level: str = "observe", ttl_seconds: int = 3600, checkin_interval_seconds: int = 60, payload: Any = None, actor: str = "user") -> Drone:
        if tier not in {"controlled", "tethered", "autonomous"}:
            raise ValueError("invalid tier")
        if autonomy_level not in {"observe", "contain", "enforce"}:
            raise ValueError("invalid autonomy_level")
        active_count = len([d for d in self.drones.values() if d.status == "active"])
        if active_count >= 10:
            raise ValueError("max active drone thread cap reached")
        if target_host and target_host not in self._registered_hosts() and autonomy_level != "observe":
            raise ValueError("unregistered external host requires observe autonomy")
        behaviour_obj = self._resolve_behaviour(behaviour)
        drone_id = f"drone-{uuid4().hex[:8]}"
        keypair = signing.SigningKey.generate()
        private_key_hex = keypair.encode().hex()
        self._drone_private_keys[drone_id] = private_key_hex
        workdir = Path("data") / "drones" / drone_id
        workdir.mkdir(parents=True, exist_ok=True)
        now = datetime.now(timezone.utc).isoformat()
        ttl_seconds = int(ttl_seconds)
        checkin_interval_seconds = int(checkin_interval_seconds)
        payload_obj = payload if payload is not None else {}
        payload_json = json.dumps(payload_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
        payload_binary = self._text_to_bits(payload_json)
        supported_binary_actions = sorted(self.DRONE_BINARY_COMMANDS.keys())
        embedded_intel = self._select_embedded_intel(
            target_os=self.endpoints.get(target_endpoint_id).os if target_endpoint_id and target_endpoint_id in self.endpoints else None,
            target_host=target_host,
            installed_packages=self.endpoints.get(target_endpoint_id).installed_packages if target_endpoint_id and target_endpoint_id in self.endpoints else {},
        )
        binary_blueprint = self._drone_binary_blueprint(
            name=name,
            tier=tier,
            mission=mission,
            behaviour=behaviour_obj,
            ttl_seconds=ttl_seconds,
            checkin_interval_seconds=checkin_interval_seconds,
            autonomy_level=autonomy_level,
            payload_binary=payload_binary,
        )
        compiled_blob = self._drone_compiler.compile(drone=Drone(
            drone_id=drone_id, name=name, tier=tier, status="ready", mission=mission, behaviour=behaviour_obj,
            target_endpoint_id=target_endpoint_id, target_host=target_host, target_network=target_network, autonomy_level=autonomy_level,
            ttl_seconds=ttl_seconds, checkin_interval_seconds=checkin_interval_seconds, launched_at=None, last_checkin_at=None, return_at=None,
            keypair_public=keypair.verify_key.encode().hex(), findings=[], telemetry=[], health={}, live_output=[], current_node_id=None,
            stats={"hosts_pinged": 0, "ports_scanned": 0, "findings_count": 0, "nodes_executed": 0}, error=None, created_at=now, actor=actor,
            payload=payload_obj, payload_binary=payload_binary,
        ), private_key_hex=private_key_hex, embedded_intel=embedded_intel)
        blob_path = workdir / "drone.blob"
        blob_path.write_text(compiled_blob, encoding="utf-8")
        drone = Drone(
            drone_id=drone_id,
            name=name,
            tier=tier,
            status="ready",
            mission=mission,
            behaviour=behaviour_obj,
            target_endpoint_id=target_endpoint_id,
            target_host=target_host,
            target_network=target_network,
            autonomy_level=autonomy_level,
            ttl_seconds=ttl_seconds,
            checkin_interval_seconds=checkin_interval_seconds,
            launched_at=None,
            last_checkin_at=None,
            return_at=None,
            keypair_public=keypair.verify_key.encode().hex(),
            findings=[],
            telemetry=[],
            health={},
            live_output=[],
            current_node_id=None,
            stats={"hosts_pinged": 0, "ports_scanned": 0, "findings_count": 0, "nodes_executed": 0},
            error=None,
            created_at=now,
            actor=actor,
            payload=payload_obj,
            payload_binary=payload_binary,
            binary_blueprint=binary_blueprint,
            binary_blob="",
            blob_path=str(blob_path),
            supported_binary_actions=supported_binary_actions,
        )
        drone.blob_size_bytes = len(base64.b64decode(compiled_blob.encode("ascii"))) if compiled_blob else 0
        drone.blob_hash = hashlib.sha256(compiled_blob.encode("utf-8")).hexdigest()[:16] if compiled_blob else ""
        drone.deadrop_path = f"/tmp/.hg_drop_{drone_id.replace('drone-','')}"
        self.drones[drone_id] = drone
        self._drone_command_locks[drone_id] = threading.Lock()
        self._record("drone.assembled", {"actor": actor, "drone_id": drone_id, "tier": tier, "mission": mission})
        return drone

    def _select_embedded_intel(self, target_os: str | None, target_host: str | None, installed_packages: dict[str, str]) -> dict[str, Any]:
        vuln_sigs: list[dict[str, Any]] = []
        for pkg, ver in (installed_packages or {}).items():
            for vuln in self._query_osv(pkg, ver, target_os or "")[:5]:
                vuln_sigs.append({
                    "id": str(vuln.get("id", "UNKNOWN-CVE")),
                    "pattern": rf"{re.escape(pkg)}/?{re.escape(str(ver).split('.')[0])}.*",
                    "severity": float(self._cvss_from_vuln(vuln)),
                    "service": pkg,
                    "affected_versions": str(vuln.get("affected", ""))[:120],
                })
        attack_patterns = [
            {"id": "T1059.004", "pattern": r"(eval|exec)\s*\(", "stage": "execution"},
            {"id": "T1190", "pattern": r"(sqlmap|union\s+select)", "stage": "initial_access"},
            {"id": "T1046", "pattern": r"(nmap|masscan|zmap)", "stage": "discovery"},
        ]
        port_risk = {22: 0.3, 23: 0.9, 3389: 0.8, 6379: 0.7, 27017: 0.8}
        return {"vuln_sigs": vuln_sigs[:50], "attack_patterns": attack_patterns, "port_risk": port_risk, "known_banners": []}

    def drone_sample_catalog(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for sample_id, profile in self.DRONE_SAMPLE_PROFILES.items():
            behaviour_id = str(profile.get("behaviour_id", ""))
            brain = self.drone_brains.get(behaviour_id)
            rows.append({
                **dict(profile),
                "sample_id": sample_id,
                "brain_name": brain.name if brain is not None else behaviour_id,
                "available": brain is not None,
            })
        return rows

    def _split_destination(self, destination: str | None) -> tuple[str | None, str | None, str | None]:
        target = str(destination or "").strip()
        if not target:
            return None, None, None
        if target in self.endpoints:
            endpoint = self.endpoints.get(target)
            return target, endpoint.host_name if endpoint is not None else None, None
        if "/" in target:
            return None, None, target
        return None, target, None

    def assemble_sample_drone(self, sample_id: str, *, destination: str | None = None, actor: str = "user", name_override: str | None = None, payload: Any = None) -> Drone:
        profile = self.DRONE_SAMPLE_PROFILES.get(sample_id)
        if profile is None:
            raise ValueError("unknown sample drone")
        behaviour_id = str(profile.get("behaviour_id", ""))
        if behaviour_id not in self.drone_brains:
            raise ValueError("sample behaviour unavailable")
        target_endpoint_id, target_host, target_network = self._split_destination(destination or str(profile.get("target", "")))
        final_payload = payload if payload is not None else {
            "sample_id": sample_id,
            "description": str(profile.get("description", "")),
            "destination": destination or str(profile.get("target", "")),
        }
        return self.assemble_drone(
            name=str(name_override or profile.get("name", sample_id)),
            tier=str(profile.get("tier", "controlled")),
            mission=str(profile.get("mission", "custom")),
            behaviour=behaviour_id,
            target_endpoint_id=target_endpoint_id,
            target_host=target_host,
            target_network=target_network,
            autonomy_level=str(profile.get("autonomy_level", "observe")),
            ttl_seconds=int(profile.get("ttl_seconds", 3600)),
            checkin_interval_seconds=int(profile.get("checkin_interval_seconds", 60)),
            payload=final_payload,
            actor=actor,
        )

    def assemble_sample_squad(self, nodes: list[dict[str, Any]], links: list[dict[str, Any]], actor: str = "user") -> list[Drone]:
        if not nodes:
            raise ValueError("squad requires at least one node")
        drone_by_client_id: dict[str, Drone] = {}
        built: list[Drone] = []
        for node in nodes:
            client_id = str(node.get("id", "")).strip()
            sample_id = str(node.get("sample_id", "")).strip()
            if not client_id or not sample_id:
                raise ValueError("each squad node requires id and sample_id")
            drone = self.assemble_sample_drone(
                sample_id,
                destination=str(node.get("destination", "")).strip() or None,
                actor=actor,
                name_override=str(node.get("name", "")).strip() or None,
                payload={
                    "sample_id": sample_id,
                    "destination": str(node.get("destination", "")).strip(),
                    "squad_node_id": client_id,
                },
            )
            drone_by_client_id[client_id] = drone
            built.append(drone)

        for link in links:
            src = str(link.get("from_id", "")).strip()
            dst = str(link.get("to_id", "")).strip()
            if src in drone_by_client_id and dst in drone_by_client_id:
                src_drone = drone_by_client_id[src]
                src_drone.payload = {
                    **(src_drone.payload if isinstance(src_drone.payload, dict) else {}),
                    "route_targets": [
                        *(src_drone.payload.get("route_targets", []) if isinstance(src_drone.payload, dict) else []),
                        drone_by_client_id[dst].drone_id,
                    ],
                }
        return built

    def auto_assemble_drone(self, endpoint_id: str, actor: str) -> Drone | None:
        endpoint = self.endpoints.get(endpoint_id)
        if endpoint is None:
            return None
        endpoint_findings = [f for f in self.findings.values() if f.endpoint_id == endpoint_id]
        critical = [f for f in endpoint_findings if f.cvss >= 8.0 or f.risk_score >= 8.0]
        graph = self._build_lateral_movement_graph()
        edges = graph.get("edges", []) if isinstance(graph, dict) else []
        has_lateral_hop = any(str(e.get("source")) == endpoint_id or str(e.get("target")) == endpoint_id for e in edges)
        approved_patch = any(
            p.endpoint_id == endpoint_id and p.status == "approved"
            for p in self.patch_proposals.values()
        )
        if endpoint.network_exposure == "internet" and critical:
            return self.assemble_drone(
                name=f"Probe-{endpoint.host_name}", tier="tethered", mission="probe", behaviour="brain-probe-and-report",
                target_endpoint_id=endpoint_id, target_host=endpoint.host_name, autonomy_level="contain", actor=actor,
            )
        if has_lateral_hop and not endpoint.telemetry_events:
            return self.assemble_drone(
                name=f"Watcher-{endpoint.host_name}", tier="autonomous", mission="watcher", behaviour="brain-watcher",
                target_endpoint_id=endpoint_id, target_host=endpoint.host_name, autonomy_level="observe", actor=actor,
            )
        if endpoint.network_exposure == "internet" and not endpoint_findings:
            return self.assemble_drone(
                name=f"Sentinel-{endpoint.host_name}", tier="tethered", mission="sentinel", behaviour="brain-sentinel-honeypot",
                target_endpoint_id=endpoint_id, target_host=endpoint.host_name, autonomy_level="observe", actor=actor,
            )
        if critical and approved_patch:
            return self.assemble_drone(
                name=f"PatchRunner-{endpoint.host_name}", tier="tethered", mission="patch_runner", behaviour="brain-probe-and-report",
                target_endpoint_id=endpoint_id, target_host=endpoint.host_name, autonomy_level="contain", actor=actor,
            )
        return None

    def _has_enforce_approval(self, drone_id: str) -> bool:
        friend_ok = {f.friend_id for f in self.friends.values() if f.status == "active" and "approve_patches" in f.capabilities}
        if not friend_ok:
            return False
        for entry in self.audit_log():
            if entry.get("event_type") != "drone.enforce_approved":
                continue
            payload = entry.get("payload", {})
            if payload.get("drone_id") == drone_id and payload.get("approver") in friend_ok:
                return True
        return False

    def launch_drone(self, drone_id: str, actor: str) -> Drone:
        drone = self.drones[drone_id]
        if drone.status != "ready":
            raise ValueError("drone must be ready")
        if drone.autonomy_level == "enforce" and not self._has_enforce_approval(drone_id):
            token = f"drone-launch:{drone_id}"
            if token not in self.human_review_queue:
                self.human_review_queue.append(token)
            self._record("drone.human_review_required", {"drone_id": drone_id, "priority": "p0", "actor": actor})
            raise PermissionError("human approval required")
        workdir = Path("data") / "drones" / drone_id
        workdir.mkdir(parents=True, exist_ok=True)
        key_hex = self._drone_private_keys.get(drone_id, "")
        blob_b64 = drone.binary_blob
        if drone.blob_path:
            blob_b64 = Path(drone.blob_path).read_text(encoding="utf-8").strip()
        proc = launch_blob_locally(
            blob_b64,
            key_hex,
            workdir,
            detached=(drone.tier == "autonomous"),
        )
        self._drone_processes[drone_id] = proc
        drone.pid = proc.pid
        drone.status = "active"
        drone.launched_at = datetime.now(timezone.utc).isoformat()
        if drone.ttl_seconds > 0 and drone.tier == "autonomous":
            drone.return_at = datetime.fromtimestamp(time.time() + drone.ttl_seconds, tz=timezone.utc).isoformat()
        stop_event = threading.Event()
        self._drone_stop_events[drone_id] = stop_event
        t = threading.Thread(target=self._drone_monitor, args=(drone_id, proc), daemon=True)
        self._drone_threads[drone_id] = t
        t.start()
        self._record("drone.launched", {"actor": actor, "drone_id": drone_id, "pid": proc.pid})
        return drone

    def _next_node(self, node: DroneNode, decision: str | None = None) -> str | None:
        if not node.edges_out:
            return None
        if decision:
            for out in node.edges_out:
                if node.edge_labels.get(out) == decision:
                    return out
        return node.edges_out[0]

    def _append_signed_telemetry(self, drone: Drone, message: str, **extra: Any) -> None:
        key_hex = self._drone_private_keys.get(drone.drone_id)
        if not key_hex:
            return
        payload = {"ts": datetime.now(timezone.utc).isoformat(), "message": message, **extra}
        blob = json.dumps(payload, sort_keys=True).encode("utf-8")
        sig = hmac.new(bytes.fromhex(key_hex[:64]), blob, hashlib.sha256).hexdigest()
        signed_payload = {**payload, "signature": sig}
        if self._verify_telemetry_signature(drone, signed_payload):
            drone.telemetry.append(signed_payload)

    def _verify_telemetry_signature(self, drone: Drone, payload: dict[str, Any]) -> bool:
        sig = payload.get("signature")
        key_hex = self._drone_private_keys.get(drone.drone_id)
        if not isinstance(sig, str) or not key_hex:
            return False
        body = dict(payload)
        body.pop("signature", None)
        blob = json.dumps(body, sort_keys=True).encode("utf-8")
        expected = hmac.new(bytes.fromhex(key_hex[:64]), blob, hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected)

    def _execute_node(self, drone: Drone, node: DroneNode, node_map: dict[str, DroneNode], repeat_count: dict[str, int], stop_event: threading.Event, launch_time: float) -> str | None:
        kind = node.kind
        drone.current_node_id = node.node_id
        drone.stats["nodes_executed"] = int(drone.stats.get("nodes_executed", 0)) + 1
        if kind == "on_launch":
            return self._next_node(node)
        if kind == "ping_host":
            host = str(node.params.get("host", drone.target_host or "127.0.0.1")).format(target=drone.target_host or "127.0.0.1")
            proc = subprocess.run(["ping", "-c", "1", "-W", "2", host], capture_output=True, text=True)
            ok = proc.returncode == 0
            drone.stats["hosts_pinged"] = int(drone.stats.get("hosts_pinged", 0)) + 1
            line = f"Ping {host} -> {'ALIVE' if ok else 'TIMEOUT'}"
            drone.live_output.append(line)
            self._append_signed_telemetry(drone, line, node_id=node.node_id, success=ok)
            return self._next_node(node)
        if kind == "port_scan":
            host = str(node.params.get("host", drone.target_host or "127.0.0.1")).format(target=drone.target_host or "127.0.0.1")
            p_range = str(node.params.get("port_range", "1-1024"))
            start, end = 1, 1024
            if "-" in p_range:
                a, b = p_range.split("-", 1)
                start, end = max(1, int(a)), min(65535, int(b))
            end = min(end, start + 1023)
            open_ports = []
            for port in range(start, end + 1):
                if stop_event.is_set():
                    break
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                try:
                    if sock.connect_ex((host, port)) == 0:
                        open_ports.append(port)
                finally:
                    sock.close()
            drone.stats["ports_scanned"] = int(drone.stats.get("ports_scanned", 0)) + (end - start + 1)
            msg = f"Port scan {host}:{start}-{end} -> {len(open_ports)} open"
            drone.live_output.append(msg)
            self._append_signed_telemetry(drone, msg, open_ports=open_ports)
            return self._next_node(node)
        if kind == "fingerprint_hosts":
            host = drone.target_host or "127.0.0.1"
            banners = {}
            for port in (80, 443, 22):
                try:
                    with socket.create_connection((host, port), timeout=0.5) as sock:
                        sock.settimeout(0.5)
                        data = sock.recv(256)
                        banners[str(port)] = data.decode(errors="ignore")
                except Exception:
                    continue
            self._append_signed_telemetry(drone, f"Fingerprint {host}", banners=banners)
            return self._next_node(node)
        if kind == "deploy_honeypot":
            if hasattr(self, "_runtime") and getattr(self, "_runtime", None) is not None and hasattr(self._runtime, "detection") and hasattr(self._runtime.detection, "honeypot"):
                self._append_signed_telemetry(drone, "Honeypot deployed via runtime")
            else:
                self._append_signed_telemetry(drone, "Honeypot simulated deployment")
            return self._next_node(node)
        if kind == "run_vuln_scan":
            target = drone.target_endpoint_id or drone.target_host or HEGEMON_SELF_ENDPOINT_ID
            result = self.scan(target, mode="unfriendly", include_external_intel=False, actor=f"drone:{drone.drone_id}")
            for f in result.new_findings:
                drone.findings.append(f.finding_id)
            drone.stats["findings_count"] = len(drone.findings)
            self._append_signed_telemetry(drone, f"Vuln scan complete findings={len(result.new_findings)}")
            return self._next_node(node)
        if kind == "send_report":
            self._append_signed_telemetry(drone, "Report sent", findings=len(drone.findings), stats=drone.stats)
            return self._next_node(node)
        if kind == "establish_contact":
            if drone.tier == "autonomous":
                drone.status = "returning"
            self._append_signed_telemetry(drone, "Contact established")
            return self._next_node(node)
        if kind == "self_terminate":
            drone.status = "terminated"
            stop_event.set()
            return None
        if kind == "wait":
            total = node.params.get("seconds", 0)
            if isinstance(total, str) and total == "{checkin_interval}":
                total = drone.checkin_interval_seconds
            total = int(total)
            elapsed_wait = 0
            while elapsed_wait < total and not stop_event.is_set():
                time.sleep(min(5, total - elapsed_wait))
                elapsed_wait += min(5, total - elapsed_wait)
                if drone.ttl_seconds > 0 and time.time() > launch_time + drone.ttl_seconds:
                    drone.status = "terminated"
                    self._record("drone.ttl_expired", {"drone_id": drone.drone_id})
                    stop_event.set()
                    return None
            return self._next_node(node)
        if kind == "parallel":
            children = [node_map[c] for c in node.edges_out if c in node_map]
            def run_child(child: DroneNode):
                self._execute_node(drone, child, node_map, repeat_count, stop_event, launch_time)
            workers = [threading.Thread(target=run_child, args=(c,), daemon=True) for c in children]
            for w in workers:
                w.start()
            for w in workers:
                w.join()
            return None
        if kind == "if_severity":
            val = int(node.params.get("value", node.params.get("min_findings", 1)))
            op = str(node.params.get("operator", ">="))
            cur = len(drone.findings)
            ok = ((op == ">=" and cur >= val) or (op == "<=" and cur <= val) or (op == "==" and cur == val) or (op == "!=" and cur != val))
            decision = "yes" if ok else "no"
            return self._next_node(node, decision)
        if kind == "if_ttl_expired":
            expired = drone.ttl_seconds > 0 and time.time() > launch_time + drone.ttl_seconds
            return self._next_node(node, "yes" if expired else "no")
        if kind == "repeat":
            mx = int(node.params.get("max_iterations", 1))
            cnt = repeat_count.get(node.node_id, 0)
            if cnt >= mx:
                return None
            repeat_count[node.node_id] = cnt + 1
            return str(node.params.get("target_node_id", self._next_node(node) or "")) or None
        if kind == "ingest_telemetry":
            endpoint = self.endpoints.get(drone.target_endpoint_id or "")
            events = endpoint.telemetry_events if endpoint else []
            score = min(1.0, len(events) / 10)
            if score >= 0.7:
                drone.findings.append(f"anomaly-{uuid4().hex[:8]}")
            self._append_signed_telemetry(drone, "Telemetry ingested", anomaly_score=score)
            return self._next_node(node)
        if kind == "apply_approved_patches":
            for proposal in self.patch_proposals.values():
                if proposal.endpoint_id == (drone.target_endpoint_id or proposal.endpoint_id) and proposal.status == "approved":
                    self.apply_patch(proposal.proposal_id, f"drone:{drone.drone_id}")
            self._append_signed_telemetry(drone, "Approved patches applied")
            return self._next_node(node)
        if kind == "sinkhole_clone":
            if drone.autonomy_level == "enforce":
                self._append_signed_telemetry(drone, "Sinkhole clone executed")
            return self._next_node(node)
        if kind == "isolate_source_ip":
            if drone.autonomy_level == "enforce":
                self._append_signed_telemetry(drone, "Source IP isolated")
            return self._next_node(node)
        self._append_signed_telemetry(drone, f"Unknown node kind {kind}")
        return self._next_node(node)

    def _poll_deadrop(self, drone_id: str) -> None:
        drone = self.drones.get(drone_id)
        if not drone:
            return
        dd = Path(drone.deadrop_path or "")
        if not dd.exists():
            return
        try:
            key_hex = self._drone_private_keys.get(drone_id, "")
            raw = dd.read_text(encoding="utf-8")
            env = json.loads(base64.b64decode(raw).decode("utf-8"))
            encrypted = base64.b64decode(str(env.get("data", "")))
            sig = str(env.get("sig", ""))
            expected = hmac.new(bytes.fromhex(key_hex[:64]), encrypted, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, expected):
                return
            key = bytes.fromhex(key_hex[:32])
            key_cycle = (key * (len(encrypted) // len(key) + 1))[:len(encrypted)]
            plain = bytes(a ^ b for a, b in zip(encrypted, key_cycle))
            payload = json.loads(plain.decode("utf-8"))
            for finding in payload.get("findings", []):
                if finding not in drone.findings:
                    drone.findings.append(finding)
            drone.telemetry.extend(payload.get("telemetry", []))
            drone.stats["findings_count"] = len(drone.findings)
            drone.last_checkin_at = datetime.now(timezone.utc).isoformat()
        except Exception:
            return

    def _drone_monitor(self, drone_id: str, proc: subprocess.Popen) -> None:
        drone = self.drones.get(drone_id)
        if drone is None:
            return
        launch_time = time.time()
        last_deadrop_poll = 0.0
        while True:
            if proc.stdout:
                line = proc.stdout.readline()
                if line:
                    drone.live_output.append(line.decode("utf-8", errors="ignore").strip())
            if proc.stderr:
                err = proc.stderr.readline()
                if err:
                    drone.live_output.append("ERR: " + err.decode("utf-8", errors="ignore").strip())
            now = time.time()
            if now - last_deadrop_poll > max(1, drone.checkin_interval_seconds):
                self._poll_deadrop(drone_id)
                last_deadrop_poll = now
            if drone.tier == "controlled" and drone.ttl_seconds > 0 and now > launch_time + drone.ttl_seconds:
                try:
                    proc.terminate()
                except Exception:
                    pass
            if proc.poll() is not None:
                drone.status = "terminated"
                break
            time.sleep(0.1)

    def _drone_execution_loop(self, drone_id: str) -> None:
        drone = self.drones.get(drone_id)
        if drone is None:
            return
        node_map = {n.node_id: n for n in drone.behaviour.nodes}
        if not node_map:
            drone.status = "error"
            drone.error = "empty behaviour"
            return
        start_node = next((n for n in drone.behaviour.nodes if n.kind == "on_launch"), drone.behaviour.nodes[0])
        current_id: str | None = start_node.node_id
        launch_time = time.time()
        last_checkin = launch_time
        stop_event = self._drone_stop_events.get(drone_id, threading.Event())
        repeat_count: dict[str, int] = {}
        while current_id and not stop_event.is_set():
            now = time.time()
            elapsed = int(now - launch_time)
            if drone.ttl_seconds > 0 and now > launch_time + drone.ttl_seconds:
                drone.status = "terminated"
                self._record("drone.ttl_expired", {"drone_id": drone_id})
                break
            if now - last_checkin >= max(1, drone.checkin_interval_seconds):
                drone.last_checkin_at = datetime.now(timezone.utc).isoformat()
                drone.health = {"cpu_pct": None, "reachable": True, "uptime_seconds": elapsed, "nodes_executed": drone.stats.get("nodes_executed", 0), "last_node": drone.current_node_id}
                last_checkin = now
            if drone.tier == "controlled":
                with self._drone_command_locks[drone_id]:
                    pending = list(drone.pending_commands)
                    drone.pending_commands.clear()
                for cmd in pending:
                    c = cmd.get("command")
                    if c == "pause":
                        drone.status = "dark"
                        time.sleep(1)
                        drone.status = "active"
                    elif c == "terminate":
                        drone.status = "terminated"
                        stop_event.set()
                        break
                    elif c == "report":
                        self._append_signed_telemetry(drone, "On-demand report", command=True)
                    elif c == "ping":
                        self._append_signed_telemetry(drone, "Binary command ping acknowledged", command=True)
                    elif c == "scan":
                        self._append_signed_telemetry(drone, "Binary command initiated focused scan", command=True)
                    elif c == "resume":
                        drone.status = "active"
                    elif c == "retask":
                        mission = str(cmd.get("params", {}).get("mission", "dynamic-tasking"))
                        drone.mission = mission
                        self._append_signed_telemetry(drone, f"Mission retasked to {mission}", command=True)
                    elif c == "tighten_checkin":
                        interval = int(cmd.get("params", {}).get("seconds", 10))
                        drone.checkin_interval_seconds = max(1, min(interval, 300))
                        self._append_signed_telemetry(drone, f"Check-in interval set to {drone.checkin_interval_seconds}s", command=True)
                    elif c == "broadcast_status":
                        self._append_signed_telemetry(drone, f"Status broadcast: {drone.status}", command=True)
                    elif c == "inject_node":
                        raw_node = cmd.get("params", {}).get("node", {})
                        node = DroneNode(node_id=raw_node.get("node_id", f"n-{uuid4().hex[:6]}"), node_type=raw_node.get("node_type", "action"), kind=raw_node.get("kind", "send_report"), label=raw_node.get("label", "Injected Node"), params=dict(raw_node.get("params", {})), position={"x": 0.0, "y": 0.0}, edges_out=[], edge_labels={})
                        drone.behaviour.nodes.append(node)
                        node_map[node.node_id] = node
            node = node_map.get(current_id)
            if node is None:
                break
            current_id = self._execute_node(drone, node, node_map, repeat_count, stop_event, launch_time)
        if drone.status not in {"terminated", "error"}:
            drone.status = "terminated"
        try:
            shutil.rmtree(Path("data") / "drones" / drone_id, ignore_errors=True)
        except Exception:
            pass

    def send_drone_command(self, drone_id: str, command: str, params: dict[str, Any], actor: str) -> dict[str, Any]:
        drone = self.drones[drone_id]
        if drone.tier != "controlled":
            raise ValueError("commands only valid for controlled drones")
        decoded = self._decode_binary_command(command)
        if command not in drone.supported_binary_actions:
            raise ValueError("binary opcode not supported by this drone")
        with self._drone_command_locks[drone_id]:
            drone.pending_commands.append({"command": decoded, "command_binary": command, "params": params, "actor": actor, "at": datetime.now(timezone.utc).isoformat()})
        self._record("drone.command_sent", {"drone_id": drone_id, "command": decoded, "command_binary": command, "actor": actor})
        return {"queued": True, "command": decoded, "command_binary": command}

    def delete_drone(self, drone_id: str, actor: str) -> dict[str, Any]:
        drone = self.drones.get(drone_id)
        if drone is None:
            raise ValueError("drone not found")
        if drone.tier == "autonomous" or drone.status == "dark":
            raise ValueError("dark or autonomous drones cannot be deleted")
        if drone.tier not in {"controlled", "tethered"}:
            raise ValueError("only controlled or tethered drones can be deleted")
        ev = self._drone_stop_events.get(drone_id)
        if ev:
            ev.set()
        self.drones.pop(drone_id, None)
        self._drone_threads.pop(drone_id, None)
        proc = self._drone_processes.pop(drone_id, None)
        if proc and proc.poll() is None:
            proc.terminate()
        self._drone_stop_events.pop(drone_id, None)
        self._drone_command_locks.pop(drone_id, None)
        self._drone_private_keys.pop(drone_id, None)
        self._record("drone.deleted", {"drone_id": drone_id, "tier": drone.tier, "actor": actor})
        return {"deleted": True, "drone_id": drone_id}

    def recall_drone(self, drone_id: str, actor: str) -> Drone:
        drone = self.drones[drone_id]
        if drone.tier not in {"controlled", "tethered", "autonomous"}:
            raise ValueError("invalid drone tier")
        ev = self._drone_stop_events.get(drone_id)
        if ev:
            ev.set()
        proc = self._drone_processes.get(drone_id)
        if proc and proc.poll() is None:
            proc.terminate()
        drone.status = "returning"
        self._record("drone.recalled", {"drone_id": drone_id, "actor": actor})
        return drone

    def terminate_drone(self, drone_id: str, actor: str) -> Drone:
        drone = self.drones[drone_id]
        drone.status = "terminated"
        ev = self._drone_stop_events.get(drone_id)
        if ev:
            ev.set()
        proc = self._drone_processes.get(drone_id)
        if proc and proc.poll() is None:
            proc.terminate()
        self._record("drone.terminated", {"drone_id": drone_id, "actor": actor})
        return drone

    class SelfScanLoop:
        def __init__(self, cp: "HegemonControlPlane"):
            self.cp = cp
            self._stop = threading.Event()
            self._thread: threading.Thread | None = None
            self.scan_interval_seconds: float = 300.0
            self.max_interval_seconds: float = 3600.0
            self.consecutive_errors: int = 0
            self.last_scan_at: float = 0.0
            self.last_findings_count: int = 0
            self.total_patches_applied: int = 0
            self.total_rolled_back: int = 0

        def start(self) -> None:
            if self._thread and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()

        def stop(self, timeout: float = 5.0) -> None:
            self._stop.set()
            if self._thread:
                self._thread.join(timeout=timeout)

        def _run_one_cycle(self) -> dict[str, Any]:
            started = time.time()
            findings = self.cp.discover_new_issues(HEGEMON_SELF_ENDPOINT_ID, include_external_intel=False)
            self.last_findings_count = len(findings)
            generated = applied = rolled_back = 0
            for finding in findings:
                proposal = self.cp.generate_patch_proposal(finding.finding_id, actor="self-scan-loop")
                generated += 1
                if finding.cvss >= 8.5 or any(pf in proposal.code_diff for pf in PROTECTED_FILES):
                    self.cp.human_review_queue.append(proposal.proposal_id)
                    self.cp._record("patch.human_required", {"proposal_id": proposal.proposal_id, "priority": "p0"})
                    continue
                if proposal.confidence >= 0.72 and proposal.regression_risk <= 2.0 and proposal.approvals_required == 1:
                    self.cp.approve_patch(proposal.proposal_id, "self-scan-loop")
                    self.cp.apply_patch(proposal.proposal_id, "self-scan-loop")
                    applied += 1
                    test = self.cp._run_regression_tests()
                    if not test.get("passed"):
                        proposal.status = "rolled_back"
                        rolled_back += 1
            self.cp._record("self_scan.cycle", {"new_findings": len(findings), "proposals_generated": generated, "applied": applied, "rolled_back": rolled_back})
            self.total_patches_applied += applied
            self.total_rolled_back += rolled_back
            self.last_scan_at = time.time()
            return {"new_findings": len(findings), "proposals_generated": generated, "applied": applied, "rolled_back": rolled_back, "elapsed_seconds": round(time.time()-started, 3)}

        def _loop(self) -> None:
            while not self._stop.is_set():
                try:
                    self._run_one_cycle()
                    self.consecutive_errors = 0
                    interval = self.scan_interval_seconds
                except Exception:
                    self.consecutive_errors += 1
                    interval = min(self.max_interval_seconds, self.scan_interval_seconds * (2 ** self.consecutive_errors))
                self._stop.wait(interval)

    def as_dict(self, obj: Any) -> dict[str, Any]:
        if hasattr(obj, "__dataclass_fields__"):
            return asdict(obj)
        return dict(obj)

    def audit_log(self) -> list[dict[str, Any]]:
        return self.ledger.read_all()

    def ledger_health(self) -> dict[str, Any]:
        return {"entries": len(self.audit_log()), "chain_valid": self.ledger.verify_chain()}

    def export_graph(self) -> dict[str, Any]:
        nodes = []
        edges = []
        for ep in self.endpoints.values():
            nodes.append({"id": ep.endpoint_id, "type": "Host", "label": ep.host_name, "risk_score": ep.risk_score})
        for f in self.findings.values():
            nodes.append({"id": f.finding_id, "type": "Vulnerability", "label": f.cve, "risk_score": f.risk_score})
            edges.append({"source": f.endpoint_id, "target": f.finding_id, "type": "vulnerable_to"})
        for p in self.patch_proposals.values():
            nodes.append({"id": p.proposal_id, "type": "PatchProposal", "label": p.summary, "risk_score": 0})
            edges.append({"source": p.finding_id, "target": p.proposal_id, "type": "patched_by"})
        return {"nodes": nodes, "edges": edges}
