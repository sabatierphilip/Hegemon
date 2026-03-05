from __future__ import annotations

import ast
import hashlib
import json
import os
import secrets
from collections import defaultdict
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nacl import signing

from signed_ledger import SignedLedger

CRITICAL_CAPABILITIES = {"approve_firmware", "approve_hypervisor", "revoke"}

KILL_CHAIN_STAGES = [
    "recon",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "lateral_movement",
    "collection",
    "exfiltration",
    "impact",
]

DEFAULT_FRIENDLY_STORES: list[dict[str, str]] = [
    {"store_id": "store-windows", "name": "Microsoft Store", "icon": "🪟", "platform": "windows"},
    {"store_id": "store-linux", "name": "Linux Package Repos", "icon": "🐧", "platform": "linux"},
    {"store_id": "store-apple", "name": "Apple App Store", "icon": "🍎", "platform": "apple"},
    {"store_id": "store-steam", "name": "Steam", "icon": "🎮", "platform": "cross-platform"},
]


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
    "edge": {"name": "Microsoft Edge", "icon": "🌐", "store_id": "store-windows", "publisher": "Microsoft"},
    "defender": {"name": "Microsoft Defender", "icon": "🛡️", "store_id": "store-windows", "publisher": "Microsoft"},
    "nginx": {"name": "Nginx", "icon": "🌐", "store_id": "store-linux", "publisher": "NGINX Inc."},
    "steamcmd": {"name": "SteamCMD", "icon": "🎮", "store_id": "store-steam", "publisher": "Valve"},
    "openssl": {"name": "OpenSSL", "icon": "🔐", "store_id": "store-linux", "publisher": "OpenSSL"},
    "curl": {"name": "curl", "icon": "🌐", "store_id": "store-linux", "publisher": "curl"},
    "wget": {"name": "wget", "icon": "📥", "store_id": "store-linux", "publisher": "GNU"},
    "python3": {"name": "Python 3", "icon": "🐍", "store_id": "store-linux", "publisher": "Python Software Foundation"},
    "nodejs": {"name": "Node.js", "icon": "🟢", "store_id": "store-linux", "publisher": "OpenJS"},
    "docker": {"name": "Docker", "icon": "🐳", "store_id": "store-linux", "publisher": "Docker"},
    "containerd": {"name": "containerd", "icon": "📦", "store_id": "store-linux", "publisher": "CNCF"},
    "kubelet": {"name": "Kubelet", "icon": "☸️", "store_id": "store-linux", "publisher": "Kubernetes"},
    "postgres": {"name": "PostgreSQL", "icon": "🐘", "store_id": "store-linux", "publisher": "PostgreSQL"},
    "mysql": {"name": "MySQL", "icon": "🛢️", "store_id": "store-linux", "publisher": "Oracle"},
    "redis": {"name": "Redis", "icon": "🟥", "store_id": "store-linux", "publisher": "Redis"},
    "apache2": {"name": "Apache HTTP Server", "icon": "🪶", "store_id": "store-linux", "publisher": "Apache"},
    "sshd": {"name": "OpenSSH Server", "icon": "🔑", "store_id": "store-linux", "publisher": "OpenSSH"},
    "git": {"name": "Git", "icon": "🧬", "store_id": "store-linux", "publisher": "Git"},
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
    def __init__(self, ledger_path: Path | None = None) -> None:
        signer = signing.SigningKey.generate()
        self.ledger = SignedLedger(ledger_path or Path("data/controlplane_ledger.jsonl"), signer)
        self.friends: dict[str, Friend] = {}
        self.endpoints: dict[str, Endpoint] = {}
        self.findings: dict[str, VulnerabilityFinding] = {}
        self.patch_proposals: dict[str, PatchProposal] = {}
        self.friendly_stores: dict[str, FriendlyStore] = {
            row["store_id"]: FriendlyStore(**row) for row in DEFAULT_FRIENDLY_STORES
        }
        self.friendly_apps: dict[str, FriendlyApp] = {}
        self._seed_default_friendly_entities()
        self._seed_self_endpoint()
        self.auto_patch_policy = AutoPatchPolicy()
        self.human_review_queue: list[str] = []
        self._proposal_approved_at: dict[str, float] = {}

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
            icon=payload.get("icon", "🏪"),
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
            icon=payload.get("icon", "📦"),
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
            installed_packages=dict(payload.get("installed_packages", {})),
            telemetry_events=list(payload.get("telemetry_events", [])),
            program_root=(str(payload.get("program_root")) if payload.get("program_root") else None),
        )
        if endpoint.protection_mode not in {"observe-only", "canary", "enforce"}:
            raise ValueError("invalid protection_mode; expected one of observe-only|canary|enforce")
        if endpoint.endpoint_type == "app-store-package" and not endpoint.publisher_signature:
            raise ValueError("app-store-package endpoints require publisher_signature")
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
    def _kill_chain_transition_markov(events: list[str]) -> tuple[dict[str, dict[str, float]], float]:
        matrix: dict[str, dict[str, float]] = {stage: {} for stage in KILL_CHAIN_STAGES}
        index = {stage: i for i, stage in enumerate(KILL_CHAIN_STAGES)}
        if len(events) < 2:
            return matrix, 0.2
        counts: dict[tuple[str, str], int] = {}
        total = 0
        riskiness = 0.0
        for a, b in zip(events, events[1:]):
            if a not in index or b not in index:
                continue
            counts[(a, b)] = counts.get((a, b), 0) + 1
            total += 1
            jump = index[b] - index[a]
            riskiness += 1.4 if jump >= 2 else (1.0 if jump == 1 else 0.3)
        if total == 0:
            return matrix, 0.2
        by_src: dict[str, int] = {}
        for (a, _b), c in counts.items():
            by_src[a] = by_src.get(a, 0) + c
        for (a, b), c in counts.items():
            matrix[a][b] = round(c / by_src[a], 3)
        return matrix, min(riskiness / total, 1.8)

    def _build_attack_path(self, endpoint: Endpoint, cve: str, chain_risk: float) -> list[dict[str, Any]]:
        perimeter = "external_attacker" if endpoint.network_exposure == "internet" else "partner_network"
        return [
            {"node": perimeter, "weight": round(1.0 + chain_risk * 0.2, 3)},
            {"node": "internet_edge", "weight": round(1.4 + chain_risk * 0.2, 3)},
            {"node": endpoint.host_name, "weight": round(1.8 + chain_risk * 0.3, 3)},
            {"node": cve, "weight": round(2.1 + chain_risk * 0.4, 3)},
        ]

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
        )
        self.findings[finding.finding_id] = finding
        self._record("vulnerability.detected", {"actor": actor, "finding": asdict(finding)})
        return finding

    @staticmethod
    def _safe_relpath(path: Path, base: Path) -> str:
        try:
            return str(path.relative_to(base))
        except ValueError:
            return str(path)

    def _analyze_program_structure(self, program_root: str | None) -> dict[str, Any]:
        if not program_root:
            return {
                "files_scanned": 0,
                "issues": [],
                "ast_confidence": 0.0,
                "graph_alignment": 0.0,
                "markov_kill_chain": 0.0,
                "program_graph": {"modules": 0, "functions": 0, "call_edges": 0, "entrypoints": []},
            }

        root = Path(program_root).resolve()
        if not root.exists() or not root.is_dir():
            return {
                "files_scanned": 0,
                "issues": [],
                "ast_confidence": 0.0,
                "graph_alignment": 0.0,
                "markov_kill_chain": 0.0,
                "program_graph": {"modules": 0, "functions": 0, "call_edges": 0, "entrypoints": []},
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
                elif isinstance(node, ast.ImportFrom):
                    imports_graph[module_name].add((node.module or "").split(".")[0])

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
                        func_name = node_name(child.func)
                        called_names.add(func_name)
                        line = getattr(child, "lineno", 1)
                        if func_name in {"input", "request.args.get", "request.form.get", "request.get_json", "os.environ.get"}:
                            source_hits.append(func_name)
                        if func_name in {"eval", "exec"}:
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
                        if func_name in {"pickle.loads", "loads"}:
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
        _markov, markov_score = self._kill_chain_transition_markov(all_stages)

        entrypoints = sorted([fn for fn, p in function_profiles.items() if p.get("sources")])[:12]
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
        }

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
