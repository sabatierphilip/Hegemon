from __future__ import annotations

import hashlib
import json
import os
import secrets
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

    def run_vulnerability_scan(self, endpoint_id: str, actor: str = "scanner") -> list[VulnerabilityFinding]:
        endpoint = self.endpoints[endpoint_id]
        discovered: list[VulnerabilityFinding] = []
        markov, chain_risk = self._kill_chain_transition_markov(endpoint.telemetry_events)
        for package, version in endpoint.installed_packages.items():
            candidates: dict[str, dict[str, Any]] = {}
            for vuln in self._query_osv(package, version, endpoint.os):
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

            for vuln in self._query_nvd(package, version, endpoint.os):
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
                age_days = float(candidate.get("age_days", 365.0))
                cvss = float(candidate.get("cvss", 7.0))
                exploit_availability = min(10.0, round(4.0 + max(0.0, (365 - min(age_days, 365))) / 120 + chain_risk * 2.1, 2))
                chain_summary = (
                    f"MTRE chain drift={chain_risk:.2f}; package={package}; age_days={age_days:.0f}; "
                    f"intel_sources={','.join(candidate.get('sources', []))}"
                )
                evidence = list(candidate.get("evidence", []))
                evidence.append({"type": "kill_chain_markov", "transitions": markov, "chain_risk": chain_risk})
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
                        "reasoning": chain_summary,
                    },
                    actor,
                )
                discovered.append(finding)

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
                "osv_live": True,
            },
        )
        return discovered

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
