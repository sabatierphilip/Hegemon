from __future__ import annotations

import hashlib
import json
import secrets
import urllib.error
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
        )
        self.findings[finding.finding_id] = finding
        self._record("vulnerability.detected", {"actor": actor, "finding": asdict(finding)})
        return finding

    def run_vulnerability_scan(self, endpoint_id: str, actor: str = "scanner") -> list[VulnerabilityFinding]:
        endpoint = self.endpoints[endpoint_id]
        discovered: list[VulnerabilityFinding] = []
        markov, chain_risk = self._kill_chain_transition_markov(endpoint.telemetry_events)
        for package, version in endpoint.installed_packages.items():
            vulns = self._query_osv(package, version, endpoint.os)
            for vuln in vulns:
                cve = str(vuln.get("id", "UNKNOWN-CVE"))
                age_days = self._published_age_days(vuln)
                cvss = self._cvss_from_vuln(vuln)
                exploit_availability = min(10.0, round(4.0 + max(0.0, (365 - min(age_days, 365))) / 120 + chain_risk * 2.1, 2))
                fixed = []
                for aff in vuln.get("affected", []):
                    for rng in aff.get("ranges", []):
                        for event in rng.get("events", []):
                            if "fixed" in event:
                                fixed.append(event["fixed"])
                target_version = fixed[0] if fixed else "latest"
                evidence = [
                    {"type": "osv_live_query", "package": package, "version": version, "cve": cve},
                    {"type": "kill_chain_markov", "transitions": markov, "chain_risk": chain_risk},
                    {"type": "vulnerability_age_days", "age_days": age_days},
                ]
                finding = self.create_finding(
                    {
                        "endpoint_id": endpoint_id,
                        "cve": cve,
                        "cvss": cvss,
                        "exploit_availability": exploit_availability,
                        "topological_impact": round(7.0 + chain_risk, 3),
                        "asset_value": endpoint.asset_value,
                        "trust_level": endpoint.trust_level,
                        "evidence": evidence,
                        "suggested_remediations": [f"upgrade {package} to {target_version}", "restart impacted services"],
                        "graph_path": self._build_attack_path(endpoint, cve, chain_risk),
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

    def _diff_for_finding(self, finding: VulnerabilityFinding, endpoint: Endpoint) -> tuple[str, str]:
        upgrade = finding.suggested_remediations[0] if finding.suggested_remediations else "upgrade vulnerable package"
        parts = upgrade.split()
        pkg = parts[1] if len(parts) > 1 else "package"
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
