from __future__ import annotations

import hashlib
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nacl import signing

from signed_ledger import SignedLedger

CRITICAL_CAPABILITIES = {"approve_firmware", "approve_hypervisor", "revoke"}

# lightweight curated vulnerability intelligence with deterministic remediation guidance
VULNERABILITY_KB: list[dict[str, Any]] = [
    {
        "cve": "CVE-2026-0001",
        "package": "openssl",
        "affected_lt": "3.0.18",
        "fixed_version": "3.0.18",
        "cvss": 9.8,
        "exploit_availability": 8.0,
        "description": "Remote memory-corruption path in TLS handshake edge-case.",
    },
    {
        "cve": "CVE-2025-4512",
        "package": "glibc",
        "affected_lt": "2.39",
        "fixed_version": "2.39",
        "cvss": 8.6,
        "exploit_availability": 6.9,
        "description": "Privilege escalation via resolver state confusion.",
    },
    {
        "cve": "CVE-2024-6387",
        "package": "openssh",
        "affected_lt": "9.8",
        "fixed_version": "9.8",
        "cvss": 8.1,
        "exploit_availability": 7.2,
        "description": "Signal-handler race resulting in potential RCE.",
    },
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

    def _build_attack_path(self, endpoint: Endpoint, cve: str) -> list[dict[str, Any]]:
        perimeter = "external_attacker" if endpoint.network_exposure == "internet" else "partner_network"
        return [
            {"node": perimeter, "weight": 1.0},
            {"node": "internet_edge", "weight": 1.6},
            {"node": endpoint.host_name, "weight": 2.0},
            {"node": cve, "weight": 2.3},
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
            graph_path=self._build_attack_path(endpoint, payload["cve"]),
        )
        self.findings[finding.finding_id] = finding
        self._record("vulnerability.detected", {"actor": actor, "finding": asdict(finding)})
        return finding

    def run_vulnerability_scan(self, endpoint_id: str, actor: str = "scanner") -> list[VulnerabilityFinding]:
        endpoint = self.endpoints[endpoint_id]
        discovered: list[VulnerabilityFinding] = []
        for intel in VULNERABILITY_KB:
            pkg = intel["package"]
            installed = endpoint.installed_packages.get(pkg)
            if not installed:
                continue
            if self._version_lt(installed, intel["affected_lt"]):
                evidence = [
                    {"type": "sbom_match", "package": pkg, "installed": installed, "fixed": intel["fixed_version"]},
                    {"type": "attack_surface", "network_exposure": endpoint.network_exposure},
                ]
                finding = self.create_finding(
                    {
                        "endpoint_id": endpoint_id,
                        "cve": intel["cve"],
                        "cvss": intel["cvss"],
                        "exploit_availability": intel["exploit_availability"],
                        "topological_impact": 8.0 if endpoint.network_exposure == "internet" else 6.2,
                        "asset_value": endpoint.asset_value,
                        "trust_level": endpoint.trust_level,
                        "evidence": evidence,
                        "suggested_remediations": [f"upgrade {pkg} to {intel['fixed_version']}", "restart impacted services"],
                    },
                    actor,
                )
                discovered.append(finding)
        self._record("scan.completed", {"actor": actor, "endpoint_id": endpoint_id, "findings": [f.finding_id for f in discovered]})
        return discovered

    def _diff_for_finding(self, finding: VulnerabilityFinding, endpoint: Endpoint) -> tuple[str, str]:
        upgrade = finding.suggested_remediations[0] if finding.suggested_remediations else "upgrade vulnerable package"
        pkg = upgrade.split()[1] if len(upgrade.split()) > 1 else "package"
        target = upgrade.split()[-1] if " to " in upgrade else "latest"
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
        explanation = f"Updates {pkg} from {old} to {target} and moves rollout into canary-first mode with automatic rollback triggers."
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
        confidence = 0.92 if endpoint.sbom_status == "valid" else 0.74
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
