from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nacl import signing

from signed_ledger import SignedLedger


CRITICAL_CAPABILITIES = {"approve_firmware", "approve_hypervisor", "revoke"}


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


@dataclass
class PatchProposal:
    proposal_id: str
    endpoint_id: str
    finding_id: str
    summary: str
    change_plan: list[str]
    test_results: dict[str, str]
    graph_path_before: list[str]
    graph_path_after: list[str]
    regression_risk: float
    confidence: float
    impact_score: float
    approvals_required: int
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

    def disable_friend(self, friend_id: str, actor: str) -> Friend:
        friend = self.friends[friend_id]
        friend.status = "disabled"
        self._record("friend.revoked", {"actor": actor, "friend_id": friend_id})
        return friend

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
        )
        if endpoint.endpoint_type == "app-store-package" and not endpoint.publisher_signature:
            raise ValueError("app-store-package endpoints require publisher_signature")
        self.endpoints[endpoint.endpoint_id] = endpoint
        self._record("endpoint.added", {"actor": actor, "endpoint": asdict(endpoint)})
        return endpoint

    @staticmethod
    def compute_risk_score(cvss: float, exploit_availability: float, topological_impact: float, asset_value: float, trust_level: float) -> float:
        alpha, beta, gamma, delta, epsilon = 0.40, 0.20, 0.20, 0.15, 0.05
        return round(
            alpha * cvss + beta * exploit_availability + gamma * topological_impact + delta * asset_value + epsilon * (10 - trust_level),
            3,
        )

    def create_finding(self, payload: dict[str, Any], actor: str) -> VulnerabilityFinding:
        finding_id = payload.get("finding_id") or f"vuln-{secrets.token_hex(4)}"
        risk = self.compute_risk_score(
            float(payload.get("cvss", 0.0)),
            float(payload.get("exploit_availability", 0.0)),
            float(payload.get("topological_impact", 0.0)),
            float(payload.get("asset_value", 0.0)),
            float(payload.get("trust_level", 5.0)),
        )
        finding = VulnerabilityFinding(
            finding_id=finding_id,
            endpoint_id=payload["endpoint_id"],
            cve=payload["cve"],
            cvss=float(payload.get("cvss", 0.0)),
            exploit_availability=float(payload.get("exploit_availability", 0.0)),
            topological_impact=float(payload.get("topological_impact", 0.0)),
            asset_value=float(payload.get("asset_value", 0.0)),
            trust_level=float(payload.get("trust_level", 5.0)),
            evidence=payload.get("evidence", []),
            suggested_remediations=payload.get("suggested_remediations", []),
            risk_score=risk,
        )
        self.findings[finding.finding_id] = finding
        self._record("vulnerability.detected", {"actor": actor, "finding": asdict(finding)})
        return finding

    def generate_patch_proposal(self, finding_id: str, actor: str) -> PatchProposal:
        finding = self.findings[finding_id]
        endpoint = self.endpoints[finding.endpoint_id]
        before_path = ["external_attacker", "internet_edge", endpoint.host_name, finding.cve]
        after_path = ["external_attacker", "internet_edge", endpoint.host_name]
        impact = max(0.0, len(before_path) - len(after_path)) + round(finding.risk_score / 10, 2)
        regression_risk = 2.5 if endpoint.endpoint_type == "app-store-package" else 1.2
        confidence = 0.92 if endpoint.sbom_status == "valid" else 0.74
        proposal_id = hashlib.sha256(f"{finding_id}:{endpoint.endpoint_id}".encode("utf-8")).hexdigest()[:12]
        change_plan = finding.suggested_remediations or [f"Upgrade vulnerable package for {finding.cve}"]
        approvals_required = 2 if endpoint.hypervisor or endpoint.firmware_baseline else 1
        proposal = PatchProposal(
            proposal_id=proposal_id,
            endpoint_id=endpoint.endpoint_id,
            finding_id=finding_id,
            summary=f"Remediate {finding.cve} on {endpoint.host_name}",
            change_plan=change_plan,
            test_results={"unit": "pass", "integration": "pass", "compatibility": "pass"},
            graph_path_before=before_path,
            graph_path_after=after_path,
            regression_risk=regression_risk,
            confidence=confidence,
            impact_score=impact,
            approvals_required=approvals_required,
            rollout_policy={"rings": ["canary", "staging", "production"], "rollback_on": ["healthcheck_failure"]},
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
