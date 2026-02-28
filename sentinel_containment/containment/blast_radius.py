from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class BlastRadiusReport:
    compromised_credentials: list[str]
    impacted_hosts: list[str]
    impacted_resources: list[str]
    estimated_impact_score: int
    rationale: str


class CredentialBlastRadiusAnalyzer:
    """Estimates the spread if suspicious credentials were abused laterally."""

    suspicious_action_tokens = ("login", "privilege", "token", "credential", "iam")

    def analyze(self, events: list[dict[str, Any]], topology: dict[str, Any]) -> BlastRadiusReport:
        suspicious_users: set[str] = set()
        impacted_hosts: set[str] = set()
        impacted_resources: set[str] = set()

        for event in events:
            action = str(event.get("action", "")).lower()
            user = str(event.get("user", "unknown"))
            host = str(event.get("host", "unknown"))
            resource = str(event.get("resource", "unknown"))

            high_risk = any(token in action for token in self.suspicious_action_tokens)
            high_risk = high_risk or float(event.get("egress_mb", 0) or 0) > 600
            high_risk = high_risk or float(event.get("api_call_count", 0) or 0) > 700

            if high_risk and user != "unknown":
                suspicious_users.add(user)

            if user in suspicious_users and host != "unknown":
                impacted_hosts.add(host)
            if user in suspicious_users and resource != "unknown":
                impacted_resources.add(resource)

        for edge in topology.get("edges", []):
            source = str(edge.get("source", ""))
            target = str(edge.get("target", ""))
            if any(host in source for host in impacted_hosts):
                impacted_resources.add(target)
            if any(host in target for host in impacted_hosts):
                impacted_resources.add(source)

        score = min(100, 30 + len(suspicious_users) * 12 + len(impacted_hosts) * 8 + len(impacted_resources) * 5)
        rationale = (
            f"{len(suspicious_users)} credential(s) map to {len(impacted_hosts)} host(s) and "
            f"{len(impacted_resources)} reachable asset(s)"
        )
        return BlastRadiusReport(
            compromised_credentials=sorted(suspicious_users),
            impacted_hosts=sorted(impacted_hosts),
            impacted_resources=sorted(impacted_resources),
            estimated_impact_score=score,
            rationale=rationale,
        )
