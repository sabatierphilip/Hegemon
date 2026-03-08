from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sentinel_containment.agents.hannibal.campaign_state import CampaignState
from sentinel_containment.drone_execution_context import DeploymentVector


@dataclass
class DeploymentAttempt:
    vector: DeploymentVector
    priority: int
    credential_ref: str
    params: dict[str, Any] = field(default_factory=dict)
    rationale: str = ""


@dataclass
class DeploymentPlan:
    drone_id: str
    target_host: str
    attempts: list[DeploymentAttempt] = field(default_factory=list)
    reasoning: str = ""
    fallback_mode: str = "remote_probe"


class DeploymentReasoner:
    REQUIRES_REMOTE_EXECUTION = {
        "credential_probe",
        "ptrace_inspect",
        "manage_service",
        "exec_remediation",
        "log_tail",
        "self_destruct",
        "inotify_watch",
    }

    def reason(self, drone_id: str, drone_type: str, target_host: str, campaign: CampaignState | None) -> DeploymentPlan:
        plan = DeploymentPlan(drone_id=drone_id, target_host=target_host)
        host_info = self._get_host_info(target_host, campaign)
        credentials = self._get_credentials_for_host(target_host, campaign)
        services = host_info.get("services", {}) if isinstance(host_info, dict) else {}
        open_ports = list(host_info.get("open_ports", [])) if isinstance(host_info, dict) else []

        reasoning_parts = [
            f"Target: {target_host}",
            f"Known open ports: {open_ports}",
            f"Known services: {list(services.keys()) if isinstance(services, dict) else []}",
            f"Available credentials: {len(credentials)}",
        ]

        priority = 1
        if 22 in open_ports and credentials:
            for cred_ref, cred in credentials.items():
                ctype = str(cred.get("type", "")).lower()
                if ctype in {"ssh_key", "ssh_password", "password"}:
                    vector = DeploymentVector.SSH_KEY if ctype == "ssh_key" else DeploymentVector.SSH_PASSWORD
                    plan.attempts.append(
                        DeploymentAttempt(
                            vector=vector,
                            priority=priority,
                            credential_ref=cred_ref,
                            params={
                                "port": 22,
                                "username": cred.get("username", "root"),
                                "key_path": cred.get("key_path", ""),
                                "password": cred.get("value", ""),
                                "password_hash": cred.get("value_hash", ""),
                            },
                            rationale="Discovered SSH credential; successful deployment confirms credential exposure.",
                        )
                    )
                    priority += 1

        if 22 in open_ports and not credentials:
            plan.attempts.append(
                DeploymentAttempt(
                    vector=DeploymentVector.SSH_DEFAULT,
                    priority=priority,
                    credential_ref="",
                    params={"port": 22, "try_defaults": True, "max_attempts": 3},
                    rationale="Probe for default SSH credentials.",
                )
            )
            priority += 1

        if 445 in open_ports:
            plan.attempts.append(
                DeploymentAttempt(
                    vector=DeploymentVector.NETWORK_SHARE,
                    priority=priority,
                    credential_ref="",
                    params={"port": 445, "protocol": "smb"},
                    rationale="Probe for writable SMB share.",
                )
            )
            priority += 1

        if isinstance(services, dict):
            for port, service in services.items():
                if isinstance(service, dict) and service.get("auth_required") is False:
                    plan.attempts.append(
                        DeploymentAttempt(
                            vector=DeploymentVector.UNAUTHENTICATED,
                            priority=priority,
                            credential_ref="",
                            params={"port": int(port), "service": str(service.get("name", ""))},
                            rationale="Unauthenticated service exposed.",
                        )
                    )
                    priority += 1

        if not plan.attempts:
            plan.fallback_mode = "remote_probe_only"
            reasoning_parts.append("No viable deployment vectors; remote-required nodes will be skipped.")
        else:
            plan.fallback_mode = "remote_probe_on_all_fail"
            reasoning_parts.append(f"Will attempt {len(plan.attempts)} deployment vector(s) in priority order.")

        plan.reasoning = "\n".join(reasoning_parts)
        return plan

    def _get_host_info(self, host: str, campaign: CampaignState | None) -> dict[str, Any]:
        if campaign is None:
            return {"ip": host, "open_ports": [], "services": {}}
        mapped = getattr(campaign, "mapped_hosts", {})
        if isinstance(mapped, dict):
            value = mapped.get(host)
            if isinstance(value, dict):
                return {"ip": host, **value}
        return {"ip": host, "open_ports": [], "services": {}}

    def _get_credentials_for_host(self, host: str, campaign: CampaignState | None) -> dict[str, Any]:
        if campaign is None:
            return {}
        creds: dict[str, Any] = {}
        for idx, finding in enumerate(getattr(campaign, "credential_findings", [])):
            if not isinstance(finding, dict):
                continue
            cred_id = str(finding.get("id") or f"cred-{idx}")
            creds[cred_id] = {
                "type": finding.get("type", "unknown"),
                "username": finding.get("username", ""),
                "key_path": finding.get("key_path", ""),
                "value": finding.get("value", ""),
                "value_hash": finding.get("value_hash", ""),
                "source_host": finding.get("source_host", ""),
            }
        return creds
