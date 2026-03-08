from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import time


class ExecutionSite(Enum):
    LOCAL = "local"
    REMOTE = "remote"
    PIVOT = "pivot"


class DeploymentVector(Enum):
    NONE = "none"
    SSH_KEY = "ssh_key"
    SSH_PASSWORD = "ssh_password"
    SSH_DEFAULT = "ssh_default"
    NETWORK_SHARE = "network_share"
    AGENT_CHANNEL = "agent_channel"
    UNAUTHENTICATED = "unauthenticated"


@dataclass
class VulnerabilitySignal:
    signal_id: str
    host: str
    severity: str
    category: str
    title: str
    detail: str
    vector: DeploymentVector
    cve_candidates: list[str] = field(default_factory=list)
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)
    confirmed: bool = False


@dataclass
class DroneExecutionContext:
    site: ExecutionSite = ExecutionSite.LOCAL
    target_host: str = ""
    deployment_vector: DeploymentVector = DeploymentVector.NONE
    deployment_attempted: bool = False
    deployment_succeeded: bool = False
    deployment_timestamp: float = 0.0
    deployment_evidence: dict[str, Any] = field(default_factory=dict)
    remote_session: Any = None
    pivot_chain: list[str] = field(default_factory=list)
    vulnerability_signals: list[VulnerabilitySignal] = field(default_factory=list)

    @property
    def is_remote(self) -> bool:
        return self.site in (ExecutionSite.REMOTE, ExecutionSite.PIVOT)

    @property
    def is_local(self) -> bool:
        return self.site == ExecutionSite.LOCAL

    def record_deployment_attempt(self, vector: DeploymentVector, target: str, evidence: dict[str, Any]) -> None:
        self.deployment_attempted = True
        self.deployment_vector = vector
        self.target_host = target
        self.deployment_evidence = evidence
        self.deployment_timestamp = time.time()

    def record_deployment_success(self, session: Any = None) -> None:
        self.deployment_succeeded = True
        self.site = ExecutionSite.REMOTE
        self.remote_session = session

    def record_deployment_failure(self, reason: str) -> None:
        self.deployment_succeeded = False
        self.site = ExecutionSite.LOCAL
        self.deployment_evidence["failure_reason"] = reason
