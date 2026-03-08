from __future__ import annotations

import logging
import socket
import time
from dataclasses import dataclass
from pathlib import Path

from sentinel_containment.agents.hannibal.deployment_reasoner import DeploymentAttempt
from sentinel_containment.drone_execution_context import (
    DeploymentVector,
    DroneExecutionContext,
    ExecutionSite,
    VulnerabilitySignal,
)

logger = logging.getLogger(__name__)

try:
    import paramiko  # type: ignore

    _PARAMIKO_AVAILABLE = True
except Exception:
    _PARAMIKO_AVAILABLE = False


@dataclass
class RemoteCommandResult:
    stdout: str
    stderr: str
    exit_code: int
    host: str
    command: str
    duration_ms: float


class RemoteExecutor:
    MAX_AUTH_ATTEMPTS = 3
    DEFAULT_CREDENTIALS = [("root", ""), ("admin", "admin"), ("ubuntu", "ubuntu")]

    def attempt_deployment(self, attempt: DeploymentAttempt, target_host: str, ctx: DroneExecutionContext):
        ctx.record_deployment_attempt(attempt.vector, target_host, dict(attempt.params))
        if attempt.vector in (DeploymentVector.SSH_KEY, DeploymentVector.SSH_PASSWORD):
            return self._try_ssh_credential(attempt, target_host, ctx)
        if attempt.vector == DeploymentVector.SSH_DEFAULT:
            return self._try_ssh_defaults(attempt, target_host, ctx)
        if attempt.vector == DeploymentVector.NETWORK_SHARE:
            return self._try_smb_share(attempt, target_host, ctx)
        if attempt.vector == DeploymentVector.UNAUTHENTICATED:
            return self._try_unauthenticated(attempt, target_host, ctx)
        return False, None

    def _try_ssh_credential(self, attempt: DeploymentAttempt, host: str, ctx: DroneExecutionContext):
        if not _PARAMIKO_AVAILABLE:
            ctx.record_deployment_failure("paramiko unavailable")
            return False, VulnerabilitySignal(
                signal_id=f"deploy-{host}-ssh-noparamiko",
                host=host,
                severity="info",
                category="tool_unavailable",
                title="SSH probe skipped",
                detail="paramiko is unavailable",
                vector=attempt.vector,
                remediation="Install paramiko",
            )
        port = int(attempt.params.get("port", 22))
        username = str(attempt.params.get("username", "root") or "root")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            if attempt.vector == DeploymentVector.SSH_KEY:
                key_path = str(attempt.params.get("key_path", ""))
                if not key_path or not Path(key_path).exists():
                    ctx.record_deployment_failure("key file not found")
                    return False, None
                client.connect(host, port=port, username=username, key_filename=key_path, timeout=5, allow_agent=False, look_for_keys=False)
            else:
                password = str(attempt.params.get("password", ""))
                if not password:
                    ctx.record_deployment_failure("password unavailable")
                    return False, VulnerabilitySignal(
                        signal_id=f"cred-{host}-ssh-hash-only",
                        host=host,
                        severity="medium",
                        category="credential_exposure",
                        title="SSH credential metadata found",
                        detail="Only hash/metadata available; no plaintext password for live auth attempt.",
                        vector=attempt.vector,
                        remediation="Rotate and audit credential exposure",
                    )
                client.connect(host, port=port, username=username, password=password, timeout=5, allow_agent=False, look_for_keys=False)
            ctx.record_deployment_success(session=client)
            signal = VulnerabilitySignal(
                signal_id=f"deploy-{host}-ssh-success",
                host=host,
                severity="high",
                category="credential_exposure",
                title="SSH credential valid",
                detail=f"Connected to {host}:{port} as {username}",
                vector=attempt.vector,
                remediation="Rotate credential and review SSH logs",
                confirmed=True,
            )
            ctx.vulnerability_signals.append(signal)
            return True, signal
        except Exception as exc:
            ctx.record_deployment_failure(type(exc).__name__)
            try:
                client.close()
            except Exception:
                pass
            return False, None

    def _try_ssh_defaults(self, attempt: DeploymentAttempt, host: str, ctx: DroneExecutionContext):
        if not _PARAMIKO_AVAILABLE:
            ctx.record_deployment_failure("paramiko unavailable")
            return False, None
        port = int(attempt.params.get("port", 22))
        max_attempts = min(int(attempt.params.get("max_attempts", 3)), self.MAX_AUTH_ATTEMPTS)
        for username, password in self.DEFAULT_CREDENTIALS[:max_attempts]:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(host, port=port, username=username, password=password, timeout=5, allow_agent=False, look_for_keys=False)
                ctx.record_deployment_success(session=client)
                signal = VulnerabilitySignal(
                    signal_id=f"deploy-{host}-ssh-default",
                    host=host,
                    severity="critical",
                    category="credential_exposure",
                    title="Default SSH credentials accepted",
                    detail=f"{username}:{password!r} authenticated on {host}:{port}",
                    vector=attempt.vector,
                    remediation="Rotate defaults immediately",
                    confirmed=True,
                )
                ctx.vulnerability_signals.append(signal)
                return True, signal
            except Exception:
                try:
                    client.close()
                except Exception:
                    pass
                continue
        ctx.record_deployment_failure("default credentials rejected")
        return False, VulnerabilitySignal(
            signal_id=f"deploy-{host}-ssh-nodefault",
            host=host,
            severity="info",
            category="service_exposure",
            title="Default SSH credentials rejected",
            detail="Tested default credential shortlist and all failed",
            vector=attempt.vector,
            remediation="No action needed for this check",
        )

    def _try_smb_share(self, attempt: DeploymentAttempt, host: str, ctx: DroneExecutionContext):
        port = int(attempt.params.get("port", 445))
        try:
            with socket.create_connection((host, port), timeout=3):
                pass
            ctx.record_deployment_failure("SMB open but no authenticated deploy channel")
            return False, VulnerabilitySignal(
                signal_id=f"deploy-{host}-smb-open",
                host=host,
                severity="medium",
                category="service_exposure",
                title="SMB service exposed",
                detail=f"{host}:{port} accepted SMB connection",
                vector=attempt.vector,
                remediation="Restrict SMB exposure",
            )
        except Exception as exc:
            ctx.record_deployment_failure(type(exc).__name__)
            return False, None

    def _try_unauthenticated(self, attempt: DeploymentAttempt, host: str, ctx: DroneExecutionContext):
        port = int(attempt.params.get("port", 0) or 0)
        svc = str(attempt.params.get("service", "unknown"))
        ctx.record_deployment_failure("service-specific unauthenticated deploy not implemented")
        return False, VulnerabilitySignal(
            signal_id=f"deploy-{host}-unauth-{port}",
            host=host,
            severity="critical",
            category="auth_bypass",
            title="Unauthenticated service exposure",
            detail=f"{svc} on {host}:{port} appears unauthenticated",
            vector=attempt.vector,
            remediation="Enforce auth and network ACLs",
        )

    def exec_remote(self, ctx: DroneExecutionContext, command: str, timeout: int = 30) -> RemoteCommandResult:
        if not ctx.is_remote or ctx.remote_session is None:
            raise RuntimeError("remote session unavailable")
        start = time.time()
        stdin, stdout, stderr = ctx.remote_session.exec_command(command, timeout=timeout)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        code = int(stdout.channel.recv_exit_status())
        return RemoteCommandResult(
            stdout=out,
            stderr=err,
            exit_code=code,
            host=ctx.target_host,
            command=command,
            duration_ms=(time.time() - start) * 1000.0,
        )

    def close(self, ctx: DroneExecutionContext) -> None:
        if ctx.remote_session is not None:
            try:
                ctx.remote_session.close()
            except Exception:
                pass
        ctx.remote_session = None
        ctx.site = ExecutionSite.LOCAL
