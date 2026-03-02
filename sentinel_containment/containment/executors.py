from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any


@dataclass
class ActionExecutionResult:
    action: str
    status: str
    details: dict[str, Any]


class ContainmentActionExecutor:
    """Executes defensive containment actions against local hosts/cloud control planes.

    The executor defaults to dry-run mode for safety. Set ``active_mode=True`` (and configure
    cloud credentials/iptables privileges) to perform live containment changes.
    """

    def __init__(self, active_mode: bool = False, aws_region: str | None = None):
        self.active_mode = active_mode
        self.aws_region = aws_region or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")

    def execute(self, host: str, action: str, context: dict[str, Any] | None = None) -> ActionExecutionResult:
        payload = context or {}
        if action == "disable_outbound_traffic":
            return self._disable_outbound_traffic(host, payload)
        if action == "disable_iam_sessions":
            return self._disable_iam_sessions(payload)
        if action == "sinkhole_suspicious_destinations":
            return self._sinkhole_destinations(payload)
        if action == "quarantine_host":
            return self._quarantine_host(host)
        return ActionExecutionResult(action=action, status="simulated", details={"reason": "no_live_executor"})

    def _quarantine_host(self, host: str) -> ActionExecutionResult:
        # OS-level quarantine falls back to outbound block semantics.
        return self._disable_outbound_traffic(host, {"quarantine": True})

    def _disable_outbound_traffic(self, host: str, payload: dict[str, Any]) -> ActionExecutionResult:
        binary = shutil.which("iptables") or shutil.which("nft")
        if not binary:
            return ActionExecutionResult(
                action="disable_outbound_traffic",
                status="skipped",
                details={"reason": "iptables_or_nft_not_available", "host": host},
            )

        if os.path.basename(binary) == "iptables":
            cmd = [binary, "-A", "OUTPUT", "-j", "DROP"]
        else:
            cmd = [binary, "add", "rule", "inet", "filter", "output", "drop"]

        if not self.active_mode:
            return ActionExecutionResult(
                action="disable_outbound_traffic",
                status="simulated",
                details={"command": shlex.join(cmd), "host": host, "payload": payload},
            )

        completed = subprocess.run(cmd, check=False, capture_output=True, text=True)
        status = "executed" if completed.returncode == 0 else "failed"
        return ActionExecutionResult(
            action="disable_outbound_traffic",
            status=status,
            details={
                "command": shlex.join(cmd),
                "returncode": completed.returncode,
                "stdout": completed.stdout.strip(),
                "stderr": completed.stderr.strip(),
                "host": host,
                "payload": payload,
            },
        )

    def _disable_iam_sessions(self, payload: dict[str, Any]) -> ActionExecutionResult:
        role_name = str(payload.get("aws_role_name", "")).strip()
        if not role_name:
            return ActionExecutionResult(
                action="disable_iam_sessions",
                status="skipped",
                details={"reason": "missing_aws_role_name"},
            )

        if not self.active_mode:
            return ActionExecutionResult(
                action="disable_iam_sessions",
                status="simulated",
                details={"provider": "aws", "role_name": role_name},
            )

        try:
            import boto3

            iam = boto3.client("iam", region_name=self.aws_region)
            policy_name = f"sentinel-deny-{role_name}"[:128]
            policy_doc = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Action": "*",
                        "Resource": "*",
                    }
                ],
            }
            iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=str(policy_doc).replace("'", '"'))
            return ActionExecutionResult(
                action="disable_iam_sessions",
                status="executed",
                details={"provider": "aws", "role_name": role_name, "policy_name": policy_name},
            )
        except Exception as exc:  # noqa: BLE001 - containment must not crash control loop
            return ActionExecutionResult(
                action="disable_iam_sessions",
                status="failed",
                details={"provider": "aws", "role_name": role_name, "error": str(exc)},
            )

    def _sinkhole_destinations(self, payload: dict[str, Any]) -> ActionExecutionResult:
        destinations = payload.get("destinations")
        if not isinstance(destinations, list) or not destinations:
            return ActionExecutionResult(
                action="sinkhole_suspicious_destinations",
                status="skipped",
                details={"reason": "missing_destinations"},
            )

        normalized = [str(d).strip() for d in destinations if str(d).strip()]
        if not normalized:
            return ActionExecutionResult(
                action="sinkhole_suspicious_destinations",
                status="skipped",
                details={"reason": "empty_destinations"},
            )

        if not self.active_mode:
            return ActionExecutionResult(
                action="sinkhole_suspicious_destinations",
                status="simulated",
                details={"destinations": normalized, "sinkhole_ip": payload.get("sinkhole_ip", "127.0.0.1")},
            )

        hosts_path = payload.get("hosts_override_path", "/etc/hosts")
        sinkhole_ip = str(payload.get("sinkhole_ip", "127.0.0.1"))
        try:
            with open(hosts_path, "a", encoding="utf-8") as hosts_file:
                for destination in normalized:
                    hosts_file.write(f"\n{sinkhole_ip} {destination}\n")
            return ActionExecutionResult(
                action="sinkhole_suspicious_destinations",
                status="executed",
                details={"destinations": normalized, "sinkhole_ip": sinkhole_ip, "hosts_path": hosts_path},
            )
        except Exception as exc:  # noqa: BLE001
            return ActionExecutionResult(
                action="sinkhole_suspicious_destinations",
                status="failed",
                details={"destinations": normalized, "sinkhole_ip": sinkhole_ip, "error": str(exc)},
            )
