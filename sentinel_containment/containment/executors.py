from __future__ import annotations

import fcntl
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-zA-Z0-9._-]+(?<!-)$")


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
        return self._disable_outbound_traffic(host, {"quarantine": True})

    @staticmethod
    def _safe_run(cmd: list[str], timeout_seconds: int = 5) -> subprocess.CompletedProcess[str]:
        return subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=timeout_seconds)

    @staticmethod
    def _has_root_privileges() -> bool:
        geteuid = getattr(os, "geteuid", None)
        return bool(geteuid and geteuid() == 0)

    def _disable_outbound_traffic(self, host: str, payload: dict[str, Any]) -> ActionExecutionResult:
        binary = shutil.which("iptables") or shutil.which("nft")
        if not binary:
            return ActionExecutionResult(
                action="disable_outbound_traffic",
                status="skipped",
                details={"reason": "iptables_or_nft_not_available", "host": host},
            )

        binary_name = os.path.basename(binary)
        if binary_name == "iptables":
            check_cmd = [binary, "-C", "OUTPUT", "-j", "DROP"]
            apply_cmd = [binary, "-A", "OUTPUT", "-j", "DROP"]
        else:
            check_cmd = [binary, "list", "chain", "inet", "filter", "output"]
            apply_cmd = [binary, "add", "rule", "inet", "filter", "output", "drop"]

        if not self.active_mode:
            return ActionExecutionResult(
                action="disable_outbound_traffic",
                status="simulated",
                details={"command": shlex.join(apply_cmd), "host": host, "payload": payload},
            )

        if not self._has_root_privileges():
            return ActionExecutionResult(
                action="disable_outbound_traffic",
                status="skipped",
                details={"reason": "insufficient_privileges", "requires": "root", "host": host},
            )

        try:
            if binary_name == "iptables":
                check = self._safe_run(check_cmd)
                if check.returncode == 0:
                    return ActionExecutionResult(
                        action="disable_outbound_traffic",
                        status="no-op",
                        details={"reason": "rule_already_present", "command": shlex.join(check_cmd), "host": host},
                    )
            else:
                check = self._safe_run(check_cmd)
                if check.returncode == 0 and " drop" in check.stdout:
                    return ActionExecutionResult(
                        action="disable_outbound_traffic",
                        status="no-op",
                        details={"reason": "rule_already_present", "command": shlex.join(check_cmd), "host": host},
                    )

            completed = self._safe_run(apply_cmd)
            status = "executed" if completed.returncode == 0 else "failed"
            return ActionExecutionResult(
                action="disable_outbound_traffic",
                status=status,
                details={
                    "command": shlex.join(apply_cmd),
                    "returncode": completed.returncode,
                    "stderr": completed.stderr.strip()[:256],
                    "host": host,
                    "payload": payload,
                },
            )
        except subprocess.TimeoutExpired:
            return ActionExecutionResult(
                action="disable_outbound_traffic",
                status="failed",
                details={"reason": "command_timeout", "command": shlex.join(apply_cmd), "host": host},
            )
        except Exception as exc:  # noqa: BLE001
            return ActionExecutionResult(
                action="disable_outbound_traffic",
                status="failed",
                details={"reason": "execution_error", "error": str(exc), "host": host},
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
            iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc, separators=(",", ":")))
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

        normalized = [str(d).strip().lower() for d in destinations if str(d).strip()]
        valid = [d for d in normalized if _HOSTNAME_RE.match(d)]
        invalid = [d for d in normalized if d not in valid]
        if not valid:
            return ActionExecutionResult(
                action="sinkhole_suspicious_destinations",
                status="skipped",
                details={"reason": "no_valid_destinations", "invalid_destinations": invalid[:10]},
            )

        hosts_path = Path(str(payload.get("hosts_override_path", "/etc/hosts")))
        sinkhole_ip = str(payload.get("sinkhole_ip", "127.0.0.1"))

        if not self.active_mode:
            return ActionExecutionResult(
                action="sinkhole_suspicious_destinations",
                status="simulated",
                details={"destinations": valid, "invalid_destinations": invalid, "sinkhole_ip": sinkhole_ip},
            )

        if not self._has_root_privileges() and str(hosts_path) == "/etc/hosts":
            return ActionExecutionResult(
                action="sinkhole_suspicious_destinations",
                status="skipped",
                details={"reason": "insufficient_privileges", "requires": "root", "hosts_path": str(hosts_path)},
            )

        try:
            hosts_path.parent.mkdir(parents=True, exist_ok=True)
            if not hosts_path.exists():
                hosts_path.write_text("", encoding="utf-8")

            with hosts_path.open("r+", encoding="utf-8") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                current = handle.read()
                lines = [line.strip() for line in current.splitlines() if line.strip()]
                existing = set(lines)
                additions = [f"{sinkhole_ip} {destination}" for destination in valid if f"{sinkhole_ip} {destination}" not in existing]
                if not additions:
                    return ActionExecutionResult(
                        action="sinkhole_suspicious_destinations",
                        status="no-op",
                        details={"reason": "entries_already_present", "hosts_path": str(hosts_path), "invalid_destinations": invalid},
                    )

                fd, tmp_path_str = tempfile.mkstemp(prefix="hosts.", dir=str(hosts_path.parent))
                tmp_path = Path(tmp_path_str)
                try:
                    with os.fdopen(fd, "w", encoding="utf-8") as tmp_file:
                        tmp_file.write(current)
                        if current and not current.endswith("\n"):
                            tmp_file.write("\n")
                        for entry in additions:
                            tmp_file.write(entry + "\n")
                        tmp_file.flush()
                        os.fsync(tmp_file.fileno())

                    backup = hosts_path.with_suffix(hosts_path.suffix + ".bak")
                    shutil.copy2(hosts_path, backup)
                    os.replace(tmp_path, hosts_path)
                finally:
                    if tmp_path.exists():
                        tmp_path.unlink(missing_ok=True)

            return ActionExecutionResult(
                action="sinkhole_suspicious_destinations",
                status="executed",
                details={
                    "added": len(additions),
                    "destinations": valid,
                    "invalid_destinations": invalid,
                    "sinkhole_ip": sinkhole_ip,
                    "hosts_path": str(hosts_path),
                },
            )
        except Exception as exc:  # noqa: BLE001
            return ActionExecutionResult(
                action="sinkhole_suspicious_destinations",
                status="failed",
                details={"destinations": valid, "sinkhole_ip": sinkhole_ip, "error": str(exc), "hosts_path": str(hosts_path)},
            )
