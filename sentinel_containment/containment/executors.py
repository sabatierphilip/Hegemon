from __future__ import annotations

import fcntl
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import tempfile
from datetime import datetime, timezone
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
        if action == "block_lateral_movement_paths":
            return self._block_lateral_movement_paths(host, payload)
        if action == "forensic_snapshot_metadata":
            return self._forensic_snapshot_metadata(host, payload)
        if action == "kill_active_model_sessions":
            return self._kill_active_model_sessions(host, payload)
        if action == "pause_model_serving_container":
            return self._pause_model_serving_container(host, payload)
        if action == "revoke_rotate_api_keys":
            return self._revoke_rotate_api_keys(host, payload)
        if action == "harden_ssh_lateral_paths":
            return self._harden_ssh_lateral_paths(host, payload)
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

    @staticmethod
    def _state_file(payload: dict[str, Any], key: str, default_name: str) -> Path:
        return Path(str(payload.get(key, f"data/{default_name}")))

    def _block_lateral_movement_paths(self, host: str, payload: dict[str, Any]) -> ActionExecutionResult:
        blocked = [str(v).strip() for v in payload.get("lateral_paths", ["ssh", "docker_socket", "kubelet_api"]) if str(v).strip()]
        if not blocked:
            return ActionExecutionResult(action="block_lateral_movement_paths", status="skipped", details={"reason": "missing_lateral_paths", "host": host})

        registry = self._state_file(payload, "lateral_block_registry_path", "lateral_blocks.json")
        registry.parent.mkdir(parents=True, exist_ok=True)
        existing: dict[str, Any] = {}
        if registry.exists():
            try:
                existing = json.loads(registry.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                existing = {}
        host_entries = set(existing.get(host, []))
        additions = [entry for entry in blocked if entry not in host_entries]
        host_entries.update(blocked)
        existing[host] = sorted(host_entries)
        registry.write_text(json.dumps(existing, indent=2, sort_keys=True), encoding="utf-8")

        ssh_hardening: dict[str, Any] = {}
        if any(path.lower() == "ssh" or "ssh" in path.lower() for path in blocked):
            ssh_result = self._harden_ssh_lateral_paths(host, payload)
            ssh_hardening = {
                "status": ssh_result.status,
                "details": ssh_result.details,
            }

        return ActionExecutionResult(
            action="block_lateral_movement_paths",
            status="executed" if additions else "no-op",
            details={
                "host": host,
                "blocked_paths": sorted(host_entries),
                "new_blocks": additions,
                "registry_path": str(registry),
                "ssh_hardening": ssh_hardening,
            },
        )

    def _forensic_snapshot_metadata(self, host: str, payload: dict[str, Any]) -> ActionExecutionResult:
        snapshot_dir = self._state_file(payload, "forensic_snapshot_dir", "forensic_snapshots")
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        snapshot = snapshot_dir / f"snapshot-{host}-{timestamp}.json"

        process_capture = self._safe_run(["ps", "-eo", "pid,ppid,user,comm,args"], timeout_seconds=8)
        net_capture = self._safe_run(["sh", "-c", "ss -tunap 2>/dev/null || netstat -an 2>/dev/null || true"], timeout_seconds=8)
        payload_doc = {
            "host": host,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "collector": "containment_executor",
            "process_table": process_capture.stdout.splitlines()[:500],
            "network_sockets": net_capture.stdout.splitlines()[:500],
            "metadata": {k: v for k, v in payload.items() if k != "forensic_snapshot_dir"},
        }
        snapshot.write_text(json.dumps(payload_doc, indent=2, sort_keys=True), encoding="utf-8")
        return ActionExecutionResult(
            action="forensic_snapshot_metadata",
            status="executed",
            details={"snapshot_path": str(snapshot), "process_rows": len(payload_doc["process_table"]), "socket_rows": len(payload_doc["network_sockets"])},
        )

    def _kill_active_model_sessions(self, host: str, payload: dict[str, Any]) -> ActionExecutionResult:
        pids = [int(pid) for pid in payload.get("model_session_pids", []) if str(pid).isdigit()]
        if not pids:
            return ActionExecutionResult(
                action="kill_active_model_sessions",
                status="skipped",
                details={"reason": "no_model_session_pids", "host": host},
            )

        terminated: list[int] = []
        failed: dict[int, str] = {}
        for pid in pids:
            try:
                if self.active_mode:
                    os.kill(pid, signal.SIGTERM)
                terminated.append(pid)
            except ProcessLookupError:
                failed[pid] = "not_found"
            except PermissionError:
                failed[pid] = "permission_denied"
            except Exception as exc:  # noqa: BLE001
                failed[pid] = str(exc)

        status = "executed" if terminated and not failed else "failed" if not terminated and failed else "partial"
        return ActionExecutionResult(
            action="kill_active_model_sessions",
            status=status if self.active_mode else "simulated",
            details={"requested_pids": pids, "terminated_pids": terminated, "failed_pids": failed, "host": host},
        )

    def _pause_model_serving_container(self, host: str, payload: dict[str, Any]) -> ActionExecutionResult:
        container_id = str(payload.get("container_id", "")).strip()
        if not container_id:
            return ActionExecutionResult(
                action="pause_model_serving_container",
                status="skipped",
                details={"reason": "missing_container_id", "host": host},
            )

        runtime = shutil.which("docker") or shutil.which("podman")
        if not runtime:
            state = self._state_file(payload, "paused_container_registry_path", "paused_containers.json")
            state.parent.mkdir(parents=True, exist_ok=True)
            current = {"containers": []}
            if state.exists():
                try:
                    current = json.loads(state.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    current = {"containers": []}
            containers = set(current.get("containers", []))
            containers.add(container_id)
            current["containers"] = sorted(containers)
            state.write_text(json.dumps(current, indent=2, sort_keys=True), encoding="utf-8")
            return ActionExecutionResult(
                action="pause_model_serving_container",
                status="executed",
                details={"runtime": "registry_only", "container_id": container_id, "registry_path": str(state)},
            )

        cmd = [runtime, "pause", container_id]
        if not self.active_mode:
            return ActionExecutionResult(action="pause_model_serving_container", status="simulated", details={"command": shlex.join(cmd), "host": host})
        completed = self._safe_run(cmd, timeout_seconds=10)
        return ActionExecutionResult(
            action="pause_model_serving_container",
            status="executed" if completed.returncode == 0 else "failed",
            details={"command": shlex.join(cmd), "returncode": completed.returncode, "stderr": completed.stderr.strip()[:256], "host": host},
        )


    def _harden_ssh_lateral_paths(self, host: str, payload: dict[str, Any]) -> ActionExecutionResult:
        principals = [str(v).strip() for v in payload.get("ssh_blocked_principals", ["root"]) if str(v).strip()]
        source_networks = [str(v).strip() for v in payload.get("ssh_allowed_source_networks", []) if str(v).strip()]
        if not principals:
            principals = ["root"]

        blocklist_path = self._state_file(payload, "ssh_blocklist_registry_path", "ssh_blocklist.json")
        include_path = self._state_file(payload, "ssh_hardening_include_path", "sshd_containment.conf")
        if not self.active_mode:
            return ActionExecutionResult(
                action="harden_ssh_lateral_paths",
                status="simulated",
                details={
                    "host": host,
                    "blocked_principals": principals,
                    "allowed_source_networks": source_networks,
                    "include_path": str(include_path),
                    "blocklist_path": str(blocklist_path),
                },
            )

        protected_targets = {"/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d", "/etc/hosts.allow", "/etc/hosts.deny"}
        if not self._has_root_privileges() and (
            str(include_path).startswith("/etc/")
            or str(blocklist_path).startswith("/etc/")
            or str(include_path) in protected_targets
            or str(blocklist_path) in protected_targets
        ):
            return ActionExecutionResult(
                action="harden_ssh_lateral_paths",
                status="skipped",
                details={"reason": "insufficient_privileges", "requires": "root", "host": host},
            )

        blocklist_path.parent.mkdir(parents=True, exist_ok=True)
        include_path.parent.mkdir(parents=True, exist_ok=True)
        state_doc: dict[str, Any] = {"hosts": {}}
        if blocklist_path.exists():
            try:
                loaded = json.loads(blocklist_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    state_doc = loaded
            except json.JSONDecodeError:
                state_doc = {"hosts": {}}

        host_doc = dict(state_doc.get("hosts", {}).get(host, {}))
        existing_principals = [str(v) for v in host_doc.get("blocked_principals", []) if str(v).strip()]
        merged = sorted(set(existing_principals).union(principals))
        host_doc["blocked_principals"] = merged
        host_doc["allowed_source_networks"] = source_networks
        host_doc["updated_at"] = datetime.now(timezone.utc).isoformat()
        state_doc.setdefault("hosts", {})[host] = host_doc
        blocklist_path.write_text(json.dumps(state_doc, indent=2, sort_keys=True), encoding="utf-8")

        include_lines = [
            "# Sentinel containment SSH hardening",
            f"# host: {host}",
            "Protocol 2",
            "PasswordAuthentication no",
            "PermitRootLogin no" if "root" in merged else "PermitRootLogin prohibit-password",
            "PubkeyAuthentication yes",
            "KbdInteractiveAuthentication no",
            "AllowTcpForwarding no",
            "X11Forwarding no",
            "PermitTunnel no",
            "GatewayPorts no",
            "ClientAliveInterval 60",
            "ClientAliveCountMax 2",
        ]
        if source_networks:
            include_lines.append(f"Match Address {','.join(source_networks)}")
            include_lines.append("    PasswordAuthentication no")
            include_lines.append("    PubkeyAuthentication yes")
        include_lines.append(f"DenyUsers {' '.join(merged)}")
        include_path.write_text("\n".join(include_lines) + "\n", encoding="utf-8")

        return ActionExecutionResult(
            action="harden_ssh_lateral_paths",
            status="executed",
            details={
                "host": host,
                "blocked_principals": merged,
                "allowed_source_networks": source_networks,
                "include_path": str(include_path),
                "blocklist_path": str(blocklist_path),
            },
        )

    def _revoke_rotate_api_keys(self, host: str, payload: dict[str, Any]) -> ActionExecutionResult:
        registry = self._state_file(payload, "api_key_registry_path", "api_keys.json")
        registry.parent.mkdir(parents=True, exist_ok=True)
        doc: dict[str, Any] = {"active_keys": [], "revoked_keys": []}
        if registry.exists():
            try:
                loaded = json.loads(registry.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    doc.update(loaded)
            except json.JSONDecodeError:
                pass

        active = [str(k) for k in doc.get("active_keys", []) if str(k).strip()]
        revoked = [str(k) for k in doc.get("revoked_keys", []) if str(k).strip()]
        rotated_from = active[:]
        revoked.extend(active)

        rotation_seed = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        replacement_count = max(1, int(payload.get("replacement_key_count", 2)))
        new_keys = [f"rotated-{host}-{rotation_seed}-{idx}" for idx in range(replacement_count)]
        doc["active_keys"] = new_keys
        doc["revoked_keys"] = sorted(set(revoked))
        doc["last_rotation_host"] = host
        doc["last_rotation_at"] = datetime.now(timezone.utc).isoformat()
        registry.write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")

        return ActionExecutionResult(
            action="revoke_rotate_api_keys",
            status="executed",
            details={"host": host, "revoked_count": len(rotated_from), "active_count": len(new_keys), "registry_path": str(registry)},
        )
