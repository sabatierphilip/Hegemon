from __future__ import annotations

import json
import platform
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover - graceful fallback
    psutil = None


def _run_command(cmd: list[str]) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20, check=False)
    except (FileNotFoundError, subprocess.SubprocessError):
        return ""
    if proc.returncode != 0:
        return ""
    return (proc.stdout or "").strip()


def detect_network_exposure() -> str:
    if psutil is None:
        return "unknown"
    for entries in psutil.net_if_addrs().values():
        for entry in entries:
            address = str(getattr(entry, "address", ""))
            if not address or ":" in address:
                continue
            if address.startswith(("10.", "127.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "192.168.")):
                continue
            if address == "0.0.0.0":
                continue
            return "internet"
    return "internal"


def collect_package_inventory() -> dict[str, str]:
    inventory: dict[str, str] = {}

    if shutil.which("dpkg-query"):
        out = _run_command(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"])
        for line in out.splitlines():
            if "\t" not in line:
                continue
            name, version = line.split("\t", 1)
            inventory[name.strip()] = version.strip()

    if shutil.which("rpm"):
        out = _run_command(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"])
        for line in out.splitlines():
            if "\t" not in line:
                continue
            name, version = line.split("\t", 1)
            inventory[name.strip()] = version.strip()

    if shutil.which("python"):
        out = _run_command(["python", "-m", "pip", "list", "--format=json"])
        try:
            rows = json.loads(out) if out else []
        except json.JSONDecodeError:
            rows = []
        for row in rows:
            name = str(row.get("name", "")).strip()
            version = str(row.get("version", "")).strip()
            if name:
                inventory[name] = version or "unknown"

    if shutil.which("npm"):
        out = _run_command(["npm", "list", "-g", "--depth=0", "--json"])
        try:
            data = json.loads(out) if out else {}
        except json.JSONDecodeError:
            data = {}
        deps = data.get("dependencies") if isinstance(data, dict) else {}
        if isinstance(deps, dict):
            for name, meta in deps.items():
                ver = str((meta or {}).get("version", "unknown")) if isinstance(meta, dict) else "unknown"
                inventory[str(name)] = ver

    if shutil.which("brew"):
        out = _run_command(["brew", "list", "--versions"])
        for line in out.splitlines():
            tokens = line.split()
            if not tokens:
                continue
            inventory[tokens[0]] = tokens[1] if len(tokens) > 1 else "unknown"

    return dict(sorted(inventory.items()))


def collect_host_facts() -> dict[str, Any]:
    return {
        "host_name": socket.gethostname(),
        "os": platform.system().lower(),
        "kernel": platform.release(),
        "network_exposure": detect_network_exposure(),
        "installed_packages": collect_package_inventory(),
    }


def read_recent_auth_telemetry(limit: int = 50) -> list[str]:
    paths = [Path("/var/log/auth.log"), Path("/var/log/secure")]
    for path in paths:
        if path.exists():
            try:
                lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            return lines[-limit:]
    return []
