from __future__ import annotations

import asyncio
import ipaddress
import socket
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any

from sentinel_containment.controlplane import HegemonControlPlane

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None


@dataclass
class DiscoveryHost:
    host: str
    open_ports: list[int] = field(default_factory=list)
    banners: dict[int, str] = field(default_factory=dict)
    inferred_os: str = "unknown"
    services: list[str] = field(default_factory=list)
    friendly: bool = False


class NetworkDiscoveryEngine:
    def __init__(self, control_plane: HegemonControlPlane):
        self.control_plane = control_plane
        self.last_started_at = 0.0
        self.last_completed_at = 0.0
        self.last_hosts: list[dict[str, Any]] = []
        self.running = False

    async def _ping(self, ip: str) -> bool:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c1", "-W1", ip, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return (await proc.wait()) == 0

    async def _banner(self, ip: str, port: int) -> tuple[int, str]:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=1.0)
            if port in {80, 8080, 443, 8443}:
                writer.write(b"GET / HTTP/1.0\r\nHost: local\r\n\r\n")
                await writer.drain()
            data = await asyncio.wait_for(reader.read(128), timeout=1.0)
            writer.close()
            return port, data.decode("utf-8", errors="ignore")
        except Exception:
            return port, ""

    def _infer(self, banners: dict[int, str]) -> tuple[str, list[str]]:
        blob = " ".join(banners.values()).lower()
        services: list[str] = []
        os_name = "unknown"
        if "nginx" in blob or "apache" in blob:
            services.append("web")
            os_name = "linux"
        if "openssh" in blob:
            services.append("ssh")
            os_name = "linux"
        if "iis" in blob:
            services.append("iis")
            os_name = "windows"
        return os_name, sorted(set(services))

    async def sweep_once(self) -> list[dict[str, Any]]:
        if psutil is None:
            self.last_hosts = []
            return []
        self.running = True
        self.last_started_at = time.time()
        nets: set[ipaddress.IPv4Network] = set()
        for addrs in psutil.net_if_addrs().values():
            for addr in addrs:
                if getattr(addr, "family", None) != socket.AF_INET:
                    continue
                ip = str(getattr(addr, "address", ""))
                mask = str(getattr(addr, "netmask", ""))
                try:
                    net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                except Exception:
                    continue
                prefix = min(int(net.prefixlen), 24)
                nets.add(ipaddress.IPv4Network(f"{net.network_address}/{prefix}", strict=False))

        discovered: list[dict[str, Any]] = []
        for net in sorted(nets, key=str):
            hosts = [str(ip) for ip in list(net.hosts())[:254]]
            alive = [ip for ip, ok in zip(hosts, await asyncio.gather(*[self._ping(ip) for ip in hosts])) if ok]
            for ip in alive:
                res = await asyncio.gather(*[self._banner(ip, p) for p in [22, 80, 443, 8080, 8443]])
                banners = {p: b for p, b in res if b}
                open_ports = [p for p, b in res if b]
                inferred_os, services = self._infer(banners)
                friendly = False
                try:
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, 5000), timeout=1.0)
                    writer.write(b"GET /api/state HTTP/1.0\r\nHost: local\r\n\r\n")
                    await writer.drain()
                    body = await asyncio.wait_for(reader.read(256), timeout=1.0)
                    writer.close()
                    friendly = b"200" in body.splitlines()[0] if body else False
                except Exception:
                    friendly = False
                row = DiscoveryHost(host=ip, open_ports=open_ports, banners=banners, inferred_os=inferred_os, services=services, friendly=friendly)
                discovered.append(row.__dict__)
                endpoint_id = f"discovered-{ip.replace('.', '-') }"
                payload = {
                    "endpoint_id": endpoint_id,
                    "host_name": ip,
                    "os": inferred_os,
                    "kernel": "unknown",
                    "sbom_status": "unknown",
                    "enrollment_method": "auto_discovery",
                    "protection_mode": "observe-only",
                }
                self.control_plane.add_endpoint(payload, actor="discovery")
                self.control_plane.ledger.append("discovery.host_found", row.__dict__)

        self.last_hosts = discovered
        self.last_completed_at = time.time()
        self.control_plane.ledger.append("discovery.sweep", {"hosts": len(discovered)})
        self.running = False
        return discovered

    def status(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "last_started_at": self.last_started_at,
            "last_completed_at": self.last_completed_at,
            "discovered_hosts": len(self.last_hosts),
        }
