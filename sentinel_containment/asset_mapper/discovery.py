from __future__ import annotations

import json
import platform
import socket
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import networkx as nx

from sentinel_containment.cloud.provider import CloudProviderAdapter


COMMON_PORTS = [22, 80, 443, 5000, 5432, 6379]


@dataclass
class AssetMapper:
    cloud_adapter: CloudProviderAdapter
    snapshot_path: Path = Path("data/topology_snapshot.json")

    def discover_local(self) -> dict[str, Any]:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        open_ports = []
        for p in COMMON_PORTS:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.2)
                if s.connect_ex(("127.0.0.1", p)) == 0:
                    open_ports.append(p)

        services = self._list_services()
        return {
            "host": hostname,
            "ip": ip,
            "os": platform.platform(),
            "open_ports": open_ports,
            "services": services,
        }

    def _list_services(self) -> list[str]:
        try:
            out = subprocess.check_output(["ps", "-eo", "comm="], text=True)
            return sorted(set(out.strip().splitlines()))[:50]
        except Exception:
            return []

    def build_graph(self) -> nx.DiGraph:
        g = nx.DiGraph()
        local = self.discover_local()
        g.add_node(local["host"], type="host", ip=local["ip"], os=local["os"])
        for port in local["open_ports"]:
            port_node = f"port:{port}"
            g.add_node(port_node, type="port")
            g.add_edge(local["host"], port_node, relation="exposes")

        for service in local["services"]:
            svc_node = f"svc:{service}"
            g.add_node(svc_node, type="service")
            g.add_edge(local["host"], svc_node, relation="runs")

        for inst in self.cloud_adapter.list_instances():
            g.add_node(inst["id"], type="instance", **inst)
            g.add_edge("cloud", inst["id"], relation="contains")
        g.add_node("cloud", type="cloud")

        for role in self.cloud_adapter.list_iam_roles():
            g.add_node(role["id"], type="iam_role", permissions=role["permissions"])
            g.add_edge("cloud", role["id"], relation="authorizes")

        for bucket in self.cloud_adapter.list_buckets():
            g.add_node(bucket["id"], type="bucket")
            g.add_edge("cloud", bucket["id"], relation="stores")

        for endpoint in self.cloud_adapter.list_model_endpoints():
            g.add_node(endpoint["id"], type="model_endpoint", url=endpoint["url"])
            g.add_edge("cloud", endpoint["id"], relation="serves")

        return g

    def snapshot(self) -> dict[str, Any]:
        graph = self.build_graph()
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "nodes": [{"id": n, **attrs} for n, attrs in graph.nodes(data=True)],
            "edges": [{"source": s, "target": t, **attrs} for s, t, attrs in graph.edges(data=True)],
        }
        self.snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        self.snapshot_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return payload
