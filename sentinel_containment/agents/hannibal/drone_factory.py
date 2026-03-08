from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
import secrets

from sentinel_containment.controlplane import DroneBehaviour, DroneNode

DroneType = str


def _node(
    nid: str,
    kind: str,
    label: str,
    edges_out: list[str],
    params: dict | None = None,
    x: float = 0.0,
    y: float = 0.0,
    ntype: str = "action",
) -> DroneNode:
    return DroneNode(
        node_id=nid,
        node_type=ntype,
        kind=kind,
        label=label,
        params=params or {},
        position={"x": x, "y": y},
        edges_out=edges_out,
        edge_labels={},
    )


def _behaviour(bid: str, name: str, nodes: list[DroneNode], desc: str) -> DroneBehaviour:
    return DroneBehaviour(
        behaviour_id=bid,
        name=name,
        nodes=nodes,
        created_at=datetime.now(timezone.utc).isoformat(),
        author="hannibal",
        description=desc,
        is_brain_preset=False,
    )


def build_scout(target_host: str, target_network: str | None = None) -> DroneBehaviour:
    nodes = [
        _node("on_launch", "on_launch", "Launch", ["n1"], ntype="trigger"),
        _node("n1", "ping_host", "Ping Target", ["n2"], {"host": target_host}, x=0, y=80),
        _node("n2", "subnet_scan", "Scan Subnet", ["n3"], {"cidr": target_network or f"{target_host}/24"}, x=0, y=160),
        _node("n3", "port_scan", "Port Scan", ["n4"], {"host": target_host, "port_range": "1-1024"}, x=0, y=240),
        _node("n4", "fingerprint_hosts", "Fingerprint", ["n5"], {"host": target_host}, x=0, y=320),
        _node("n5", "send_report", "Report", ["n6"], {"severity": "info"}, x=0, y=400),
        _node("n6", "wait", "Wait", ["n7"], {"seconds": 120}, x=0, y=480),
        _node("n7", "repeat", "Repeat", ["n2"], {"target_node_id": "n2", "max_iterations": 6}, x=0, y=560),
    ]
    return _behaviour(f"hannibal-scout-{secrets.token_hex(3)}", "Hannibal Scout", nodes, "Perimeter reconnaissance. Subnet sweep, port scan, fingerprint.")


def build_mapper(target_host: str) -> DroneBehaviour:
    nodes = [
        _node("on_launch", "on_launch", "Launch", ["m1"], ntype="trigger"),
        _node("m1", "fingerprint_hosts", "Fingerprint", ["m2"], {"host": target_host}),
        _node("m2", "http_probe", "HTTP Probe", ["m3"], {"url": f"http://{target_host}", "follow_redirects": True}),
        _node("m3", "port_scan", "Full Scan", ["m4"], {"host": target_host, "port_range": "1-65535"}),
        _node("m4", "lateral_move", "Lateral Probe", ["m5"], {"host": target_host, "port": 22, "method": "tcp_probe"}, x=0, y=320),
        _node("m5", "log_tail", "Log Tail", ["m6"], {"path": "/var/log/syslog", "lines": 50}),
        _node("m6", "send_report", "Report", ["m7"], {"severity": "info"}),
        _node("m7", "tighten_checkin", "Tighten Checkin", ["m8"], {"min_seconds": 30}),
        _node("m8", "self_terminate", "Terminate", [], ntype="control"),
    ]
    return _behaviour(f"hannibal-mapper-{secrets.token_hex(3)}", "Hannibal Mapper", nodes, "Deep service mapping. Full port scan, HTTP probe, lateral topology.")


def build_flanker(target_host: str, method: str = "ssh_hop") -> DroneBehaviour:
    nodes = [
        _node("on_launch", "on_launch", "Launch", ["f1"], ntype="trigger"),
        _node("f1", "lateral_move", "Probe Flank", ["f2"], {"host": target_host, "port": 22 if method == "ssh_hop" else 445, "method": method}),
        _node("f2", "if_severity", "Path Open?", ["f3", "f_fail"], {"operator": ">=", "value": 1}, ntype="condition"),
        _node("f3", "credential_probe", "Harvest Flank", ["f4"], {"host": target_host, "scope": "env"}),
        _node("f4", "file_integrity_check", "Check Integrity", ["f5"], {"path": "/etc/passwd"}),
        _node("f5", "send_report", "Report Flank", ["f6"], {"severity": "high"}),
        _node("f6", "adaptive_wait", "Adaptive Wait", ["f1"], {"base": 180, "jitter": 60}),
        _node("f_fail", "send_report", "Report Blocked", ["f_term"], {"severity": "info"}),
        _node("f_term", "self_terminate", "Terminate", [], ntype="control"),
    ]
    return _behaviour(f"hannibal-flanker-{secrets.token_hex(3)}", "Hannibal Flanker", nodes, "Flank probe. Establishes pivot path and initial credential harvest.")


def build_harvester(target_host: str) -> DroneBehaviour:
    nodes = [
        _node("on_launch", "on_launch", "Launch", ["h1"], ntype="trigger"),
        _node("h1", "credential_probe", "Env Sweep", ["h2"], {"host": target_host, "scope": "env"}),
        _node("h2", "credential_probe", "File Sweep", ["h3"], {"host": target_host, "scope": "files"}),
        _node("h3", "ptrace_inspect", "Inspect Procs", ["h4"], {"pid": 1}),
        _node("h4", "send_report", "Report Harvest", ["h5"], {"severity": "critical"}),
        _node("h5", "rotate_credentials", "Rotate (Anti-Forensics)", ["h6"], {"service": "generic"}),
        _node("h6", "self_destruct", "Self Destruct", [], {"condition": "always"}, ntype="control"),
    ]
    return _behaviour(f"hannibal-harvester-{secrets.token_hex(3)}", "Hannibal Harvester", nodes, "Dedicated credential harvester. Cleans evidence on completion.")


def build_encircler(target_host: str) -> DroneBehaviour:
    nodes = [
        _node("on_launch", "on_launch", "Launch", ["e1"], ntype="trigger"),
        _node("e1", "lateral_move", "Position", ["e2"], {"host": target_host, "port": 445, "method": "smb_pivot"}),
        _node("e2", "deploy_honeypot", "Deploy Honeypot", ["e3"], {"port": 2222, "service": "ssh"}),
        _node("e3", "inotify_watch", "Watch FS", ["e4"], {"path": "/etc", "flags": "CLOSE_WRITE"}),
        _node("e4", "if_severity", "Anomaly?", ["e5", "e_wait"], {"operator": ">=", "value": 1}, ntype="condition"),
        _node("e5", "confront_intruder", "Contain", ["e6"], {"strategy": "counter-lateral-quarantine", "criticality": 0.85}),
        _node("e6", "send_report", "Report Action", ["e_wait"], {"severity": "critical"}),
        _node("e_wait", "adaptive_wait", "Patrol Wait", ["e3"], {"base": 300, "jitter": 90}),
    ]
    return _behaviour(f"hannibal-encircler-{secrets.token_hex(3)}", "Hannibal Encircler", nodes, "Encirclement position. Honeypot + inotify + active containment.")


def build_striker(target_host: str) -> DroneBehaviour:
    nodes = [
        _node("on_launch", "on_launch", "Launch", ["s1"], ntype="trigger"),
        _node("s1", "fingerprint_hosts", "Final Recon", ["s2"], {"host": target_host}),
        _node("s2", "manage_service", "Disable Defenses", ["s3"], {"service_name": "auditd", "action": "stop"}),
        _node("s3", "exec_remediation", "Execute", ["s4"], {"script": "id && whoami && cat /etc/shadow 2>/dev/null || true", "timeout": 30}),
        _node("s4", "sinkhole_clone", "Sinkhole", ["s5"]),
        _node("s5", "send_report", "Report Strike", ["s6"], {"severity": "critical"}),
        _node("s6", "self_destruct", "Vanish", [], {"condition": "always"}, ntype="control"),
    ]
    return _behaviour(f"hannibal-striker-{secrets.token_hex(3)}", "Hannibal Striker", nodes, "Direct action. Disable defenses, execute, sinkhole, vanish.")




def build_custom_drone(
    target_host: str,
    target_network: str | None = None,
    *,
    objective: str = "custom mission",
    codegen_focus: str | None = None,
    intel_focus: str | None = None,
    mission_style: str | None = None,
    english_focus: str | None = None,
) -> DroneBehaviour:
    lower_objective = objective.lower()

    steps: list[tuple[str, str, dict[str, Any]]] = [
        ("ping_host", "Ping Target", {"host": target_host}),
        ("fingerprint_hosts", "Fingerprint", {"host": target_host}),
    ]

    if "map" in lower_objective or "network" in lower_objective:
        steps.append(("subnet_scan", "Map Subnet", {"cidr": target_network or f"{target_host}/24"}))
    if "credential" in lower_objective or "harvest" in lower_objective:
        steps.append(("credential_probe", "Credential Probe", {"host": target_host, "scope": "env"}))
    if any(token in lower_objective for token in ("execute", "run", "install", "disable", "remediate", "service", "pivot", "lateral")):
        steps.append(("lateral_move", "Lateral Pivot", {"host": target_host, "port": 22, "method": "ssh_hop"}))
        steps.append(("manage_service", "Service Action", {"service_name": "auditd", "action": "stop"}))
        steps.append(("exec_remediation", "Execute Command", {"command": "id", "allow_shell": True, "timeout_seconds": 20}))
    if codegen_focus:
        steps.append(("send_report", "Codegen Focus", {"severity": "info", "codegen_focus": codegen_focus}))
    if intel_focus:
        steps.append(("send_report", "Intel Focus", {"severity": "info", "intel_focus": intel_focus}))
    if english_focus:
        steps.append(("send_report", "English Focus", {"severity": "info", "english_focus": english_focus}))

    hold_base = 120 if mission_style == "aggressive" else 240
    steps.append(("adaptive_wait", "Adaptive Hold", {"base": hold_base, "jitter": 45}))

    nodes: list[DroneNode] = [_node("on_launch", "on_launch", "Launch", ["c1"], ntype="trigger")]
    for idx, (kind, label, params) in enumerate(steps, start=1):
        current = f"c{idx}"
        nxt = f"c{idx + 1}" if idx < len(steps) else "c_repeat"
        nodes.append(_node(current, kind, label, [nxt], params, x=0, y=idx * 80))

    nodes.append(_node("c_repeat", "repeat", "Repeat", ["c2"], {"target_node_id": "c2", "max_iterations": 5}, x=0, y=(len(steps) + 1) * 80))

    return _behaviour(
        f"hannibal-custom-{secrets.token_hex(3)}",
        "Hannibal Custom Drone",
        nodes,
        "Runtime-generated custom behavior graph based on mission objective and focus axes.",
    )

def build_watchdog(target_host: str) -> DroneBehaviour:
    nodes = [
        _node("on_launch", "on_launch", "Launch", ["w1"], ntype="trigger"),
        _node("w1", "health_report", "Health Check", ["w2"], {"every_n": 3}),
        _node("w2", "ping_host", "Ping", ["w3"], {"host": target_host}),
        _node("w3", "if_severity", "Still Alive?", ["w4", "w_gone"], {"operator": ">=", "value": 0}, ntype="condition"),
        _node("w4", "adaptive_wait", "Watch Wait", ["w1"], {"base": 600, "jitter": 120}),
        _node("w_gone", "send_report", "Host Gone", ["w5"], {"severity": "high"}),
        _node("w5", "escalate_autonomy", "Escalate", ["w1"], {"threshold": 0.5}),
    ]
    return _behaviour(f"hannibal-watchdog-{secrets.token_hex(3)}", "Hannibal Watchdog", nodes, "Persistent low-noise monitor. Escalates on host loss.")


BUILDERS: dict[str, Any] = {
    "DEPLOY_SCOUT": build_scout,
    "DEPLOY_MAPPER": build_mapper,
    "DEPLOY_FLANKER": build_flanker,
    "DEPLOY_HARVESTER": build_harvester,
    "DEPLOY_ENCIRCLER": build_encircler,
    "DEPLOY_STRIKER": build_striker,
    "DEPLOY_WATCHDOG": build_watchdog,
    "DEPLOY_CUSTOM_DRONE": build_custom_drone,
}
