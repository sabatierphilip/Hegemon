from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import textwrap
import zlib
from pathlib import Path
from typing import Any

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel_containment.controlplane import Drone

_ALLOWED_IMPORTS = (
    "os", "sys", "socket", "time", "json", "hashlib", "hmac", "zlib", "base64",
    "threading", "subprocess", "pathlib", "datetime", "math", "re", "struct", "shutil", "ipaddress",
)


class DroneBlobCompiler:
    """Compiles a DroneBehaviour graph to a signed compressed base64 blob."""

    def compile(self, drone: "Drone", private_key_hex: str, embedded_intel: dict[str, Any]) -> str:
        source = self._render_script(drone, private_key_hex, embedded_intel)
        return self._encode_blob(source, private_key_hex, drone.drone_id)

    def _render_script(self, drone: "Drone", private_key_hex: str, embedded_intel: dict[str, Any]) -> str:
        nodes = {
            n.node_id: {
                "kind": n.kind,
                "params": n.params,
                "edges_out": list(n.edges_out),
                "edge_labels": dict(n.edge_labels),
            }
            for n in drone.behaviour.nodes
        }
        start_node = next((n.node_id for n in drone.behaviour.nodes if n.kind == "on_launch"), drone.behaviour.nodes[0].node_id if drone.behaviour.nodes else "")
        deadrop = f"/tmp/.hg_drop_{drone.drone_id.replace('drone-', '')}"
        report_endpoint = "http://127.0.0.1:5000/api/drones/report"
        script = f'''
import os, sys, socket, time, json, hashlib, hmac, zlib, base64, threading, subprocess, pathlib, datetime, math, re, struct, shutil, ipaddress

DRONE_ID = {drone.drone_id!r}
DRONE_NAME = {drone.name!r}
DRONE_TIER = {drone.tier!r}
MISSION = {drone.mission!r}
AUTONOMY = {drone.autonomy_level!r}
TTL_SECONDS = {int(drone.ttl_seconds)}
CHECKIN_SECS = {int(drone.checkin_interval_seconds)}
REPORT_ENDPOINT = {report_endpoint!r}
DEADROP_PATH = {deadrop!r}
PRIVATE_KEY_HEX = {private_key_hex!r}
PUBLIC_KEY_HEX = {str(drone.keypair_public or '')!r}
LAUNCH_TIME = 0.0
SCRIPT_HASH = {hashlib.sha256((drone.drone_id + drone.name).encode()).hexdigest()!r}
CHILD_DRONE_BLOB = ""
PAYLOAD_BIN = {str(getattr(drone, 'payload_binary', '') or '')!r}
PAYLOAD_JSON = {json.dumps(getattr(drone, 'payload', {}), ensure_ascii=False)}

EMBEDDED_VULN_SIGS = {json.dumps(embedded_intel.get('vuln_sigs', []), ensure_ascii=False)}
EMBEDDED_ATTACK_PATTERNS = {json.dumps(embedded_intel.get('attack_patterns', []), ensure_ascii=False)}
EMBEDDED_PORT_RISK = {json.dumps(embedded_intel.get('port_risk', {}), ensure_ascii=False)}

_state = {{
    "status": "active",
    "findings": [],
    "telemetry": [],
    "live_output": [],
    "stats": {{"hosts_pinged": 0, "ports_scanned": 0, "findings_count": 0, "nodes_executed": 0}},
    "current_node_id": None,
    "repeat_counts": {{}},
    "child_drone_ids": [],
    "alive_hosts": [],
    "host_banners": {{}},
    "anomaly_score": 0.0,
    "payload": PAYLOAD_JSON,
}}
_stop = threading.Event()

NODES = {json.dumps(nodes, ensure_ascii=False)}
START_NODE = {start_node!r}


def _sign(payload: bytes) -> str:
    return hmac.new(bytes.fromhex(PRIVATE_KEY_HEX[:64]), payload, hashlib.sha256).hexdigest()

def _verify(payload: bytes, sig: str) -> bool:
    return hmac.compare_digest(_sign(payload), sig)

def _xor_encrypt(data: bytes, key: bytes) -> bytes:
    key_cycle = (key * (len(data) // len(key) + 1))[:len(data)]
    return bytes(a ^ b for a, b in zip(data, key_cycle))

def _write_deadrop(findings, telemetry):
    payload = json.dumps({{"findings": findings, "telemetry": telemetry, "drone_id": DRONE_ID, "ts": time.time()}}).encode()
    key = bytes.fromhex(PRIVATE_KEY_HEX[:32])
    encrypted = _xor_encrypt(payload, key)
    sig = _sign(encrypted)
    envelope = base64.b64encode(json.dumps({{"sig": sig, "data": base64.b64encode(encrypted).decode()}}).encode()).decode()
    pathlib.Path(DEADROP_PATH).write_text(envelope, encoding="utf-8")


def _read_deadrop(path: str):
    p = pathlib.Path(path)
    if not p.exists():
        return None
    env = json.loads(base64.b64decode(p.read_text(encoding='utf-8')).decode())
    encrypted = base64.b64decode(env.get('data', ''))
    if not _verify(encrypted, str(env.get('sig', ''))):
        return None
    key = bytes.fromhex(PRIVATE_KEY_HEX[:32])
    plain = _xor_encrypt(encrypted, key)
    return json.loads(plain.decode('utf-8', errors='ignore'))


def _next_node(node, decision=None):
    outs = node.get('edges_out', [])
    labels = node.get('edge_labels', {{}})
    if decision:
        for out in outs:
            if labels.get(out) == decision:
                return out
    return outs[0] if outs else None

def _append(msg, **extra):
    row = {{'ts': time.time(), 'message': msg, **extra}}
    row['signature'] = _sign(json.dumps(row, sort_keys=True).encode())
    _state['telemetry'].append(row)
    _state['live_output'].append(msg)
    print(msg, flush=True)

def _adaptive_wait(params):
    base = max(1, int(params.get('base_seconds', 60)))
    alive = len(_state.get('alive_hosts', []))
    findings = len(_state.get('findings', []))
    if alive > 0 and _state['stats'].get('hosts_pinged', 1) > 0 and alive / max(1, _state['stats']['hosts_pinged']) > 0.5:
        base //= 2
    if findings == 0:
        base *= 2
    return max(5, min(base, max(5, TTL_SECONDS // 4 if TTL_SECONDS > 0 else 300)))

def _check_integrity():
    if TTL_SECONDS > 0 and (time.time() - LAUNCH_TIME) > (TTL_SECONDS * 1.5):
        return False
    return True

def _should_adapt():
    current = _state.get('current_node_id')
    ttl_remaining = TTL_SECONDS - int(time.time() - LAUNCH_TIME) if TTL_SECONDS > 0 else 999999
    if len(_state['findings']) > 3 and current and NODES.get(current, {{}}).get('kind') == 'wait':
        for nid, n in NODES.items():
            if n.get('kind') in ('send_report', 'report_to_control_plane'):
                return True, nid
    if ttl_remaining < max(1, int(TTL_SECONDS * 0.2)):
        for nid, n in NODES.items():
            if n.get('kind') in ('write_deadrop', 'self_destruct', 'self_terminate'):
                return True, nid
    if _state.get('anomaly_score', 0.0) > 0.8 and AUTONOMY == 'enforce':
        for nid, n in NODES.items():
            if n.get('kind') == 'isolate_source_ip':
                return True, nid
    return False, None

def _execute(node_id):
    node = NODES.get(node_id)
    if not node:
        return None
    kind = node.get('kind', 'noop')
    params = node.get('params', {{}})
    _state['current_node_id'] = node_id
    _state['stats']['nodes_executed'] += 1
    if kind == 'on_launch':
        return _next_node(node)
    if kind == 'ping_host':
        host = str(params.get('host', '127.0.0.1'))
        ok = False
        try:
            proc = subprocess.run(['ping','-c','1','-W','2',host], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            ok = proc.returncode == 0
        except Exception:
            ok = False
        _state['stats']['hosts_pinged'] += 1
        if ok:
            _state['alive_hosts'].append(host)
        _append(f'Ping {{host}} -> {{"ALIVE" if ok else "TIMEOUT"}}')
        return _next_node(node)
    if kind == 'subnet_scan':
        cidr = str(params.get('cidr', '10.0.0.0/24'))
        net = ipaddress.ip_network(cidr, strict=False)
        if net.prefixlen < 24:
            _append(f'Subnet scan blocked for {{cidr}} (/24 max)')
            return _next_node(node)
        for host in list(net.hosts())[:254]:
            if _stop.is_set():
                break
            _execute({{'kind':'ping_host','params':{{'host':str(host)}},'edges_out':[]}})
        return _next_node(node)
    if kind in ('port_scan', 'banner_grab'):
        host = str(params.get('host', '127.0.0.1'))
        ports = [21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,27017] if kind == 'banner_grab' else list(range(1,1025))
        open_ports = []
        banners = {{}}
        for port in ports[:1024]:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            try:
                if s.connect_ex((host, int(port))) == 0:
                    open_ports.append(port)
                    try:
                        data = s.recv(256)
                        banners[str(port)] = data.decode(errors='ignore')
                    except Exception:
                        pass
            finally:
                s.close()
        _state['stats']['ports_scanned'] += len(ports[:1024])
        _state['host_banners'][host] = banners
        for port, banner in banners.items():
            for sig in EMBEDDED_VULN_SIGS:
                pat = str(sig.get('pattern', ''))
                if pat and re.search(pat, banner or '', re.IGNORECASE):
                    _state['findings'].append({{'id': sig.get('id','unknown'), 'confidence': 0.65, 'source': 'local-intel', 'host': host, 'port': port}})
        _state['stats']['findings_count'] = len(_state['findings'])
        _append(f'Scan {{host}} complete, open={{len(open_ports)}}')
        return _next_node(node)
    if kind in ('local_intel', 'local_intel_match'):
        for host, banners in _state.get('host_banners', {{}}).items():
            for port, banner in banners.items():
                for sig in EMBEDDED_VULN_SIGS:
                    pat = str(sig.get('pattern', ''))
                    if pat and re.search(pat, banner or '', re.IGNORECASE):
                        _state['findings'].append({{'id': sig.get('id','unknown'),'confidence':min(0.65,float(sig.get('severity',5))/10),'source':'local-intel','host':host,'port':port}})
        _state['stats']['findings_count'] = len(_state['findings'])
        return _next_node(node)
    if kind in ('send_report', 'report_to_control_plane'):
        _write_deadrop(_state['findings'], _state['telemetry']) if DRONE_TIER == 'autonomous' else None
        _append('Report generated', findings=len(_state['findings']))
        return _next_node(node)
    if kind == 'write_deadrop':
        _write_deadrop(_state['findings'], _state['telemetry'])
        _append('Deadrop written')
        return _next_node(node)
    if kind == 'peer_sync':
        dd = pathlib.Path(DEADROP_PATH).parent
        if dd.exists():
            for child in dd.glob('.hg_drop_*'):
                row = _read_deadrop(str(child))
                if isinstance(row, dict):
                    for f in row.get('findings', []):
                        if f not in _state['findings']:
                            _state['findings'].append(f)
        _state['stats']['findings_count'] = len(_state['findings'])
        return _next_node(node)
    if kind == 'adaptive_wait':
        wait_s = _adaptive_wait(params)
        time.sleep(wait_s)
        return _next_node(node)
    if kind == 'wait':
        time.sleep(max(0, int(params.get('seconds', CHECKIN_SECS))))
        return _next_node(node)
    if kind == 'conditional_retask':
        cond = str(params.get('condition_key', 'findings_count'))
        threshold = float(params.get('threshold', 1))
        target = str(params.get('target_node_id', ''))
        cur = float(_state['stats'].get(cond, len(_state['findings'])))
        if cur >= threshold and target in NODES:
            return target
        return _next_node(node)
    if kind == 'spawn_child_drone':
        if AUTONOMY == 'enforce' and DRONE_TIER == 'autonomous' and CHILD_DRONE_BLOB and len(_state['child_drone_ids']) < 3:
            p = pathlib.Path(os.getcwd()) / f"child_{{int(time.time())}}.py"
            src = zlib.decompress(base64.b64decode(CHILD_DRONE_BLOB.encode())).decode()
            p.write_text(src, encoding='utf-8')
            proc = subprocess.Popen([sys.executable, str(p)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            _state['child_drone_ids'].append(proc.pid)
        return _next_node(node)
    if kind in ('self_destruct',):
        for pid in list(_state.get('child_drone_ids', [])):
            try:
                os.kill(int(pid), 15)
            except Exception:
                pass
        p = pathlib.Path(DEADROP_PATH)
        if p.exists():
            p.write_bytes(os.urandom(max(64, p.stat().st_size)))
            p.unlink(missing_ok=True)
        try:
            me = pathlib.Path(sys.argv[0])
            if me.exists():
                me.write_bytes(os.urandom(max(64, me.stat().st_size)))
                me.unlink(missing_ok=True)
        except Exception:
            pass
        os._exit(0)
    if kind in ('self_terminate',):
        _stop.set()
        return None
    return _next_node(node)


def main():
    current = START_NODE
    while current and not _stop.is_set():
        if not _check_integrity():
            _execute('self_destruct')
            return
        adapt, nxt = _should_adapt() if DRONE_TIER == 'autonomous' else (False, None)
        if adapt and nxt in NODES:
            current = nxt
            continue
        if TTL_SECONDS > 0 and time.time() > LAUNCH_TIME + TTL_SECONDS:
            _stop.set()
            break
        current = _execute(current)

if __name__ == '__main__':
    globals()['LAUNCH_TIME'] = time.time()
    main()
'''
        return textwrap.dedent(script).strip() + "\n"

    def _encode_blob(self, script_source: str, private_key_hex: str, drone_id: str) -> str:
        src_bytes = script_source.encode("utf-8")
        compressed = zlib.compress(src_bytes, level=9)
        sig = hmac.new(bytes.fromhex(private_key_hex[:64]), compressed, hashlib.sha256).hexdigest()
        envelope = json.dumps({"v": 2, "drone_id": drone_id, "sig": sig, "blob": base64.b64encode(compressed).decode("ascii")})
        return base64.b64encode(envelope.encode()).decode("ascii")


def decode_blob(blob_b64: str, private_key_hex: str) -> str:
    envelope = json.loads(base64.b64decode(blob_b64))
    compressed = base64.b64decode(envelope["blob"])
    expected_sig = hmac.new(bytes.fromhex(private_key_hex[:64]), compressed, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(envelope["sig"], expected_sig):
        raise ValueError("blob signature verification failed")
    return zlib.decompress(compressed).decode("utf-8")


def launch_blob_locally(blob_b64: str, private_key_hex: str, workdir: Path, *, detached: bool = False) -> subprocess.Popen[bytes]:
    source = decode_blob(blob_b64, private_key_hex)
    script_path = workdir / "drone.py"
    script_path.write_text(source, encoding="utf-8")
    os.chmod(script_path, 0o700)
    if detached:
        return subprocess.Popen(
            [sys.executable, str(script_path)],
            cwd=str(workdir),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
    return subprocess.Popen([sys.executable, str(script_path)], cwd=str(workdir), stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def deploy_blob_remote(blob_b64: str, private_key_hex: str, host: str, ssh_key_path: str, remote_workdir: str) -> dict[str, Any]:
    source = decode_blob(blob_b64, private_key_hex)
    did_match = re.search(r'^DRONE_ID\s*=\s*"([^"]+)"', source, re.MULTILINE)
    drone_id = did_match.group(1) if did_match else "drone"
    local_tmp = Path("/tmp") / f"drone_{drone_id}.py"
    local_tmp.write_text(source, encoding="utf-8")
    remote_path = f"{remote_workdir.rstrip('/')}/drone_{drone_id}.py"
    subprocess.run(["scp", "-i", ssh_key_path, str(local_tmp), f"{host}:{remote_path}"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    cmd = f"mkdir -p {remote_workdir} && nohup python3 {remote_path} >/dev/null 2>&1 & echo $!"
    proc = subprocess.run(["ssh", "-i", ssh_key_path, host, cmd], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return {"pid": int((proc.stdout or "0").strip() or 0), "host": host, "remote_path": remote_path}
