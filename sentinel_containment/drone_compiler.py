from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import random
import re
import secrets
import string
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



def _random_bin_basename(prefix: str, *, min_len: int = 8, max_len: int = 20) -> str:
    length = random.randint(min_len, max_len)
    token = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(length))
    return f"{prefix}_{token}.bin"


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
        deadrop = f"data/drones/{drone.drone_id}/deadrop"
        report_endpoint = "http://127.0.0.1:5000/api/drones/report"
        payload_literal = repr(getattr(drone, 'payload', {}) or {})
        vuln_sigs_literal = repr(embedded_intel.get('vuln_sigs', []) or [])
        attack_patterns_literal = repr(embedded_intel.get('attack_patterns', []) or [])
        port_risk_literal = repr(embedded_intel.get('port_risk', {}) or {})
        script = f'''
import os, sys, socket, time, json, hashlib, hmac, zlib, base64, threading, subprocess, pathlib, datetime, math, re, struct, shutil, ipaddress
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DRONE_ID = {drone.drone_id!r}
DRONE_NAME = {drone.name!r}
DRONE_TIER = {drone.tier!r}
MISSION = {drone.mission!r}
AUTONOMY = {drone.autonomy_level!r}
TTL_SECONDS = {int(drone.ttl_seconds)}
CHECKIN_SECS = {int(drone.checkin_interval_seconds)}
REPORT_ENDPOINT = {report_endpoint!r}
DEADROP_PATH = {deadrop!r}
PUBLIC_KEY_HEX = {str(drone.keypair_public or '')!r}
LAUNCH_TIME = 0.0
SCRIPT_HASH = {hashlib.sha256((drone.drone_id + drone.name).encode()).hexdigest()!r}
CHILD_DRONE_BLOB = {str(getattr(drone, "runtime", {}).get("child_drone_blob", "") or "")!r}
PAYLOAD_BIN = {str(getattr(drone, 'payload_binary', '') or '')!r}
PAYLOAD_JSON = {payload_literal}

EMBEDDED_VULN_SIGS = {vuln_sigs_literal}
EMBEDDED_ATTACK_PATTERNS = {attack_patterns_literal}
EMBEDDED_PORT_RISK = {port_risk_literal}
RING_LEVEL = {int(getattr(drone, "compiler_ring", 3) or 3)}
ARTIFACT_FORMAT = {str(getattr(drone, "artifact_format", "binary_blob") or "binary_blob")!r}
RUNTIME_CFG = {repr(getattr(drone, "runtime", {}) or {})}

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

NODES = {repr(nodes)}
START_NODE = {start_node!r}


def _script_random_bin_name(prefix: str) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    rand_len = 8 + (int.from_bytes(os.urandom(1), "big") % 13)
    token = "".join(alphabet[int.from_bytes(os.urandom(1), "big") % len(alphabet)] for _ in range(rand_len))
    return f"{{prefix}}_{{token}}.bin"


def _sign(payload: bytes) -> str:
    return hmac.new(bytes.fromhex(_private_key_hex()[:64]), payload, hashlib.sha256).hexdigest()

def _verify(payload: bytes, sig: str) -> bool:
    return hmac.compare_digest(_sign(payload), sig)

def _private_key_hex() -> str:
    key = os.environ.get('HG_DRONE_KEY_HEX', '').strip()
    if len(key) < 64:
        raise RuntimeError('missing HG_DRONE_KEY_HEX')
    return key

def _aes_key() -> bytes:
    return hashlib.sha256(bytes.fromhex(_private_key_hex()[:64])).digest()

def _write_deadrop(findings, telemetry):
    p = pathlib.Path(DEADROP_PATH)
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({{"findings": findings, "telemetry": telemetry, "drone_id": DRONE_ID, "ts": time.time()}}).encode()
    aad = f"{{DRONE_ID}}:deadrop:v3:aes-256-gcm".encode()
    nonce = os.urandom(12)
    encrypted = AESGCM(_aes_key()).encrypt(nonce, payload, aad)
    sig = _sign(encrypted)
    envelope = base64.b64encode(json.dumps({{
        "v": 3,
        "alg": "AES-256-GCM",
        "aad": base64.b64encode(aad).decode(),
        "sig": sig,
        "nonce": base64.b64encode(nonce).decode(),
        "data": base64.b64encode(encrypted).decode(),
    }}).encode()).decode()
    p.write_text(envelope, encoding="utf-8")
    os.chmod(p, 0o600)


def _read_deadrop(path: str):
    p = pathlib.Path(path)
    if not p.exists():
        return None
    env = json.loads(base64.b64decode(p.read_text(encoding='utf-8')).decode())
    if str(env.get('alg', '')).upper() != 'AES-256-GCM':
        return None
    encrypted = base64.b64decode(env.get('data', ''))
    if not _verify(encrypted, str(env.get('sig', ''))):
        return None
    nonce = base64.b64decode(env.get('nonce', ''))
    aad = base64.b64decode(env.get('aad', '')) if env.get('aad') else f"{{DRONE_ID}}:deadrop:v3:aes-256-gcm".encode()
    plain = AESGCM(_aes_key()).decrypt(nonce, encrypted, aad)
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
    _state['telemetry'] = _state['telemetry'][-500:]
    _state['live_output'].append(msg)
    _state['live_output'] = _state['live_output'][-500:]
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

def _ring_bootstrap():
    feed = RUNTIME_CFG.get('telemetry', {{}}).get('kernel_feed', {{}}) if isinstance(RUNTIME_CFG.get('telemetry', {{}}), dict) else {{}}
    provider = str(feed.get('provider', 'userland'))
    if RING_LEVEL <= 1:
        _append('Ring 1 micro-kernel envelope armed', provider=provider, artifact=ARTIFACT_FORMAT)
        _state['kernel_feed_mode'] = 'ring1-hyperguard'
    elif RING_LEVEL == 2:
        _append('Ring 2 syscall relay armed', provider=provider, artifact=ARTIFACT_FORMAT)
        _state['kernel_feed_mode'] = 'ring2-sysrelay'
    else:
        _append('Ring 3 userland runtime armed', provider=provider, artifact=ARTIFACT_FORMAT)
        _state['kernel_feed_mode'] = 'ring3-userland'


def _execute(node_id):
    node = NODES.get(node_id)
    if not node:
        return None
    kind = node.get('kind', 'noop')
    params = node.get('params', {{}})
    _state['current_node_id'] = node_id
    _state['stats']['nodes_executed'] += 1
    if kind == 'on_launch':
        _ring_bootstrap()
        return _next_node(node)
    if kind == 'on_ttl_expiry':
        if TTL_SECONDS > 0 and time.time() > LAUNCH_TIME + TTL_SECONDS:
            _append('TTL expired branch taken')
            return _next_node(node)
        _append('TTL not expired; continuing')
        return _next_node(node)
    if kind == 'on_error':
        if _state.get('errors'):
            _append('Error branch triggered', errors=len(_state.get('errors', [])))
        return _next_node(node)
    if kind == 'ping_host':
        host = str(params.get('host', '127.0.0.1'))
        message = str(params.get('message', '') or '')
        fallback_port = max(1, min(65535, int(params.get('fallback_port', 443) or 443)))
        method = 'icmp'
        ok = False
        ping_cmd = ['ping', '-c', '1', '-W', '2', host]
        if message:
            hex_payload = message.encode('utf-8', errors='ignore').hex()[:32]
            if hex_payload:
                ping_cmd.extend(['-p', hex_payload])
        try:
            proc = subprocess.run(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            ok = proc.returncode == 0
        except Exception:
            ok = False
        if message and not ok:
            method = f'tcp:{{fallback_port}}'
            try:
                with socket.create_connection((host, fallback_port), timeout=2) as sock:
                    sock.sendall(message.encode('utf-8', errors='ignore'))
                ok = True
            except Exception:
                ok = False
        _state['stats']['hosts_pinged'] += 1
        if ok and host not in _state['alive_hosts']:
            _state['alive_hosts'].append(host)
        _append(f'Ping {{host}} via {{method}} -> {{"ALIVE" if ok else "TIMEOUT"}}', payload=bool(message))
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
    if kind == 'http_probe':
        import urllib.request, urllib.error
        url = str(params.get('url', '')).strip()
        method = str(params.get('method', 'GET')).upper()
        expect_status = int(params.get('expect_status', 200) or 200)
        if not url:
            _append('http_probe: no URL supplied')
            return _next_node(node)
        try:
            req = urllib.request.Request(url, method=method)
            with urllib.request.urlopen(req, timeout=5) as resp:
                status = int(getattr(resp, 'status', 0) or 0)
                body_sample = resp.read(256).decode('utf-8', errors='ignore')
            _append(f'HTTP probe {{url}} -> {{status}}', expected=expect_status, matched=status == expect_status)
            if status != expect_status:
                _state['findings'].append({{
                    'id': f'http-probe-{{hashlib.sha256(url.encode()).hexdigest()[:8]}}',
                    'confidence': 0.66,
                    'source': 'http_probe',
                    'url': url,
                    'status': status,
                    'expected': expect_status,
                    'body_sample': body_sample[:120],
                }})
        except Exception as exc:
            _state['findings'].append({{
                'id': f'http-probe-failed-{{hashlib.sha256(url.encode()).hexdigest()[:8]}}',
                'confidence': 0.5,
                'source': 'http_probe',
                'url': url,
                'error': str(exc)[:120],
            }})
            _append(f'HTTP probe failed for {{url}}', error=str(exc)[:80])
        _state['stats']['findings_count'] = len(_state['findings'])
        return _next_node(node)
    if kind == 'dns_resolve':
        hostname = str(params.get('hostname', '')).strip()
        if not hostname:
            _append('dns_resolve: hostname missing')
            return _next_node(node)
        try:
            infos = socket.getaddrinfo(hostname, None)
            addrs = sorted({{row[4][0] for row in infos if row and row[4]}})[:20]
            _append(f'DNS resolve {{hostname}} -> {{len(addrs)}} records')
            _state.setdefault('dns_records', {{}})[hostname] = addrs
        except Exception as exc:
            _state['findings'].append({{
                'id': f'dns-resolve-failed-{{hashlib.sha256(hostname.encode()).hexdigest()[:8]}}',
                'confidence': 0.42,
                'source': 'dns_resolve',
                'hostname': hostname,
                'error': str(exc)[:100],
            }})
        _state['stats']['findings_count'] = len(_state['findings'])
        return _next_node(node)
    if kind == 'tls_check':
        import ssl
        host = str(params.get('host', '127.0.0.1')).strip() or '127.0.0.1'
        port = max(1, min(65535, int(params.get('port', 443) or 443)))
        ok = False
        cert_subject = ''
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=4) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                    cert = ssock.getpeercert() or {{}}
                    cert_subject = str(cert.get('subject', ''))[:120]
            ok = True
        except Exception as exc:
            _state['findings'].append({{
                'id': f'tls-check-failed-{{hashlib.sha256(host.encode()).hexdigest()[:8]}}',
                'confidence': 0.6,
                'source': 'tls_check',
                'host': host,
                'port': port,
                'error': str(exc)[:120],
            }})
        _append(f'TLS check {{host}}:{{port}} -> {{"valid" if ok else "invalid"}}', cert_subject=cert_subject)
        _state['stats']['findings_count'] = len(_state['findings'])
        return _next_node(node)
    if kind == 'icmp_sweep':
        cidr = str(params.get('cidr', '')).strip()
        if not cidr:
            _append('icmp_sweep: cidr missing')
            return _next_node(node)
        net = ipaddress.ip_network(cidr, strict=False)
        responders = []
        for host in list(net.hosts())[:128]:
            if _stop.is_set():
                break
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.25)
            try:
                if s.connect_ex((str(host), 443)) == 0:
                    responders.append(str(host))
            finally:
                s.close()
        _state['alive_hosts'] = sorted(set(_state.get('alive_hosts', []) + responders))[:512]
        _append(f'ICMP-style sweep {{cidr}} -> {{len(responders)}} responders (tcp/443 heuristic)')
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
    if kind == 'ingest_telemetry':
        telemetry_path = pathlib.Path(DEADROP_PATH).parent / 'telemetry.jsonl'
        ingested = 0
        if telemetry_path.exists():
            try:
                for line in telemetry_path.read_text(encoding='utf-8', errors='ignore').splitlines()[-100:]:
                    row = json.loads(line)
                    _state['telemetry'].append(row)
                    ingested += 1
            except Exception:
                pass
        _state['telemetry'] = _state['telemetry'][-500:]
        _append('Telemetry ingested', count=ingested)
        return _next_node(node)
    if kind == 'file_integrity_check':
        path = str(params.get('path', '')).strip()
        algo = str(params.get('hash_algo', 'sha256')).strip().lower() or 'sha256'
        if not path:
            _append('file_integrity_check: missing path')
            return _next_node(node)
        p = pathlib.Path(path)
        if not p.exists() or not p.is_file():
            _state['findings'].append({{'id': f'fic-missing-{{hashlib.sha256(path.encode()).hexdigest()[:8]}}', 'confidence': 0.58, 'source': 'file_integrity_check', 'path': path, 'status': 'missing'}})
            _state['stats']['findings_count'] = len(_state['findings'])
            return _next_node(node)
        data = p.read_bytes()
        digest = hashlib.new(algo, data).hexdigest() if algo in hashlib.algorithms_available else hashlib.sha256(data).hexdigest()
        _state.setdefault('file_hashes', {{}})[path] = digest
        _append(f'Integrity hash {{path}}', hash=digest[:32], algo=algo)
        return _next_node(node)
    if kind == 'process_watch':
        pattern = str(params.get('name_pattern', '')).strip()
        hits = []
        try:
            out = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=5)
            lines = (out.stdout or '').splitlines()
            if pattern:
                hits = [ln[:200] for ln in lines if re.search(pattern, ln, re.IGNORECASE)]
            else:
                hits = lines[:10]
        except Exception:
            hits = []
        _state.setdefault('process_hits', {{}})[pattern or '*'] = hits[:25]
        _append('process_watch complete', matches=len(hits))
        return _next_node(node)
    if kind == 'network_baseline_diff':
        iface = str(params.get('interface', 'eth0')).strip() or 'eth0'
        path = pathlib.Path('/proc/net/dev')
        current = ''
        if path.exists():
            current = path.read_text(encoding='utf-8', errors='ignore')[:3000]
        prev = _state.get('net_baseline', '')
        delta = abs(len(current) - len(str(prev)))
        _state['net_baseline'] = current
        _append(f'network_baseline_diff on {{iface}}', delta=delta)
        if delta > 300:
            _state['findings'].append({{'id': f'net-delta-{{hashlib.sha256(iface.encode()).hexdigest()[:8]}}', 'confidence': 0.62, 'source': 'network_baseline_diff', 'interface': iface, 'delta': delta}})
            _state['stats']['findings_count'] = len(_state['findings'])
        return _next_node(node)
    if kind == 'log_tail':
        path = str(params.get('path', '/var/log/syslog')).strip() or '/var/log/syslog'
        lines = max(1, min(500, int(params.get('lines', 100) or 100)))
        p = pathlib.Path(path)
        if p.exists() and p.is_file() and os.access(str(p), os.R_OK):
            sample = p.read_text(encoding='utf-8', errors='ignore').splitlines()[-lines:]
            _state.setdefault('log_samples', {{}})[path] = sample[-50:]
            _append(f'log_tail {{path}}', lines=len(sample))
        else:
            _append(f'log_tail inaccessible {{path}}')
        return _next_node(node)
    if kind == 'registry_watch':
        hive = str(params.get('hive', 'HKLM'))
        key = str(params.get('key', ''))
        _append('registry_watch simulated', hive=hive, key=key)
        return _next_node(node)
    if kind == 'env_snapshot':
        snap = {{k: os.environ.get(k, '')[:120] for k in sorted(os.environ)[:80]}}
        _state['env_snapshot'] = snap
        _append('env_snapshot captured', keys=len(snap))
        return _next_node(node)
    if kind in ('lateral_move', 'pivot_host'):
        host = str(params.get('host', params.get('target_host', '127.0.0.1'))).strip() or '127.0.0.1'
        port = max(1, min(65535, int(params.get('port', 22) or 22)))
        method = str(params.get('method', 'tcp_probe'))
        moved = False
        banner = ''
        try:
            with socket.create_connection((host, port), timeout=3) as sock:
                moved = True
                try:
                    sock.settimeout(1.0)
                    banner = sock.recv(256).decode('utf-8', errors='ignore').strip()[:80]
                except Exception:
                    pass
        except Exception as exc:
            _state['findings'].append({{
                'id': f'lateral-blocked-{{hashlib.sha256(host.encode()).hexdigest()[:8]}}',
                'confidence': 0.4, 'source': 'lateral_move',
                'host': host, 'port': port, 'error': str(exc)[:60],
            }})
        if moved:
            if host not in _state['alive_hosts']:
                _state['alive_hosts'].append(host)
            _state['findings'].append({{
                'id': f'lateral-reachable-{{hashlib.sha256(host.encode()).hexdigest()[:8]}}',
                'confidence': 0.75, 'source': 'lateral_move',
                'host': host, 'port': port, 'method': method, 'banner': banner,
            }})
        _append(
            f'Lateral move {{host}}:{{port}} via {{method}} -> {{"reachable" if moved else "blocked"}}',
            banner=banner, moved=moved,
        )
        _state['stats']['findings_count'] = len(_state['findings'])
        return _next_node(node)
    if kind in ('confront_intruder', 'countermeasure', 'block_ip'):
        target = str(params.get('ip', params.get('target', 'unknown')) or 'unknown')
        strategy = str(params.get('strategy', params.get('direction', 'bidirectional_block')))
        _append(f'Confrontation action engaged for {{target}}', strategy=strategy)
        _state['findings'].append({{'id': 'confrontation-engaged', 'confidence': 0.72, 'source': 'countermeasure', 'target': target, 'strategy': strategy}})
        _state['stats']['findings_count'] = len(_state['findings'])
        return _next_node(node)
    if kind == 'kill_process':
        target = str(params.get('name', '')).strip()
        if not target:
            _append('kill_process: no process name provided')
            return _next_node(node)
        killed = 0
        try:
            out = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=5)
            for ln in (out.stdout or '').splitlines():
                if target.lower() in ln.lower() and 'python' not in ln.lower():
                    parts = ln.split()
                    if len(parts) > 1 and parts[1].isdigit():
                        try:
                            os.kill(int(parts[1]), 15)
                            killed += 1
                        except Exception:
                            pass
        except Exception:
            pass
        _append(f'kill_process {{target}}', killed=killed)
        return _next_node(node)
    if kind == 'quarantine_file':
        src = str(params.get('path', '')).strip()
        dest = str(params.get('dest', '/tmp/quarantine')).strip() or '/tmp/quarantine'
        if not src:
            _append('quarantine_file: missing path')
            return _next_node(node)
        s = pathlib.Path(src)
        d = pathlib.Path(dest)
        d.mkdir(parents=True, exist_ok=True)
        if s.exists() and s.is_file():
            q = d / f"{{s.name}}.quarantine"
            shutil.copy2(str(s), str(q))
            _append(f'quarantine_file moved {{src}}', quarantine_path=str(q))
        else:
            _append(f'quarantine_file missing {{src}}')
        return _next_node(node)
    if kind == 'rotate_credentials':
        service = str(params.get('service', 'generic')).strip() or 'generic'
        token = hashlib.sha256(f"{{service}}:{{time.time()}}:{{DRONE_ID}}".encode()).hexdigest()
        _state.setdefault('rotated_credentials', {{}})[service] = token[:24]
        _append(f'rotate_credentials {{service}} complete')
        return _next_node(node)
    if kind == 'emit_alert':
        level = str(params.get('level', 'critical'))
        message = str(params.get('message', 'alert'))
        _state['findings'].append({{'id': f'emit-alert-{{hashlib.sha256(message.encode()).hexdigest()[:8]}}', 'confidence': 0.7, 'source': 'emit_alert', 'level': level, 'message': message[:180]}})
        _state['stats']['findings_count'] = len(_state['findings'])
        _append('Alert emitted', level=level)
        return _next_node(node)
    if kind == 'exec_remediation':
        script = str(params.get('script', '')).strip()
        timeout = max(1, min(120, int(params.get('timeout', 30) or 30)))
        if not script:
            _append('exec_remediation: empty script')
            return _next_node(node)
        try:
            r = subprocess.run(script, shell=True, capture_output=True, text=True, timeout=timeout)
            _append('exec_remediation complete', rc=r.returncode, stdout=(r.stdout or '')[:200], stderr=(r.stderr or '')[:200])
        except Exception as exc:
            _state.setdefault('errors', []).append(f'exec_remediation: {{exc}}')
        return _next_node(node)
    if kind in ('credential_harvest', 'credential_probe'):
        host = str(params.get('host', 'local'))
        scope = str(params.get('scope', 'env'))
        found: list[dict] = []

        if scope in ('env', 'both'):
            sensitive_keys = [k for k in os.environ if any(
                w in k.upper() for w in
                ('PASSWORD', 'SECRET', 'TOKEN', 'KEY', 'PASS', 'AUTH', 'CREDENTIAL', 'API_KEY')
            )]
            for k in sensitive_keys:
                v = os.environ[k]
                found.append({{
                    'source': 'env', 'key': k,
                    'preview': v[:4] + '***' if len(v) > 4 else '***',
                    'length': len(v),
                }})

        if scope in ('files', 'both'):
            credential_paths = [
                pathlib.Path.home() / '.ssh' / 'id_rsa',
                pathlib.Path.home() / '.ssh' / 'id_ed25519',
                pathlib.Path.home() / '.aws' / 'credentials',
                pathlib.Path.home() / '.config' / 'gcloud' / 'credentials.db',
                pathlib.Path('/etc/passwd'),
            ]
            for cp in credential_paths:
                if cp.exists() and cp.is_file():
                    found.append({{
                        'source': 'file', 'path': str(cp),
                        'size': cp.stat().st_size,
                        'readable': os.access(str(cp), os.R_OK),
                    }})

        if found:
            _state['findings'].append({{
                'id': f'credential-probe-{{hashlib.sha256(host.encode()).hexdigest()[:8]}}',
                'confidence': 0.85, 'source': 'credential',
                'host': host, 'count': len(found), 'items': found[:10],
            }})
        _append(f'Credential probe on {{host}}: {{len(found)}} items found', scope=scope)
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
    if kind == 'parallel':
        fanout = [edge for edge in node.get('edges_out', []) if edge in NODES]
        if fanout:
            for nid in fanout[1:3]:
                try:
                    _execute(nid)
                except Exception as exc:
                    _state.setdefault('errors', []).append(f'parallel branch error: {{exc}}')
            return fanout[0]
        return _next_node(node)
    if kind == 'if_ttl_expired':
        expired = TTL_SECONDS > 0 and time.time() > LAUNCH_TIME + TTL_SECONDS
        return _next_node(node, 'yes' if expired else 'no')
    if kind == 'if_severity':
        min_findings = int(params.get('min_findings', params.get('value', 1)) or 1)
        meets = len(_state.get('findings', [])) >= min_findings
        return _next_node(node, 'yes' if meets else 'no')
    if kind in ('logical_and', 'logical_or', 'logical_xor', 'logical_not', 'expr_check'):
        result = False
        findings = len(_state.get('findings', []))
        anomaly = float(_state.get('anomaly_score', 0.0))
        if kind == 'logical_and':
            result = findings > 0 and anomaly >= 0.0
        elif kind == 'logical_or':
            result = findings > 0 or anomaly > 0.7
        elif kind == 'logical_xor':
            result = bool(findings > 0) ^ bool(anomaly > 0.7)
        elif kind == 'logical_not':
            result = not bool(findings > 0)
        else:
            field = str(params.get('field', 'stats.findings_count'))
            op = str(params.get('operator', '>='))
            try:
                value = float(params.get('value', params.get('threshold', 1)))
            except Exception:
                value = 1.0
            current = float(findings if 'findings' in field else anomaly)
            if op == '>=':
                result = current >= value
            elif op == '>':
                result = current > value
            elif op == '<=':
                result = current <= value
            elif op == '<':
                result = current < value
            elif op == '==':
                result = abs(current - value) < 1e-9
            elif op == '!=':
                result = abs(current - value) >= 1e-9
        _append(f'logical check {{kind}}', result=result)
        return _next_node(node, 'yes' if result else 'no')
    if kind == 'checkin_interval':
        _append('checkin_interval node executed', checkin=CHECKIN_SECS)
        time.sleep(max(1, int(CHECKIN_SECS)))
        return _next_node(node)
    if kind == 'self_destruct_on_findings':
        threshold = max(1, int(params.get('threshold', 5) or 5))
        if len(_state.get('findings', [])) >= threshold:
            _append('self_destruct_on_findings triggered', threshold=threshold)
            return 'self_destruct'
        return _next_node(node)
    if kind == 'self_destruct_on_anomaly':
        threshold = float(params.get('threshold', 0.8) or 0.8)
        if float(_state.get('anomaly_score', 0.0)) >= threshold:
            _append('self_destruct_on_anomaly triggered', threshold=threshold)
            return 'self_destruct'
        return _next_node(node)
    if kind == 'self_destruct_on_hmac_fail':
        fails = int(_state.get('hmac_failures', 0))
        max_failures = max(1, int(params.get('max_failures', 3) or 3))
        if fails >= max_failures:
            return 'self_destruct'
        return _next_node(node)
    if kind == 'self_destruct_on_duplicate':
        max_instances = max(1, int(params.get('max', 1) or 1))
        current_instances = int(_state.get('instance_count', 1))
        if current_instances > max_instances:
            return 'self_destruct'
        return _next_node(node)
    if kind == 'self_destruct_on_kill_signal':
        if bool(_state.get('kill_signal', False)):
            return 'self_destruct'
        return _next_node(node)
    if kind == 'tighten_checkin':
        threshold = max(1, int(params.get('threshold', 3) or 3))
        min_seconds = max(1, int(params.get('min_seconds', 10) or 10))
        if len(_state.get('findings', [])) >= threshold:
            _state['dynamic_checkin'] = min_seconds
        _append('tighten_checkin evaluated', dynamic=_state.get('dynamic_checkin', CHECKIN_SECS))
        return _next_node(node)
    if kind == 'widen_checkin':
        idle_cycles = max(1, int(params.get('idle_cycles', 5) or 5))
        max_seconds = max(10, int(params.get('max_seconds', 300) or 300))
        _state['idle_cycles'] = int(_state.get('idle_cycles', 0)) + 1
        if _state['idle_cycles'] >= idle_cycles:
            _state['dynamic_checkin'] = min(max_seconds, int(_state.get('dynamic_checkin', CHECKIN_SECS)) + 10)
        return _next_node(node)
    if kind == 'update_payload_from_deadrop':
        row = _read_deadrop(DEADROP_PATH)
        if isinstance(row, dict):
            _state['payload'] = {{**_state.get('payload', {{}}), **dict(row.get('payload', {{}}) or {{}})}}
            _append('payload patched from deadrop')
        return _next_node(node)
    if kind == 'spawn_replacement':
        _append('spawn_replacement requested')
        return _next_node(node)
    if kind == 'escalate_autonomy':
        threshold = float(params.get('threshold', 0.8) or 0.8)
        if float(_state.get('anomaly_score', 0.0)) >= threshold:
            _state['autonomy_escalated'] = True
            _append('autonomy escalated')
        return _next_node(node)
    if kind == 'health_report':
        every_n = max(1, int(params.get('every_n', 5) or 5))
        if int(_state['stats'].get('nodes_executed', 0)) % every_n == 0:
            _append('health_report', stats=_state['stats'])
        return _next_node(node)
    if kind == 'instance_guard':
        max_instances = max(1, int(params.get('max', 1) or 1))
        if int(_state.get('instance_count', 1)) > max_instances:
            _append('instance_guard blocked execution', max=max_instances)
            return None
        return _next_node(node)
    if kind == 'spawn_child_drone':
        max_ch = max(1, min(10, int(params.get('max_children', 3))))
        if AUTONOMY == 'enforce' and DRONE_TIER == 'autonomous' and CHILD_DRONE_BLOB and len(_state['child_drone_ids']) < max_ch:
            child_dir = pathlib.Path(DEADROP_PATH).parent / 'children'
            child_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(str(child_dir), 0o700)
            p = child_dir / _script_random_bin_name("child")
            src = zlib.decompress(base64.b64decode(CHILD_DRONE_BLOB.encode())).decode()
            p.write_bytes(src.encode('utf-8'))
            os.chmod(p, 0o700)
            child_env = {{**os.environ, 'HG_DRONE_KEY_HEX': _private_key_hex()}}
            proc = subprocess.Popen(
                [sys.executable, str(p)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                close_fds=True,
                env=child_env,
            )
            _state['child_drone_ids'].append(proc.pid)
        return _next_node(node)

    if kind == 'manage_service' and RING_LEVEL <= 2:
        import platform as _plat, subprocess as _sp
        svc = str(params.get('service_name', ''))
        action = str(params.get('action', 'status'))
        if not svc:
            _append('manage_service: no service_name provided')
            return _next_node(node)
        if _plat.system() == 'Windows':
            r = _sp.run(['sc', action, svc], capture_output=True, text=True, timeout=10)
        else:
            r = _sp.run(['systemctl', action, svc], capture_output=True, text=True, timeout=10)
        _append(f'manage_service {{svc}} {{action}}: rc={{r.returncode}}', stdout=r.stdout[:200])
        return _next_node(node)

    if kind == 'manage_systemd_unit' and RING_LEVEL <= 2:
        unit = str(params.get('unit', ''))
        action = str(params.get('action', 'status'))
        if not unit:
            _append('manage_systemd_unit: no unit provided')
            return _next_node(node)
        r = subprocess.run(['systemctl', action, unit], capture_output=True, text=True, timeout=10)
        _append(f'systemd {{unit}} {{action}}: rc={{r.returncode}}', stdout=r.stdout[:200])
        return _next_node(node)

    if kind == 'inotify_watch' and RING_LEVEL <= 2:
        import ctypes, threading as _th
        path = str(params.get('path', '/etc'))
        _append(f'inotify_watch armed on {{path}}')
        def _watch():
            try:
                libc = ctypes.CDLL(None)
                ifd = libc.inotify_init()
                IN_CLOSE_WRITE = 0x00000008
                IN_CREATE = 0x00000100
                IN_ATTRIB = 0x00000004
                libc.inotify_add_watch(ifd, path.encode(), IN_CLOSE_WRITE | IN_CREATE | IN_ATTRIB)
                buf = ctypes.create_string_buffer(4096)
                while not _stop.is_set():
                    n = libc.read(ifd, buf, 4096)
                    if n > 0:
                        _state['findings'].append({{
                            'id': f'inotify-{{hashlib.sha256(path.encode()).hexdigest()[:8]}}',
                            'type': 'inotify', 'path': path, 'ts': time.time(), 'confidence': 0.9
                        }})
            except Exception as exc:
                _state.setdefault('errors', []).append(f'inotify: {{exc}}')
        _th.Thread(target=_watch, daemon=True).start()
        return _next_node(node)

    if kind == 'ptrace_inspect' and RING_LEVEL <= 2:
        pid = int(params.get('pid', 0))
        if pid <= 0:
            _append('ptrace_inspect: invalid pid')
            return _next_node(node)
        maps_path = pathlib.Path(f'/proc/{{pid}}/maps')
        if maps_path.exists():
            try:
                maps = maps_path.read_text(errors='ignore')[:2000]
                _state['findings'].append({{
                    'id': f'ptrace-{{pid}}', 'type': 'ptrace_maps', 'pid': pid,
                    'maps_sample': maps[:500], 'confidence': 0.8
                }})
                _append(f'ptrace_inspect pid={{pid}}: {{len(maps)}} chars of maps')
            except PermissionError:
                _append(f'ptrace_inspect pid={{pid}}: permission denied')
        return _next_node(node)
    if kind == 'read_proc_mem' and RING_LEVEL <= 2:
        pid = int(params.get('pid', 0))
        if pid <= 0:
            _append('read_proc_mem: invalid pid')
            return _next_node(node)
        mem_path = pathlib.Path(f'/proc/{{pid}}/mem')
        if mem_path.exists() and os.access(str(mem_path), os.R_OK):
            try:
                with mem_path.open('rb') as fh:
                    sample = fh.read(128)
                _state['findings'].append({{'id': f'proc-mem-{{pid}}', 'type': 'proc_mem', 'pid': pid, 'sample_len': len(sample), 'confidence': 0.7}})
            except Exception as exc:
                _append('read_proc_mem failed', error=str(exc)[:80])
        return _next_node(node)
    if kind == 'inspect_namespaces' and RING_LEVEL <= 2:
        proc_ns = pathlib.Path('/proc/self/ns')
        rows = []
        if proc_ns.exists():
            for ns in proc_ns.iterdir():
                try:
                    rows.append({{'ns': ns.name, 'target': os.readlink(str(ns))[:120]}})
                except Exception:
                    pass
        _state['namespaces'] = rows
        _append('inspect_namespaces complete', count=len(rows))
        return _next_node(node)
    if kind == 'snapshot_vss' and RING_LEVEL <= 2:
        volume = str(params.get('volume', 'C:\\'))
        _append('snapshot_vss requested', volume=volume, status='simulated')
        return _next_node(node)
    if kind == 'load_driver' and RING_LEVEL <= 2:
        driver_path = str(params.get('driver_path', '')).strip()
        driver_name = str(params.get('driver_name', '')).strip()
        loaded = False
        if driver_path:
            try:
                if os.name == 'nt':
                    r = subprocess.run(['sc', 'start', driver_name or 'driver'], capture_output=True, text=True, timeout=10)
                else:
                    r = subprocess.run(['insmod', driver_path], capture_output=True, text=True, timeout=10)
                loaded = r.returncode == 0
                _append('load_driver attempted', loaded=loaded, rc=r.returncode)
            except Exception as exc:
                _append('load_driver failed', error=str(exc)[:100])
        else:
            _append('load_driver: missing driver_path')
        return _next_node(node)
    if kind in ('repeat', 'loop'):
        max_iterations = max(0, int(params.get('max_iterations', 1)))
        target = str(params.get('target_node_id', ''))
        cnt = int(_state['repeat_counts'].get(node_id, 0))
        if cnt >= max_iterations:
            _state['repeat_counts'][node_id] = 0
            return _next_node(node)
        _state['repeat_counts'][node_id] = cnt + 1
        if target and target in NODES:
            return target
        return _next_node(node)
    if kind in ('loop_until', 'while_condition'):
        key = str(params.get('condition_key', 'findings_count'))
        operator = str(params.get('operator', '<'))
        threshold = float(params.get('threshold', 1))
        target = str(params.get('target_node_id', ''))
        current_value = float(_state['stats'].get(key, len(_state['findings'])))
        should_loop = False
        if operator == '<':
            should_loop = current_value < threshold
        elif operator == '<=':
            should_loop = current_value <= threshold
        elif operator == '>':
            should_loop = current_value > threshold
        elif operator == '>=':
            should_loop = current_value >= threshold
        elif operator == '==':
            should_loop = abs(current_value - threshold) < 1e-9
        elif operator == '!=':
            should_loop = abs(current_value - threshold) >= 1e-9
        if should_loop and target and target in NODES:
            return target
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
    script_path = workdir / _random_bin_basename("drone")
    script_path.write_bytes(source.encode("utf-8"))
    os.chmod(script_path, 0o700)
    proc_env = {**os.environ, "HG_DRONE_KEY_HEX": private_key_hex}
    if detached:
        return subprocess.Popen(
            [sys.executable, str(script_path)],
            cwd=str(workdir),
            env=proc_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
    return subprocess.Popen([sys.executable, str(script_path)], cwd=str(workdir), env=proc_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def deploy_blob_remote(blob_b64: str, private_key_hex: str, host: str, ssh_key_path: str, remote_workdir: str) -> dict[str, Any]:
    source = decode_blob(blob_b64, private_key_hex)
    did_match = re.search(r'^DRONE_ID\s*=\s*"([^"]+)"', source, re.MULTILINE)
    drone_id = did_match.group(1) if did_match else "drone"
    local_name = _random_bin_basename(f"drone_{drone_id}")
    local_tmp = Path("/tmp") / local_name
    local_tmp.write_bytes(source.encode("utf-8"))
    remote_path = f"{remote_workdir.rstrip('/')}/{local_name}"
    subprocess.run(["scp", "-i", ssh_key_path, str(local_tmp), f"{host}:{remote_path}"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    cmd = f"mkdir -p {remote_workdir} && nohup python3 {remote_path} >/dev/null 2>&1 & echo $!"
    proc = subprocess.run(["ssh", "-i", ssh_key_path, host, cmd], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return {"pid": int((proc.stdout or "0").strip() or 0), "host": host, "remote_path": remote_path}
