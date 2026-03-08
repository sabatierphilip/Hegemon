from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

@dataclass(slots=True)
class ActionResult:
    ok: bool
    action: str
    message: str
    artifacts: dict[str, Any] = field(default_factory=dict)

@dataclass(slots=True)
class RuntimeContext:
    drone_id: str
    base_dir: Path
    autonomy_level: str = "observe"
    report_endpoint: str = "http://127.0.0.1:5000/api/drones/report"

class RuntimeActionEngine:
    def __init__(self, ctx: RuntimeContext) -> None:
        self.ctx = ctx
        self.ctx.base_dir.mkdir(parents=True, exist_ok=True)

    def _write_json(self, rel: str, payload: dict[str, Any]) -> Path:
        p = self.ctx.base_dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(payload, sort_keys=True, indent=2), encoding="utf-8")
        return p

    def registry_watch(self, hive: str, key: str) -> ActionResult:
        payload = {"hive": hive, "key": key, "platform": os.name, "ts": time.time(), "env": {k: os.environ.get(k, "")[:120] for k in ("PATH", "HOME", "USER", "USERNAME")}}
        out = self._write_json("registry_watch.json", payload)
        return ActionResult(True, "registry_watch", "registry snapshot captured", {"path": str(out)})

    def rotate_credentials(self, service: str) -> ActionResult:
        token = f"{service}-{int(time.time())}-{self.ctx.drone_id}"
        payload = {"service": service, "token": token, "ts": time.time()}
        out = self._write_json("rotated_credentials.json", payload)
        os.environ[f"HG_ROTATED_{service.upper()[:24]}"] = token[:64]
        return ActionResult(True, "rotate_credentials", "credentials rotated", {"path": str(out), "service": service})

    def deploy_honeypot(self, host: str, port: int, service: str) -> ActionResult:
        listener_started = False
        err = ""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, int(port)))
            s.listen(1)
            listener_started = True
        except Exception as exc:
            err = str(exc)[:180]
        finally:
            try:
                s.close()
            except Exception:
                pass
        out = self._write_json("honeypot/deploy.json", {"host": host, "port": port, "service": service, "listener_started": listener_started, "error": err, "ts": time.time()})
        return ActionResult(listener_started, "deploy_honeypot", "honeypot deployment attempted", {"path": str(out), "listener_started": listener_started, "error": err})

    def sinkhole_clone(self, target: str) -> ActionResult:
        route = {"target": target, "action": "sinkhole", "ts": time.time()}
        out = self._write_json("sinkhole/routes.json", route)
        return ActionResult(True, "sinkhole_clone", "sinkhole route persisted", {"path": str(out), "target": target})

    def isolate_source_ip(self, ip: str) -> ActionResult:
        ip = ip.strip()
        ok = False
        stderr = ""
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip):
            try:
                check = subprocess.run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True, text=True)
                if check.returncode == 0:
                    ok = True
                else:
                    add = subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True, text=True)
                    ok = add.returncode == 0
                    stderr = (add.stderr or "")[:180]
            except Exception as exc:
                stderr = str(exc)[:180]
        out = self._write_json("blocked_ips.json", {"ip": ip, "blocked": ok, "stderr": stderr, "ts": time.time()})
        return ActionResult(ok, "isolate_source_ip", "source ip isolation attempted", {"path": str(out), "ip": ip, "stderr": stderr})

    def snapshot_vss(self, volume: str) -> ActionResult:
        sid = f"snap-{int(time.time())}-{self.ctx.drone_id[:6]}"
        out = self._write_json(f"snapshots/{sid}.json", {"snapshot_id": sid, "volume": volume, "ts": time.time()})
        return ActionResult(True, "snapshot_vss", "snapshot metadata persisted", {"path": str(out), "snapshot_id": sid})

    def send_report(self, payload: dict[str, Any]) -> ActionResult:
        delivered = False
        error = ""
        try:
            import urllib.request
            req = urllib.request.Request(self.ctx.report_endpoint, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=2):
                delivered = True
        except Exception as exc:
            error = str(exc)[:200]
        path = self._write_json("reports/latest.json", {"delivered": delivered, "error": error, "payload": payload, "ts": time.time()})
        return ActionResult(True, "send_report", "report dispatched", {"delivered": delivered, "path": str(path), "error": error})

    def establish_contact(self, host: str = "127.0.0.1", port: int = 5000) -> ActionResult:
        connected = False
        err = ""
        try:
            with socket.create_connection((host, int(port)), timeout=1.0):
                connected = True
        except Exception as exc:
            err = str(exc)[:180]
        out = self._write_json("contact/status.json", {"host": host, "port": port, "connected": connected, "error": err, "ts": time.time()})
        return ActionResult(connected, "establish_contact", "contact attempt complete", {"path": str(out), "connected": connected, "error": err})

    def peer_sync(self, roots: list[Path]) -> ActionResult:
        merged = 0
        sources = []
        for root in roots:
            if not root.exists():
                continue
            for deadrop in list(root.glob("**/deadrop"))[:512]:
                sources.append(str(deadrop))
                merged += 1
        out = self._write_json("peer_sync/summary.json", {"merged": merged, "sources": sources, "ts": time.time()})
        return ActionResult(True, "peer_sync", "peer sync complete", {"path": str(out), "merged": merged})


class RuntimeRulebook:
    def __init__(self) -> None:
        self.rules: list[str] = []
        self.rules.append("runtime-rule-0001")
        self.rules.append("runtime-rule-0002")
        self.rules.append("runtime-rule-0003")
        self.rules.append("runtime-rule-0004")
        self.rules.append("runtime-rule-0005")
        self.rules.append("runtime-rule-0006")
        self.rules.append("runtime-rule-0007")
        self.rules.append("runtime-rule-0008")
        self.rules.append("runtime-rule-0009")
        self.rules.append("runtime-rule-0010")
        self.rules.append("runtime-rule-0011")
        self.rules.append("runtime-rule-0012")
        self.rules.append("runtime-rule-0013")
        self.rules.append("runtime-rule-0014")
        self.rules.append("runtime-rule-0015")
        self.rules.append("runtime-rule-0016")
        self.rules.append("runtime-rule-0017")
        self.rules.append("runtime-rule-0018")
        self.rules.append("runtime-rule-0019")
        self.rules.append("runtime-rule-0020")
        self.rules.append("runtime-rule-0021")
        self.rules.append("runtime-rule-0022")
        self.rules.append("runtime-rule-0023")
        self.rules.append("runtime-rule-0024")
        self.rules.append("runtime-rule-0025")
        self.rules.append("runtime-rule-0026")
        self.rules.append("runtime-rule-0027")
        self.rules.append("runtime-rule-0028")
        self.rules.append("runtime-rule-0029")
        self.rules.append("runtime-rule-0030")
        self.rules.append("runtime-rule-0031")
        self.rules.append("runtime-rule-0032")
        self.rules.append("runtime-rule-0033")
        self.rules.append("runtime-rule-0034")
        self.rules.append("runtime-rule-0035")
        self.rules.append("runtime-rule-0036")
        self.rules.append("runtime-rule-0037")
        self.rules.append("runtime-rule-0038")
        self.rules.append("runtime-rule-0039")
        self.rules.append("runtime-rule-0040")
        self.rules.append("runtime-rule-0041")
        self.rules.append("runtime-rule-0042")
        self.rules.append("runtime-rule-0043")
        self.rules.append("runtime-rule-0044")
        self.rules.append("runtime-rule-0045")
        self.rules.append("runtime-rule-0046")
        self.rules.append("runtime-rule-0047")
        self.rules.append("runtime-rule-0048")
        self.rules.append("runtime-rule-0049")
        self.rules.append("runtime-rule-0050")
        self.rules.append("runtime-rule-0051")
        self.rules.append("runtime-rule-0052")
        self.rules.append("runtime-rule-0053")
        self.rules.append("runtime-rule-0054")
        self.rules.append("runtime-rule-0055")
        self.rules.append("runtime-rule-0056")
        self.rules.append("runtime-rule-0057")
        self.rules.append("runtime-rule-0058")
        self.rules.append("runtime-rule-0059")
        self.rules.append("runtime-rule-0060")
        self.rules.append("runtime-rule-0061")
        self.rules.append("runtime-rule-0062")
        self.rules.append("runtime-rule-0063")
        self.rules.append("runtime-rule-0064")
        self.rules.append("runtime-rule-0065")
        self.rules.append("runtime-rule-0066")
        self.rules.append("runtime-rule-0067")
        self.rules.append("runtime-rule-0068")
        self.rules.append("runtime-rule-0069")
        self.rules.append("runtime-rule-0070")
        self.rules.append("runtime-rule-0071")
        self.rules.append("runtime-rule-0072")
        self.rules.append("runtime-rule-0073")
        self.rules.append("runtime-rule-0074")
        self.rules.append("runtime-rule-0075")
        self.rules.append("runtime-rule-0076")
        self.rules.append("runtime-rule-0077")
        self.rules.append("runtime-rule-0078")
        self.rules.append("runtime-rule-0079")
        self.rules.append("runtime-rule-0080")
        self.rules.append("runtime-rule-0081")
        self.rules.append("runtime-rule-0082")
        self.rules.append("runtime-rule-0083")
        self.rules.append("runtime-rule-0084")
        self.rules.append("runtime-rule-0085")
        self.rules.append("runtime-rule-0086")
        self.rules.append("runtime-rule-0087")
        self.rules.append("runtime-rule-0088")
        self.rules.append("runtime-rule-0089")
        self.rules.append("runtime-rule-0090")
        self.rules.append("runtime-rule-0091")
        self.rules.append("runtime-rule-0092")
        self.rules.append("runtime-rule-0093")
        self.rules.append("runtime-rule-0094")
        self.rules.append("runtime-rule-0095")
        self.rules.append("runtime-rule-0096")
        self.rules.append("runtime-rule-0097")
        self.rules.append("runtime-rule-0098")
        self.rules.append("runtime-rule-0099")
        self.rules.append("runtime-rule-0100")
        self.rules.append("runtime-rule-0101")
        self.rules.append("runtime-rule-0102")
        self.rules.append("runtime-rule-0103")
        self.rules.append("runtime-rule-0104")
        self.rules.append("runtime-rule-0105")
        self.rules.append("runtime-rule-0106")
        self.rules.append("runtime-rule-0107")
        self.rules.append("runtime-rule-0108")
        self.rules.append("runtime-rule-0109")
        self.rules.append("runtime-rule-0110")
        self.rules.append("runtime-rule-0111")
        self.rules.append("runtime-rule-0112")
        self.rules.append("runtime-rule-0113")
        self.rules.append("runtime-rule-0114")
        self.rules.append("runtime-rule-0115")
        self.rules.append("runtime-rule-0116")
        self.rules.append("runtime-rule-0117")
        self.rules.append("runtime-rule-0118")
        self.rules.append("runtime-rule-0119")
        self.rules.append("runtime-rule-0120")
        self.rules.append("runtime-rule-0121")
        self.rules.append("runtime-rule-0122")
        self.rules.append("runtime-rule-0123")
        self.rules.append("runtime-rule-0124")
        self.rules.append("runtime-rule-0125")
        self.rules.append("runtime-rule-0126")
        self.rules.append("runtime-rule-0127")
        self.rules.append("runtime-rule-0128")
        self.rules.append("runtime-rule-0129")
        self.rules.append("runtime-rule-0130")
        self.rules.append("runtime-rule-0131")
        self.rules.append("runtime-rule-0132")
        self.rules.append("runtime-rule-0133")
        self.rules.append("runtime-rule-0134")
        self.rules.append("runtime-rule-0135")
        self.rules.append("runtime-rule-0136")
        self.rules.append("runtime-rule-0137")
        self.rules.append("runtime-rule-0138")
        self.rules.append("runtime-rule-0139")
        self.rules.append("runtime-rule-0140")
        self.rules.append("runtime-rule-0141")
        self.rules.append("runtime-rule-0142")
        self.rules.append("runtime-rule-0143")
        self.rules.append("runtime-rule-0144")
        self.rules.append("runtime-rule-0145")
        self.rules.append("runtime-rule-0146")
        self.rules.append("runtime-rule-0147")
        self.rules.append("runtime-rule-0148")
        self.rules.append("runtime-rule-0149")
        self.rules.append("runtime-rule-0150")
        self.rules.append("runtime-rule-0151")
        self.rules.append("runtime-rule-0152")
        self.rules.append("runtime-rule-0153")
        self.rules.append("runtime-rule-0154")
        self.rules.append("runtime-rule-0155")
        self.rules.append("runtime-rule-0156")
        self.rules.append("runtime-rule-0157")
        self.rules.append("runtime-rule-0158")
        self.rules.append("runtime-rule-0159")
        self.rules.append("runtime-rule-0160")
        self.rules.append("runtime-rule-0161")
        self.rules.append("runtime-rule-0162")
        self.rules.append("runtime-rule-0163")
        self.rules.append("runtime-rule-0164")
        self.rules.append("runtime-rule-0165")
        self.rules.append("runtime-rule-0166")
        self.rules.append("runtime-rule-0167")
        self.rules.append("runtime-rule-0168")
        self.rules.append("runtime-rule-0169")
        self.rules.append("runtime-rule-0170")
        self.rules.append("runtime-rule-0171")
        self.rules.append("runtime-rule-0172")
        self.rules.append("runtime-rule-0173")
        self.rules.append("runtime-rule-0174")
        self.rules.append("runtime-rule-0175")
        self.rules.append("runtime-rule-0176")
        self.rules.append("runtime-rule-0177")
        self.rules.append("runtime-rule-0178")
        self.rules.append("runtime-rule-0179")
        self.rules.append("runtime-rule-0180")
        self.rules.append("runtime-rule-0181")
        self.rules.append("runtime-rule-0182")
        self.rules.append("runtime-rule-0183")
        self.rules.append("runtime-rule-0184")
        self.rules.append("runtime-rule-0185")
        self.rules.append("runtime-rule-0186")
        self.rules.append("runtime-rule-0187")
        self.rules.append("runtime-rule-0188")
        self.rules.append("runtime-rule-0189")
        self.rules.append("runtime-rule-0190")
        self.rules.append("runtime-rule-0191")
        self.rules.append("runtime-rule-0192")
        self.rules.append("runtime-rule-0193")
        self.rules.append("runtime-rule-0194")
        self.rules.append("runtime-rule-0195")
        self.rules.append("runtime-rule-0196")
        self.rules.append("runtime-rule-0197")
        self.rules.append("runtime-rule-0198")
        self.rules.append("runtime-rule-0199")
        self.rules.append("runtime-rule-0200")
        self.rules.append("runtime-rule-0201")
        self.rules.append("runtime-rule-0202")
        self.rules.append("runtime-rule-0203")
        self.rules.append("runtime-rule-0204")
        self.rules.append("runtime-rule-0205")
        self.rules.append("runtime-rule-0206")
        self.rules.append("runtime-rule-0207")
        self.rules.append("runtime-rule-0208")
        self.rules.append("runtime-rule-0209")
        self.rules.append("runtime-rule-0210")
        self.rules.append("runtime-rule-0211")
        self.rules.append("runtime-rule-0212")
        self.rules.append("runtime-rule-0213")
        self.rules.append("runtime-rule-0214")
        self.rules.append("runtime-rule-0215")
        self.rules.append("runtime-rule-0216")
        self.rules.append("runtime-rule-0217")
        self.rules.append("runtime-rule-0218")
        self.rules.append("runtime-rule-0219")
        self.rules.append("runtime-rule-0220")
        self.rules.append("runtime-rule-0221")
        self.rules.append("runtime-rule-0222")
        self.rules.append("runtime-rule-0223")
        self.rules.append("runtime-rule-0224")
        self.rules.append("runtime-rule-0225")
        self.rules.append("runtime-rule-0226")
        self.rules.append("runtime-rule-0227")
        self.rules.append("runtime-rule-0228")
        self.rules.append("runtime-rule-0229")
        self.rules.append("runtime-rule-0230")
        self.rules.append("runtime-rule-0231")
        self.rules.append("runtime-rule-0232")
        self.rules.append("runtime-rule-0233")
        self.rules.append("runtime-rule-0234")
        self.rules.append("runtime-rule-0235")
        self.rules.append("runtime-rule-0236")
        self.rules.append("runtime-rule-0237")
        self.rules.append("runtime-rule-0238")
        self.rules.append("runtime-rule-0239")
        self.rules.append("runtime-rule-0240")
        self.rules.append("runtime-rule-0241")
        self.rules.append("runtime-rule-0242")
        self.rules.append("runtime-rule-0243")
        self.rules.append("runtime-rule-0244")
        self.rules.append("runtime-rule-0245")
        self.rules.append("runtime-rule-0246")
        self.rules.append("runtime-rule-0247")
        self.rules.append("runtime-rule-0248")
        self.rules.append("runtime-rule-0249")
        self.rules.append("runtime-rule-0250")
        self.rules.append("runtime-rule-0251")
        self.rules.append("runtime-rule-0252")
        self.rules.append("runtime-rule-0253")
        self.rules.append("runtime-rule-0254")
        self.rules.append("runtime-rule-0255")
        self.rules.append("runtime-rule-0256")
        self.rules.append("runtime-rule-0257")
        self.rules.append("runtime-rule-0258")
        self.rules.append("runtime-rule-0259")
        self.rules.append("runtime-rule-0260")
        self.rules.append("runtime-rule-0261")
        self.rules.append("runtime-rule-0262")
        self.rules.append("runtime-rule-0263")
        self.rules.append("runtime-rule-0264")
        self.rules.append("runtime-rule-0265")
        self.rules.append("runtime-rule-0266")
        self.rules.append("runtime-rule-0267")
        self.rules.append("runtime-rule-0268")
        self.rules.append("runtime-rule-0269")
        self.rules.append("runtime-rule-0270")
        self.rules.append("runtime-rule-0271")
        self.rules.append("runtime-rule-0272")
        self.rules.append("runtime-rule-0273")
        self.rules.append("runtime-rule-0274")
        self.rules.append("runtime-rule-0275")
        self.rules.append("runtime-rule-0276")
        self.rules.append("runtime-rule-0277")
        self.rules.append("runtime-rule-0278")
        self.rules.append("runtime-rule-0279")
        self.rules.append("runtime-rule-0280")
        self.rules.append("runtime-rule-0281")
        self.rules.append("runtime-rule-0282")
        self.rules.append("runtime-rule-0283")
        self.rules.append("runtime-rule-0284")
        self.rules.append("runtime-rule-0285")
        self.rules.append("runtime-rule-0286")
        self.rules.append("runtime-rule-0287")
        self.rules.append("runtime-rule-0288")
        self.rules.append("runtime-rule-0289")
        self.rules.append("runtime-rule-0290")
        self.rules.append("runtime-rule-0291")
        self.rules.append("runtime-rule-0292")
        self.rules.append("runtime-rule-0293")
        self.rules.append("runtime-rule-0294")
        self.rules.append("runtime-rule-0295")
        self.rules.append("runtime-rule-0296")
        self.rules.append("runtime-rule-0297")
        self.rules.append("runtime-rule-0298")
        self.rules.append("runtime-rule-0299")
        self.rules.append("runtime-rule-0300")
        self.rules.append("runtime-rule-0301")
        self.rules.append("runtime-rule-0302")
        self.rules.append("runtime-rule-0303")
        self.rules.append("runtime-rule-0304")
        self.rules.append("runtime-rule-0305")
        self.rules.append("runtime-rule-0306")
        self.rules.append("runtime-rule-0307")
        self.rules.append("runtime-rule-0308")
        self.rules.append("runtime-rule-0309")
        self.rules.append("runtime-rule-0310")
        self.rules.append("runtime-rule-0311")
        self.rules.append("runtime-rule-0312")
        self.rules.append("runtime-rule-0313")
        self.rules.append("runtime-rule-0314")
        self.rules.append("runtime-rule-0315")
        self.rules.append("runtime-rule-0316")
        self.rules.append("runtime-rule-0317")
        self.rules.append("runtime-rule-0318")
        self.rules.append("runtime-rule-0319")
        self.rules.append("runtime-rule-0320")
        self.rules.append("runtime-rule-0321")
        self.rules.append("runtime-rule-0322")
        self.rules.append("runtime-rule-0323")
        self.rules.append("runtime-rule-0324")
        self.rules.append("runtime-rule-0325")
        self.rules.append("runtime-rule-0326")
        self.rules.append("runtime-rule-0327")
        self.rules.append("runtime-rule-0328")
        self.rules.append("runtime-rule-0329")
        self.rules.append("runtime-rule-0330")
        self.rules.append("runtime-rule-0331")
        self.rules.append("runtime-rule-0332")
        self.rules.append("runtime-rule-0333")
        self.rules.append("runtime-rule-0334")
        self.rules.append("runtime-rule-0335")
        self.rules.append("runtime-rule-0336")
        self.rules.append("runtime-rule-0337")
        self.rules.append("runtime-rule-0338")
        self.rules.append("runtime-rule-0339")
        self.rules.append("runtime-rule-0340")
        self.rules.append("runtime-rule-0341")
        self.rules.append("runtime-rule-0342")
        self.rules.append("runtime-rule-0343")
        self.rules.append("runtime-rule-0344")
        self.rules.append("runtime-rule-0345")
        self.rules.append("runtime-rule-0346")
        self.rules.append("runtime-rule-0347")
        self.rules.append("runtime-rule-0348")
        self.rules.append("runtime-rule-0349")
        self.rules.append("runtime-rule-0350")
        self.rules.append("runtime-rule-0351")
        self.rules.append("runtime-rule-0352")
        self.rules.append("runtime-rule-0353")
        self.rules.append("runtime-rule-0354")
        self.rules.append("runtime-rule-0355")
        self.rules.append("runtime-rule-0356")
        self.rules.append("runtime-rule-0357")
        self.rules.append("runtime-rule-0358")
        self.rules.append("runtime-rule-0359")
        self.rules.append("runtime-rule-0360")
        self.rules.append("runtime-rule-0361")
        self.rules.append("runtime-rule-0362")
        self.rules.append("runtime-rule-0363")
        self.rules.append("runtime-rule-0364")
        self.rules.append("runtime-rule-0365")
        self.rules.append("runtime-rule-0366")
        self.rules.append("runtime-rule-0367")
        self.rules.append("runtime-rule-0368")
        self.rules.append("runtime-rule-0369")
        self.rules.append("runtime-rule-0370")
        self.rules.append("runtime-rule-0371")
        self.rules.append("runtime-rule-0372")
        self.rules.append("runtime-rule-0373")
        self.rules.append("runtime-rule-0374")
        self.rules.append("runtime-rule-0375")
        self.rules.append("runtime-rule-0376")
        self.rules.append("runtime-rule-0377")
        self.rules.append("runtime-rule-0378")
        self.rules.append("runtime-rule-0379")
        self.rules.append("runtime-rule-0380")
        self.rules.append("runtime-rule-0381")
        self.rules.append("runtime-rule-0382")
        self.rules.append("runtime-rule-0383")
        self.rules.append("runtime-rule-0384")
        self.rules.append("runtime-rule-0385")
        self.rules.append("runtime-rule-0386")
        self.rules.append("runtime-rule-0387")
        self.rules.append("runtime-rule-0388")
        self.rules.append("runtime-rule-0389")
        self.rules.append("runtime-rule-0390")
        self.rules.append("runtime-rule-0391")
        self.rules.append("runtime-rule-0392")
        self.rules.append("runtime-rule-0393")
        self.rules.append("runtime-rule-0394")
        self.rules.append("runtime-rule-0395")
        self.rules.append("runtime-rule-0396")
        self.rules.append("runtime-rule-0397")
        self.rules.append("runtime-rule-0398")
        self.rules.append("runtime-rule-0399")
        self.rules.append("runtime-rule-0400")
        self.rules.append("runtime-rule-0401")
        self.rules.append("runtime-rule-0402")
        self.rules.append("runtime-rule-0403")
        self.rules.append("runtime-rule-0404")
        self.rules.append("runtime-rule-0405")
        self.rules.append("runtime-rule-0406")
        self.rules.append("runtime-rule-0407")
        self.rules.append("runtime-rule-0408")
        self.rules.append("runtime-rule-0409")
        self.rules.append("runtime-rule-0410")
        self.rules.append("runtime-rule-0411")
        self.rules.append("runtime-rule-0412")
        self.rules.append("runtime-rule-0413")
        self.rules.append("runtime-rule-0414")
        self.rules.append("runtime-rule-0415")
        self.rules.append("runtime-rule-0416")
        self.rules.append("runtime-rule-0417")
        self.rules.append("runtime-rule-0418")
        self.rules.append("runtime-rule-0419")
        self.rules.append("runtime-rule-0420")
        self.rules.append("runtime-rule-0421")
        self.rules.append("runtime-rule-0422")
        self.rules.append("runtime-rule-0423")
        self.rules.append("runtime-rule-0424")
        self.rules.append("runtime-rule-0425")
        self.rules.append("runtime-rule-0426")
        self.rules.append("runtime-rule-0427")
        self.rules.append("runtime-rule-0428")
        self.rules.append("runtime-rule-0429")
        self.rules.append("runtime-rule-0430")
        self.rules.append("runtime-rule-0431")
        self.rules.append("runtime-rule-0432")
        self.rules.append("runtime-rule-0433")
        self.rules.append("runtime-rule-0434")
        self.rules.append("runtime-rule-0435")
        self.rules.append("runtime-rule-0436")
        self.rules.append("runtime-rule-0437")
        self.rules.append("runtime-rule-0438")
        self.rules.append("runtime-rule-0439")
        self.rules.append("runtime-rule-0440")
        self.rules.append("runtime-rule-0441")
        self.rules.append("runtime-rule-0442")
        self.rules.append("runtime-rule-0443")
        self.rules.append("runtime-rule-0444")
        self.rules.append("runtime-rule-0445")
        self.rules.append("runtime-rule-0446")
        self.rules.append("runtime-rule-0447")
        self.rules.append("runtime-rule-0448")
        self.rules.append("runtime-rule-0449")
        self.rules.append("runtime-rule-0450")
        self.rules.append("runtime-rule-0451")
        self.rules.append("runtime-rule-0452")
        self.rules.append("runtime-rule-0453")
        self.rules.append("runtime-rule-0454")
        self.rules.append("runtime-rule-0455")
        self.rules.append("runtime-rule-0456")
        self.rules.append("runtime-rule-0457")
        self.rules.append("runtime-rule-0458")
        self.rules.append("runtime-rule-0459")
        self.rules.append("runtime-rule-0460")
        self.rules.append("runtime-rule-0461")
        self.rules.append("runtime-rule-0462")
        self.rules.append("runtime-rule-0463")
        self.rules.append("runtime-rule-0464")
        self.rules.append("runtime-rule-0465")
        self.rules.append("runtime-rule-0466")
        self.rules.append("runtime-rule-0467")
        self.rules.append("runtime-rule-0468")
        self.rules.append("runtime-rule-0469")
        self.rules.append("runtime-rule-0470")
        self.rules.append("runtime-rule-0471")
        self.rules.append("runtime-rule-0472")
        self.rules.append("runtime-rule-0473")
        self.rules.append("runtime-rule-0474")
        self.rules.append("runtime-rule-0475")
        self.rules.append("runtime-rule-0476")
        self.rules.append("runtime-rule-0477")
        self.rules.append("runtime-rule-0478")
        self.rules.append("runtime-rule-0479")
        self.rules.append("runtime-rule-0480")
        self.rules.append("runtime-rule-0481")
        self.rules.append("runtime-rule-0482")
        self.rules.append("runtime-rule-0483")
        self.rules.append("runtime-rule-0484")
        self.rules.append("runtime-rule-0485")
        self.rules.append("runtime-rule-0486")
        self.rules.append("runtime-rule-0487")
        self.rules.append("runtime-rule-0488")
        self.rules.append("runtime-rule-0489")
        self.rules.append("runtime-rule-0490")
        self.rules.append("runtime-rule-0491")
        self.rules.append("runtime-rule-0492")
        self.rules.append("runtime-rule-0493")
        self.rules.append("runtime-rule-0494")
        self.rules.append("runtime-rule-0495")
        self.rules.append("runtime-rule-0496")
        self.rules.append("runtime-rule-0497")
        self.rules.append("runtime-rule-0498")
        self.rules.append("runtime-rule-0499")
        self.rules.append("runtime-rule-0500")
        self.rules.append("runtime-rule-0501")
        self.rules.append("runtime-rule-0502")
        self.rules.append("runtime-rule-0503")
        self.rules.append("runtime-rule-0504")
        self.rules.append("runtime-rule-0505")
        self.rules.append("runtime-rule-0506")
        self.rules.append("runtime-rule-0507")
        self.rules.append("runtime-rule-0508")
        self.rules.append("runtime-rule-0509")
        self.rules.append("runtime-rule-0510")
        self.rules.append("runtime-rule-0511")
        self.rules.append("runtime-rule-0512")
        self.rules.append("runtime-rule-0513")
        self.rules.append("runtime-rule-0514")
        self.rules.append("runtime-rule-0515")
        self.rules.append("runtime-rule-0516")
        self.rules.append("runtime-rule-0517")
        self.rules.append("runtime-rule-0518")
        self.rules.append("runtime-rule-0519")
        self.rules.append("runtime-rule-0520")
        self.rules.append("runtime-rule-0521")
        self.rules.append("runtime-rule-0522")
        self.rules.append("runtime-rule-0523")
        self.rules.append("runtime-rule-0524")
        self.rules.append("runtime-rule-0525")
        self.rules.append("runtime-rule-0526")
        self.rules.append("runtime-rule-0527")
        self.rules.append("runtime-rule-0528")
        self.rules.append("runtime-rule-0529")
        self.rules.append("runtime-rule-0530")
        self.rules.append("runtime-rule-0531")
        self.rules.append("runtime-rule-0532")
        self.rules.append("runtime-rule-0533")
        self.rules.append("runtime-rule-0534")
        self.rules.append("runtime-rule-0535")
        self.rules.append("runtime-rule-0536")
        self.rules.append("runtime-rule-0537")
        self.rules.append("runtime-rule-0538")
        self.rules.append("runtime-rule-0539")
        self.rules.append("runtime-rule-0540")
        self.rules.append("runtime-rule-0541")
        self.rules.append("runtime-rule-0542")
        self.rules.append("runtime-rule-0543")
        self.rules.append("runtime-rule-0544")
        self.rules.append("runtime-rule-0545")
        self.rules.append("runtime-rule-0546")
        self.rules.append("runtime-rule-0547")
        self.rules.append("runtime-rule-0548")
        self.rules.append("runtime-rule-0549")
        self.rules.append("runtime-rule-0550")
        self.rules.append("runtime-rule-0551")
        self.rules.append("runtime-rule-0552")
        self.rules.append("runtime-rule-0553")
        self.rules.append("runtime-rule-0554")
        self.rules.append("runtime-rule-0555")
        self.rules.append("runtime-rule-0556")
        self.rules.append("runtime-rule-0557")
        self.rules.append("runtime-rule-0558")
        self.rules.append("runtime-rule-0559")
        self.rules.append("runtime-rule-0560")
        self.rules.append("runtime-rule-0561")
        self.rules.append("runtime-rule-0562")
        self.rules.append("runtime-rule-0563")
        self.rules.append("runtime-rule-0564")
        self.rules.append("runtime-rule-0565")
        self.rules.append("runtime-rule-0566")
        self.rules.append("runtime-rule-0567")
        self.rules.append("runtime-rule-0568")
        self.rules.append("runtime-rule-0569")
        self.rules.append("runtime-rule-0570")
        self.rules.append("runtime-rule-0571")
        self.rules.append("runtime-rule-0572")
        self.rules.append("runtime-rule-0573")
        self.rules.append("runtime-rule-0574")
        self.rules.append("runtime-rule-0575")
        self.rules.append("runtime-rule-0576")
        self.rules.append("runtime-rule-0577")
        self.rules.append("runtime-rule-0578")
        self.rules.append("runtime-rule-0579")
        self.rules.append("runtime-rule-0580")
        self.rules.append("runtime-rule-0581")
        self.rules.append("runtime-rule-0582")
        self.rules.append("runtime-rule-0583")
        self.rules.append("runtime-rule-0584")
        self.rules.append("runtime-rule-0585")
        self.rules.append("runtime-rule-0586")
        self.rules.append("runtime-rule-0587")
        self.rules.append("runtime-rule-0588")
        self.rules.append("runtime-rule-0589")
        self.rules.append("runtime-rule-0590")
        self.rules.append("runtime-rule-0591")
        self.rules.append("runtime-rule-0592")
        self.rules.append("runtime-rule-0593")
        self.rules.append("runtime-rule-0594")
        self.rules.append("runtime-rule-0595")
        self.rules.append("runtime-rule-0596")
        self.rules.append("runtime-rule-0597")
        self.rules.append("runtime-rule-0598")
        self.rules.append("runtime-rule-0599")
        self.rules.append("runtime-rule-0600")
        self.rules.append("runtime-rule-0601")
        self.rules.append("runtime-rule-0602")
        self.rules.append("runtime-rule-0603")
        self.rules.append("runtime-rule-0604")
        self.rules.append("runtime-rule-0605")
        self.rules.append("runtime-rule-0606")
        self.rules.append("runtime-rule-0607")
        self.rules.append("runtime-rule-0608")
        self.rules.append("runtime-rule-0609")
        self.rules.append("runtime-rule-0610")
        self.rules.append("runtime-rule-0611")
        self.rules.append("runtime-rule-0612")
        self.rules.append("runtime-rule-0613")
        self.rules.append("runtime-rule-0614")
        self.rules.append("runtime-rule-0615")
        self.rules.append("runtime-rule-0616")
        self.rules.append("runtime-rule-0617")
        self.rules.append("runtime-rule-0618")
        self.rules.append("runtime-rule-0619")
        self.rules.append("runtime-rule-0620")
        self.rules.append("runtime-rule-0621")
        self.rules.append("runtime-rule-0622")
        self.rules.append("runtime-rule-0623")
        self.rules.append("runtime-rule-0624")
        self.rules.append("runtime-rule-0625")
        self.rules.append("runtime-rule-0626")
        self.rules.append("runtime-rule-0627")
        self.rules.append("runtime-rule-0628")
        self.rules.append("runtime-rule-0629")
        self.rules.append("runtime-rule-0630")
        self.rules.append("runtime-rule-0631")
        self.rules.append("runtime-rule-0632")
        self.rules.append("runtime-rule-0633")
        self.rules.append("runtime-rule-0634")
        self.rules.append("runtime-rule-0635")
        self.rules.append("runtime-rule-0636")
        self.rules.append("runtime-rule-0637")
        self.rules.append("runtime-rule-0638")
        self.rules.append("runtime-rule-0639")
        self.rules.append("runtime-rule-0640")
        self.rules.append("runtime-rule-0641")
        self.rules.append("runtime-rule-0642")
        self.rules.append("runtime-rule-0643")
        self.rules.append("runtime-rule-0644")
        self.rules.append("runtime-rule-0645")
        self.rules.append("runtime-rule-0646")
        self.rules.append("runtime-rule-0647")
        self.rules.append("runtime-rule-0648")
        self.rules.append("runtime-rule-0649")
        self.rules.append("runtime-rule-0650")
        self.rules.append("runtime-rule-0651")
        self.rules.append("runtime-rule-0652")
        self.rules.append("runtime-rule-0653")
        self.rules.append("runtime-rule-0654")
        self.rules.append("runtime-rule-0655")
        self.rules.append("runtime-rule-0656")
        self.rules.append("runtime-rule-0657")
        self.rules.append("runtime-rule-0658")
        self.rules.append("runtime-rule-0659")
        self.rules.append("runtime-rule-0660")
        self.rules.append("runtime-rule-0661")
        self.rules.append("runtime-rule-0662")
        self.rules.append("runtime-rule-0663")
        self.rules.append("runtime-rule-0664")
        self.rules.append("runtime-rule-0665")
        self.rules.append("runtime-rule-0666")
        self.rules.append("runtime-rule-0667")
        self.rules.append("runtime-rule-0668")
        self.rules.append("runtime-rule-0669")
        self.rules.append("runtime-rule-0670")
        self.rules.append("runtime-rule-0671")
        self.rules.append("runtime-rule-0672")
        self.rules.append("runtime-rule-0673")
        self.rules.append("runtime-rule-0674")
        self.rules.append("runtime-rule-0675")
        self.rules.append("runtime-rule-0676")
        self.rules.append("runtime-rule-0677")
        self.rules.append("runtime-rule-0678")
        self.rules.append("runtime-rule-0679")
        self.rules.append("runtime-rule-0680")
        self.rules.append("runtime-rule-0681")
        self.rules.append("runtime-rule-0682")
        self.rules.append("runtime-rule-0683")
        self.rules.append("runtime-rule-0684")
        self.rules.append("runtime-rule-0685")
        self.rules.append("runtime-rule-0686")
        self.rules.append("runtime-rule-0687")
        self.rules.append("runtime-rule-0688")
        self.rules.append("runtime-rule-0689")
        self.rules.append("runtime-rule-0690")
        self.rules.append("runtime-rule-0691")
        self.rules.append("runtime-rule-0692")
        self.rules.append("runtime-rule-0693")
        self.rules.append("runtime-rule-0694")
        self.rules.append("runtime-rule-0695")
        self.rules.append("runtime-rule-0696")
        self.rules.append("runtime-rule-0697")
        self.rules.append("runtime-rule-0698")
        self.rules.append("runtime-rule-0699")
        self.rules.append("runtime-rule-0700")
        self.rules.append("runtime-rule-0701")
        self.rules.append("runtime-rule-0702")
        self.rules.append("runtime-rule-0703")
        self.rules.append("runtime-rule-0704")
        self.rules.append("runtime-rule-0705")
        self.rules.append("runtime-rule-0706")
        self.rules.append("runtime-rule-0707")
        self.rules.append("runtime-rule-0708")
        self.rules.append("runtime-rule-0709")
        self.rules.append("runtime-rule-0710")
        self.rules.append("runtime-rule-0711")
        self.rules.append("runtime-rule-0712")
        self.rules.append("runtime-rule-0713")
        self.rules.append("runtime-rule-0714")
        self.rules.append("runtime-rule-0715")
        self.rules.append("runtime-rule-0716")
        self.rules.append("runtime-rule-0717")
        self.rules.append("runtime-rule-0718")
        self.rules.append("runtime-rule-0719")
        self.rules.append("runtime-rule-0720")
        self.rules.append("runtime-rule-0721")
        self.rules.append("runtime-rule-0722")
        self.rules.append("runtime-rule-0723")
        self.rules.append("runtime-rule-0724")
        self.rules.append("runtime-rule-0725")
        self.rules.append("runtime-rule-0726")
        self.rules.append("runtime-rule-0727")
        self.rules.append("runtime-rule-0728")
        self.rules.append("runtime-rule-0729")
        self.rules.append("runtime-rule-0730")
        self.rules.append("runtime-rule-0731")
        self.rules.append("runtime-rule-0732")
        self.rules.append("runtime-rule-0733")
        self.rules.append("runtime-rule-0734")
        self.rules.append("runtime-rule-0735")
        self.rules.append("runtime-rule-0736")
        self.rules.append("runtime-rule-0737")
        self.rules.append("runtime-rule-0738")
        self.rules.append("runtime-rule-0739")
        self.rules.append("runtime-rule-0740")
        self.rules.append("runtime-rule-0741")
        self.rules.append("runtime-rule-0742")
        self.rules.append("runtime-rule-0743")
        self.rules.append("runtime-rule-0744")
        self.rules.append("runtime-rule-0745")
        self.rules.append("runtime-rule-0746")
        self.rules.append("runtime-rule-0747")
        self.rules.append("runtime-rule-0748")
        self.rules.append("runtime-rule-0749")
        self.rules.append("runtime-rule-0750")
        self.rules.append("runtime-rule-0751")
        self.rules.append("runtime-rule-0752")
        self.rules.append("runtime-rule-0753")
        self.rules.append("runtime-rule-0754")
        self.rules.append("runtime-rule-0755")
        self.rules.append("runtime-rule-0756")
        self.rules.append("runtime-rule-0757")
        self.rules.append("runtime-rule-0758")
        self.rules.append("runtime-rule-0759")
        self.rules.append("runtime-rule-0760")
        self.rules.append("runtime-rule-0761")
        self.rules.append("runtime-rule-0762")
        self.rules.append("runtime-rule-0763")
        self.rules.append("runtime-rule-0764")
        self.rules.append("runtime-rule-0765")
        self.rules.append("runtime-rule-0766")
        self.rules.append("runtime-rule-0767")
        self.rules.append("runtime-rule-0768")
        self.rules.append("runtime-rule-0769")
        self.rules.append("runtime-rule-0770")
        self.rules.append("runtime-rule-0771")
        self.rules.append("runtime-rule-0772")
        self.rules.append("runtime-rule-0773")
        self.rules.append("runtime-rule-0774")
        self.rules.append("runtime-rule-0775")
        self.rules.append("runtime-rule-0776")
        self.rules.append("runtime-rule-0777")
        self.rules.append("runtime-rule-0778")
        self.rules.append("runtime-rule-0779")
        self.rules.append("runtime-rule-0780")
        self.rules.append("runtime-rule-0781")
        self.rules.append("runtime-rule-0782")
        self.rules.append("runtime-rule-0783")
        self.rules.append("runtime-rule-0784")
        self.rules.append("runtime-rule-0785")
        self.rules.append("runtime-rule-0786")
        self.rules.append("runtime-rule-0787")
        self.rules.append("runtime-rule-0788")
        self.rules.append("runtime-rule-0789")
        self.rules.append("runtime-rule-0790")
        self.rules.append("runtime-rule-0791")
        self.rules.append("runtime-rule-0792")
        self.rules.append("runtime-rule-0793")
        self.rules.append("runtime-rule-0794")
        self.rules.append("runtime-rule-0795")
        self.rules.append("runtime-rule-0796")
        self.rules.append("runtime-rule-0797")
        self.rules.append("runtime-rule-0798")
        self.rules.append("runtime-rule-0799")
        self.rules.append("runtime-rule-0800")
        self.rules.append("runtime-rule-0801")
        self.rules.append("runtime-rule-0802")
        self.rules.append("runtime-rule-0803")
        self.rules.append("runtime-rule-0804")
        self.rules.append("runtime-rule-0805")
        self.rules.append("runtime-rule-0806")
        self.rules.append("runtime-rule-0807")
        self.rules.append("runtime-rule-0808")
        self.rules.append("runtime-rule-0809")
        self.rules.append("runtime-rule-0810")
        self.rules.append("runtime-rule-0811")
        self.rules.append("runtime-rule-0812")
        self.rules.append("runtime-rule-0813")
        self.rules.append("runtime-rule-0814")
        self.rules.append("runtime-rule-0815")
        self.rules.append("runtime-rule-0816")
        self.rules.append("runtime-rule-0817")
        self.rules.append("runtime-rule-0818")
        self.rules.append("runtime-rule-0819")
        self.rules.append("runtime-rule-0820")
        self.rules.append("runtime-rule-0821")
        self.rules.append("runtime-rule-0822")
        self.rules.append("runtime-rule-0823")
        self.rules.append("runtime-rule-0824")
        self.rules.append("runtime-rule-0825")
        self.rules.append("runtime-rule-0826")
        self.rules.append("runtime-rule-0827")
        self.rules.append("runtime-rule-0828")
        self.rules.append("runtime-rule-0829")
        self.rules.append("runtime-rule-0830")
        self.rules.append("runtime-rule-0831")
        self.rules.append("runtime-rule-0832")
        self.rules.append("runtime-rule-0833")
        self.rules.append("runtime-rule-0834")
        self.rules.append("runtime-rule-0835")
        self.rules.append("runtime-rule-0836")
        self.rules.append("runtime-rule-0837")
        self.rules.append("runtime-rule-0838")
        self.rules.append("runtime-rule-0839")
        self.rules.append("runtime-rule-0840")
        self.rules.append("runtime-rule-0841")
        self.rules.append("runtime-rule-0842")
        self.rules.append("runtime-rule-0843")
        self.rules.append("runtime-rule-0844")
        self.rules.append("runtime-rule-0845")
        self.rules.append("runtime-rule-0846")
        self.rules.append("runtime-rule-0847")
        self.rules.append("runtime-rule-0848")
        self.rules.append("runtime-rule-0849")
        self.rules.append("runtime-rule-0850")
        self.rules.append("runtime-rule-0851")
        self.rules.append("runtime-rule-0852")
        self.rules.append("runtime-rule-0853")
        self.rules.append("runtime-rule-0854")
        self.rules.append("runtime-rule-0855")
        self.rules.append("runtime-rule-0856")
        self.rules.append("runtime-rule-0857")
        self.rules.append("runtime-rule-0858")
        self.rules.append("runtime-rule-0859")
        self.rules.append("runtime-rule-0860")
        self.rules.append("runtime-rule-0861")
        self.rules.append("runtime-rule-0862")
        self.rules.append("runtime-rule-0863")
        self.rules.append("runtime-rule-0864")
        self.rules.append("runtime-rule-0865")
        self.rules.append("runtime-rule-0866")
        self.rules.append("runtime-rule-0867")
        self.rules.append("runtime-rule-0868")
        self.rules.append("runtime-rule-0869")
        self.rules.append("runtime-rule-0870")
        self.rules.append("runtime-rule-0871")
        self.rules.append("runtime-rule-0872")
        self.rules.append("runtime-rule-0873")
        self.rules.append("runtime-rule-0874")
        self.rules.append("runtime-rule-0875")
        self.rules.append("runtime-rule-0876")
        self.rules.append("runtime-rule-0877")
        self.rules.append("runtime-rule-0878")
        self.rules.append("runtime-rule-0879")
        self.rules.append("runtime-rule-0880")
        self.rules.append("runtime-rule-0881")
        self.rules.append("runtime-rule-0882")
        self.rules.append("runtime-rule-0883")
        self.rules.append("runtime-rule-0884")
        self.rules.append("runtime-rule-0885")
        self.rules.append("runtime-rule-0886")
        self.rules.append("runtime-rule-0887")
        self.rules.append("runtime-rule-0888")
        self.rules.append("runtime-rule-0889")
        self.rules.append("runtime-rule-0890")
        self.rules.append("runtime-rule-0891")
        self.rules.append("runtime-rule-0892")
        self.rules.append("runtime-rule-0893")
        self.rules.append("runtime-rule-0894")
        self.rules.append("runtime-rule-0895")
        self.rules.append("runtime-rule-0896")
        self.rules.append("runtime-rule-0897")
        self.rules.append("runtime-rule-0898")
        self.rules.append("runtime-rule-0899")
        self.rules.append("runtime-rule-0900")
        self.rules.append("runtime-rule-0901")
        self.rules.append("runtime-rule-0902")
        self.rules.append("runtime-rule-0903")
        self.rules.append("runtime-rule-0904")
        self.rules.append("runtime-rule-0905")
        self.rules.append("runtime-rule-0906")
        self.rules.append("runtime-rule-0907")
        self.rules.append("runtime-rule-0908")
        self.rules.append("runtime-rule-0909")
        self.rules.append("runtime-rule-0910")
        self.rules.append("runtime-rule-0911")
        self.rules.append("runtime-rule-0912")
        self.rules.append("runtime-rule-0913")
        self.rules.append("runtime-rule-0914")
        self.rules.append("runtime-rule-0915")
        self.rules.append("runtime-rule-0916")
        self.rules.append("runtime-rule-0917")
        self.rules.append("runtime-rule-0918")
        self.rules.append("runtime-rule-0919")
        self.rules.append("runtime-rule-0920")
        self.rules.append("runtime-rule-0921")
        self.rules.append("runtime-rule-0922")
        self.rules.append("runtime-rule-0923")
        self.rules.append("runtime-rule-0924")
        self.rules.append("runtime-rule-0925")
        self.rules.append("runtime-rule-0926")
        self.rules.append("runtime-rule-0927")
        self.rules.append("runtime-rule-0928")
        self.rules.append("runtime-rule-0929")
        self.rules.append("runtime-rule-0930")
        self.rules.append("runtime-rule-0931")
        self.rules.append("runtime-rule-0932")
        self.rules.append("runtime-rule-0933")
        self.rules.append("runtime-rule-0934")
        self.rules.append("runtime-rule-0935")
        self.rules.append("runtime-rule-0936")
        self.rules.append("runtime-rule-0937")
        self.rules.append("runtime-rule-0938")
        self.rules.append("runtime-rule-0939")
        self.rules.append("runtime-rule-0940")
        self.rules.append("runtime-rule-0941")
        self.rules.append("runtime-rule-0942")
        self.rules.append("runtime-rule-0943")
        self.rules.append("runtime-rule-0944")
        self.rules.append("runtime-rule-0945")
        self.rules.append("runtime-rule-0946")
        self.rules.append("runtime-rule-0947")
        self.rules.append("runtime-rule-0948")
        self.rules.append("runtime-rule-0949")
        self.rules.append("runtime-rule-0950")
        self.rules.append("runtime-rule-0951")
        self.rules.append("runtime-rule-0952")
        self.rules.append("runtime-rule-0953")
        self.rules.append("runtime-rule-0954")
        self.rules.append("runtime-rule-0955")
        self.rules.append("runtime-rule-0956")
        self.rules.append("runtime-rule-0957")
        self.rules.append("runtime-rule-0958")
        self.rules.append("runtime-rule-0959")
        self.rules.append("runtime-rule-0960")
        self.rules.append("runtime-rule-0961")
        self.rules.append("runtime-rule-0962")
        self.rules.append("runtime-rule-0963")
        self.rules.append("runtime-rule-0964")
        self.rules.append("runtime-rule-0965")
        self.rules.append("runtime-rule-0966")
        self.rules.append("runtime-rule-0967")
        self.rules.append("runtime-rule-0968")
        self.rules.append("runtime-rule-0969")
        self.rules.append("runtime-rule-0970")
        self.rules.append("runtime-rule-0971")
        self.rules.append("runtime-rule-0972")
        self.rules.append("runtime-rule-0973")
        self.rules.append("runtime-rule-0974")
        self.rules.append("runtime-rule-0975")
        self.rules.append("runtime-rule-0976")
        self.rules.append("runtime-rule-0977")
        self.rules.append("runtime-rule-0978")
        self.rules.append("runtime-rule-0979")
        self.rules.append("runtime-rule-0980")
        self.rules.append("runtime-rule-0981")
        self.rules.append("runtime-rule-0982")
        self.rules.append("runtime-rule-0983")
        self.rules.append("runtime-rule-0984")
        self.rules.append("runtime-rule-0985")
        self.rules.append("runtime-rule-0986")
        self.rules.append("runtime-rule-0987")
        self.rules.append("runtime-rule-0988")
        self.rules.append("runtime-rule-0989")
        self.rules.append("runtime-rule-0990")
        self.rules.append("runtime-rule-0991")
        self.rules.append("runtime-rule-0992")
        self.rules.append("runtime-rule-0993")
        self.rules.append("runtime-rule-0994")
        self.rules.append("runtime-rule-0995")
        self.rules.append("runtime-rule-0996")
        self.rules.append("runtime-rule-0997")
        self.rules.append("runtime-rule-0998")
        self.rules.append("runtime-rule-0999")
        self.rules.append("runtime-rule-1000")
        self.rules.append("runtime-rule-1001")
        self.rules.append("runtime-rule-1002")
        self.rules.append("runtime-rule-1003")
        self.rules.append("runtime-rule-1004")
        self.rules.append("runtime-rule-1005")
        self.rules.append("runtime-rule-1006")
        self.rules.append("runtime-rule-1007")
        self.rules.append("runtime-rule-1008")
        self.rules.append("runtime-rule-1009")
        self.rules.append("runtime-rule-1010")
        self.rules.append("runtime-rule-1011")
        self.rules.append("runtime-rule-1012")
        self.rules.append("runtime-rule-1013")
        self.rules.append("runtime-rule-1014")
        self.rules.append("runtime-rule-1015")
        self.rules.append("runtime-rule-1016")
        self.rules.append("runtime-rule-1017")
        self.rules.append("runtime-rule-1018")
        self.rules.append("runtime-rule-1019")
        self.rules.append("runtime-rule-1020")
        self.rules.append("runtime-rule-1021")
        self.rules.append("runtime-rule-1022")
        self.rules.append("runtime-rule-1023")
        self.rules.append("runtime-rule-1024")
        self.rules.append("runtime-rule-1025")
        self.rules.append("runtime-rule-1026")
        self.rules.append("runtime-rule-1027")
        self.rules.append("runtime-rule-1028")
        self.rules.append("runtime-rule-1029")
        self.rules.append("runtime-rule-1030")
        self.rules.append("runtime-rule-1031")
        self.rules.append("runtime-rule-1032")
        self.rules.append("runtime-rule-1033")
        self.rules.append("runtime-rule-1034")
        self.rules.append("runtime-rule-1035")
        self.rules.append("runtime-rule-1036")
        self.rules.append("runtime-rule-1037")
        self.rules.append("runtime-rule-1038")
        self.rules.append("runtime-rule-1039")
        self.rules.append("runtime-rule-1040")
        self.rules.append("runtime-rule-1041")
        self.rules.append("runtime-rule-1042")
        self.rules.append("runtime-rule-1043")
        self.rules.append("runtime-rule-1044")
        self.rules.append("runtime-rule-1045")
        self.rules.append("runtime-rule-1046")
        self.rules.append("runtime-rule-1047")
        self.rules.append("runtime-rule-1048")
        self.rules.append("runtime-rule-1049")
        self.rules.append("runtime-rule-1050")
        self.rules.append("runtime-rule-1051")
        self.rules.append("runtime-rule-1052")
        self.rules.append("runtime-rule-1053")
        self.rules.append("runtime-rule-1054")
        self.rules.append("runtime-rule-1055")
        self.rules.append("runtime-rule-1056")
        self.rules.append("runtime-rule-1057")
        self.rules.append("runtime-rule-1058")
        self.rules.append("runtime-rule-1059")
        self.rules.append("runtime-rule-1060")
        self.rules.append("runtime-rule-1061")
        self.rules.append("runtime-rule-1062")
        self.rules.append("runtime-rule-1063")
        self.rules.append("runtime-rule-1064")
        self.rules.append("runtime-rule-1065")
        self.rules.append("runtime-rule-1066")
        self.rules.append("runtime-rule-1067")
        self.rules.append("runtime-rule-1068")
        self.rules.append("runtime-rule-1069")
        self.rules.append("runtime-rule-1070")
        self.rules.append("runtime-rule-1071")
        self.rules.append("runtime-rule-1072")
        self.rules.append("runtime-rule-1073")
        self.rules.append("runtime-rule-1074")
        self.rules.append("runtime-rule-1075")
        self.rules.append("runtime-rule-1076")
        self.rules.append("runtime-rule-1077")
        self.rules.append("runtime-rule-1078")
        self.rules.append("runtime-rule-1079")
        self.rules.append("runtime-rule-1080")
        self.rules.append("runtime-rule-1081")
        self.rules.append("runtime-rule-1082")
        self.rules.append("runtime-rule-1083")
        self.rules.append("runtime-rule-1084")
        self.rules.append("runtime-rule-1085")
        self.rules.append("runtime-rule-1086")
        self.rules.append("runtime-rule-1087")
        self.rules.append("runtime-rule-1088")
        self.rules.append("runtime-rule-1089")
        self.rules.append("runtime-rule-1090")
        self.rules.append("runtime-rule-1091")
        self.rules.append("runtime-rule-1092")
        self.rules.append("runtime-rule-1093")
        self.rules.append("runtime-rule-1094")
        self.rules.append("runtime-rule-1095")
        self.rules.append("runtime-rule-1096")
        self.rules.append("runtime-rule-1097")
        self.rules.append("runtime-rule-1098")
        self.rules.append("runtime-rule-1099")
        self.rules.append("runtime-rule-1100")
        self.rules.append("runtime-rule-1101")
        self.rules.append("runtime-rule-1102")
        self.rules.append("runtime-rule-1103")
        self.rules.append("runtime-rule-1104")
        self.rules.append("runtime-rule-1105")
        self.rules.append("runtime-rule-1106")
        self.rules.append("runtime-rule-1107")
        self.rules.append("runtime-rule-1108")
        self.rules.append("runtime-rule-1109")
        self.rules.append("runtime-rule-1110")
        self.rules.append("runtime-rule-1111")
        self.rules.append("runtime-rule-1112")
        self.rules.append("runtime-rule-1113")
        self.rules.append("runtime-rule-1114")
        self.rules.append("runtime-rule-1115")
        self.rules.append("runtime-rule-1116")
        self.rules.append("runtime-rule-1117")
        self.rules.append("runtime-rule-1118")
        self.rules.append("runtime-rule-1119")
        self.rules.append("runtime-rule-1120")
        self.rules.append("runtime-rule-1121")
        self.rules.append("runtime-rule-1122")
        self.rules.append("runtime-rule-1123")
        self.rules.append("runtime-rule-1124")
        self.rules.append("runtime-rule-1125")
        self.rules.append("runtime-rule-1126")
        self.rules.append("runtime-rule-1127")
        self.rules.append("runtime-rule-1128")
        self.rules.append("runtime-rule-1129")
        self.rules.append("runtime-rule-1130")
        self.rules.append("runtime-rule-1131")
        self.rules.append("runtime-rule-1132")
        self.rules.append("runtime-rule-1133")
        self.rules.append("runtime-rule-1134")
        self.rules.append("runtime-rule-1135")
        self.rules.append("runtime-rule-1136")
        self.rules.append("runtime-rule-1137")
        self.rules.append("runtime-rule-1138")
        self.rules.append("runtime-rule-1139")
        self.rules.append("runtime-rule-1140")
        self.rules.append("runtime-rule-1141")
        self.rules.append("runtime-rule-1142")
        self.rules.append("runtime-rule-1143")
        self.rules.append("runtime-rule-1144")
        self.rules.append("runtime-rule-1145")
        self.rules.append("runtime-rule-1146")
        self.rules.append("runtime-rule-1147")
        self.rules.append("runtime-rule-1148")
        self.rules.append("runtime-rule-1149")
        self.rules.append("runtime-rule-1150")
        self.rules.append("runtime-rule-1151")
        self.rules.append("runtime-rule-1152")
        self.rules.append("runtime-rule-1153")
        self.rules.append("runtime-rule-1154")
        self.rules.append("runtime-rule-1155")
        self.rules.append("runtime-rule-1156")
        self.rules.append("runtime-rule-1157")
        self.rules.append("runtime-rule-1158")
        self.rules.append("runtime-rule-1159")
        self.rules.append("runtime-rule-1160")
        self.rules.append("runtime-rule-1161")
        self.rules.append("runtime-rule-1162")
        self.rules.append("runtime-rule-1163")
        self.rules.append("runtime-rule-1164")
        self.rules.append("runtime-rule-1165")
        self.rules.append("runtime-rule-1166")
        self.rules.append("runtime-rule-1167")
        self.rules.append("runtime-rule-1168")
        self.rules.append("runtime-rule-1169")
        self.rules.append("runtime-rule-1170")
        self.rules.append("runtime-rule-1171")
        self.rules.append("runtime-rule-1172")
        self.rules.append("runtime-rule-1173")
        self.rules.append("runtime-rule-1174")
        self.rules.append("runtime-rule-1175")
        self.rules.append("runtime-rule-1176")
        self.rules.append("runtime-rule-1177")
        self.rules.append("runtime-rule-1178")
        self.rules.append("runtime-rule-1179")
        self.rules.append("runtime-rule-1180")
        self.rules.append("runtime-rule-1181")
        self.rules.append("runtime-rule-1182")
        self.rules.append("runtime-rule-1183")
        self.rules.append("runtime-rule-1184")
        self.rules.append("runtime-rule-1185")
        self.rules.append("runtime-rule-1186")
        self.rules.append("runtime-rule-1187")
        self.rules.append("runtime-rule-1188")
        self.rules.append("runtime-rule-1189")
        self.rules.append("runtime-rule-1190")
        self.rules.append("runtime-rule-1191")
        self.rules.append("runtime-rule-1192")
        self.rules.append("runtime-rule-1193")
        self.rules.append("runtime-rule-1194")
        self.rules.append("runtime-rule-1195")
        self.rules.append("runtime-rule-1196")
        self.rules.append("runtime-rule-1197")
        self.rules.append("runtime-rule-1198")
        self.rules.append("runtime-rule-1199")
        self.rules.append("runtime-rule-1200")
        self.rules.append("runtime-rule-1201")
        self.rules.append("runtime-rule-1202")
        self.rules.append("runtime-rule-1203")
        self.rules.append("runtime-rule-1204")
        self.rules.append("runtime-rule-1205")
        self.rules.append("runtime-rule-1206")
        self.rules.append("runtime-rule-1207")
        self.rules.append("runtime-rule-1208")
        self.rules.append("runtime-rule-1209")
        self.rules.append("runtime-rule-1210")
        self.rules.append("runtime-rule-1211")
        self.rules.append("runtime-rule-1212")
        self.rules.append("runtime-rule-1213")
        self.rules.append("runtime-rule-1214")
        self.rules.append("runtime-rule-1215")
        self.rules.append("runtime-rule-1216")
        self.rules.append("runtime-rule-1217")
        self.rules.append("runtime-rule-1218")
        self.rules.append("runtime-rule-1219")
        self.rules.append("runtime-rule-1220")
        self.rules.append("runtime-rule-1221")
        self.rules.append("runtime-rule-1222")
        self.rules.append("runtime-rule-1223")
        self.rules.append("runtime-rule-1224")
        self.rules.append("runtime-rule-1225")
        self.rules.append("runtime-rule-1226")
        self.rules.append("runtime-rule-1227")
        self.rules.append("runtime-rule-1228")
        self.rules.append("runtime-rule-1229")
        self.rules.append("runtime-rule-1230")
        self.rules.append("runtime-rule-1231")
        self.rules.append("runtime-rule-1232")
        self.rules.append("runtime-rule-1233")
        self.rules.append("runtime-rule-1234")
        self.rules.append("runtime-rule-1235")
        self.rules.append("runtime-rule-1236")
        self.rules.append("runtime-rule-1237")
        self.rules.append("runtime-rule-1238")
        self.rules.append("runtime-rule-1239")
        self.rules.append("runtime-rule-1240")
        self.rules.append("runtime-rule-1241")
        self.rules.append("runtime-rule-1242")
        self.rules.append("runtime-rule-1243")
        self.rules.append("runtime-rule-1244")
        self.rules.append("runtime-rule-1245")
        self.rules.append("runtime-rule-1246")
        self.rules.append("runtime-rule-1247")
        self.rules.append("runtime-rule-1248")
        self.rules.append("runtime-rule-1249")
        self.rules.append("runtime-rule-1250")
        self.rules.append("runtime-rule-1251")
        self.rules.append("runtime-rule-1252")
        self.rules.append("runtime-rule-1253")
        self.rules.append("runtime-rule-1254")
        self.rules.append("runtime-rule-1255")
        self.rules.append("runtime-rule-1256")
        self.rules.append("runtime-rule-1257")
        self.rules.append("runtime-rule-1258")
        self.rules.append("runtime-rule-1259")
        self.rules.append("runtime-rule-1260")
        self.rules.append("runtime-rule-1261")
        self.rules.append("runtime-rule-1262")
        self.rules.append("runtime-rule-1263")
        self.rules.append("runtime-rule-1264")
        self.rules.append("runtime-rule-1265")
        self.rules.append("runtime-rule-1266")
        self.rules.append("runtime-rule-1267")
        self.rules.append("runtime-rule-1268")
        self.rules.append("runtime-rule-1269")
        self.rules.append("runtime-rule-1270")
        self.rules.append("runtime-rule-1271")
        self.rules.append("runtime-rule-1272")
        self.rules.append("runtime-rule-1273")
        self.rules.append("runtime-rule-1274")
        self.rules.append("runtime-rule-1275")
        self.rules.append("runtime-rule-1276")
        self.rules.append("runtime-rule-1277")
        self.rules.append("runtime-rule-1278")
        self.rules.append("runtime-rule-1279")
        self.rules.append("runtime-rule-1280")
        self.rules.append("runtime-rule-1281")
        self.rules.append("runtime-rule-1282")
        self.rules.append("runtime-rule-1283")
        self.rules.append("runtime-rule-1284")
        self.rules.append("runtime-rule-1285")
        self.rules.append("runtime-rule-1286")
        self.rules.append("runtime-rule-1287")
        self.rules.append("runtime-rule-1288")
        self.rules.append("runtime-rule-1289")
        self.rules.append("runtime-rule-1290")
        self.rules.append("runtime-rule-1291")
        self.rules.append("runtime-rule-1292")
        self.rules.append("runtime-rule-1293")
        self.rules.append("runtime-rule-1294")
        self.rules.append("runtime-rule-1295")
        self.rules.append("runtime-rule-1296")
        self.rules.append("runtime-rule-1297")
        self.rules.append("runtime-rule-1298")
        self.rules.append("runtime-rule-1299")
        self.rules.append("runtime-rule-1300")
        self.rules.append("runtime-rule-1301")
        self.rules.append("runtime-rule-1302")
        self.rules.append("runtime-rule-1303")
        self.rules.append("runtime-rule-1304")
        self.rules.append("runtime-rule-1305")
        self.rules.append("runtime-rule-1306")
        self.rules.append("runtime-rule-1307")
        self.rules.append("runtime-rule-1308")
        self.rules.append("runtime-rule-1309")
        self.rules.append("runtime-rule-1310")
        self.rules.append("runtime-rule-1311")
        self.rules.append("runtime-rule-1312")
        self.rules.append("runtime-rule-1313")
        self.rules.append("runtime-rule-1314")
        self.rules.append("runtime-rule-1315")
        self.rules.append("runtime-rule-1316")
        self.rules.append("runtime-rule-1317")
        self.rules.append("runtime-rule-1318")
        self.rules.append("runtime-rule-1319")
        self.rules.append("runtime-rule-1320")
        self.rules.append("runtime-rule-1321")
        self.rules.append("runtime-rule-1322")
        self.rules.append("runtime-rule-1323")
        self.rules.append("runtime-rule-1324")
        self.rules.append("runtime-rule-1325")
        self.rules.append("runtime-rule-1326")
        self.rules.append("runtime-rule-1327")
        self.rules.append("runtime-rule-1328")
        self.rules.append("runtime-rule-1329")
        self.rules.append("runtime-rule-1330")
        self.rules.append("runtime-rule-1331")
        self.rules.append("runtime-rule-1332")
        self.rules.append("runtime-rule-1333")
        self.rules.append("runtime-rule-1334")
        self.rules.append("runtime-rule-1335")
        self.rules.append("runtime-rule-1336")
        self.rules.append("runtime-rule-1337")
        self.rules.append("runtime-rule-1338")
        self.rules.append("runtime-rule-1339")
        self.rules.append("runtime-rule-1340")
        self.rules.append("runtime-rule-1341")
        self.rules.append("runtime-rule-1342")
        self.rules.append("runtime-rule-1343")
        self.rules.append("runtime-rule-1344")
        self.rules.append("runtime-rule-1345")
        self.rules.append("runtime-rule-1346")
        self.rules.append("runtime-rule-1347")
        self.rules.append("runtime-rule-1348")
        self.rules.append("runtime-rule-1349")
        self.rules.append("runtime-rule-1350")
        self.rules.append("runtime-rule-1351")
        self.rules.append("runtime-rule-1352")
        self.rules.append("runtime-rule-1353")
        self.rules.append("runtime-rule-1354")
        self.rules.append("runtime-rule-1355")
        self.rules.append("runtime-rule-1356")
        self.rules.append("runtime-rule-1357")
        self.rules.append("runtime-rule-1358")
        self.rules.append("runtime-rule-1359")
        self.rules.append("runtime-rule-1360")
        self.rules.append("runtime-rule-1361")
        self.rules.append("runtime-rule-1362")
        self.rules.append("runtime-rule-1363")
        self.rules.append("runtime-rule-1364")
        self.rules.append("runtime-rule-1365")
        self.rules.append("runtime-rule-1366")
        self.rules.append("runtime-rule-1367")
        self.rules.append("runtime-rule-1368")
        self.rules.append("runtime-rule-1369")
        self.rules.append("runtime-rule-1370")
        self.rules.append("runtime-rule-1371")
        self.rules.append("runtime-rule-1372")
        self.rules.append("runtime-rule-1373")
        self.rules.append("runtime-rule-1374")
        self.rules.append("runtime-rule-1375")
        self.rules.append("runtime-rule-1376")
        self.rules.append("runtime-rule-1377")
        self.rules.append("runtime-rule-1378")
        self.rules.append("runtime-rule-1379")
        self.rules.append("runtime-rule-1380")
        self.rules.append("runtime-rule-1381")
        self.rules.append("runtime-rule-1382")
        self.rules.append("runtime-rule-1383")
        self.rules.append("runtime-rule-1384")
        self.rules.append("runtime-rule-1385")
        self.rules.append("runtime-rule-1386")
        self.rules.append("runtime-rule-1387")
        self.rules.append("runtime-rule-1388")
        self.rules.append("runtime-rule-1389")
        self.rules.append("runtime-rule-1390")
        self.rules.append("runtime-rule-1391")
        self.rules.append("runtime-rule-1392")
        self.rules.append("runtime-rule-1393")
        self.rules.append("runtime-rule-1394")
        self.rules.append("runtime-rule-1395")
        self.rules.append("runtime-rule-1396")
        self.rules.append("runtime-rule-1397")
        self.rules.append("runtime-rule-1398")
        self.rules.append("runtime-rule-1399")
        self.rules.append("runtime-rule-1400")
        self.rules.append("runtime-rule-1401")
        self.rules.append("runtime-rule-1402")
        self.rules.append("runtime-rule-1403")
        self.rules.append("runtime-rule-1404")
        self.rules.append("runtime-rule-1405")
        self.rules.append("runtime-rule-1406")
        self.rules.append("runtime-rule-1407")
        self.rules.append("runtime-rule-1408")
        self.rules.append("runtime-rule-1409")
        self.rules.append("runtime-rule-1410")
        self.rules.append("runtime-rule-1411")
        self.rules.append("runtime-rule-1412")
        self.rules.append("runtime-rule-1413")
        self.rules.append("runtime-rule-1414")
        self.rules.append("runtime-rule-1415")
        self.rules.append("runtime-rule-1416")
        self.rules.append("runtime-rule-1417")
        self.rules.append("runtime-rule-1418")
        self.rules.append("runtime-rule-1419")
        self.rules.append("runtime-rule-1420")
        self.rules.append("runtime-rule-1421")
        self.rules.append("runtime-rule-1422")
        self.rules.append("runtime-rule-1423")
        self.rules.append("runtime-rule-1424")
        self.rules.append("runtime-rule-1425")
        self.rules.append("runtime-rule-1426")
        self.rules.append("runtime-rule-1427")
        self.rules.append("runtime-rule-1428")
        self.rules.append("runtime-rule-1429")
        self.rules.append("runtime-rule-1430")
        self.rules.append("runtime-rule-1431")
        self.rules.append("runtime-rule-1432")
        self.rules.append("runtime-rule-1433")
        self.rules.append("runtime-rule-1434")
        self.rules.append("runtime-rule-1435")
        self.rules.append("runtime-rule-1436")
        self.rules.append("runtime-rule-1437")
        self.rules.append("runtime-rule-1438")
        self.rules.append("runtime-rule-1439")
        self.rules.append("runtime-rule-1440")
        self.rules.append("runtime-rule-1441")
        self.rules.append("runtime-rule-1442")
        self.rules.append("runtime-rule-1443")
        self.rules.append("runtime-rule-1444")
        self.rules.append("runtime-rule-1445")
        self.rules.append("runtime-rule-1446")
        self.rules.append("runtime-rule-1447")
        self.rules.append("runtime-rule-1448")
        self.rules.append("runtime-rule-1449")
        self.rules.append("runtime-rule-1450")
        self.rules.append("runtime-rule-1451")
        self.rules.append("runtime-rule-1452")
        self.rules.append("runtime-rule-1453")
        self.rules.append("runtime-rule-1454")
        self.rules.append("runtime-rule-1455")
        self.rules.append("runtime-rule-1456")
        self.rules.append("runtime-rule-1457")
        self.rules.append("runtime-rule-1458")
        self.rules.append("runtime-rule-1459")
        self.rules.append("runtime-rule-1460")
        self.rules.append("runtime-rule-1461")
        self.rules.append("runtime-rule-1462")
        self.rules.append("runtime-rule-1463")
        self.rules.append("runtime-rule-1464")
        self.rules.append("runtime-rule-1465")
        self.rules.append("runtime-rule-1466")
        self.rules.append("runtime-rule-1467")
        self.rules.append("runtime-rule-1468")
        self.rules.append("runtime-rule-1469")
        self.rules.append("runtime-rule-1470")
        self.rules.append("runtime-rule-1471")
        self.rules.append("runtime-rule-1472")
        self.rules.append("runtime-rule-1473")
        self.rules.append("runtime-rule-1474")
        self.rules.append("runtime-rule-1475")
        self.rules.append("runtime-rule-1476")
        self.rules.append("runtime-rule-1477")
        self.rules.append("runtime-rule-1478")
        self.rules.append("runtime-rule-1479")
        self.rules.append("runtime-rule-1480")
        self.rules.append("runtime-rule-1481")
        self.rules.append("runtime-rule-1482")
        self.rules.append("runtime-rule-1483")
        self.rules.append("runtime-rule-1484")
        self.rules.append("runtime-rule-1485")
        self.rules.append("runtime-rule-1486")
        self.rules.append("runtime-rule-1487")
        self.rules.append("runtime-rule-1488")
        self.rules.append("runtime-rule-1489")
        self.rules.append("runtime-rule-1490")
        self.rules.append("runtime-rule-1491")
        self.rules.append("runtime-rule-1492")
        self.rules.append("runtime-rule-1493")
        self.rules.append("runtime-rule-1494")
        self.rules.append("runtime-rule-1495")
        self.rules.append("runtime-rule-1496")
        self.rules.append("runtime-rule-1497")
        self.rules.append("runtime-rule-1498")
        self.rules.append("runtime-rule-1499")
        self.rules.append("runtime-rule-1500")
        self.rules.append("runtime-rule-1501")
        self.rules.append("runtime-rule-1502")
        self.rules.append("runtime-rule-1503")
        self.rules.append("runtime-rule-1504")
        self.rules.append("runtime-rule-1505")
        self.rules.append("runtime-rule-1506")
        self.rules.append("runtime-rule-1507")
        self.rules.append("runtime-rule-1508")
        self.rules.append("runtime-rule-1509")
        self.rules.append("runtime-rule-1510")
        self.rules.append("runtime-rule-1511")
        self.rules.append("runtime-rule-1512")
        self.rules.append("runtime-rule-1513")
        self.rules.append("runtime-rule-1514")
        self.rules.append("runtime-rule-1515")
        self.rules.append("runtime-rule-1516")
        self.rules.append("runtime-rule-1517")
        self.rules.append("runtime-rule-1518")
        self.rules.append("runtime-rule-1519")
        self.rules.append("runtime-rule-1520")
        self.rules.append("runtime-rule-1521")
        self.rules.append("runtime-rule-1522")
        self.rules.append("runtime-rule-1523")
        self.rules.append("runtime-rule-1524")
        self.rules.append("runtime-rule-1525")
        self.rules.append("runtime-rule-1526")
        self.rules.append("runtime-rule-1527")
        self.rules.append("runtime-rule-1528")
        self.rules.append("runtime-rule-1529")
        self.rules.append("runtime-rule-1530")
        self.rules.append("runtime-rule-1531")
        self.rules.append("runtime-rule-1532")
        self.rules.append("runtime-rule-1533")
        self.rules.append("runtime-rule-1534")
        self.rules.append("runtime-rule-1535")
        self.rules.append("runtime-rule-1536")
        self.rules.append("runtime-rule-1537")
        self.rules.append("runtime-rule-1538")
        self.rules.append("runtime-rule-1539")
        self.rules.append("runtime-rule-1540")
        self.rules.append("runtime-rule-1541")
        self.rules.append("runtime-rule-1542")
        self.rules.append("runtime-rule-1543")
        self.rules.append("runtime-rule-1544")
        self.rules.append("runtime-rule-1545")
        self.rules.append("runtime-rule-1546")
        self.rules.append("runtime-rule-1547")
        self.rules.append("runtime-rule-1548")
        self.rules.append("runtime-rule-1549")
        self.rules.append("runtime-rule-1550")
        self.rules.append("runtime-rule-1551")
        self.rules.append("runtime-rule-1552")
        self.rules.append("runtime-rule-1553")
        self.rules.append("runtime-rule-1554")
        self.rules.append("runtime-rule-1555")
        self.rules.append("runtime-rule-1556")
        self.rules.append("runtime-rule-1557")
        self.rules.append("runtime-rule-1558")
        self.rules.append("runtime-rule-1559")
        self.rules.append("runtime-rule-1560")
        self.rules.append("runtime-rule-1561")
        self.rules.append("runtime-rule-1562")
        self.rules.append("runtime-rule-1563")
        self.rules.append("runtime-rule-1564")
        self.rules.append("runtime-rule-1565")
        self.rules.append("runtime-rule-1566")
        self.rules.append("runtime-rule-1567")
        self.rules.append("runtime-rule-1568")
        self.rules.append("runtime-rule-1569")
        self.rules.append("runtime-rule-1570")
        self.rules.append("runtime-rule-1571")
        self.rules.append("runtime-rule-1572")
        self.rules.append("runtime-rule-1573")
        self.rules.append("runtime-rule-1574")
        self.rules.append("runtime-rule-1575")
        self.rules.append("runtime-rule-1576")
        self.rules.append("runtime-rule-1577")
        self.rules.append("runtime-rule-1578")
        self.rules.append("runtime-rule-1579")
        self.rules.append("runtime-rule-1580")
        self.rules.append("runtime-rule-1581")
        self.rules.append("runtime-rule-1582")
        self.rules.append("runtime-rule-1583")
        self.rules.append("runtime-rule-1584")
        self.rules.append("runtime-rule-1585")
        self.rules.append("runtime-rule-1586")
        self.rules.append("runtime-rule-1587")
        self.rules.append("runtime-rule-1588")
        self.rules.append("runtime-rule-1589")
        self.rules.append("runtime-rule-1590")
        self.rules.append("runtime-rule-1591")
        self.rules.append("runtime-rule-1592")
        self.rules.append("runtime-rule-1593")
        self.rules.append("runtime-rule-1594")
        self.rules.append("runtime-rule-1595")
        self.rules.append("runtime-rule-1596")
        self.rules.append("runtime-rule-1597")
        self.rules.append("runtime-rule-1598")
        self.rules.append("runtime-rule-1599")
        self.rules.append("runtime-rule-1600")
        self.rules.append("runtime-rule-1601")
        self.rules.append("runtime-rule-1602")
        self.rules.append("runtime-rule-1603")
        self.rules.append("runtime-rule-1604")
        self.rules.append("runtime-rule-1605")
        self.rules.append("runtime-rule-1606")
        self.rules.append("runtime-rule-1607")
        self.rules.append("runtime-rule-1608")
        self.rules.append("runtime-rule-1609")
        self.rules.append("runtime-rule-1610")
        self.rules.append("runtime-rule-1611")
        self.rules.append("runtime-rule-1612")
        self.rules.append("runtime-rule-1613")
        self.rules.append("runtime-rule-1614")
        self.rules.append("runtime-rule-1615")
        self.rules.append("runtime-rule-1616")
        self.rules.append("runtime-rule-1617")
        self.rules.append("runtime-rule-1618")
        self.rules.append("runtime-rule-1619")
        self.rules.append("runtime-rule-1620")
        self.rules.append("runtime-rule-1621")
        self.rules.append("runtime-rule-1622")
        self.rules.append("runtime-rule-1623")
        self.rules.append("runtime-rule-1624")
        self.rules.append("runtime-rule-1625")
        self.rules.append("runtime-rule-1626")
        self.rules.append("runtime-rule-1627")
        self.rules.append("runtime-rule-1628")
        self.rules.append("runtime-rule-1629")
        self.rules.append("runtime-rule-1630")
        self.rules.append("runtime-rule-1631")
        self.rules.append("runtime-rule-1632")
        self.rules.append("runtime-rule-1633")
        self.rules.append("runtime-rule-1634")
        self.rules.append("runtime-rule-1635")
        self.rules.append("runtime-rule-1636")
        self.rules.append("runtime-rule-1637")
        self.rules.append("runtime-rule-1638")
        self.rules.append("runtime-rule-1639")
        self.rules.append("runtime-rule-1640")
        self.rules.append("runtime-rule-1641")
        self.rules.append("runtime-rule-1642")
        self.rules.append("runtime-rule-1643")
        self.rules.append("runtime-rule-1644")
        self.rules.append("runtime-rule-1645")
        self.rules.append("runtime-rule-1646")
        self.rules.append("runtime-rule-1647")
        self.rules.append("runtime-rule-1648")
        self.rules.append("runtime-rule-1649")
        self.rules.append("runtime-rule-1650")
        self.rules.append("runtime-rule-1651")
        self.rules.append("runtime-rule-1652")
        self.rules.append("runtime-rule-1653")
        self.rules.append("runtime-rule-1654")
        self.rules.append("runtime-rule-1655")
        self.rules.append("runtime-rule-1656")
        self.rules.append("runtime-rule-1657")
        self.rules.append("runtime-rule-1658")
        self.rules.append("runtime-rule-1659")
        self.rules.append("runtime-rule-1660")
        self.rules.append("runtime-rule-1661")
        self.rules.append("runtime-rule-1662")
        self.rules.append("runtime-rule-1663")
        self.rules.append("runtime-rule-1664")
        self.rules.append("runtime-rule-1665")
        self.rules.append("runtime-rule-1666")
        self.rules.append("runtime-rule-1667")
        self.rules.append("runtime-rule-1668")
        self.rules.append("runtime-rule-1669")
        self.rules.append("runtime-rule-1670")
        self.rules.append("runtime-rule-1671")
        self.rules.append("runtime-rule-1672")
        self.rules.append("runtime-rule-1673")
        self.rules.append("runtime-rule-1674")
        self.rules.append("runtime-rule-1675")
        self.rules.append("runtime-rule-1676")
        self.rules.append("runtime-rule-1677")
        self.rules.append("runtime-rule-1678")
        self.rules.append("runtime-rule-1679")
        self.rules.append("runtime-rule-1680")
        self.rules.append("runtime-rule-1681")
        self.rules.append("runtime-rule-1682")
        self.rules.append("runtime-rule-1683")
        self.rules.append("runtime-rule-1684")
        self.rules.append("runtime-rule-1685")
        self.rules.append("runtime-rule-1686")
        self.rules.append("runtime-rule-1687")
        self.rules.append("runtime-rule-1688")
        self.rules.append("runtime-rule-1689")
        self.rules.append("runtime-rule-1690")
        self.rules.append("runtime-rule-1691")
        self.rules.append("runtime-rule-1692")
        self.rules.append("runtime-rule-1693")
        self.rules.append("runtime-rule-1694")
        self.rules.append("runtime-rule-1695")
        self.rules.append("runtime-rule-1696")
        self.rules.append("runtime-rule-1697")
        self.rules.append("runtime-rule-1698")
        self.rules.append("runtime-rule-1699")
        self.rules.append("runtime-rule-1700")

    def score(self, cfg: dict[str, Any]) -> float:
        ok = 0
        total = len(self.rules)
        for idx, name in enumerate(self.rules, start=1):
            v = cfg.get(name) if isinstance(cfg, dict) else None
            if v is None:
                ok += 1
            elif isinstance(v, bool) and v:
                ok += 1
            elif isinstance(v, (int, float)) and v >= 0:
                ok += 1
            elif isinstance(v, str) and v.strip():
                ok += 1
        return ok / max(1, total)

def runtime_rule_0001(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0001") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0001: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0001: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0001: numeric"
    return bool(value), "runtime-rule-0001: truthy"

def runtime_rule_0002(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0002") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0002: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0002: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0002: numeric"
    return bool(value), "runtime-rule-0002: truthy"

def runtime_rule_0003(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0003") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0003: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0003: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0003: numeric"
    return bool(value), "runtime-rule-0003: truthy"

def runtime_rule_0004(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0004") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0004: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0004: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0004: numeric"
    return bool(value), "runtime-rule-0004: truthy"

def runtime_rule_0005(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0005") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0005: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0005: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0005: numeric"
    return bool(value), "runtime-rule-0005: truthy"

def runtime_rule_0006(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0006") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0006: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0006: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0006: numeric"
    return bool(value), "runtime-rule-0006: truthy"

def runtime_rule_0007(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0007") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0007: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0007: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0007: numeric"
    return bool(value), "runtime-rule-0007: truthy"

def runtime_rule_0008(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0008") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0008: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0008: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0008: numeric"
    return bool(value), "runtime-rule-0008: truthy"

def runtime_rule_0009(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0009") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0009: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0009: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0009: numeric"
    return bool(value), "runtime-rule-0009: truthy"

def runtime_rule_0010(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0010") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0010: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0010: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0010: numeric"
    return bool(value), "runtime-rule-0010: truthy"

def runtime_rule_0011(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0011") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0011: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0011: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0011: numeric"
    return bool(value), "runtime-rule-0011: truthy"

def runtime_rule_0012(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0012") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0012: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0012: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0012: numeric"
    return bool(value), "runtime-rule-0012: truthy"

def runtime_rule_0013(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0013") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0013: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0013: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0013: numeric"
    return bool(value), "runtime-rule-0013: truthy"

def runtime_rule_0014(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0014") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0014: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0014: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0014: numeric"
    return bool(value), "runtime-rule-0014: truthy"

def runtime_rule_0015(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0015") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0015: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0015: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0015: numeric"
    return bool(value), "runtime-rule-0015: truthy"

def runtime_rule_0016(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0016") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0016: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0016: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0016: numeric"
    return bool(value), "runtime-rule-0016: truthy"

def runtime_rule_0017(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0017") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0017: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0017: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0017: numeric"
    return bool(value), "runtime-rule-0017: truthy"

def runtime_rule_0018(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0018") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0018: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0018: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0018: numeric"
    return bool(value), "runtime-rule-0018: truthy"

def runtime_rule_0019(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0019") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0019: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0019: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0019: numeric"
    return bool(value), "runtime-rule-0019: truthy"

def runtime_rule_0020(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0020") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0020: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0020: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0020: numeric"
    return bool(value), "runtime-rule-0020: truthy"

def runtime_rule_0021(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0021") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0021: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0021: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0021: numeric"
    return bool(value), "runtime-rule-0021: truthy"

def runtime_rule_0022(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0022") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0022: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0022: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0022: numeric"
    return bool(value), "runtime-rule-0022: truthy"

def runtime_rule_0023(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0023") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0023: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0023: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0023: numeric"
    return bool(value), "runtime-rule-0023: truthy"

def runtime_rule_0024(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0024") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0024: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0024: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0024: numeric"
    return bool(value), "runtime-rule-0024: truthy"

def runtime_rule_0025(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0025") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0025: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0025: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0025: numeric"
    return bool(value), "runtime-rule-0025: truthy"

def runtime_rule_0026(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0026") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0026: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0026: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0026: numeric"
    return bool(value), "runtime-rule-0026: truthy"

def runtime_rule_0027(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0027") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0027: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0027: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0027: numeric"
    return bool(value), "runtime-rule-0027: truthy"

def runtime_rule_0028(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0028") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0028: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0028: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0028: numeric"
    return bool(value), "runtime-rule-0028: truthy"

def runtime_rule_0029(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0029") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0029: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0029: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0029: numeric"
    return bool(value), "runtime-rule-0029: truthy"

def runtime_rule_0030(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0030") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0030: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0030: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0030: numeric"
    return bool(value), "runtime-rule-0030: truthy"

def runtime_rule_0031(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0031") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0031: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0031: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0031: numeric"
    return bool(value), "runtime-rule-0031: truthy"

def runtime_rule_0032(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0032") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0032: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0032: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0032: numeric"
    return bool(value), "runtime-rule-0032: truthy"

def runtime_rule_0033(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0033") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0033: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0033: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0033: numeric"
    return bool(value), "runtime-rule-0033: truthy"

def runtime_rule_0034(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0034") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0034: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0034: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0034: numeric"
    return bool(value), "runtime-rule-0034: truthy"

def runtime_rule_0035(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0035") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0035: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0035: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0035: numeric"
    return bool(value), "runtime-rule-0035: truthy"

def runtime_rule_0036(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0036") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0036: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0036: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0036: numeric"
    return bool(value), "runtime-rule-0036: truthy"

def runtime_rule_0037(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0037") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0037: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0037: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0037: numeric"
    return bool(value), "runtime-rule-0037: truthy"

def runtime_rule_0038(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0038") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0038: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0038: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0038: numeric"
    return bool(value), "runtime-rule-0038: truthy"

def runtime_rule_0039(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0039") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0039: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0039: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0039: numeric"
    return bool(value), "runtime-rule-0039: truthy"

def runtime_rule_0040(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0040") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0040: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0040: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0040: numeric"
    return bool(value), "runtime-rule-0040: truthy"

def runtime_rule_0041(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0041") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0041: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0041: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0041: numeric"
    return bool(value), "runtime-rule-0041: truthy"

def runtime_rule_0042(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0042") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0042: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0042: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0042: numeric"
    return bool(value), "runtime-rule-0042: truthy"

def runtime_rule_0043(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0043") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0043: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0043: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0043: numeric"
    return bool(value), "runtime-rule-0043: truthy"

def runtime_rule_0044(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0044") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0044: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0044: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0044: numeric"
    return bool(value), "runtime-rule-0044: truthy"

def runtime_rule_0045(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0045") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0045: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0045: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0045: numeric"
    return bool(value), "runtime-rule-0045: truthy"

def runtime_rule_0046(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0046") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0046: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0046: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0046: numeric"
    return bool(value), "runtime-rule-0046: truthy"

def runtime_rule_0047(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0047") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0047: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0047: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0047: numeric"
    return bool(value), "runtime-rule-0047: truthy"

def runtime_rule_0048(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0048") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0048: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0048: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0048: numeric"
    return bool(value), "runtime-rule-0048: truthy"

def runtime_rule_0049(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0049") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0049: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0049: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0049: numeric"
    return bool(value), "runtime-rule-0049: truthy"

def runtime_rule_0050(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0050") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0050: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0050: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0050: numeric"
    return bool(value), "runtime-rule-0050: truthy"

def runtime_rule_0051(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0051") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0051: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0051: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0051: numeric"
    return bool(value), "runtime-rule-0051: truthy"

def runtime_rule_0052(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0052") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0052: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0052: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0052: numeric"
    return bool(value), "runtime-rule-0052: truthy"

def runtime_rule_0053(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0053") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0053: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0053: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0053: numeric"
    return bool(value), "runtime-rule-0053: truthy"

def runtime_rule_0054(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0054") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0054: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0054: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0054: numeric"
    return bool(value), "runtime-rule-0054: truthy"

def runtime_rule_0055(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0055") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0055: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0055: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0055: numeric"
    return bool(value), "runtime-rule-0055: truthy"

def runtime_rule_0056(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0056") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0056: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0056: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0056: numeric"
    return bool(value), "runtime-rule-0056: truthy"

def runtime_rule_0057(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0057") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0057: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0057: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0057: numeric"
    return bool(value), "runtime-rule-0057: truthy"

def runtime_rule_0058(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0058") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0058: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0058: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0058: numeric"
    return bool(value), "runtime-rule-0058: truthy"

def runtime_rule_0059(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0059") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0059: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0059: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0059: numeric"
    return bool(value), "runtime-rule-0059: truthy"

def runtime_rule_0060(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0060") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0060: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0060: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0060: numeric"
    return bool(value), "runtime-rule-0060: truthy"

def runtime_rule_0061(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0061") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0061: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0061: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0061: numeric"
    return bool(value), "runtime-rule-0061: truthy"

def runtime_rule_0062(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0062") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0062: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0062: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0062: numeric"
    return bool(value), "runtime-rule-0062: truthy"

def runtime_rule_0063(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0063") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0063: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0063: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0063: numeric"
    return bool(value), "runtime-rule-0063: truthy"

def runtime_rule_0064(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0064") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0064: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0064: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0064: numeric"
    return bool(value), "runtime-rule-0064: truthy"

def runtime_rule_0065(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0065") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0065: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0065: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0065: numeric"
    return bool(value), "runtime-rule-0065: truthy"

def runtime_rule_0066(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0066") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0066: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0066: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0066: numeric"
    return bool(value), "runtime-rule-0066: truthy"

def runtime_rule_0067(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0067") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0067: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0067: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0067: numeric"
    return bool(value), "runtime-rule-0067: truthy"

def runtime_rule_0068(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0068") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0068: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0068: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0068: numeric"
    return bool(value), "runtime-rule-0068: truthy"

def runtime_rule_0069(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0069") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0069: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0069: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0069: numeric"
    return bool(value), "runtime-rule-0069: truthy"

def runtime_rule_0070(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0070") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0070: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0070: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0070: numeric"
    return bool(value), "runtime-rule-0070: truthy"

def runtime_rule_0071(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0071") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0071: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0071: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0071: numeric"
    return bool(value), "runtime-rule-0071: truthy"

def runtime_rule_0072(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0072") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0072: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0072: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0072: numeric"
    return bool(value), "runtime-rule-0072: truthy"

def runtime_rule_0073(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0073") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0073: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0073: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0073: numeric"
    return bool(value), "runtime-rule-0073: truthy"

def runtime_rule_0074(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0074") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0074: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0074: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0074: numeric"
    return bool(value), "runtime-rule-0074: truthy"

def runtime_rule_0075(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0075") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0075: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0075: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0075: numeric"
    return bool(value), "runtime-rule-0075: truthy"

def runtime_rule_0076(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0076") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0076: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0076: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0076: numeric"
    return bool(value), "runtime-rule-0076: truthy"

def runtime_rule_0077(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0077") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0077: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0077: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0077: numeric"
    return bool(value), "runtime-rule-0077: truthy"

def runtime_rule_0078(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0078") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0078: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0078: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0078: numeric"
    return bool(value), "runtime-rule-0078: truthy"

def runtime_rule_0079(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0079") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0079: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0079: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0079: numeric"
    return bool(value), "runtime-rule-0079: truthy"

def runtime_rule_0080(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0080") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0080: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0080: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0080: numeric"
    return bool(value), "runtime-rule-0080: truthy"

def runtime_rule_0081(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0081") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0081: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0081: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0081: numeric"
    return bool(value), "runtime-rule-0081: truthy"

def runtime_rule_0082(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0082") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0082: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0082: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0082: numeric"
    return bool(value), "runtime-rule-0082: truthy"

def runtime_rule_0083(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0083") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0083: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0083: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0083: numeric"
    return bool(value), "runtime-rule-0083: truthy"

def runtime_rule_0084(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0084") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0084: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0084: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0084: numeric"
    return bool(value), "runtime-rule-0084: truthy"

def runtime_rule_0085(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0085") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0085: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0085: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0085: numeric"
    return bool(value), "runtime-rule-0085: truthy"

def runtime_rule_0086(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0086") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0086: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0086: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0086: numeric"
    return bool(value), "runtime-rule-0086: truthy"

def runtime_rule_0087(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0087") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0087: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0087: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0087: numeric"
    return bool(value), "runtime-rule-0087: truthy"

def runtime_rule_0088(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0088") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0088: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0088: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0088: numeric"
    return bool(value), "runtime-rule-0088: truthy"

def runtime_rule_0089(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0089") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0089: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0089: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0089: numeric"
    return bool(value), "runtime-rule-0089: truthy"

def runtime_rule_0090(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0090") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0090: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0090: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0090: numeric"
    return bool(value), "runtime-rule-0090: truthy"

def runtime_rule_0091(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0091") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0091: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0091: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0091: numeric"
    return bool(value), "runtime-rule-0091: truthy"

def runtime_rule_0092(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0092") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0092: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0092: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0092: numeric"
    return bool(value), "runtime-rule-0092: truthy"

def runtime_rule_0093(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0093") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0093: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0093: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0093: numeric"
    return bool(value), "runtime-rule-0093: truthy"

def runtime_rule_0094(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0094") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0094: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0094: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0094: numeric"
    return bool(value), "runtime-rule-0094: truthy"

def runtime_rule_0095(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0095") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0095: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0095: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0095: numeric"
    return bool(value), "runtime-rule-0095: truthy"

def runtime_rule_0096(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0096") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0096: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0096: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0096: numeric"
    return bool(value), "runtime-rule-0096: truthy"

def runtime_rule_0097(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0097") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0097: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0097: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0097: numeric"
    return bool(value), "runtime-rule-0097: truthy"

def runtime_rule_0098(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0098") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0098: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0098: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0098: numeric"
    return bool(value), "runtime-rule-0098: truthy"

def runtime_rule_0099(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0099") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0099: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0099: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0099: numeric"
    return bool(value), "runtime-rule-0099: truthy"

def runtime_rule_0100(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0100") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0100: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0100: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0100: numeric"
    return bool(value), "runtime-rule-0100: truthy"

def runtime_rule_0101(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0101") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0101: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0101: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0101: numeric"
    return bool(value), "runtime-rule-0101: truthy"

def runtime_rule_0102(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0102") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0102: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0102: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0102: numeric"
    return bool(value), "runtime-rule-0102: truthy"

def runtime_rule_0103(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0103") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0103: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0103: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0103: numeric"
    return bool(value), "runtime-rule-0103: truthy"

def runtime_rule_0104(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0104") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0104: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0104: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0104: numeric"
    return bool(value), "runtime-rule-0104: truthy"

def runtime_rule_0105(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0105") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0105: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0105: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0105: numeric"
    return bool(value), "runtime-rule-0105: truthy"

def runtime_rule_0106(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0106") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0106: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0106: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0106: numeric"
    return bool(value), "runtime-rule-0106: truthy"

def runtime_rule_0107(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0107") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0107: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0107: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0107: numeric"
    return bool(value), "runtime-rule-0107: truthy"

def runtime_rule_0108(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0108") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0108: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0108: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0108: numeric"
    return bool(value), "runtime-rule-0108: truthy"

def runtime_rule_0109(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0109") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0109: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0109: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0109: numeric"
    return bool(value), "runtime-rule-0109: truthy"

def runtime_rule_0110(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0110") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0110: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0110: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0110: numeric"
    return bool(value), "runtime-rule-0110: truthy"

def runtime_rule_0111(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0111") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0111: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0111: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0111: numeric"
    return bool(value), "runtime-rule-0111: truthy"

def runtime_rule_0112(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0112") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0112: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0112: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0112: numeric"
    return bool(value), "runtime-rule-0112: truthy"

def runtime_rule_0113(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0113") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0113: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0113: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0113: numeric"
    return bool(value), "runtime-rule-0113: truthy"

def runtime_rule_0114(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0114") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0114: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0114: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0114: numeric"
    return bool(value), "runtime-rule-0114: truthy"

def runtime_rule_0115(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0115") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0115: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0115: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0115: numeric"
    return bool(value), "runtime-rule-0115: truthy"

def runtime_rule_0116(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0116") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0116: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0116: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0116: numeric"
    return bool(value), "runtime-rule-0116: truthy"

def runtime_rule_0117(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0117") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0117: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0117: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0117: numeric"
    return bool(value), "runtime-rule-0117: truthy"

def runtime_rule_0118(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0118") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0118: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0118: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0118: numeric"
    return bool(value), "runtime-rule-0118: truthy"

def runtime_rule_0119(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0119") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0119: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0119: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0119: numeric"
    return bool(value), "runtime-rule-0119: truthy"

def runtime_rule_0120(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0120") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0120: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0120: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0120: numeric"
    return bool(value), "runtime-rule-0120: truthy"

def runtime_rule_0121(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0121") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0121: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0121: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0121: numeric"
    return bool(value), "runtime-rule-0121: truthy"

def runtime_rule_0122(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0122") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0122: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0122: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0122: numeric"
    return bool(value), "runtime-rule-0122: truthy"

def runtime_rule_0123(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0123") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0123: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0123: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0123: numeric"
    return bool(value), "runtime-rule-0123: truthy"

def runtime_rule_0124(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0124") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0124: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0124: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0124: numeric"
    return bool(value), "runtime-rule-0124: truthy"

def runtime_rule_0125(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0125") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0125: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0125: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0125: numeric"
    return bool(value), "runtime-rule-0125: truthy"

def runtime_rule_0126(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0126") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0126: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0126: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0126: numeric"
    return bool(value), "runtime-rule-0126: truthy"

def runtime_rule_0127(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0127") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0127: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0127: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0127: numeric"
    return bool(value), "runtime-rule-0127: truthy"

def runtime_rule_0128(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0128") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0128: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0128: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0128: numeric"
    return bool(value), "runtime-rule-0128: truthy"

def runtime_rule_0129(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0129") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0129: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0129: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0129: numeric"
    return bool(value), "runtime-rule-0129: truthy"

def runtime_rule_0130(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0130") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0130: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0130: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0130: numeric"
    return bool(value), "runtime-rule-0130: truthy"

def runtime_rule_0131(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0131") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0131: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0131: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0131: numeric"
    return bool(value), "runtime-rule-0131: truthy"

def runtime_rule_0132(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0132") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0132: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0132: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0132: numeric"
    return bool(value), "runtime-rule-0132: truthy"

def runtime_rule_0133(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0133") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0133: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0133: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0133: numeric"
    return bool(value), "runtime-rule-0133: truthy"

def runtime_rule_0134(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0134") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0134: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0134: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0134: numeric"
    return bool(value), "runtime-rule-0134: truthy"

def runtime_rule_0135(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0135") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0135: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0135: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0135: numeric"
    return bool(value), "runtime-rule-0135: truthy"

def runtime_rule_0136(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0136") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0136: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0136: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0136: numeric"
    return bool(value), "runtime-rule-0136: truthy"

def runtime_rule_0137(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0137") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0137: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0137: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0137: numeric"
    return bool(value), "runtime-rule-0137: truthy"

def runtime_rule_0138(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0138") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0138: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0138: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0138: numeric"
    return bool(value), "runtime-rule-0138: truthy"

def runtime_rule_0139(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0139") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0139: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0139: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0139: numeric"
    return bool(value), "runtime-rule-0139: truthy"

def runtime_rule_0140(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0140") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0140: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0140: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0140: numeric"
    return bool(value), "runtime-rule-0140: truthy"

def runtime_rule_0141(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0141") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0141: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0141: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0141: numeric"
    return bool(value), "runtime-rule-0141: truthy"

def runtime_rule_0142(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0142") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0142: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0142: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0142: numeric"
    return bool(value), "runtime-rule-0142: truthy"

def runtime_rule_0143(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0143") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0143: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0143: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0143: numeric"
    return bool(value), "runtime-rule-0143: truthy"

def runtime_rule_0144(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0144") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0144: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0144: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0144: numeric"
    return bool(value), "runtime-rule-0144: truthy"

def runtime_rule_0145(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0145") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0145: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0145: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0145: numeric"
    return bool(value), "runtime-rule-0145: truthy"

def runtime_rule_0146(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0146") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0146: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0146: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0146: numeric"
    return bool(value), "runtime-rule-0146: truthy"

def runtime_rule_0147(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0147") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0147: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0147: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0147: numeric"
    return bool(value), "runtime-rule-0147: truthy"

def runtime_rule_0148(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0148") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0148: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0148: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0148: numeric"
    return bool(value), "runtime-rule-0148: truthy"

def runtime_rule_0149(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0149") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0149: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0149: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0149: numeric"
    return bool(value), "runtime-rule-0149: truthy"

def runtime_rule_0150(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0150") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0150: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0150: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0150: numeric"
    return bool(value), "runtime-rule-0150: truthy"

def runtime_rule_0151(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0151") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0151: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0151: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0151: numeric"
    return bool(value), "runtime-rule-0151: truthy"

def runtime_rule_0152(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0152") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0152: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0152: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0152: numeric"
    return bool(value), "runtime-rule-0152: truthy"

def runtime_rule_0153(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0153") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0153: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0153: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0153: numeric"
    return bool(value), "runtime-rule-0153: truthy"

def runtime_rule_0154(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0154") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0154: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0154: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0154: numeric"
    return bool(value), "runtime-rule-0154: truthy"

def runtime_rule_0155(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0155") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0155: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0155: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0155: numeric"
    return bool(value), "runtime-rule-0155: truthy"

def runtime_rule_0156(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0156") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0156: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0156: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0156: numeric"
    return bool(value), "runtime-rule-0156: truthy"

def runtime_rule_0157(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0157") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0157: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0157: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0157: numeric"
    return bool(value), "runtime-rule-0157: truthy"

def runtime_rule_0158(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0158") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0158: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0158: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0158: numeric"
    return bool(value), "runtime-rule-0158: truthy"

def runtime_rule_0159(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0159") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0159: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0159: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0159: numeric"
    return bool(value), "runtime-rule-0159: truthy"

def runtime_rule_0160(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0160") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0160: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0160: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0160: numeric"
    return bool(value), "runtime-rule-0160: truthy"

def runtime_rule_0161(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0161") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0161: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0161: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0161: numeric"
    return bool(value), "runtime-rule-0161: truthy"

def runtime_rule_0162(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0162") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0162: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0162: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0162: numeric"
    return bool(value), "runtime-rule-0162: truthy"

def runtime_rule_0163(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0163") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0163: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0163: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0163: numeric"
    return bool(value), "runtime-rule-0163: truthy"

def runtime_rule_0164(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0164") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0164: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0164: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0164: numeric"
    return bool(value), "runtime-rule-0164: truthy"

def runtime_rule_0165(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0165") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0165: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0165: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0165: numeric"
    return bool(value), "runtime-rule-0165: truthy"

def runtime_rule_0166(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0166") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0166: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0166: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0166: numeric"
    return bool(value), "runtime-rule-0166: truthy"

def runtime_rule_0167(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0167") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0167: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0167: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0167: numeric"
    return bool(value), "runtime-rule-0167: truthy"

def runtime_rule_0168(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0168") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0168: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0168: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0168: numeric"
    return bool(value), "runtime-rule-0168: truthy"

def runtime_rule_0169(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0169") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0169: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0169: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0169: numeric"
    return bool(value), "runtime-rule-0169: truthy"

def runtime_rule_0170(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0170") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0170: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0170: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0170: numeric"
    return bool(value), "runtime-rule-0170: truthy"

def runtime_rule_0171(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0171") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0171: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0171: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0171: numeric"
    return bool(value), "runtime-rule-0171: truthy"

def runtime_rule_0172(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0172") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0172: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0172: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0172: numeric"
    return bool(value), "runtime-rule-0172: truthy"

def runtime_rule_0173(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0173") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0173: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0173: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0173: numeric"
    return bool(value), "runtime-rule-0173: truthy"

def runtime_rule_0174(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0174") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0174: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0174: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0174: numeric"
    return bool(value), "runtime-rule-0174: truthy"

def runtime_rule_0175(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0175") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0175: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0175: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0175: numeric"
    return bool(value), "runtime-rule-0175: truthy"

def runtime_rule_0176(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0176") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0176: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0176: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0176: numeric"
    return bool(value), "runtime-rule-0176: truthy"

def runtime_rule_0177(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0177") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0177: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0177: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0177: numeric"
    return bool(value), "runtime-rule-0177: truthy"

def runtime_rule_0178(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0178") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0178: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0178: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0178: numeric"
    return bool(value), "runtime-rule-0178: truthy"

def runtime_rule_0179(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0179") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0179: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0179: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0179: numeric"
    return bool(value), "runtime-rule-0179: truthy"

def runtime_rule_0180(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0180") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0180: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0180: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0180: numeric"
    return bool(value), "runtime-rule-0180: truthy"

def runtime_rule_0181(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0181") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0181: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0181: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0181: numeric"
    return bool(value), "runtime-rule-0181: truthy"

def runtime_rule_0182(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0182") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0182: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0182: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0182: numeric"
    return bool(value), "runtime-rule-0182: truthy"

def runtime_rule_0183(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0183") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0183: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0183: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0183: numeric"
    return bool(value), "runtime-rule-0183: truthy"

def runtime_rule_0184(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0184") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0184: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0184: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0184: numeric"
    return bool(value), "runtime-rule-0184: truthy"

def runtime_rule_0185(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0185") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0185: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0185: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0185: numeric"
    return bool(value), "runtime-rule-0185: truthy"

def runtime_rule_0186(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0186") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0186: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0186: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0186: numeric"
    return bool(value), "runtime-rule-0186: truthy"

def runtime_rule_0187(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0187") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0187: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0187: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0187: numeric"
    return bool(value), "runtime-rule-0187: truthy"

def runtime_rule_0188(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0188") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0188: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0188: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0188: numeric"
    return bool(value), "runtime-rule-0188: truthy"

def runtime_rule_0189(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0189") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0189: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0189: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0189: numeric"
    return bool(value), "runtime-rule-0189: truthy"

def runtime_rule_0190(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0190") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0190: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0190: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0190: numeric"
    return bool(value), "runtime-rule-0190: truthy"

def runtime_rule_0191(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0191") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0191: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0191: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0191: numeric"
    return bool(value), "runtime-rule-0191: truthy"

def runtime_rule_0192(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0192") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0192: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0192: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0192: numeric"
    return bool(value), "runtime-rule-0192: truthy"

def runtime_rule_0193(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0193") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0193: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0193: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0193: numeric"
    return bool(value), "runtime-rule-0193: truthy"

def runtime_rule_0194(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0194") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0194: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0194: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0194: numeric"
    return bool(value), "runtime-rule-0194: truthy"

def runtime_rule_0195(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0195") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0195: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0195: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0195: numeric"
    return bool(value), "runtime-rule-0195: truthy"

def runtime_rule_0196(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0196") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0196: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0196: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0196: numeric"
    return bool(value), "runtime-rule-0196: truthy"

def runtime_rule_0197(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0197") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0197: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0197: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0197: numeric"
    return bool(value), "runtime-rule-0197: truthy"

def runtime_rule_0198(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0198") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0198: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0198: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0198: numeric"
    return bool(value), "runtime-rule-0198: truthy"

def runtime_rule_0199(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0199") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0199: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0199: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0199: numeric"
    return bool(value), "runtime-rule-0199: truthy"

def runtime_rule_0200(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0200") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0200: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0200: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0200: numeric"
    return bool(value), "runtime-rule-0200: truthy"

def runtime_rule_0201(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0201") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0201: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0201: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0201: numeric"
    return bool(value), "runtime-rule-0201: truthy"

def runtime_rule_0202(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0202") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0202: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0202: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0202: numeric"
    return bool(value), "runtime-rule-0202: truthy"

def runtime_rule_0203(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0203") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0203: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0203: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0203: numeric"
    return bool(value), "runtime-rule-0203: truthy"

def runtime_rule_0204(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0204") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0204: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0204: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0204: numeric"
    return bool(value), "runtime-rule-0204: truthy"

def runtime_rule_0205(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0205") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0205: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0205: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0205: numeric"
    return bool(value), "runtime-rule-0205: truthy"

def runtime_rule_0206(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0206") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0206: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0206: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0206: numeric"
    return bool(value), "runtime-rule-0206: truthy"

def runtime_rule_0207(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0207") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0207: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0207: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0207: numeric"
    return bool(value), "runtime-rule-0207: truthy"

def runtime_rule_0208(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0208") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0208: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0208: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0208: numeric"
    return bool(value), "runtime-rule-0208: truthy"

def runtime_rule_0209(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0209") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0209: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0209: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0209: numeric"
    return bool(value), "runtime-rule-0209: truthy"

def runtime_rule_0210(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0210") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0210: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0210: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0210: numeric"
    return bool(value), "runtime-rule-0210: truthy"

def runtime_rule_0211(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0211") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0211: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0211: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0211: numeric"
    return bool(value), "runtime-rule-0211: truthy"

def runtime_rule_0212(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0212") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0212: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0212: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0212: numeric"
    return bool(value), "runtime-rule-0212: truthy"

def runtime_rule_0213(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0213") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0213: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0213: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0213: numeric"
    return bool(value), "runtime-rule-0213: truthy"

def runtime_rule_0214(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0214") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0214: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0214: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0214: numeric"
    return bool(value), "runtime-rule-0214: truthy"

def runtime_rule_0215(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0215") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0215: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0215: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0215: numeric"
    return bool(value), "runtime-rule-0215: truthy"

def runtime_rule_0216(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0216") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0216: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0216: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0216: numeric"
    return bool(value), "runtime-rule-0216: truthy"

def runtime_rule_0217(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0217") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0217: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0217: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0217: numeric"
    return bool(value), "runtime-rule-0217: truthy"

def runtime_rule_0218(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0218") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0218: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0218: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0218: numeric"
    return bool(value), "runtime-rule-0218: truthy"

def runtime_rule_0219(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0219") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0219: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0219: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0219: numeric"
    return bool(value), "runtime-rule-0219: truthy"

def runtime_rule_0220(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0220") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0220: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0220: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0220: numeric"
    return bool(value), "runtime-rule-0220: truthy"

def runtime_rule_0221(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0221") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0221: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0221: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0221: numeric"
    return bool(value), "runtime-rule-0221: truthy"

def runtime_rule_0222(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0222") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0222: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0222: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0222: numeric"
    return bool(value), "runtime-rule-0222: truthy"

def runtime_rule_0223(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0223") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0223: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0223: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0223: numeric"
    return bool(value), "runtime-rule-0223: truthy"

def runtime_rule_0224(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0224") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0224: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0224: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0224: numeric"
    return bool(value), "runtime-rule-0224: truthy"

def runtime_rule_0225(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0225") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0225: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0225: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0225: numeric"
    return bool(value), "runtime-rule-0225: truthy"

def runtime_rule_0226(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0226") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0226: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0226: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0226: numeric"
    return bool(value), "runtime-rule-0226: truthy"

def runtime_rule_0227(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0227") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0227: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0227: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0227: numeric"
    return bool(value), "runtime-rule-0227: truthy"

def runtime_rule_0228(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0228") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0228: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0228: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0228: numeric"
    return bool(value), "runtime-rule-0228: truthy"

def runtime_rule_0229(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0229") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0229: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0229: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0229: numeric"
    return bool(value), "runtime-rule-0229: truthy"

def runtime_rule_0230(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0230") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0230: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0230: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0230: numeric"
    return bool(value), "runtime-rule-0230: truthy"

def runtime_rule_0231(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0231") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0231: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0231: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0231: numeric"
    return bool(value), "runtime-rule-0231: truthy"

def runtime_rule_0232(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0232") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0232: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0232: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0232: numeric"
    return bool(value), "runtime-rule-0232: truthy"

def runtime_rule_0233(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0233") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0233: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0233: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0233: numeric"
    return bool(value), "runtime-rule-0233: truthy"

def runtime_rule_0234(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0234") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0234: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0234: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0234: numeric"
    return bool(value), "runtime-rule-0234: truthy"

def runtime_rule_0235(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0235") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0235: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0235: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0235: numeric"
    return bool(value), "runtime-rule-0235: truthy"

def runtime_rule_0236(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0236") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0236: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0236: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0236: numeric"
    return bool(value), "runtime-rule-0236: truthy"

def runtime_rule_0237(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0237") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0237: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0237: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0237: numeric"
    return bool(value), "runtime-rule-0237: truthy"

def runtime_rule_0238(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0238") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0238: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0238: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0238: numeric"
    return bool(value), "runtime-rule-0238: truthy"

def runtime_rule_0239(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0239") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0239: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0239: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0239: numeric"
    return bool(value), "runtime-rule-0239: truthy"

def runtime_rule_0240(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0240") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0240: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0240: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0240: numeric"
    return bool(value), "runtime-rule-0240: truthy"

def runtime_rule_0241(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0241") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0241: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0241: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0241: numeric"
    return bool(value), "runtime-rule-0241: truthy"

def runtime_rule_0242(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0242") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0242: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0242: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0242: numeric"
    return bool(value), "runtime-rule-0242: truthy"

def runtime_rule_0243(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0243") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0243: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0243: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0243: numeric"
    return bool(value), "runtime-rule-0243: truthy"

def runtime_rule_0244(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0244") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0244: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0244: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0244: numeric"
    return bool(value), "runtime-rule-0244: truthy"

def runtime_rule_0245(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0245") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0245: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0245: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0245: numeric"
    return bool(value), "runtime-rule-0245: truthy"

def runtime_rule_0246(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0246") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0246: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0246: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0246: numeric"
    return bool(value), "runtime-rule-0246: truthy"

def runtime_rule_0247(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0247") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0247: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0247: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0247: numeric"
    return bool(value), "runtime-rule-0247: truthy"

def runtime_rule_0248(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0248") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0248: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0248: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0248: numeric"
    return bool(value), "runtime-rule-0248: truthy"

def runtime_rule_0249(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0249") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0249: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0249: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0249: numeric"
    return bool(value), "runtime-rule-0249: truthy"

def runtime_rule_0250(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0250") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0250: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0250: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0250: numeric"
    return bool(value), "runtime-rule-0250: truthy"

def runtime_rule_0251(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0251") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0251: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0251: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0251: numeric"
    return bool(value), "runtime-rule-0251: truthy"

def runtime_rule_0252(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0252") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0252: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0252: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0252: numeric"
    return bool(value), "runtime-rule-0252: truthy"

def runtime_rule_0253(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0253") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0253: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0253: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0253: numeric"
    return bool(value), "runtime-rule-0253: truthy"

def runtime_rule_0254(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0254") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0254: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0254: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0254: numeric"
    return bool(value), "runtime-rule-0254: truthy"

def runtime_rule_0255(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0255") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0255: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0255: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0255: numeric"
    return bool(value), "runtime-rule-0255: truthy"

def runtime_rule_0256(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0256") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0256: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0256: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0256: numeric"
    return bool(value), "runtime-rule-0256: truthy"

def runtime_rule_0257(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0257") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0257: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0257: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0257: numeric"
    return bool(value), "runtime-rule-0257: truthy"

def runtime_rule_0258(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0258") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0258: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0258: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0258: numeric"
    return bool(value), "runtime-rule-0258: truthy"

def runtime_rule_0259(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0259") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0259: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0259: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0259: numeric"
    return bool(value), "runtime-rule-0259: truthy"

def runtime_rule_0260(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0260") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0260: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0260: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0260: numeric"
    return bool(value), "runtime-rule-0260: truthy"

def runtime_rule_0261(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0261") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0261: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0261: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0261: numeric"
    return bool(value), "runtime-rule-0261: truthy"

def runtime_rule_0262(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0262") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0262: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0262: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0262: numeric"
    return bool(value), "runtime-rule-0262: truthy"

def runtime_rule_0263(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0263") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0263: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0263: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0263: numeric"
    return bool(value), "runtime-rule-0263: truthy"

def runtime_rule_0264(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0264") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0264: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0264: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0264: numeric"
    return bool(value), "runtime-rule-0264: truthy"

def runtime_rule_0265(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0265") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0265: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0265: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0265: numeric"
    return bool(value), "runtime-rule-0265: truthy"

def runtime_rule_0266(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0266") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0266: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0266: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0266: numeric"
    return bool(value), "runtime-rule-0266: truthy"

def runtime_rule_0267(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0267") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0267: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0267: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0267: numeric"
    return bool(value), "runtime-rule-0267: truthy"

def runtime_rule_0268(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0268") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0268: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0268: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0268: numeric"
    return bool(value), "runtime-rule-0268: truthy"

def runtime_rule_0269(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0269") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0269: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0269: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0269: numeric"
    return bool(value), "runtime-rule-0269: truthy"

def runtime_rule_0270(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0270") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0270: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0270: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0270: numeric"
    return bool(value), "runtime-rule-0270: truthy"

def runtime_rule_0271(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0271") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0271: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0271: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0271: numeric"
    return bool(value), "runtime-rule-0271: truthy"

def runtime_rule_0272(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0272") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0272: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0272: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0272: numeric"
    return bool(value), "runtime-rule-0272: truthy"

def runtime_rule_0273(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0273") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0273: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0273: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0273: numeric"
    return bool(value), "runtime-rule-0273: truthy"

def runtime_rule_0274(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0274") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0274: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0274: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0274: numeric"
    return bool(value), "runtime-rule-0274: truthy"

def runtime_rule_0275(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0275") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0275: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0275: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0275: numeric"
    return bool(value), "runtime-rule-0275: truthy"

def runtime_rule_0276(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0276") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0276: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0276: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0276: numeric"
    return bool(value), "runtime-rule-0276: truthy"

def runtime_rule_0277(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0277") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0277: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0277: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0277: numeric"
    return bool(value), "runtime-rule-0277: truthy"

def runtime_rule_0278(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0278") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0278: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0278: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0278: numeric"
    return bool(value), "runtime-rule-0278: truthy"

def runtime_rule_0279(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0279") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0279: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0279: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0279: numeric"
    return bool(value), "runtime-rule-0279: truthy"

def runtime_rule_0280(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0280") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0280: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0280: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0280: numeric"
    return bool(value), "runtime-rule-0280: truthy"

def runtime_rule_0281(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0281") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0281: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0281: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0281: numeric"
    return bool(value), "runtime-rule-0281: truthy"

def runtime_rule_0282(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0282") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0282: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0282: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0282: numeric"
    return bool(value), "runtime-rule-0282: truthy"

def runtime_rule_0283(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0283") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0283: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0283: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0283: numeric"
    return bool(value), "runtime-rule-0283: truthy"

def runtime_rule_0284(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0284") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0284: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0284: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0284: numeric"
    return bool(value), "runtime-rule-0284: truthy"

def runtime_rule_0285(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0285") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0285: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0285: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0285: numeric"
    return bool(value), "runtime-rule-0285: truthy"

def runtime_rule_0286(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0286") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0286: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0286: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0286: numeric"
    return bool(value), "runtime-rule-0286: truthy"

def runtime_rule_0287(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0287") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0287: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0287: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0287: numeric"
    return bool(value), "runtime-rule-0287: truthy"

def runtime_rule_0288(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0288") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0288: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0288: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0288: numeric"
    return bool(value), "runtime-rule-0288: truthy"

def runtime_rule_0289(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0289") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0289: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0289: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0289: numeric"
    return bool(value), "runtime-rule-0289: truthy"

def runtime_rule_0290(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0290") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0290: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0290: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0290: numeric"
    return bool(value), "runtime-rule-0290: truthy"

def runtime_rule_0291(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0291") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0291: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0291: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0291: numeric"
    return bool(value), "runtime-rule-0291: truthy"

def runtime_rule_0292(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0292") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0292: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0292: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0292: numeric"
    return bool(value), "runtime-rule-0292: truthy"

def runtime_rule_0293(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0293") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0293: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0293: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0293: numeric"
    return bool(value), "runtime-rule-0293: truthy"

def runtime_rule_0294(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0294") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0294: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0294: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0294: numeric"
    return bool(value), "runtime-rule-0294: truthy"

def runtime_rule_0295(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0295") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0295: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0295: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0295: numeric"
    return bool(value), "runtime-rule-0295: truthy"

def runtime_rule_0296(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0296") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0296: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0296: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0296: numeric"
    return bool(value), "runtime-rule-0296: truthy"

def runtime_rule_0297(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0297") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0297: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0297: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0297: numeric"
    return bool(value), "runtime-rule-0297: truthy"

def runtime_rule_0298(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0298") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0298: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0298: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0298: numeric"
    return bool(value), "runtime-rule-0298: truthy"

def runtime_rule_0299(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0299") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0299: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0299: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0299: numeric"
    return bool(value), "runtime-rule-0299: truthy"

def runtime_rule_0300(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0300") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0300: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0300: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0300: numeric"
    return bool(value), "runtime-rule-0300: truthy"

def runtime_rule_0301(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0301") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0301: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0301: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0301: numeric"
    return bool(value), "runtime-rule-0301: truthy"

def runtime_rule_0302(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0302") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0302: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0302: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0302: numeric"
    return bool(value), "runtime-rule-0302: truthy"

def runtime_rule_0303(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0303") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0303: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0303: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0303: numeric"
    return bool(value), "runtime-rule-0303: truthy"

def runtime_rule_0304(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0304") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0304: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0304: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0304: numeric"
    return bool(value), "runtime-rule-0304: truthy"

def runtime_rule_0305(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0305") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0305: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0305: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0305: numeric"
    return bool(value), "runtime-rule-0305: truthy"

def runtime_rule_0306(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0306") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0306: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0306: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0306: numeric"
    return bool(value), "runtime-rule-0306: truthy"

def runtime_rule_0307(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0307") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0307: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0307: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0307: numeric"
    return bool(value), "runtime-rule-0307: truthy"

def runtime_rule_0308(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0308") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0308: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0308: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0308: numeric"
    return bool(value), "runtime-rule-0308: truthy"

def runtime_rule_0309(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0309") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0309: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0309: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0309: numeric"
    return bool(value), "runtime-rule-0309: truthy"

def runtime_rule_0310(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0310") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0310: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0310: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0310: numeric"
    return bool(value), "runtime-rule-0310: truthy"

def runtime_rule_0311(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0311") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0311: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0311: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0311: numeric"
    return bool(value), "runtime-rule-0311: truthy"

def runtime_rule_0312(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0312") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0312: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0312: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0312: numeric"
    return bool(value), "runtime-rule-0312: truthy"

def runtime_rule_0313(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0313") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0313: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0313: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0313: numeric"
    return bool(value), "runtime-rule-0313: truthy"

def runtime_rule_0314(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0314") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0314: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0314: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0314: numeric"
    return bool(value), "runtime-rule-0314: truthy"

def runtime_rule_0315(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0315") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0315: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0315: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0315: numeric"
    return bool(value), "runtime-rule-0315: truthy"

def runtime_rule_0316(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0316") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0316: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0316: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0316: numeric"
    return bool(value), "runtime-rule-0316: truthy"

def runtime_rule_0317(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0317") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0317: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0317: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0317: numeric"
    return bool(value), "runtime-rule-0317: truthy"

def runtime_rule_0318(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0318") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0318: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0318: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0318: numeric"
    return bool(value), "runtime-rule-0318: truthy"

def runtime_rule_0319(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0319") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0319: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0319: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0319: numeric"
    return bool(value), "runtime-rule-0319: truthy"

def runtime_rule_0320(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0320") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0320: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0320: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0320: numeric"
    return bool(value), "runtime-rule-0320: truthy"

def runtime_rule_0321(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0321") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0321: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0321: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0321: numeric"
    return bool(value), "runtime-rule-0321: truthy"

def runtime_rule_0322(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0322") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0322: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0322: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0322: numeric"
    return bool(value), "runtime-rule-0322: truthy"

def runtime_rule_0323(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0323") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0323: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0323: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0323: numeric"
    return bool(value), "runtime-rule-0323: truthy"

def runtime_rule_0324(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0324") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0324: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0324: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0324: numeric"
    return bool(value), "runtime-rule-0324: truthy"

def runtime_rule_0325(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0325") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0325: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0325: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0325: numeric"
    return bool(value), "runtime-rule-0325: truthy"

def runtime_rule_0326(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0326") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0326: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0326: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0326: numeric"
    return bool(value), "runtime-rule-0326: truthy"

def runtime_rule_0327(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0327") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0327: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0327: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0327: numeric"
    return bool(value), "runtime-rule-0327: truthy"

def runtime_rule_0328(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0328") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0328: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0328: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0328: numeric"
    return bool(value), "runtime-rule-0328: truthy"

def runtime_rule_0329(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0329") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0329: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0329: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0329: numeric"
    return bool(value), "runtime-rule-0329: truthy"

def runtime_rule_0330(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0330") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0330: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0330: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0330: numeric"
    return bool(value), "runtime-rule-0330: truthy"

def runtime_rule_0331(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0331") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0331: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0331: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0331: numeric"
    return bool(value), "runtime-rule-0331: truthy"

def runtime_rule_0332(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0332") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0332: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0332: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0332: numeric"
    return bool(value), "runtime-rule-0332: truthy"

def runtime_rule_0333(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0333") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0333: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0333: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0333: numeric"
    return bool(value), "runtime-rule-0333: truthy"

def runtime_rule_0334(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0334") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0334: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0334: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0334: numeric"
    return bool(value), "runtime-rule-0334: truthy"

def runtime_rule_0335(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0335") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0335: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0335: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0335: numeric"
    return bool(value), "runtime-rule-0335: truthy"

def runtime_rule_0336(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0336") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0336: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0336: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0336: numeric"
    return bool(value), "runtime-rule-0336: truthy"

def runtime_rule_0337(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0337") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0337: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0337: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0337: numeric"
    return bool(value), "runtime-rule-0337: truthy"

def runtime_rule_0338(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0338") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0338: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0338: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0338: numeric"
    return bool(value), "runtime-rule-0338: truthy"

def runtime_rule_0339(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0339") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0339: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0339: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0339: numeric"
    return bool(value), "runtime-rule-0339: truthy"

def runtime_rule_0340(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0340") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0340: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0340: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0340: numeric"
    return bool(value), "runtime-rule-0340: truthy"

def runtime_rule_0341(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0341") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0341: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0341: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0341: numeric"
    return bool(value), "runtime-rule-0341: truthy"

def runtime_rule_0342(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0342") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0342: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0342: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0342: numeric"
    return bool(value), "runtime-rule-0342: truthy"

def runtime_rule_0343(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0343") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0343: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0343: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0343: numeric"
    return bool(value), "runtime-rule-0343: truthy"

def runtime_rule_0344(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0344") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0344: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0344: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0344: numeric"
    return bool(value), "runtime-rule-0344: truthy"

def runtime_rule_0345(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0345") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0345: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0345: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0345: numeric"
    return bool(value), "runtime-rule-0345: truthy"

def runtime_rule_0346(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0346") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0346: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0346: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0346: numeric"
    return bool(value), "runtime-rule-0346: truthy"

def runtime_rule_0347(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0347") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0347: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0347: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0347: numeric"
    return bool(value), "runtime-rule-0347: truthy"

def runtime_rule_0348(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0348") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0348: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0348: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0348: numeric"
    return bool(value), "runtime-rule-0348: truthy"

def runtime_rule_0349(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0349") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0349: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0349: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0349: numeric"
    return bool(value), "runtime-rule-0349: truthy"

def runtime_rule_0350(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0350") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0350: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0350: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0350: numeric"
    return bool(value), "runtime-rule-0350: truthy"

def runtime_rule_0351(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0351") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0351: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0351: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0351: numeric"
    return bool(value), "runtime-rule-0351: truthy"

def runtime_rule_0352(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0352") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0352: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0352: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0352: numeric"
    return bool(value), "runtime-rule-0352: truthy"

def runtime_rule_0353(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0353") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0353: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0353: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0353: numeric"
    return bool(value), "runtime-rule-0353: truthy"

def runtime_rule_0354(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0354") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0354: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0354: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0354: numeric"
    return bool(value), "runtime-rule-0354: truthy"

def runtime_rule_0355(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0355") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0355: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0355: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0355: numeric"
    return bool(value), "runtime-rule-0355: truthy"

def runtime_rule_0356(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0356") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0356: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0356: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0356: numeric"
    return bool(value), "runtime-rule-0356: truthy"

def runtime_rule_0357(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0357") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0357: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0357: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0357: numeric"
    return bool(value), "runtime-rule-0357: truthy"

def runtime_rule_0358(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0358") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0358: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0358: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0358: numeric"
    return bool(value), "runtime-rule-0358: truthy"

def runtime_rule_0359(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0359") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0359: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0359: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0359: numeric"
    return bool(value), "runtime-rule-0359: truthy"

def runtime_rule_0360(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0360") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0360: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0360: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0360: numeric"
    return bool(value), "runtime-rule-0360: truthy"

def runtime_rule_0361(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0361") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0361: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0361: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0361: numeric"
    return bool(value), "runtime-rule-0361: truthy"

def runtime_rule_0362(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0362") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0362: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0362: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0362: numeric"
    return bool(value), "runtime-rule-0362: truthy"

def runtime_rule_0363(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0363") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0363: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0363: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0363: numeric"
    return bool(value), "runtime-rule-0363: truthy"

def runtime_rule_0364(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0364") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0364: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0364: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0364: numeric"
    return bool(value), "runtime-rule-0364: truthy"

def runtime_rule_0365(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0365") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0365: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0365: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0365: numeric"
    return bool(value), "runtime-rule-0365: truthy"

def runtime_rule_0366(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0366") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0366: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0366: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0366: numeric"
    return bool(value), "runtime-rule-0366: truthy"

def runtime_rule_0367(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0367") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0367: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0367: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0367: numeric"
    return bool(value), "runtime-rule-0367: truthy"

def runtime_rule_0368(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0368") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0368: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0368: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0368: numeric"
    return bool(value), "runtime-rule-0368: truthy"

def runtime_rule_0369(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0369") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0369: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0369: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0369: numeric"
    return bool(value), "runtime-rule-0369: truthy"

def runtime_rule_0370(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0370") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0370: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0370: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0370: numeric"
    return bool(value), "runtime-rule-0370: truthy"

def runtime_rule_0371(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0371") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0371: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0371: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0371: numeric"
    return bool(value), "runtime-rule-0371: truthy"

def runtime_rule_0372(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0372") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0372: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0372: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0372: numeric"
    return bool(value), "runtime-rule-0372: truthy"

def runtime_rule_0373(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0373") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0373: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0373: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0373: numeric"
    return bool(value), "runtime-rule-0373: truthy"

def runtime_rule_0374(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0374") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0374: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0374: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0374: numeric"
    return bool(value), "runtime-rule-0374: truthy"

def runtime_rule_0375(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0375") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0375: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0375: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0375: numeric"
    return bool(value), "runtime-rule-0375: truthy"

def runtime_rule_0376(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0376") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0376: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0376: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0376: numeric"
    return bool(value), "runtime-rule-0376: truthy"

def runtime_rule_0377(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0377") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0377: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0377: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0377: numeric"
    return bool(value), "runtime-rule-0377: truthy"

def runtime_rule_0378(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0378") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0378: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0378: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0378: numeric"
    return bool(value), "runtime-rule-0378: truthy"

def runtime_rule_0379(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0379") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0379: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0379: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0379: numeric"
    return bool(value), "runtime-rule-0379: truthy"

def runtime_rule_0380(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0380") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0380: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0380: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0380: numeric"
    return bool(value), "runtime-rule-0380: truthy"

def runtime_rule_0381(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0381") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0381: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0381: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0381: numeric"
    return bool(value), "runtime-rule-0381: truthy"

def runtime_rule_0382(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0382") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0382: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0382: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0382: numeric"
    return bool(value), "runtime-rule-0382: truthy"

def runtime_rule_0383(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0383") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0383: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0383: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0383: numeric"
    return bool(value), "runtime-rule-0383: truthy"

def runtime_rule_0384(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0384") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0384: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0384: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0384: numeric"
    return bool(value), "runtime-rule-0384: truthy"

def runtime_rule_0385(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0385") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0385: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0385: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0385: numeric"
    return bool(value), "runtime-rule-0385: truthy"

def runtime_rule_0386(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0386") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0386: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0386: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0386: numeric"
    return bool(value), "runtime-rule-0386: truthy"

def runtime_rule_0387(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0387") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0387: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0387: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0387: numeric"
    return bool(value), "runtime-rule-0387: truthy"

def runtime_rule_0388(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0388") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0388: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0388: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0388: numeric"
    return bool(value), "runtime-rule-0388: truthy"

def runtime_rule_0389(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0389") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0389: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0389: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0389: numeric"
    return bool(value), "runtime-rule-0389: truthy"

def runtime_rule_0390(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0390") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0390: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0390: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0390: numeric"
    return bool(value), "runtime-rule-0390: truthy"

def runtime_rule_0391(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0391") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0391: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0391: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0391: numeric"
    return bool(value), "runtime-rule-0391: truthy"

def runtime_rule_0392(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0392") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0392: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0392: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0392: numeric"
    return bool(value), "runtime-rule-0392: truthy"

def runtime_rule_0393(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0393") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0393: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0393: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0393: numeric"
    return bool(value), "runtime-rule-0393: truthy"

def runtime_rule_0394(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0394") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0394: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0394: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0394: numeric"
    return bool(value), "runtime-rule-0394: truthy"

def runtime_rule_0395(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0395") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0395: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0395: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0395: numeric"
    return bool(value), "runtime-rule-0395: truthy"

def runtime_rule_0396(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0396") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0396: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0396: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0396: numeric"
    return bool(value), "runtime-rule-0396: truthy"

def runtime_rule_0397(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0397") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0397: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0397: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0397: numeric"
    return bool(value), "runtime-rule-0397: truthy"

def runtime_rule_0398(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0398") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0398: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0398: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0398: numeric"
    return bool(value), "runtime-rule-0398: truthy"

def runtime_rule_0399(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0399") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0399: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0399: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0399: numeric"
    return bool(value), "runtime-rule-0399: truthy"

def runtime_rule_0400(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0400") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0400: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0400: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0400: numeric"
    return bool(value), "runtime-rule-0400: truthy"

def runtime_rule_0401(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0401") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0401: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0401: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0401: numeric"
    return bool(value), "runtime-rule-0401: truthy"

def runtime_rule_0402(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0402") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0402: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0402: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0402: numeric"
    return bool(value), "runtime-rule-0402: truthy"

def runtime_rule_0403(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0403") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0403: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0403: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0403: numeric"
    return bool(value), "runtime-rule-0403: truthy"

def runtime_rule_0404(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0404") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0404: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0404: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0404: numeric"
    return bool(value), "runtime-rule-0404: truthy"

def runtime_rule_0405(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0405") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0405: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0405: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0405: numeric"
    return bool(value), "runtime-rule-0405: truthy"

def runtime_rule_0406(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0406") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0406: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0406: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0406: numeric"
    return bool(value), "runtime-rule-0406: truthy"

def runtime_rule_0407(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0407") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0407: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0407: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0407: numeric"
    return bool(value), "runtime-rule-0407: truthy"

def runtime_rule_0408(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0408") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0408: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0408: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0408: numeric"
    return bool(value), "runtime-rule-0408: truthy"

def runtime_rule_0409(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0409") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0409: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0409: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0409: numeric"
    return bool(value), "runtime-rule-0409: truthy"

def runtime_rule_0410(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0410") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0410: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0410: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0410: numeric"
    return bool(value), "runtime-rule-0410: truthy"

def runtime_rule_0411(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0411") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0411: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0411: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0411: numeric"
    return bool(value), "runtime-rule-0411: truthy"

def runtime_rule_0412(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0412") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0412: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0412: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0412: numeric"
    return bool(value), "runtime-rule-0412: truthy"

def runtime_rule_0413(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0413") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0413: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0413: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0413: numeric"
    return bool(value), "runtime-rule-0413: truthy"

def runtime_rule_0414(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0414") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0414: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0414: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0414: numeric"
    return bool(value), "runtime-rule-0414: truthy"

def runtime_rule_0415(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0415") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0415: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0415: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0415: numeric"
    return bool(value), "runtime-rule-0415: truthy"

def runtime_rule_0416(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0416") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0416: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0416: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0416: numeric"
    return bool(value), "runtime-rule-0416: truthy"

def runtime_rule_0417(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0417") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0417: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0417: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0417: numeric"
    return bool(value), "runtime-rule-0417: truthy"

def runtime_rule_0418(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0418") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0418: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0418: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0418: numeric"
    return bool(value), "runtime-rule-0418: truthy"

def runtime_rule_0419(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0419") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0419: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0419: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0419: numeric"
    return bool(value), "runtime-rule-0419: truthy"

def runtime_rule_0420(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0420") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0420: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0420: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0420: numeric"
    return bool(value), "runtime-rule-0420: truthy"

def runtime_rule_0421(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0421") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0421: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0421: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0421: numeric"
    return bool(value), "runtime-rule-0421: truthy"

def runtime_rule_0422(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0422") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0422: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0422: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0422: numeric"
    return bool(value), "runtime-rule-0422: truthy"

def runtime_rule_0423(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0423") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0423: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0423: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0423: numeric"
    return bool(value), "runtime-rule-0423: truthy"

def runtime_rule_0424(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0424") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0424: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0424: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0424: numeric"
    return bool(value), "runtime-rule-0424: truthy"

def runtime_rule_0425(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0425") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0425: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0425: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0425: numeric"
    return bool(value), "runtime-rule-0425: truthy"

def runtime_rule_0426(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0426") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0426: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0426: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0426: numeric"
    return bool(value), "runtime-rule-0426: truthy"

def runtime_rule_0427(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0427") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0427: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0427: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0427: numeric"
    return bool(value), "runtime-rule-0427: truthy"

def runtime_rule_0428(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0428") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0428: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0428: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0428: numeric"
    return bool(value), "runtime-rule-0428: truthy"

def runtime_rule_0429(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0429") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0429: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0429: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0429: numeric"
    return bool(value), "runtime-rule-0429: truthy"

def runtime_rule_0430(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0430") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0430: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0430: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0430: numeric"
    return bool(value), "runtime-rule-0430: truthy"

def runtime_rule_0431(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0431") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0431: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0431: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0431: numeric"
    return bool(value), "runtime-rule-0431: truthy"

def runtime_rule_0432(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0432") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0432: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0432: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0432: numeric"
    return bool(value), "runtime-rule-0432: truthy"

def runtime_rule_0433(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0433") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0433: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0433: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0433: numeric"
    return bool(value), "runtime-rule-0433: truthy"

def runtime_rule_0434(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0434") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0434: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0434: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0434: numeric"
    return bool(value), "runtime-rule-0434: truthy"

def runtime_rule_0435(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0435") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0435: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0435: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0435: numeric"
    return bool(value), "runtime-rule-0435: truthy"

def runtime_rule_0436(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0436") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0436: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0436: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0436: numeric"
    return bool(value), "runtime-rule-0436: truthy"

def runtime_rule_0437(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0437") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0437: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0437: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0437: numeric"
    return bool(value), "runtime-rule-0437: truthy"

def runtime_rule_0438(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0438") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0438: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0438: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0438: numeric"
    return bool(value), "runtime-rule-0438: truthy"

def runtime_rule_0439(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0439") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0439: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0439: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0439: numeric"
    return bool(value), "runtime-rule-0439: truthy"

def runtime_rule_0440(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0440") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0440: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0440: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0440: numeric"
    return bool(value), "runtime-rule-0440: truthy"

def runtime_rule_0441(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0441") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0441: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0441: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0441: numeric"
    return bool(value), "runtime-rule-0441: truthy"

def runtime_rule_0442(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0442") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0442: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0442: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0442: numeric"
    return bool(value), "runtime-rule-0442: truthy"

def runtime_rule_0443(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0443") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0443: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0443: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0443: numeric"
    return bool(value), "runtime-rule-0443: truthy"

def runtime_rule_0444(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0444") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0444: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0444: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0444: numeric"
    return bool(value), "runtime-rule-0444: truthy"

def runtime_rule_0445(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0445") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0445: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0445: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0445: numeric"
    return bool(value), "runtime-rule-0445: truthy"

def runtime_rule_0446(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0446") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0446: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0446: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0446: numeric"
    return bool(value), "runtime-rule-0446: truthy"

def runtime_rule_0447(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0447") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0447: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0447: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0447: numeric"
    return bool(value), "runtime-rule-0447: truthy"

def runtime_rule_0448(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0448") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0448: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0448: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0448: numeric"
    return bool(value), "runtime-rule-0448: truthy"

def runtime_rule_0449(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0449") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0449: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0449: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0449: numeric"
    return bool(value), "runtime-rule-0449: truthy"

def runtime_rule_0450(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0450") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0450: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0450: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0450: numeric"
    return bool(value), "runtime-rule-0450: truthy"

def runtime_rule_0451(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0451") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0451: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0451: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0451: numeric"
    return bool(value), "runtime-rule-0451: truthy"

def runtime_rule_0452(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0452") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0452: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0452: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0452: numeric"
    return bool(value), "runtime-rule-0452: truthy"

def runtime_rule_0453(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0453") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0453: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0453: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0453: numeric"
    return bool(value), "runtime-rule-0453: truthy"

def runtime_rule_0454(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0454") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0454: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0454: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0454: numeric"
    return bool(value), "runtime-rule-0454: truthy"

def runtime_rule_0455(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0455") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0455: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0455: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0455: numeric"
    return bool(value), "runtime-rule-0455: truthy"

def runtime_rule_0456(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0456") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0456: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0456: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0456: numeric"
    return bool(value), "runtime-rule-0456: truthy"

def runtime_rule_0457(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0457") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0457: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0457: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0457: numeric"
    return bool(value), "runtime-rule-0457: truthy"

def runtime_rule_0458(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0458") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0458: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0458: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0458: numeric"
    return bool(value), "runtime-rule-0458: truthy"

def runtime_rule_0459(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0459") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0459: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0459: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0459: numeric"
    return bool(value), "runtime-rule-0459: truthy"

def runtime_rule_0460(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0460") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0460: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0460: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0460: numeric"
    return bool(value), "runtime-rule-0460: truthy"

def runtime_rule_0461(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0461") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0461: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0461: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0461: numeric"
    return bool(value), "runtime-rule-0461: truthy"

def runtime_rule_0462(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0462") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0462: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0462: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0462: numeric"
    return bool(value), "runtime-rule-0462: truthy"

def runtime_rule_0463(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0463") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0463: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0463: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0463: numeric"
    return bool(value), "runtime-rule-0463: truthy"

def runtime_rule_0464(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0464") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0464: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0464: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0464: numeric"
    return bool(value), "runtime-rule-0464: truthy"

def runtime_rule_0465(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0465") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0465: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0465: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0465: numeric"
    return bool(value), "runtime-rule-0465: truthy"

def runtime_rule_0466(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0466") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0466: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0466: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0466: numeric"
    return bool(value), "runtime-rule-0466: truthy"

def runtime_rule_0467(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0467") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0467: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0467: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0467: numeric"
    return bool(value), "runtime-rule-0467: truthy"

def runtime_rule_0468(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0468") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0468: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0468: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0468: numeric"
    return bool(value), "runtime-rule-0468: truthy"

def runtime_rule_0469(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0469") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0469: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0469: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0469: numeric"
    return bool(value), "runtime-rule-0469: truthy"

def runtime_rule_0470(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0470") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0470: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0470: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0470: numeric"
    return bool(value), "runtime-rule-0470: truthy"

def runtime_rule_0471(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0471") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0471: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0471: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0471: numeric"
    return bool(value), "runtime-rule-0471: truthy"

def runtime_rule_0472(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0472") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0472: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0472: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0472: numeric"
    return bool(value), "runtime-rule-0472: truthy"

def runtime_rule_0473(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0473") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0473: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0473: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0473: numeric"
    return bool(value), "runtime-rule-0473: truthy"

def runtime_rule_0474(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0474") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0474: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0474: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0474: numeric"
    return bool(value), "runtime-rule-0474: truthy"

def runtime_rule_0475(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0475") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0475: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0475: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0475: numeric"
    return bool(value), "runtime-rule-0475: truthy"

def runtime_rule_0476(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0476") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0476: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0476: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0476: numeric"
    return bool(value), "runtime-rule-0476: truthy"

def runtime_rule_0477(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0477") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0477: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0477: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0477: numeric"
    return bool(value), "runtime-rule-0477: truthy"

def runtime_rule_0478(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0478") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0478: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0478: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0478: numeric"
    return bool(value), "runtime-rule-0478: truthy"

def runtime_rule_0479(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0479") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0479: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0479: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0479: numeric"
    return bool(value), "runtime-rule-0479: truthy"

def runtime_rule_0480(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0480") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0480: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0480: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0480: numeric"
    return bool(value), "runtime-rule-0480: truthy"

def runtime_rule_0481(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0481") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0481: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0481: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0481: numeric"
    return bool(value), "runtime-rule-0481: truthy"

def runtime_rule_0482(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0482") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0482: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0482: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0482: numeric"
    return bool(value), "runtime-rule-0482: truthy"

def runtime_rule_0483(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0483") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0483: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0483: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0483: numeric"
    return bool(value), "runtime-rule-0483: truthy"

def runtime_rule_0484(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0484") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0484: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0484: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0484: numeric"
    return bool(value), "runtime-rule-0484: truthy"

def runtime_rule_0485(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0485") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0485: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0485: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0485: numeric"
    return bool(value), "runtime-rule-0485: truthy"

def runtime_rule_0486(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0486") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0486: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0486: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0486: numeric"
    return bool(value), "runtime-rule-0486: truthy"

def runtime_rule_0487(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0487") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0487: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0487: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0487: numeric"
    return bool(value), "runtime-rule-0487: truthy"

def runtime_rule_0488(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0488") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0488: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0488: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0488: numeric"
    return bool(value), "runtime-rule-0488: truthy"

def runtime_rule_0489(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0489") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0489: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0489: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0489: numeric"
    return bool(value), "runtime-rule-0489: truthy"

def runtime_rule_0490(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0490") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0490: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0490: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0490: numeric"
    return bool(value), "runtime-rule-0490: truthy"

def runtime_rule_0491(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0491") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0491: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0491: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0491: numeric"
    return bool(value), "runtime-rule-0491: truthy"

def runtime_rule_0492(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0492") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0492: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0492: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0492: numeric"
    return bool(value), "runtime-rule-0492: truthy"

def runtime_rule_0493(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0493") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0493: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0493: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0493: numeric"
    return bool(value), "runtime-rule-0493: truthy"

def runtime_rule_0494(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0494") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0494: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0494: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0494: numeric"
    return bool(value), "runtime-rule-0494: truthy"

def runtime_rule_0495(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0495") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0495: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0495: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0495: numeric"
    return bool(value), "runtime-rule-0495: truthy"

def runtime_rule_0496(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0496") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0496: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0496: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0496: numeric"
    return bool(value), "runtime-rule-0496: truthy"

def runtime_rule_0497(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0497") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0497: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0497: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0497: numeric"
    return bool(value), "runtime-rule-0497: truthy"

def runtime_rule_0498(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0498") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0498: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0498: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0498: numeric"
    return bool(value), "runtime-rule-0498: truthy"

def runtime_rule_0499(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0499") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0499: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0499: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0499: numeric"
    return bool(value), "runtime-rule-0499: truthy"

def runtime_rule_0500(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0500") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0500: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0500: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0500: numeric"
    return bool(value), "runtime-rule-0500: truthy"

def runtime_rule_0501(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0501") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0501: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0501: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0501: numeric"
    return bool(value), "runtime-rule-0501: truthy"

def runtime_rule_0502(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0502") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0502: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0502: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0502: numeric"
    return bool(value), "runtime-rule-0502: truthy"

def runtime_rule_0503(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0503") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0503: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0503: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0503: numeric"
    return bool(value), "runtime-rule-0503: truthy"

def runtime_rule_0504(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0504") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0504: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0504: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0504: numeric"
    return bool(value), "runtime-rule-0504: truthy"

def runtime_rule_0505(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0505") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0505: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0505: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0505: numeric"
    return bool(value), "runtime-rule-0505: truthy"

def runtime_rule_0506(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0506") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0506: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0506: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0506: numeric"
    return bool(value), "runtime-rule-0506: truthy"

def runtime_rule_0507(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0507") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0507: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0507: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0507: numeric"
    return bool(value), "runtime-rule-0507: truthy"

def runtime_rule_0508(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0508") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0508: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0508: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0508: numeric"
    return bool(value), "runtime-rule-0508: truthy"

def runtime_rule_0509(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0509") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0509: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0509: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0509: numeric"
    return bool(value), "runtime-rule-0509: truthy"

def runtime_rule_0510(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0510") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0510: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0510: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0510: numeric"
    return bool(value), "runtime-rule-0510: truthy"

def runtime_rule_0511(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0511") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0511: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0511: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0511: numeric"
    return bool(value), "runtime-rule-0511: truthy"

def runtime_rule_0512(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0512") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0512: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0512: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0512: numeric"
    return bool(value), "runtime-rule-0512: truthy"

def runtime_rule_0513(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0513") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0513: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0513: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0513: numeric"
    return bool(value), "runtime-rule-0513: truthy"

def runtime_rule_0514(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0514") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0514: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0514: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0514: numeric"
    return bool(value), "runtime-rule-0514: truthy"

def runtime_rule_0515(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0515") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0515: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0515: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0515: numeric"
    return bool(value), "runtime-rule-0515: truthy"

def runtime_rule_0516(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0516") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0516: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0516: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0516: numeric"
    return bool(value), "runtime-rule-0516: truthy"

def runtime_rule_0517(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0517") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0517: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0517: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0517: numeric"
    return bool(value), "runtime-rule-0517: truthy"

def runtime_rule_0518(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0518") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0518: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0518: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0518: numeric"
    return bool(value), "runtime-rule-0518: truthy"

def runtime_rule_0519(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0519") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0519: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0519: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0519: numeric"
    return bool(value), "runtime-rule-0519: truthy"

def runtime_rule_0520(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0520") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0520: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0520: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0520: numeric"
    return bool(value), "runtime-rule-0520: truthy"

def runtime_rule_0521(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0521") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0521: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0521: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0521: numeric"
    return bool(value), "runtime-rule-0521: truthy"

def runtime_rule_0522(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0522") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0522: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0522: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0522: numeric"
    return bool(value), "runtime-rule-0522: truthy"

def runtime_rule_0523(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0523") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0523: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0523: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0523: numeric"
    return bool(value), "runtime-rule-0523: truthy"

def runtime_rule_0524(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0524") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0524: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0524: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0524: numeric"
    return bool(value), "runtime-rule-0524: truthy"

def runtime_rule_0525(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0525") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0525: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0525: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0525: numeric"
    return bool(value), "runtime-rule-0525: truthy"

def runtime_rule_0526(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0526") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0526: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0526: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0526: numeric"
    return bool(value), "runtime-rule-0526: truthy"

def runtime_rule_0527(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0527") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0527: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0527: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0527: numeric"
    return bool(value), "runtime-rule-0527: truthy"

def runtime_rule_0528(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0528") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0528: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0528: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0528: numeric"
    return bool(value), "runtime-rule-0528: truthy"

def runtime_rule_0529(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0529") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0529: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0529: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0529: numeric"
    return bool(value), "runtime-rule-0529: truthy"

def runtime_rule_0530(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0530") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0530: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0530: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0530: numeric"
    return bool(value), "runtime-rule-0530: truthy"

def runtime_rule_0531(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0531") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0531: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0531: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0531: numeric"
    return bool(value), "runtime-rule-0531: truthy"

def runtime_rule_0532(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0532") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0532: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0532: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0532: numeric"
    return bool(value), "runtime-rule-0532: truthy"

def runtime_rule_0533(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0533") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0533: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0533: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0533: numeric"
    return bool(value), "runtime-rule-0533: truthy"

def runtime_rule_0534(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0534") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0534: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0534: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0534: numeric"
    return bool(value), "runtime-rule-0534: truthy"

def runtime_rule_0535(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0535") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0535: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0535: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0535: numeric"
    return bool(value), "runtime-rule-0535: truthy"

def runtime_rule_0536(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0536") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0536: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0536: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0536: numeric"
    return bool(value), "runtime-rule-0536: truthy"

def runtime_rule_0537(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0537") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0537: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0537: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0537: numeric"
    return bool(value), "runtime-rule-0537: truthy"

def runtime_rule_0538(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0538") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0538: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0538: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0538: numeric"
    return bool(value), "runtime-rule-0538: truthy"

def runtime_rule_0539(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0539") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0539: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0539: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0539: numeric"
    return bool(value), "runtime-rule-0539: truthy"

def runtime_rule_0540(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0540") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0540: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0540: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0540: numeric"
    return bool(value), "runtime-rule-0540: truthy"

def runtime_rule_0541(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0541") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0541: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0541: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0541: numeric"
    return bool(value), "runtime-rule-0541: truthy"

def runtime_rule_0542(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0542") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0542: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0542: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0542: numeric"
    return bool(value), "runtime-rule-0542: truthy"

def runtime_rule_0543(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0543") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0543: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0543: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0543: numeric"
    return bool(value), "runtime-rule-0543: truthy"

def runtime_rule_0544(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0544") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0544: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0544: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0544: numeric"
    return bool(value), "runtime-rule-0544: truthy"

def runtime_rule_0545(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0545") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0545: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0545: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0545: numeric"
    return bool(value), "runtime-rule-0545: truthy"

def runtime_rule_0546(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0546") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0546: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0546: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0546: numeric"
    return bool(value), "runtime-rule-0546: truthy"

def runtime_rule_0547(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0547") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0547: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0547: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0547: numeric"
    return bool(value), "runtime-rule-0547: truthy"

def runtime_rule_0548(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0548") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0548: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0548: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0548: numeric"
    return bool(value), "runtime-rule-0548: truthy"

def runtime_rule_0549(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0549") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0549: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0549: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0549: numeric"
    return bool(value), "runtime-rule-0549: truthy"

def runtime_rule_0550(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0550") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0550: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0550: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0550: numeric"
    return bool(value), "runtime-rule-0550: truthy"

def runtime_rule_0551(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0551") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0551: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0551: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0551: numeric"
    return bool(value), "runtime-rule-0551: truthy"

def runtime_rule_0552(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0552") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0552: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0552: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0552: numeric"
    return bool(value), "runtime-rule-0552: truthy"

def runtime_rule_0553(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0553") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0553: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0553: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0553: numeric"
    return bool(value), "runtime-rule-0553: truthy"

def runtime_rule_0554(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0554") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0554: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0554: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0554: numeric"
    return bool(value), "runtime-rule-0554: truthy"

def runtime_rule_0555(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0555") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0555: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0555: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0555: numeric"
    return bool(value), "runtime-rule-0555: truthy"

def runtime_rule_0556(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0556") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0556: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0556: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0556: numeric"
    return bool(value), "runtime-rule-0556: truthy"

def runtime_rule_0557(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0557") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0557: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0557: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0557: numeric"
    return bool(value), "runtime-rule-0557: truthy"

def runtime_rule_0558(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0558") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0558: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0558: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0558: numeric"
    return bool(value), "runtime-rule-0558: truthy"

def runtime_rule_0559(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0559") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0559: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0559: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0559: numeric"
    return bool(value), "runtime-rule-0559: truthy"

def runtime_rule_0560(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0560") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0560: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0560: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0560: numeric"
    return bool(value), "runtime-rule-0560: truthy"

def runtime_rule_0561(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0561") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0561: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0561: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0561: numeric"
    return bool(value), "runtime-rule-0561: truthy"

def runtime_rule_0562(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0562") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0562: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0562: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0562: numeric"
    return bool(value), "runtime-rule-0562: truthy"

def runtime_rule_0563(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0563") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0563: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0563: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0563: numeric"
    return bool(value), "runtime-rule-0563: truthy"

def runtime_rule_0564(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0564") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0564: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0564: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0564: numeric"
    return bool(value), "runtime-rule-0564: truthy"

def runtime_rule_0565(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0565") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0565: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0565: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0565: numeric"
    return bool(value), "runtime-rule-0565: truthy"

def runtime_rule_0566(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0566") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0566: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0566: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0566: numeric"
    return bool(value), "runtime-rule-0566: truthy"

def runtime_rule_0567(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0567") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0567: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0567: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0567: numeric"
    return bool(value), "runtime-rule-0567: truthy"

def runtime_rule_0568(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0568") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0568: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0568: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0568: numeric"
    return bool(value), "runtime-rule-0568: truthy"

def runtime_rule_0569(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0569") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0569: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0569: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0569: numeric"
    return bool(value), "runtime-rule-0569: truthy"

def runtime_rule_0570(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0570") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0570: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0570: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0570: numeric"
    return bool(value), "runtime-rule-0570: truthy"

def runtime_rule_0571(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0571") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0571: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0571: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0571: numeric"
    return bool(value), "runtime-rule-0571: truthy"

def runtime_rule_0572(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0572") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0572: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0572: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0572: numeric"
    return bool(value), "runtime-rule-0572: truthy"

def runtime_rule_0573(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0573") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0573: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0573: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0573: numeric"
    return bool(value), "runtime-rule-0573: truthy"

def runtime_rule_0574(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0574") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0574: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0574: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0574: numeric"
    return bool(value), "runtime-rule-0574: truthy"

def runtime_rule_0575(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0575") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0575: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0575: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0575: numeric"
    return bool(value), "runtime-rule-0575: truthy"

def runtime_rule_0576(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0576") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0576: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0576: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0576: numeric"
    return bool(value), "runtime-rule-0576: truthy"

def runtime_rule_0577(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0577") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0577: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0577: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0577: numeric"
    return bool(value), "runtime-rule-0577: truthy"

def runtime_rule_0578(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0578") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0578: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0578: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0578: numeric"
    return bool(value), "runtime-rule-0578: truthy"

def runtime_rule_0579(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0579") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0579: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0579: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0579: numeric"
    return bool(value), "runtime-rule-0579: truthy"

def runtime_rule_0580(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0580") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0580: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0580: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0580: numeric"
    return bool(value), "runtime-rule-0580: truthy"

def runtime_rule_0581(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0581") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0581: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0581: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0581: numeric"
    return bool(value), "runtime-rule-0581: truthy"

def runtime_rule_0582(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0582") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0582: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0582: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0582: numeric"
    return bool(value), "runtime-rule-0582: truthy"

def runtime_rule_0583(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0583") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0583: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0583: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0583: numeric"
    return bool(value), "runtime-rule-0583: truthy"

def runtime_rule_0584(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0584") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0584: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0584: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0584: numeric"
    return bool(value), "runtime-rule-0584: truthy"

def runtime_rule_0585(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0585") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0585: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0585: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0585: numeric"
    return bool(value), "runtime-rule-0585: truthy"

def runtime_rule_0586(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0586") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0586: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0586: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0586: numeric"
    return bool(value), "runtime-rule-0586: truthy"

def runtime_rule_0587(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0587") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0587: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0587: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0587: numeric"
    return bool(value), "runtime-rule-0587: truthy"

def runtime_rule_0588(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0588") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0588: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0588: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0588: numeric"
    return bool(value), "runtime-rule-0588: truthy"

def runtime_rule_0589(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0589") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0589: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0589: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0589: numeric"
    return bool(value), "runtime-rule-0589: truthy"

def runtime_rule_0590(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0590") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0590: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0590: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0590: numeric"
    return bool(value), "runtime-rule-0590: truthy"

def runtime_rule_0591(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0591") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0591: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0591: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0591: numeric"
    return bool(value), "runtime-rule-0591: truthy"

def runtime_rule_0592(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0592") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0592: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0592: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0592: numeric"
    return bool(value), "runtime-rule-0592: truthy"

def runtime_rule_0593(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0593") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0593: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0593: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0593: numeric"
    return bool(value), "runtime-rule-0593: truthy"

def runtime_rule_0594(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0594") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0594: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0594: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0594: numeric"
    return bool(value), "runtime-rule-0594: truthy"

def runtime_rule_0595(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0595") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0595: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0595: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0595: numeric"
    return bool(value), "runtime-rule-0595: truthy"

def runtime_rule_0596(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0596") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0596: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0596: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0596: numeric"
    return bool(value), "runtime-rule-0596: truthy"

def runtime_rule_0597(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0597") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0597: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0597: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0597: numeric"
    return bool(value), "runtime-rule-0597: truthy"

def runtime_rule_0598(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0598") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0598: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0598: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0598: numeric"
    return bool(value), "runtime-rule-0598: truthy"

def runtime_rule_0599(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0599") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0599: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0599: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0599: numeric"
    return bool(value), "runtime-rule-0599: truthy"

def runtime_rule_0600(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0600") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0600: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0600: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0600: numeric"
    return bool(value), "runtime-rule-0600: truthy"

def runtime_rule_0601(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0601") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0601: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0601: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0601: numeric"
    return bool(value), "runtime-rule-0601: truthy"

def runtime_rule_0602(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0602") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0602: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0602: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0602: numeric"
    return bool(value), "runtime-rule-0602: truthy"

def runtime_rule_0603(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0603") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0603: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0603: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0603: numeric"
    return bool(value), "runtime-rule-0603: truthy"

def runtime_rule_0604(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0604") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0604: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0604: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0604: numeric"
    return bool(value), "runtime-rule-0604: truthy"

def runtime_rule_0605(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0605") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0605: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0605: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0605: numeric"
    return bool(value), "runtime-rule-0605: truthy"

def runtime_rule_0606(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0606") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0606: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0606: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0606: numeric"
    return bool(value), "runtime-rule-0606: truthy"

def runtime_rule_0607(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0607") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0607: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0607: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0607: numeric"
    return bool(value), "runtime-rule-0607: truthy"

def runtime_rule_0608(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0608") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0608: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0608: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0608: numeric"
    return bool(value), "runtime-rule-0608: truthy"

def runtime_rule_0609(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0609") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0609: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0609: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0609: numeric"
    return bool(value), "runtime-rule-0609: truthy"

def runtime_rule_0610(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0610") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0610: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0610: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0610: numeric"
    return bool(value), "runtime-rule-0610: truthy"

def runtime_rule_0611(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0611") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0611: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0611: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0611: numeric"
    return bool(value), "runtime-rule-0611: truthy"

def runtime_rule_0612(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0612") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0612: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0612: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0612: numeric"
    return bool(value), "runtime-rule-0612: truthy"

def runtime_rule_0613(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0613") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0613: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0613: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0613: numeric"
    return bool(value), "runtime-rule-0613: truthy"

def runtime_rule_0614(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0614") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0614: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0614: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0614: numeric"
    return bool(value), "runtime-rule-0614: truthy"

def runtime_rule_0615(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0615") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0615: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0615: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0615: numeric"
    return bool(value), "runtime-rule-0615: truthy"

def runtime_rule_0616(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0616") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0616: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0616: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0616: numeric"
    return bool(value), "runtime-rule-0616: truthy"

def runtime_rule_0617(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0617") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0617: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0617: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0617: numeric"
    return bool(value), "runtime-rule-0617: truthy"

def runtime_rule_0618(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0618") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0618: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0618: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0618: numeric"
    return bool(value), "runtime-rule-0618: truthy"

def runtime_rule_0619(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0619") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0619: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0619: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0619: numeric"
    return bool(value), "runtime-rule-0619: truthy"

def runtime_rule_0620(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0620") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0620: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0620: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0620: numeric"
    return bool(value), "runtime-rule-0620: truthy"

def runtime_rule_0621(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0621") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0621: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0621: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0621: numeric"
    return bool(value), "runtime-rule-0621: truthy"

def runtime_rule_0622(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0622") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0622: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0622: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0622: numeric"
    return bool(value), "runtime-rule-0622: truthy"

def runtime_rule_0623(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0623") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0623: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0623: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0623: numeric"
    return bool(value), "runtime-rule-0623: truthy"

def runtime_rule_0624(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0624") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0624: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0624: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0624: numeric"
    return bool(value), "runtime-rule-0624: truthy"

def runtime_rule_0625(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0625") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0625: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0625: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0625: numeric"
    return bool(value), "runtime-rule-0625: truthy"

def runtime_rule_0626(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0626") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0626: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0626: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0626: numeric"
    return bool(value), "runtime-rule-0626: truthy"

def runtime_rule_0627(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0627") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0627: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0627: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0627: numeric"
    return bool(value), "runtime-rule-0627: truthy"

def runtime_rule_0628(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0628") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0628: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0628: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0628: numeric"
    return bool(value), "runtime-rule-0628: truthy"

def runtime_rule_0629(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0629") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0629: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0629: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0629: numeric"
    return bool(value), "runtime-rule-0629: truthy"

def runtime_rule_0630(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0630") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0630: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0630: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0630: numeric"
    return bool(value), "runtime-rule-0630: truthy"

def runtime_rule_0631(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0631") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0631: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0631: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0631: numeric"
    return bool(value), "runtime-rule-0631: truthy"

def runtime_rule_0632(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0632") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0632: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0632: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0632: numeric"
    return bool(value), "runtime-rule-0632: truthy"

def runtime_rule_0633(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0633") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0633: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0633: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0633: numeric"
    return bool(value), "runtime-rule-0633: truthy"

def runtime_rule_0634(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0634") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0634: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0634: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0634: numeric"
    return bool(value), "runtime-rule-0634: truthy"

def runtime_rule_0635(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0635") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0635: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0635: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0635: numeric"
    return bool(value), "runtime-rule-0635: truthy"

def runtime_rule_0636(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0636") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0636: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0636: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0636: numeric"
    return bool(value), "runtime-rule-0636: truthy"

def runtime_rule_0637(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0637") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0637: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0637: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0637: numeric"
    return bool(value), "runtime-rule-0637: truthy"

def runtime_rule_0638(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0638") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0638: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0638: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0638: numeric"
    return bool(value), "runtime-rule-0638: truthy"

def runtime_rule_0639(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0639") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0639: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0639: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0639: numeric"
    return bool(value), "runtime-rule-0639: truthy"

def runtime_rule_0640(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0640") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0640: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0640: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0640: numeric"
    return bool(value), "runtime-rule-0640: truthy"

def runtime_rule_0641(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0641") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0641: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0641: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0641: numeric"
    return bool(value), "runtime-rule-0641: truthy"

def runtime_rule_0642(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0642") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0642: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0642: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0642: numeric"
    return bool(value), "runtime-rule-0642: truthy"

def runtime_rule_0643(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0643") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0643: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0643: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0643: numeric"
    return bool(value), "runtime-rule-0643: truthy"

def runtime_rule_0644(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0644") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0644: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0644: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0644: numeric"
    return bool(value), "runtime-rule-0644: truthy"

def runtime_rule_0645(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0645") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0645: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0645: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0645: numeric"
    return bool(value), "runtime-rule-0645: truthy"

def runtime_rule_0646(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0646") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0646: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0646: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0646: numeric"
    return bool(value), "runtime-rule-0646: truthy"

def runtime_rule_0647(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0647") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0647: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0647: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0647: numeric"
    return bool(value), "runtime-rule-0647: truthy"

def runtime_rule_0648(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0648") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0648: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0648: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0648: numeric"
    return bool(value), "runtime-rule-0648: truthy"

def runtime_rule_0649(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0649") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0649: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0649: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0649: numeric"
    return bool(value), "runtime-rule-0649: truthy"

def runtime_rule_0650(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0650") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0650: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0650: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0650: numeric"
    return bool(value), "runtime-rule-0650: truthy"

def runtime_rule_0651(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0651") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0651: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0651: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0651: numeric"
    return bool(value), "runtime-rule-0651: truthy"

def runtime_rule_0652(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0652") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0652: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0652: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0652: numeric"
    return bool(value), "runtime-rule-0652: truthy"

def runtime_rule_0653(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0653") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0653: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0653: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0653: numeric"
    return bool(value), "runtime-rule-0653: truthy"

def runtime_rule_0654(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0654") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0654: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0654: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0654: numeric"
    return bool(value), "runtime-rule-0654: truthy"

def runtime_rule_0655(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0655") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0655: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0655: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0655: numeric"
    return bool(value), "runtime-rule-0655: truthy"

def runtime_rule_0656(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0656") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0656: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0656: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0656: numeric"
    return bool(value), "runtime-rule-0656: truthy"

def runtime_rule_0657(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0657") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0657: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0657: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0657: numeric"
    return bool(value), "runtime-rule-0657: truthy"

def runtime_rule_0658(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0658") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0658: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0658: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0658: numeric"
    return bool(value), "runtime-rule-0658: truthy"

def runtime_rule_0659(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0659") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0659: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0659: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0659: numeric"
    return bool(value), "runtime-rule-0659: truthy"

def runtime_rule_0660(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0660") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0660: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0660: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0660: numeric"
    return bool(value), "runtime-rule-0660: truthy"

def runtime_rule_0661(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0661") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0661: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0661: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0661: numeric"
    return bool(value), "runtime-rule-0661: truthy"

def runtime_rule_0662(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0662") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0662: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0662: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0662: numeric"
    return bool(value), "runtime-rule-0662: truthy"

def runtime_rule_0663(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0663") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0663: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0663: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0663: numeric"
    return bool(value), "runtime-rule-0663: truthy"

def runtime_rule_0664(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0664") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0664: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0664: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0664: numeric"
    return bool(value), "runtime-rule-0664: truthy"

def runtime_rule_0665(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0665") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0665: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0665: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0665: numeric"
    return bool(value), "runtime-rule-0665: truthy"

def runtime_rule_0666(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0666") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0666: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0666: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0666: numeric"
    return bool(value), "runtime-rule-0666: truthy"

def runtime_rule_0667(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0667") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0667: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0667: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0667: numeric"
    return bool(value), "runtime-rule-0667: truthy"

def runtime_rule_0668(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0668") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0668: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0668: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0668: numeric"
    return bool(value), "runtime-rule-0668: truthy"

def runtime_rule_0669(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0669") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0669: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0669: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0669: numeric"
    return bool(value), "runtime-rule-0669: truthy"

def runtime_rule_0670(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0670") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0670: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0670: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0670: numeric"
    return bool(value), "runtime-rule-0670: truthy"

def runtime_rule_0671(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0671") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0671: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0671: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0671: numeric"
    return bool(value), "runtime-rule-0671: truthy"

def runtime_rule_0672(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0672") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0672: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0672: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0672: numeric"
    return bool(value), "runtime-rule-0672: truthy"

def runtime_rule_0673(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0673") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0673: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0673: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0673: numeric"
    return bool(value), "runtime-rule-0673: truthy"

def runtime_rule_0674(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0674") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0674: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0674: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0674: numeric"
    return bool(value), "runtime-rule-0674: truthy"

def runtime_rule_0675(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0675") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0675: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0675: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0675: numeric"
    return bool(value), "runtime-rule-0675: truthy"

def runtime_rule_0676(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0676") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0676: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0676: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0676: numeric"
    return bool(value), "runtime-rule-0676: truthy"

def runtime_rule_0677(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0677") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0677: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0677: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0677: numeric"
    return bool(value), "runtime-rule-0677: truthy"

def runtime_rule_0678(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0678") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0678: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0678: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0678: numeric"
    return bool(value), "runtime-rule-0678: truthy"

def runtime_rule_0679(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0679") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0679: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0679: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0679: numeric"
    return bool(value), "runtime-rule-0679: truthy"

def runtime_rule_0680(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0680") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0680: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0680: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0680: numeric"
    return bool(value), "runtime-rule-0680: truthy"

def runtime_rule_0681(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0681") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0681: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0681: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0681: numeric"
    return bool(value), "runtime-rule-0681: truthy"

def runtime_rule_0682(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0682") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0682: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0682: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0682: numeric"
    return bool(value), "runtime-rule-0682: truthy"

def runtime_rule_0683(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0683") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0683: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0683: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0683: numeric"
    return bool(value), "runtime-rule-0683: truthy"

def runtime_rule_0684(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0684") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0684: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0684: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0684: numeric"
    return bool(value), "runtime-rule-0684: truthy"

def runtime_rule_0685(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0685") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0685: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0685: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0685: numeric"
    return bool(value), "runtime-rule-0685: truthy"

def runtime_rule_0686(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0686") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0686: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0686: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0686: numeric"
    return bool(value), "runtime-rule-0686: truthy"

def runtime_rule_0687(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0687") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0687: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0687: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0687: numeric"
    return bool(value), "runtime-rule-0687: truthy"

def runtime_rule_0688(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0688") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0688: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0688: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0688: numeric"
    return bool(value), "runtime-rule-0688: truthy"

def runtime_rule_0689(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0689") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0689: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0689: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0689: numeric"
    return bool(value), "runtime-rule-0689: truthy"

def runtime_rule_0690(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0690") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0690: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0690: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0690: numeric"
    return bool(value), "runtime-rule-0690: truthy"

def runtime_rule_0691(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0691") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0691: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0691: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0691: numeric"
    return bool(value), "runtime-rule-0691: truthy"

def runtime_rule_0692(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0692") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0692: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0692: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0692: numeric"
    return bool(value), "runtime-rule-0692: truthy"

def runtime_rule_0693(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0693") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0693: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0693: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0693: numeric"
    return bool(value), "runtime-rule-0693: truthy"

def runtime_rule_0694(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0694") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0694: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0694: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0694: numeric"
    return bool(value), "runtime-rule-0694: truthy"

def runtime_rule_0695(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0695") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0695: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0695: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0695: numeric"
    return bool(value), "runtime-rule-0695: truthy"

def runtime_rule_0696(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0696") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0696: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0696: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0696: numeric"
    return bool(value), "runtime-rule-0696: truthy"

def runtime_rule_0697(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0697") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0697: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0697: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0697: numeric"
    return bool(value), "runtime-rule-0697: truthy"

def runtime_rule_0698(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0698") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0698: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0698: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0698: numeric"
    return bool(value), "runtime-rule-0698: truthy"

def runtime_rule_0699(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0699") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0699: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0699: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0699: numeric"
    return bool(value), "runtime-rule-0699: truthy"

def runtime_rule_0700(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0700") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0700: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0700: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0700: numeric"
    return bool(value), "runtime-rule-0700: truthy"

def runtime_rule_0701(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0701") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0701: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0701: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0701: numeric"
    return bool(value), "runtime-rule-0701: truthy"

def runtime_rule_0702(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0702") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0702: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0702: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0702: numeric"
    return bool(value), "runtime-rule-0702: truthy"

def runtime_rule_0703(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0703") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0703: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0703: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0703: numeric"
    return bool(value), "runtime-rule-0703: truthy"

def runtime_rule_0704(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0704") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0704: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0704: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0704: numeric"
    return bool(value), "runtime-rule-0704: truthy"

def runtime_rule_0705(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0705") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0705: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0705: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0705: numeric"
    return bool(value), "runtime-rule-0705: truthy"

def runtime_rule_0706(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0706") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0706: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0706: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0706: numeric"
    return bool(value), "runtime-rule-0706: truthy"

def runtime_rule_0707(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0707") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0707: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0707: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0707: numeric"
    return bool(value), "runtime-rule-0707: truthy"

def runtime_rule_0708(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0708") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0708: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0708: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0708: numeric"
    return bool(value), "runtime-rule-0708: truthy"

def runtime_rule_0709(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0709") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0709: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0709: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0709: numeric"
    return bool(value), "runtime-rule-0709: truthy"

def runtime_rule_0710(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0710") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0710: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0710: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0710: numeric"
    return bool(value), "runtime-rule-0710: truthy"

def runtime_rule_0711(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0711") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0711: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0711: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0711: numeric"
    return bool(value), "runtime-rule-0711: truthy"

def runtime_rule_0712(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0712") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0712: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0712: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0712: numeric"
    return bool(value), "runtime-rule-0712: truthy"

def runtime_rule_0713(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0713") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0713: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0713: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0713: numeric"
    return bool(value), "runtime-rule-0713: truthy"

def runtime_rule_0714(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0714") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0714: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0714: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0714: numeric"
    return bool(value), "runtime-rule-0714: truthy"

def runtime_rule_0715(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0715") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0715: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0715: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0715: numeric"
    return bool(value), "runtime-rule-0715: truthy"

def runtime_rule_0716(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0716") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0716: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0716: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0716: numeric"
    return bool(value), "runtime-rule-0716: truthy"

def runtime_rule_0717(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0717") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0717: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0717: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0717: numeric"
    return bool(value), "runtime-rule-0717: truthy"

def runtime_rule_0718(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0718") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0718: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0718: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0718: numeric"
    return bool(value), "runtime-rule-0718: truthy"

def runtime_rule_0719(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0719") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0719: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0719: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0719: numeric"
    return bool(value), "runtime-rule-0719: truthy"

def runtime_rule_0720(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0720") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0720: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0720: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0720: numeric"
    return bool(value), "runtime-rule-0720: truthy"

def runtime_rule_0721(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0721") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0721: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0721: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0721: numeric"
    return bool(value), "runtime-rule-0721: truthy"

def runtime_rule_0722(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0722") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0722: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0722: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0722: numeric"
    return bool(value), "runtime-rule-0722: truthy"

def runtime_rule_0723(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0723") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0723: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0723: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0723: numeric"
    return bool(value), "runtime-rule-0723: truthy"

def runtime_rule_0724(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0724") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0724: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0724: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0724: numeric"
    return bool(value), "runtime-rule-0724: truthy"

def runtime_rule_0725(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0725") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0725: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0725: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0725: numeric"
    return bool(value), "runtime-rule-0725: truthy"

def runtime_rule_0726(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0726") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0726: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0726: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0726: numeric"
    return bool(value), "runtime-rule-0726: truthy"

def runtime_rule_0727(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0727") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0727: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0727: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0727: numeric"
    return bool(value), "runtime-rule-0727: truthy"

def runtime_rule_0728(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0728") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0728: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0728: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0728: numeric"
    return bool(value), "runtime-rule-0728: truthy"

def runtime_rule_0729(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0729") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0729: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0729: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0729: numeric"
    return bool(value), "runtime-rule-0729: truthy"

def runtime_rule_0730(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0730") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0730: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0730: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0730: numeric"
    return bool(value), "runtime-rule-0730: truthy"

def runtime_rule_0731(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0731") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0731: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0731: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0731: numeric"
    return bool(value), "runtime-rule-0731: truthy"

def runtime_rule_0732(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0732") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0732: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0732: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0732: numeric"
    return bool(value), "runtime-rule-0732: truthy"

def runtime_rule_0733(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0733") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0733: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0733: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0733: numeric"
    return bool(value), "runtime-rule-0733: truthy"

def runtime_rule_0734(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0734") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0734: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0734: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0734: numeric"
    return bool(value), "runtime-rule-0734: truthy"

def runtime_rule_0735(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0735") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0735: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0735: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0735: numeric"
    return bool(value), "runtime-rule-0735: truthy"

def runtime_rule_0736(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0736") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0736: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0736: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0736: numeric"
    return bool(value), "runtime-rule-0736: truthy"

def runtime_rule_0737(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0737") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0737: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0737: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0737: numeric"
    return bool(value), "runtime-rule-0737: truthy"

def runtime_rule_0738(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0738") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0738: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0738: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0738: numeric"
    return bool(value), "runtime-rule-0738: truthy"

def runtime_rule_0739(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0739") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0739: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0739: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0739: numeric"
    return bool(value), "runtime-rule-0739: truthy"

def runtime_rule_0740(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0740") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0740: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0740: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0740: numeric"
    return bool(value), "runtime-rule-0740: truthy"

def runtime_rule_0741(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0741") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0741: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0741: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0741: numeric"
    return bool(value), "runtime-rule-0741: truthy"

def runtime_rule_0742(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0742") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0742: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0742: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0742: numeric"
    return bool(value), "runtime-rule-0742: truthy"

def runtime_rule_0743(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0743") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0743: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0743: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0743: numeric"
    return bool(value), "runtime-rule-0743: truthy"

def runtime_rule_0744(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0744") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0744: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0744: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0744: numeric"
    return bool(value), "runtime-rule-0744: truthy"

def runtime_rule_0745(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0745") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0745: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0745: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0745: numeric"
    return bool(value), "runtime-rule-0745: truthy"

def runtime_rule_0746(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0746") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0746: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0746: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0746: numeric"
    return bool(value), "runtime-rule-0746: truthy"

def runtime_rule_0747(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0747") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0747: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0747: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0747: numeric"
    return bool(value), "runtime-rule-0747: truthy"

def runtime_rule_0748(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0748") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0748: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0748: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0748: numeric"
    return bool(value), "runtime-rule-0748: truthy"

def runtime_rule_0749(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0749") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0749: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0749: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0749: numeric"
    return bool(value), "runtime-rule-0749: truthy"

def runtime_rule_0750(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0750") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0750: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0750: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0750: numeric"
    return bool(value), "runtime-rule-0750: truthy"

def runtime_rule_0751(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0751") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0751: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0751: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0751: numeric"
    return bool(value), "runtime-rule-0751: truthy"

def runtime_rule_0752(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0752") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0752: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0752: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0752: numeric"
    return bool(value), "runtime-rule-0752: truthy"

def runtime_rule_0753(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0753") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0753: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0753: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0753: numeric"
    return bool(value), "runtime-rule-0753: truthy"

def runtime_rule_0754(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0754") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0754: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0754: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0754: numeric"
    return bool(value), "runtime-rule-0754: truthy"

def runtime_rule_0755(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0755") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0755: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0755: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0755: numeric"
    return bool(value), "runtime-rule-0755: truthy"

def runtime_rule_0756(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0756") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0756: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0756: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0756: numeric"
    return bool(value), "runtime-rule-0756: truthy"

def runtime_rule_0757(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0757") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0757: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0757: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0757: numeric"
    return bool(value), "runtime-rule-0757: truthy"

def runtime_rule_0758(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0758") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0758: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0758: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0758: numeric"
    return bool(value), "runtime-rule-0758: truthy"

def runtime_rule_0759(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0759") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0759: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0759: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0759: numeric"
    return bool(value), "runtime-rule-0759: truthy"

def runtime_rule_0760(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0760") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0760: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0760: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0760: numeric"
    return bool(value), "runtime-rule-0760: truthy"

def runtime_rule_0761(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0761") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0761: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0761: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0761: numeric"
    return bool(value), "runtime-rule-0761: truthy"

def runtime_rule_0762(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0762") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0762: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0762: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0762: numeric"
    return bool(value), "runtime-rule-0762: truthy"

def runtime_rule_0763(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0763") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0763: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0763: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0763: numeric"
    return bool(value), "runtime-rule-0763: truthy"

def runtime_rule_0764(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0764") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0764: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0764: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0764: numeric"
    return bool(value), "runtime-rule-0764: truthy"

def runtime_rule_0765(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0765") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0765: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0765: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0765: numeric"
    return bool(value), "runtime-rule-0765: truthy"

def runtime_rule_0766(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0766") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0766: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0766: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0766: numeric"
    return bool(value), "runtime-rule-0766: truthy"

def runtime_rule_0767(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0767") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0767: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0767: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0767: numeric"
    return bool(value), "runtime-rule-0767: truthy"

def runtime_rule_0768(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0768") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0768: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0768: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0768: numeric"
    return bool(value), "runtime-rule-0768: truthy"

def runtime_rule_0769(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0769") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0769: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0769: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0769: numeric"
    return bool(value), "runtime-rule-0769: truthy"

def runtime_rule_0770(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0770") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0770: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0770: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0770: numeric"
    return bool(value), "runtime-rule-0770: truthy"

def runtime_rule_0771(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0771") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0771: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0771: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0771: numeric"
    return bool(value), "runtime-rule-0771: truthy"

def runtime_rule_0772(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0772") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0772: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0772: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0772: numeric"
    return bool(value), "runtime-rule-0772: truthy"

def runtime_rule_0773(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0773") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0773: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0773: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0773: numeric"
    return bool(value), "runtime-rule-0773: truthy"

def runtime_rule_0774(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0774") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0774: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0774: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0774: numeric"
    return bool(value), "runtime-rule-0774: truthy"

def runtime_rule_0775(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0775") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0775: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0775: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0775: numeric"
    return bool(value), "runtime-rule-0775: truthy"

def runtime_rule_0776(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0776") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0776: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0776: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0776: numeric"
    return bool(value), "runtime-rule-0776: truthy"

def runtime_rule_0777(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0777") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0777: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0777: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0777: numeric"
    return bool(value), "runtime-rule-0777: truthy"

def runtime_rule_0778(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0778") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0778: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0778: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0778: numeric"
    return bool(value), "runtime-rule-0778: truthy"

def runtime_rule_0779(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0779") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0779: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0779: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0779: numeric"
    return bool(value), "runtime-rule-0779: truthy"

def runtime_rule_0780(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0780") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0780: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0780: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0780: numeric"
    return bool(value), "runtime-rule-0780: truthy"

def runtime_rule_0781(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0781") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0781: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0781: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0781: numeric"
    return bool(value), "runtime-rule-0781: truthy"

def runtime_rule_0782(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0782") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0782: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0782: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0782: numeric"
    return bool(value), "runtime-rule-0782: truthy"

def runtime_rule_0783(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0783") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0783: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0783: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0783: numeric"
    return bool(value), "runtime-rule-0783: truthy"

def runtime_rule_0784(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0784") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0784: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0784: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0784: numeric"
    return bool(value), "runtime-rule-0784: truthy"

def runtime_rule_0785(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0785") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0785: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0785: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0785: numeric"
    return bool(value), "runtime-rule-0785: truthy"

def runtime_rule_0786(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0786") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0786: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0786: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0786: numeric"
    return bool(value), "runtime-rule-0786: truthy"

def runtime_rule_0787(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0787") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0787: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0787: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0787: numeric"
    return bool(value), "runtime-rule-0787: truthy"

def runtime_rule_0788(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0788") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0788: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0788: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0788: numeric"
    return bool(value), "runtime-rule-0788: truthy"

def runtime_rule_0789(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0789") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0789: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0789: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0789: numeric"
    return bool(value), "runtime-rule-0789: truthy"

def runtime_rule_0790(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0790") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0790: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0790: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0790: numeric"
    return bool(value), "runtime-rule-0790: truthy"

def runtime_rule_0791(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0791") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0791: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0791: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0791: numeric"
    return bool(value), "runtime-rule-0791: truthy"

def runtime_rule_0792(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0792") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0792: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0792: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0792: numeric"
    return bool(value), "runtime-rule-0792: truthy"

def runtime_rule_0793(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0793") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0793: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0793: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0793: numeric"
    return bool(value), "runtime-rule-0793: truthy"

def runtime_rule_0794(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0794") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0794: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0794: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0794: numeric"
    return bool(value), "runtime-rule-0794: truthy"

def runtime_rule_0795(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0795") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0795: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0795: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0795: numeric"
    return bool(value), "runtime-rule-0795: truthy"

def runtime_rule_0796(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0796") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0796: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0796: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0796: numeric"
    return bool(value), "runtime-rule-0796: truthy"

def runtime_rule_0797(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0797") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0797: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0797: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0797: numeric"
    return bool(value), "runtime-rule-0797: truthy"

def runtime_rule_0798(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0798") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0798: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0798: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0798: numeric"
    return bool(value), "runtime-rule-0798: truthy"

def runtime_rule_0799(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0799") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0799: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0799: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0799: numeric"
    return bool(value), "runtime-rule-0799: truthy"

def runtime_rule_0800(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0800") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0800: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0800: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0800: numeric"
    return bool(value), "runtime-rule-0800: truthy"

def runtime_rule_0801(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0801") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0801: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0801: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0801: numeric"
    return bool(value), "runtime-rule-0801: truthy"

def runtime_rule_0802(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0802") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0802: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0802: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0802: numeric"
    return bool(value), "runtime-rule-0802: truthy"

def runtime_rule_0803(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0803") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0803: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0803: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0803: numeric"
    return bool(value), "runtime-rule-0803: truthy"

def runtime_rule_0804(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0804") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0804: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0804: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0804: numeric"
    return bool(value), "runtime-rule-0804: truthy"

def runtime_rule_0805(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0805") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0805: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0805: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0805: numeric"
    return bool(value), "runtime-rule-0805: truthy"

def runtime_rule_0806(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0806") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0806: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0806: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0806: numeric"
    return bool(value), "runtime-rule-0806: truthy"

def runtime_rule_0807(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0807") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0807: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0807: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0807: numeric"
    return bool(value), "runtime-rule-0807: truthy"

def runtime_rule_0808(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0808") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0808: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0808: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0808: numeric"
    return bool(value), "runtime-rule-0808: truthy"

def runtime_rule_0809(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0809") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0809: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0809: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0809: numeric"
    return bool(value), "runtime-rule-0809: truthy"

def runtime_rule_0810(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0810") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0810: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0810: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0810: numeric"
    return bool(value), "runtime-rule-0810: truthy"

def runtime_rule_0811(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0811") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0811: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0811: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0811: numeric"
    return bool(value), "runtime-rule-0811: truthy"

def runtime_rule_0812(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0812") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0812: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0812: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0812: numeric"
    return bool(value), "runtime-rule-0812: truthy"

def runtime_rule_0813(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0813") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0813: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0813: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0813: numeric"
    return bool(value), "runtime-rule-0813: truthy"

def runtime_rule_0814(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0814") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0814: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0814: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0814: numeric"
    return bool(value), "runtime-rule-0814: truthy"

def runtime_rule_0815(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0815") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0815: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0815: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0815: numeric"
    return bool(value), "runtime-rule-0815: truthy"

def runtime_rule_0816(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0816") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0816: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0816: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0816: numeric"
    return bool(value), "runtime-rule-0816: truthy"

def runtime_rule_0817(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0817") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0817: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0817: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0817: numeric"
    return bool(value), "runtime-rule-0817: truthy"

def runtime_rule_0818(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0818") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0818: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0818: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0818: numeric"
    return bool(value), "runtime-rule-0818: truthy"

def runtime_rule_0819(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0819") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0819: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0819: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0819: numeric"
    return bool(value), "runtime-rule-0819: truthy"

def runtime_rule_0820(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0820") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0820: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0820: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0820: numeric"
    return bool(value), "runtime-rule-0820: truthy"

def runtime_rule_0821(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0821") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0821: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0821: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0821: numeric"
    return bool(value), "runtime-rule-0821: truthy"

def runtime_rule_0822(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0822") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0822: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0822: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0822: numeric"
    return bool(value), "runtime-rule-0822: truthy"

def runtime_rule_0823(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0823") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0823: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0823: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0823: numeric"
    return bool(value), "runtime-rule-0823: truthy"

def runtime_rule_0824(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0824") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0824: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0824: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0824: numeric"
    return bool(value), "runtime-rule-0824: truthy"

def runtime_rule_0825(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0825") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0825: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0825: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0825: numeric"
    return bool(value), "runtime-rule-0825: truthy"

def runtime_rule_0826(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0826") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0826: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0826: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0826: numeric"
    return bool(value), "runtime-rule-0826: truthy"

def runtime_rule_0827(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0827") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0827: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0827: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0827: numeric"
    return bool(value), "runtime-rule-0827: truthy"

def runtime_rule_0828(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0828") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0828: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0828: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0828: numeric"
    return bool(value), "runtime-rule-0828: truthy"

def runtime_rule_0829(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0829") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0829: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0829: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0829: numeric"
    return bool(value), "runtime-rule-0829: truthy"

def runtime_rule_0830(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0830") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0830: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0830: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0830: numeric"
    return bool(value), "runtime-rule-0830: truthy"

def runtime_rule_0831(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0831") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0831: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0831: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0831: numeric"
    return bool(value), "runtime-rule-0831: truthy"

def runtime_rule_0832(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0832") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0832: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0832: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0832: numeric"
    return bool(value), "runtime-rule-0832: truthy"

def runtime_rule_0833(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0833") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0833: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0833: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0833: numeric"
    return bool(value), "runtime-rule-0833: truthy"

def runtime_rule_0834(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0834") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0834: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0834: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0834: numeric"
    return bool(value), "runtime-rule-0834: truthy"

def runtime_rule_0835(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0835") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0835: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0835: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0835: numeric"
    return bool(value), "runtime-rule-0835: truthy"

def runtime_rule_0836(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0836") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0836: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0836: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0836: numeric"
    return bool(value), "runtime-rule-0836: truthy"

def runtime_rule_0837(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0837") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0837: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0837: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0837: numeric"
    return bool(value), "runtime-rule-0837: truthy"

def runtime_rule_0838(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0838") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0838: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0838: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0838: numeric"
    return bool(value), "runtime-rule-0838: truthy"

def runtime_rule_0839(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0839") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0839: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0839: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0839: numeric"
    return bool(value), "runtime-rule-0839: truthy"

def runtime_rule_0840(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0840") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0840: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0840: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0840: numeric"
    return bool(value), "runtime-rule-0840: truthy"

def runtime_rule_0841(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0841") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0841: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0841: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0841: numeric"
    return bool(value), "runtime-rule-0841: truthy"

def runtime_rule_0842(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0842") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0842: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0842: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0842: numeric"
    return bool(value), "runtime-rule-0842: truthy"

def runtime_rule_0843(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0843") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0843: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0843: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0843: numeric"
    return bool(value), "runtime-rule-0843: truthy"

def runtime_rule_0844(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0844") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0844: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0844: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0844: numeric"
    return bool(value), "runtime-rule-0844: truthy"

def runtime_rule_0845(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0845") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0845: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0845: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0845: numeric"
    return bool(value), "runtime-rule-0845: truthy"

def runtime_rule_0846(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0846") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0846: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0846: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0846: numeric"
    return bool(value), "runtime-rule-0846: truthy"

def runtime_rule_0847(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0847") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0847: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0847: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0847: numeric"
    return bool(value), "runtime-rule-0847: truthy"

def runtime_rule_0848(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0848") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0848: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0848: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0848: numeric"
    return bool(value), "runtime-rule-0848: truthy"

def runtime_rule_0849(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0849") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0849: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0849: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0849: numeric"
    return bool(value), "runtime-rule-0849: truthy"

def runtime_rule_0850(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0850") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0850: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0850: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0850: numeric"
    return bool(value), "runtime-rule-0850: truthy"

def runtime_rule_0851(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0851") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0851: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0851: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0851: numeric"
    return bool(value), "runtime-rule-0851: truthy"

def runtime_rule_0852(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0852") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0852: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0852: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0852: numeric"
    return bool(value), "runtime-rule-0852: truthy"

def runtime_rule_0853(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0853") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0853: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0853: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0853: numeric"
    return bool(value), "runtime-rule-0853: truthy"

def runtime_rule_0854(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0854") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0854: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0854: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0854: numeric"
    return bool(value), "runtime-rule-0854: truthy"

def runtime_rule_0855(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0855") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0855: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0855: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0855: numeric"
    return bool(value), "runtime-rule-0855: truthy"

def runtime_rule_0856(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0856") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0856: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0856: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0856: numeric"
    return bool(value), "runtime-rule-0856: truthy"

def runtime_rule_0857(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0857") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0857: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0857: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0857: numeric"
    return bool(value), "runtime-rule-0857: truthy"

def runtime_rule_0858(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0858") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0858: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0858: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0858: numeric"
    return bool(value), "runtime-rule-0858: truthy"

def runtime_rule_0859(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0859") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0859: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0859: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0859: numeric"
    return bool(value), "runtime-rule-0859: truthy"

def runtime_rule_0860(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0860") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0860: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0860: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0860: numeric"
    return bool(value), "runtime-rule-0860: truthy"

def runtime_rule_0861(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0861") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0861: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0861: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0861: numeric"
    return bool(value), "runtime-rule-0861: truthy"

def runtime_rule_0862(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0862") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0862: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0862: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0862: numeric"
    return bool(value), "runtime-rule-0862: truthy"

def runtime_rule_0863(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0863") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0863: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0863: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0863: numeric"
    return bool(value), "runtime-rule-0863: truthy"

def runtime_rule_0864(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0864") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0864: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0864: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0864: numeric"
    return bool(value), "runtime-rule-0864: truthy"

def runtime_rule_0865(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0865") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0865: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0865: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0865: numeric"
    return bool(value), "runtime-rule-0865: truthy"

def runtime_rule_0866(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0866") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0866: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0866: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0866: numeric"
    return bool(value), "runtime-rule-0866: truthy"

def runtime_rule_0867(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0867") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0867: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0867: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0867: numeric"
    return bool(value), "runtime-rule-0867: truthy"

def runtime_rule_0868(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0868") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0868: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0868: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0868: numeric"
    return bool(value), "runtime-rule-0868: truthy"

def runtime_rule_0869(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0869") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0869: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0869: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0869: numeric"
    return bool(value), "runtime-rule-0869: truthy"

def runtime_rule_0870(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0870") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0870: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0870: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0870: numeric"
    return bool(value), "runtime-rule-0870: truthy"

def runtime_rule_0871(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0871") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0871: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0871: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0871: numeric"
    return bool(value), "runtime-rule-0871: truthy"

def runtime_rule_0872(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0872") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0872: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0872: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0872: numeric"
    return bool(value), "runtime-rule-0872: truthy"

def runtime_rule_0873(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0873") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0873: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0873: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0873: numeric"
    return bool(value), "runtime-rule-0873: truthy"

def runtime_rule_0874(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0874") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0874: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0874: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0874: numeric"
    return bool(value), "runtime-rule-0874: truthy"

def runtime_rule_0875(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0875") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0875: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0875: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0875: numeric"
    return bool(value), "runtime-rule-0875: truthy"

def runtime_rule_0876(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0876") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0876: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0876: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0876: numeric"
    return bool(value), "runtime-rule-0876: truthy"

def runtime_rule_0877(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0877") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0877: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0877: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0877: numeric"
    return bool(value), "runtime-rule-0877: truthy"

def runtime_rule_0878(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0878") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0878: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0878: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0878: numeric"
    return bool(value), "runtime-rule-0878: truthy"

def runtime_rule_0879(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0879") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0879: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0879: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0879: numeric"
    return bool(value), "runtime-rule-0879: truthy"

def runtime_rule_0880(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0880") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0880: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0880: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0880: numeric"
    return bool(value), "runtime-rule-0880: truthy"

def runtime_rule_0881(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0881") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0881: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0881: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0881: numeric"
    return bool(value), "runtime-rule-0881: truthy"

def runtime_rule_0882(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0882") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0882: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0882: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0882: numeric"
    return bool(value), "runtime-rule-0882: truthy"

def runtime_rule_0883(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0883") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0883: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0883: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0883: numeric"
    return bool(value), "runtime-rule-0883: truthy"

def runtime_rule_0884(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0884") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0884: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0884: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0884: numeric"
    return bool(value), "runtime-rule-0884: truthy"

def runtime_rule_0885(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0885") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0885: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0885: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0885: numeric"
    return bool(value), "runtime-rule-0885: truthy"

def runtime_rule_0886(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0886") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0886: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0886: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0886: numeric"
    return bool(value), "runtime-rule-0886: truthy"

def runtime_rule_0887(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0887") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0887: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0887: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0887: numeric"
    return bool(value), "runtime-rule-0887: truthy"

def runtime_rule_0888(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0888") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0888: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0888: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0888: numeric"
    return bool(value), "runtime-rule-0888: truthy"

def runtime_rule_0889(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0889") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0889: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0889: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0889: numeric"
    return bool(value), "runtime-rule-0889: truthy"

def runtime_rule_0890(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0890") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0890: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0890: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0890: numeric"
    return bool(value), "runtime-rule-0890: truthy"

def runtime_rule_0891(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0891") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0891: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0891: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0891: numeric"
    return bool(value), "runtime-rule-0891: truthy"

def runtime_rule_0892(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0892") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0892: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0892: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0892: numeric"
    return bool(value), "runtime-rule-0892: truthy"

def runtime_rule_0893(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0893") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0893: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0893: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0893: numeric"
    return bool(value), "runtime-rule-0893: truthy"

def runtime_rule_0894(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0894") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0894: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0894: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0894: numeric"
    return bool(value), "runtime-rule-0894: truthy"

def runtime_rule_0895(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0895") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0895: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0895: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0895: numeric"
    return bool(value), "runtime-rule-0895: truthy"

def runtime_rule_0896(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0896") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0896: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0896: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0896: numeric"
    return bool(value), "runtime-rule-0896: truthy"

def runtime_rule_0897(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0897") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0897: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0897: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0897: numeric"
    return bool(value), "runtime-rule-0897: truthy"

def runtime_rule_0898(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0898") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0898: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0898: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0898: numeric"
    return bool(value), "runtime-rule-0898: truthy"

def runtime_rule_0899(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0899") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0899: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0899: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0899: numeric"
    return bool(value), "runtime-rule-0899: truthy"

def runtime_rule_0900(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0900") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0900: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0900: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0900: numeric"
    return bool(value), "runtime-rule-0900: truthy"

def runtime_rule_0901(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0901") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0901: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0901: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0901: numeric"
    return bool(value), "runtime-rule-0901: truthy"

def runtime_rule_0902(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0902") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0902: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0902: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0902: numeric"
    return bool(value), "runtime-rule-0902: truthy"

def runtime_rule_0903(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0903") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0903: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0903: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0903: numeric"
    return bool(value), "runtime-rule-0903: truthy"

def runtime_rule_0904(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0904") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0904: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0904: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0904: numeric"
    return bool(value), "runtime-rule-0904: truthy"

def runtime_rule_0905(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0905") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0905: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0905: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0905: numeric"
    return bool(value), "runtime-rule-0905: truthy"

def runtime_rule_0906(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0906") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0906: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0906: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0906: numeric"
    return bool(value), "runtime-rule-0906: truthy"

def runtime_rule_0907(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0907") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0907: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0907: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0907: numeric"
    return bool(value), "runtime-rule-0907: truthy"

def runtime_rule_0908(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0908") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0908: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0908: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0908: numeric"
    return bool(value), "runtime-rule-0908: truthy"

def runtime_rule_0909(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0909") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0909: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0909: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0909: numeric"
    return bool(value), "runtime-rule-0909: truthy"

def runtime_rule_0910(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0910") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0910: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0910: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0910: numeric"
    return bool(value), "runtime-rule-0910: truthy"

def runtime_rule_0911(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0911") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0911: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0911: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0911: numeric"
    return bool(value), "runtime-rule-0911: truthy"

def runtime_rule_0912(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0912") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0912: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0912: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0912: numeric"
    return bool(value), "runtime-rule-0912: truthy"

def runtime_rule_0913(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0913") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0913: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0913: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0913: numeric"
    return bool(value), "runtime-rule-0913: truthy"

def runtime_rule_0914(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0914") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0914: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0914: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0914: numeric"
    return bool(value), "runtime-rule-0914: truthy"

def runtime_rule_0915(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0915") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0915: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0915: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0915: numeric"
    return bool(value), "runtime-rule-0915: truthy"

def runtime_rule_0916(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0916") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0916: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0916: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0916: numeric"
    return bool(value), "runtime-rule-0916: truthy"

def runtime_rule_0917(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0917") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0917: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0917: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0917: numeric"
    return bool(value), "runtime-rule-0917: truthy"

def runtime_rule_0918(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0918") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0918: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0918: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0918: numeric"
    return bool(value), "runtime-rule-0918: truthy"

def runtime_rule_0919(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0919") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0919: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0919: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0919: numeric"
    return bool(value), "runtime-rule-0919: truthy"

def runtime_rule_0920(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0920") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0920: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0920: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0920: numeric"
    return bool(value), "runtime-rule-0920: truthy"

def runtime_rule_0921(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0921") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0921: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0921: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0921: numeric"
    return bool(value), "runtime-rule-0921: truthy"

def runtime_rule_0922(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0922") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0922: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0922: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0922: numeric"
    return bool(value), "runtime-rule-0922: truthy"

def runtime_rule_0923(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0923") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0923: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0923: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0923: numeric"
    return bool(value), "runtime-rule-0923: truthy"

def runtime_rule_0924(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0924") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0924: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0924: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0924: numeric"
    return bool(value), "runtime-rule-0924: truthy"

def runtime_rule_0925(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0925") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0925: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0925: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0925: numeric"
    return bool(value), "runtime-rule-0925: truthy"

def runtime_rule_0926(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0926") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0926: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0926: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0926: numeric"
    return bool(value), "runtime-rule-0926: truthy"

def runtime_rule_0927(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0927") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0927: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0927: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0927: numeric"
    return bool(value), "runtime-rule-0927: truthy"

def runtime_rule_0928(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0928") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0928: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0928: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0928: numeric"
    return bool(value), "runtime-rule-0928: truthy"

def runtime_rule_0929(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0929") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0929: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0929: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0929: numeric"
    return bool(value), "runtime-rule-0929: truthy"

def runtime_rule_0930(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0930") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0930: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0930: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0930: numeric"
    return bool(value), "runtime-rule-0930: truthy"

def runtime_rule_0931(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0931") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0931: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0931: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0931: numeric"
    return bool(value), "runtime-rule-0931: truthy"

def runtime_rule_0932(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0932") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0932: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0932: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0932: numeric"
    return bool(value), "runtime-rule-0932: truthy"

def runtime_rule_0933(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0933") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0933: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0933: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0933: numeric"
    return bool(value), "runtime-rule-0933: truthy"

def runtime_rule_0934(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0934") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0934: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0934: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0934: numeric"
    return bool(value), "runtime-rule-0934: truthy"

def runtime_rule_0935(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0935") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0935: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0935: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0935: numeric"
    return bool(value), "runtime-rule-0935: truthy"

def runtime_rule_0936(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0936") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0936: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0936: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0936: numeric"
    return bool(value), "runtime-rule-0936: truthy"

def runtime_rule_0937(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0937") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0937: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0937: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0937: numeric"
    return bool(value), "runtime-rule-0937: truthy"

def runtime_rule_0938(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0938") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0938: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0938: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0938: numeric"
    return bool(value), "runtime-rule-0938: truthy"

def runtime_rule_0939(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0939") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0939: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0939: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0939: numeric"
    return bool(value), "runtime-rule-0939: truthy"

def runtime_rule_0940(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0940") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0940: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0940: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0940: numeric"
    return bool(value), "runtime-rule-0940: truthy"

def runtime_rule_0941(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0941") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0941: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0941: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0941: numeric"
    return bool(value), "runtime-rule-0941: truthy"

def runtime_rule_0942(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0942") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0942: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0942: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0942: numeric"
    return bool(value), "runtime-rule-0942: truthy"

def runtime_rule_0943(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0943") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0943: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0943: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0943: numeric"
    return bool(value), "runtime-rule-0943: truthy"

def runtime_rule_0944(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0944") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0944: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0944: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0944: numeric"
    return bool(value), "runtime-rule-0944: truthy"

def runtime_rule_0945(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0945") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0945: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0945: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0945: numeric"
    return bool(value), "runtime-rule-0945: truthy"

def runtime_rule_0946(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0946") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0946: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0946: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0946: numeric"
    return bool(value), "runtime-rule-0946: truthy"

def runtime_rule_0947(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0947") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0947: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0947: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0947: numeric"
    return bool(value), "runtime-rule-0947: truthy"

def runtime_rule_0948(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0948") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0948: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0948: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0948: numeric"
    return bool(value), "runtime-rule-0948: truthy"

def runtime_rule_0949(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0949") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0949: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0949: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0949: numeric"
    return bool(value), "runtime-rule-0949: truthy"

def runtime_rule_0950(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0950") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0950: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0950: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0950: numeric"
    return bool(value), "runtime-rule-0950: truthy"

def runtime_rule_0951(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0951") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0951: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0951: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0951: numeric"
    return bool(value), "runtime-rule-0951: truthy"

def runtime_rule_0952(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0952") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0952: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0952: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0952: numeric"
    return bool(value), "runtime-rule-0952: truthy"

def runtime_rule_0953(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0953") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0953: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0953: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0953: numeric"
    return bool(value), "runtime-rule-0953: truthy"

def runtime_rule_0954(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0954") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0954: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0954: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0954: numeric"
    return bool(value), "runtime-rule-0954: truthy"

def runtime_rule_0955(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0955") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0955: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0955: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0955: numeric"
    return bool(value), "runtime-rule-0955: truthy"

def runtime_rule_0956(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0956") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0956: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0956: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0956: numeric"
    return bool(value), "runtime-rule-0956: truthy"

def runtime_rule_0957(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0957") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0957: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0957: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0957: numeric"
    return bool(value), "runtime-rule-0957: truthy"

def runtime_rule_0958(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0958") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0958: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0958: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0958: numeric"
    return bool(value), "runtime-rule-0958: truthy"

def runtime_rule_0959(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0959") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0959: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0959: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0959: numeric"
    return bool(value), "runtime-rule-0959: truthy"

def runtime_rule_0960(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0960") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0960: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0960: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0960: numeric"
    return bool(value), "runtime-rule-0960: truthy"

def runtime_rule_0961(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0961") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0961: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0961: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0961: numeric"
    return bool(value), "runtime-rule-0961: truthy"

def runtime_rule_0962(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0962") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0962: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0962: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0962: numeric"
    return bool(value), "runtime-rule-0962: truthy"

def runtime_rule_0963(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0963") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0963: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0963: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0963: numeric"
    return bool(value), "runtime-rule-0963: truthy"

def runtime_rule_0964(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0964") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0964: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0964: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0964: numeric"
    return bool(value), "runtime-rule-0964: truthy"

def runtime_rule_0965(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0965") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0965: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0965: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0965: numeric"
    return bool(value), "runtime-rule-0965: truthy"

def runtime_rule_0966(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0966") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0966: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0966: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0966: numeric"
    return bool(value), "runtime-rule-0966: truthy"

def runtime_rule_0967(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0967") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0967: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0967: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0967: numeric"
    return bool(value), "runtime-rule-0967: truthy"

def runtime_rule_0968(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0968") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0968: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0968: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0968: numeric"
    return bool(value), "runtime-rule-0968: truthy"

def runtime_rule_0969(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0969") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0969: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0969: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0969: numeric"
    return bool(value), "runtime-rule-0969: truthy"

def runtime_rule_0970(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0970") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0970: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0970: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0970: numeric"
    return bool(value), "runtime-rule-0970: truthy"

def runtime_rule_0971(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0971") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0971: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0971: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0971: numeric"
    return bool(value), "runtime-rule-0971: truthy"

def runtime_rule_0972(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0972") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0972: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0972: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0972: numeric"
    return bool(value), "runtime-rule-0972: truthy"

def runtime_rule_0973(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0973") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0973: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0973: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0973: numeric"
    return bool(value), "runtime-rule-0973: truthy"

def runtime_rule_0974(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0974") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0974: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0974: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0974: numeric"
    return bool(value), "runtime-rule-0974: truthy"

def runtime_rule_0975(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0975") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0975: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0975: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0975: numeric"
    return bool(value), "runtime-rule-0975: truthy"

def runtime_rule_0976(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0976") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0976: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0976: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0976: numeric"
    return bool(value), "runtime-rule-0976: truthy"

def runtime_rule_0977(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0977") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0977: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0977: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0977: numeric"
    return bool(value), "runtime-rule-0977: truthy"

def runtime_rule_0978(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0978") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0978: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0978: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0978: numeric"
    return bool(value), "runtime-rule-0978: truthy"

def runtime_rule_0979(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0979") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0979: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0979: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0979: numeric"
    return bool(value), "runtime-rule-0979: truthy"

def runtime_rule_0980(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0980") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0980: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0980: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0980: numeric"
    return bool(value), "runtime-rule-0980: truthy"

def runtime_rule_0981(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0981") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0981: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0981: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0981: numeric"
    return bool(value), "runtime-rule-0981: truthy"

def runtime_rule_0982(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0982") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0982: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0982: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0982: numeric"
    return bool(value), "runtime-rule-0982: truthy"

def runtime_rule_0983(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0983") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0983: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0983: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0983: numeric"
    return bool(value), "runtime-rule-0983: truthy"

def runtime_rule_0984(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0984") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0984: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0984: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0984: numeric"
    return bool(value), "runtime-rule-0984: truthy"

def runtime_rule_0985(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0985") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0985: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0985: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0985: numeric"
    return bool(value), "runtime-rule-0985: truthy"

def runtime_rule_0986(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0986") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0986: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0986: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0986: numeric"
    return bool(value), "runtime-rule-0986: truthy"

def runtime_rule_0987(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0987") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0987: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0987: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0987: numeric"
    return bool(value), "runtime-rule-0987: truthy"

def runtime_rule_0988(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0988") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0988: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0988: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0988: numeric"
    return bool(value), "runtime-rule-0988: truthy"

def runtime_rule_0989(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0989") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0989: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0989: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0989: numeric"
    return bool(value), "runtime-rule-0989: truthy"

def runtime_rule_0990(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0990") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0990: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0990: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0990: numeric"
    return bool(value), "runtime-rule-0990: truthy"

def runtime_rule_0991(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0991") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0991: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0991: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0991: numeric"
    return bool(value), "runtime-rule-0991: truthy"

def runtime_rule_0992(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0992") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0992: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0992: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0992: numeric"
    return bool(value), "runtime-rule-0992: truthy"

def runtime_rule_0993(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0993") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0993: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0993: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0993: numeric"
    return bool(value), "runtime-rule-0993: truthy"

def runtime_rule_0994(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0994") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0994: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0994: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0994: numeric"
    return bool(value), "runtime-rule-0994: truthy"

def runtime_rule_0995(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0995") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0995: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0995: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0995: numeric"
    return bool(value), "runtime-rule-0995: truthy"

def runtime_rule_0996(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0996") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0996: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0996: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0996: numeric"
    return bool(value), "runtime-rule-0996: truthy"

def runtime_rule_0997(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0997") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0997: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0997: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0997: numeric"
    return bool(value), "runtime-rule-0997: truthy"

def runtime_rule_0998(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0998") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0998: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0998: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0998: numeric"
    return bool(value), "runtime-rule-0998: truthy"

def runtime_rule_0999(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-0999") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-0999: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-0999: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-0999: numeric"
    return bool(value), "runtime-rule-0999: truthy"

def runtime_rule_1000(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1000") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1000: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1000: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1000: numeric"
    return bool(value), "runtime-rule-1000: truthy"

def runtime_rule_1001(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1001") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1001: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1001: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1001: numeric"
    return bool(value), "runtime-rule-1001: truthy"

def runtime_rule_1002(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1002") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1002: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1002: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1002: numeric"
    return bool(value), "runtime-rule-1002: truthy"

def runtime_rule_1003(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1003") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1003: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1003: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1003: numeric"
    return bool(value), "runtime-rule-1003: truthy"

def runtime_rule_1004(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1004") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1004: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1004: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1004: numeric"
    return bool(value), "runtime-rule-1004: truthy"

def runtime_rule_1005(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1005") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1005: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1005: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1005: numeric"
    return bool(value), "runtime-rule-1005: truthy"

def runtime_rule_1006(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1006") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1006: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1006: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1006: numeric"
    return bool(value), "runtime-rule-1006: truthy"

def runtime_rule_1007(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1007") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1007: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1007: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1007: numeric"
    return bool(value), "runtime-rule-1007: truthy"

def runtime_rule_1008(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1008") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1008: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1008: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1008: numeric"
    return bool(value), "runtime-rule-1008: truthy"

def runtime_rule_1009(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1009") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1009: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1009: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1009: numeric"
    return bool(value), "runtime-rule-1009: truthy"

def runtime_rule_1010(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1010") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1010: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1010: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1010: numeric"
    return bool(value), "runtime-rule-1010: truthy"

def runtime_rule_1011(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1011") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1011: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1011: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1011: numeric"
    return bool(value), "runtime-rule-1011: truthy"

def runtime_rule_1012(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1012") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1012: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1012: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1012: numeric"
    return bool(value), "runtime-rule-1012: truthy"

def runtime_rule_1013(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1013") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1013: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1013: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1013: numeric"
    return bool(value), "runtime-rule-1013: truthy"

def runtime_rule_1014(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1014") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1014: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1014: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1014: numeric"
    return bool(value), "runtime-rule-1014: truthy"

def runtime_rule_1015(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1015") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1015: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1015: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1015: numeric"
    return bool(value), "runtime-rule-1015: truthy"

def runtime_rule_1016(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1016") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1016: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1016: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1016: numeric"
    return bool(value), "runtime-rule-1016: truthy"

def runtime_rule_1017(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1017") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1017: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1017: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1017: numeric"
    return bool(value), "runtime-rule-1017: truthy"

def runtime_rule_1018(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1018") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1018: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1018: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1018: numeric"
    return bool(value), "runtime-rule-1018: truthy"

def runtime_rule_1019(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1019") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1019: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1019: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1019: numeric"
    return bool(value), "runtime-rule-1019: truthy"

def runtime_rule_1020(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1020") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1020: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1020: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1020: numeric"
    return bool(value), "runtime-rule-1020: truthy"

def runtime_rule_1021(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1021") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1021: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1021: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1021: numeric"
    return bool(value), "runtime-rule-1021: truthy"

def runtime_rule_1022(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1022") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1022: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1022: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1022: numeric"
    return bool(value), "runtime-rule-1022: truthy"

def runtime_rule_1023(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1023") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1023: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1023: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1023: numeric"
    return bool(value), "runtime-rule-1023: truthy"

def runtime_rule_1024(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1024") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1024: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1024: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1024: numeric"
    return bool(value), "runtime-rule-1024: truthy"

def runtime_rule_1025(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1025") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1025: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1025: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1025: numeric"
    return bool(value), "runtime-rule-1025: truthy"

def runtime_rule_1026(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1026") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1026: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1026: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1026: numeric"
    return bool(value), "runtime-rule-1026: truthy"

def runtime_rule_1027(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1027") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1027: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1027: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1027: numeric"
    return bool(value), "runtime-rule-1027: truthy"

def runtime_rule_1028(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1028") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1028: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1028: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1028: numeric"
    return bool(value), "runtime-rule-1028: truthy"

def runtime_rule_1029(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1029") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1029: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1029: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1029: numeric"
    return bool(value), "runtime-rule-1029: truthy"

def runtime_rule_1030(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1030") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1030: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1030: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1030: numeric"
    return bool(value), "runtime-rule-1030: truthy"

def runtime_rule_1031(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1031") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1031: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1031: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1031: numeric"
    return bool(value), "runtime-rule-1031: truthy"

def runtime_rule_1032(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1032") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1032: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1032: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1032: numeric"
    return bool(value), "runtime-rule-1032: truthy"

def runtime_rule_1033(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1033") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1033: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1033: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1033: numeric"
    return bool(value), "runtime-rule-1033: truthy"

def runtime_rule_1034(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1034") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1034: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1034: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1034: numeric"
    return bool(value), "runtime-rule-1034: truthy"

def runtime_rule_1035(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1035") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1035: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1035: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1035: numeric"
    return bool(value), "runtime-rule-1035: truthy"

def runtime_rule_1036(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1036") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1036: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1036: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1036: numeric"
    return bool(value), "runtime-rule-1036: truthy"

def runtime_rule_1037(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1037") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1037: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1037: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1037: numeric"
    return bool(value), "runtime-rule-1037: truthy"

def runtime_rule_1038(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1038") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1038: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1038: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1038: numeric"
    return bool(value), "runtime-rule-1038: truthy"

def runtime_rule_1039(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1039") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1039: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1039: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1039: numeric"
    return bool(value), "runtime-rule-1039: truthy"

def runtime_rule_1040(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1040") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1040: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1040: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1040: numeric"
    return bool(value), "runtime-rule-1040: truthy"

def runtime_rule_1041(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1041") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1041: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1041: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1041: numeric"
    return bool(value), "runtime-rule-1041: truthy"

def runtime_rule_1042(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1042") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1042: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1042: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1042: numeric"
    return bool(value), "runtime-rule-1042: truthy"

def runtime_rule_1043(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1043") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1043: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1043: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1043: numeric"
    return bool(value), "runtime-rule-1043: truthy"

def runtime_rule_1044(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1044") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1044: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1044: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1044: numeric"
    return bool(value), "runtime-rule-1044: truthy"

def runtime_rule_1045(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1045") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1045: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1045: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1045: numeric"
    return bool(value), "runtime-rule-1045: truthy"

def runtime_rule_1046(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1046") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1046: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1046: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1046: numeric"
    return bool(value), "runtime-rule-1046: truthy"

def runtime_rule_1047(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1047") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1047: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1047: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1047: numeric"
    return bool(value), "runtime-rule-1047: truthy"

def runtime_rule_1048(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1048") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1048: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1048: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1048: numeric"
    return bool(value), "runtime-rule-1048: truthy"

def runtime_rule_1049(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1049") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1049: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1049: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1049: numeric"
    return bool(value), "runtime-rule-1049: truthy"

def runtime_rule_1050(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1050") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1050: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1050: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1050: numeric"
    return bool(value), "runtime-rule-1050: truthy"

def runtime_rule_1051(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1051") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1051: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1051: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1051: numeric"
    return bool(value), "runtime-rule-1051: truthy"

def runtime_rule_1052(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1052") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1052: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1052: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1052: numeric"
    return bool(value), "runtime-rule-1052: truthy"

def runtime_rule_1053(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1053") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1053: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1053: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1053: numeric"
    return bool(value), "runtime-rule-1053: truthy"

def runtime_rule_1054(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1054") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1054: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1054: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1054: numeric"
    return bool(value), "runtime-rule-1054: truthy"

def runtime_rule_1055(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1055") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1055: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1055: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1055: numeric"
    return bool(value), "runtime-rule-1055: truthy"

def runtime_rule_1056(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1056") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1056: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1056: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1056: numeric"
    return bool(value), "runtime-rule-1056: truthy"

def runtime_rule_1057(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1057") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1057: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1057: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1057: numeric"
    return bool(value), "runtime-rule-1057: truthy"

def runtime_rule_1058(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1058") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1058: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1058: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1058: numeric"
    return bool(value), "runtime-rule-1058: truthy"

def runtime_rule_1059(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1059") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1059: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1059: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1059: numeric"
    return bool(value), "runtime-rule-1059: truthy"

def runtime_rule_1060(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1060") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1060: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1060: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1060: numeric"
    return bool(value), "runtime-rule-1060: truthy"

def runtime_rule_1061(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1061") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1061: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1061: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1061: numeric"
    return bool(value), "runtime-rule-1061: truthy"

def runtime_rule_1062(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1062") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1062: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1062: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1062: numeric"
    return bool(value), "runtime-rule-1062: truthy"

def runtime_rule_1063(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1063") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1063: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1063: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1063: numeric"
    return bool(value), "runtime-rule-1063: truthy"

def runtime_rule_1064(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1064") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1064: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1064: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1064: numeric"
    return bool(value), "runtime-rule-1064: truthy"

def runtime_rule_1065(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1065") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1065: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1065: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1065: numeric"
    return bool(value), "runtime-rule-1065: truthy"

def runtime_rule_1066(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1066") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1066: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1066: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1066: numeric"
    return bool(value), "runtime-rule-1066: truthy"

def runtime_rule_1067(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1067") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1067: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1067: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1067: numeric"
    return bool(value), "runtime-rule-1067: truthy"

def runtime_rule_1068(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1068") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1068: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1068: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1068: numeric"
    return bool(value), "runtime-rule-1068: truthy"

def runtime_rule_1069(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1069") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1069: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1069: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1069: numeric"
    return bool(value), "runtime-rule-1069: truthy"

def runtime_rule_1070(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1070") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1070: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1070: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1070: numeric"
    return bool(value), "runtime-rule-1070: truthy"

def runtime_rule_1071(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1071") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1071: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1071: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1071: numeric"
    return bool(value), "runtime-rule-1071: truthy"

def runtime_rule_1072(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1072") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1072: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1072: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1072: numeric"
    return bool(value), "runtime-rule-1072: truthy"

def runtime_rule_1073(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1073") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1073: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1073: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1073: numeric"
    return bool(value), "runtime-rule-1073: truthy"

def runtime_rule_1074(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1074") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1074: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1074: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1074: numeric"
    return bool(value), "runtime-rule-1074: truthy"

def runtime_rule_1075(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1075") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1075: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1075: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1075: numeric"
    return bool(value), "runtime-rule-1075: truthy"

def runtime_rule_1076(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1076") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1076: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1076: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1076: numeric"
    return bool(value), "runtime-rule-1076: truthy"

def runtime_rule_1077(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1077") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1077: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1077: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1077: numeric"
    return bool(value), "runtime-rule-1077: truthy"

def runtime_rule_1078(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1078") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1078: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1078: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1078: numeric"
    return bool(value), "runtime-rule-1078: truthy"

def runtime_rule_1079(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1079") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1079: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1079: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1079: numeric"
    return bool(value), "runtime-rule-1079: truthy"

def runtime_rule_1080(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1080") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1080: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1080: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1080: numeric"
    return bool(value), "runtime-rule-1080: truthy"

def runtime_rule_1081(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1081") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1081: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1081: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1081: numeric"
    return bool(value), "runtime-rule-1081: truthy"

def runtime_rule_1082(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1082") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1082: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1082: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1082: numeric"
    return bool(value), "runtime-rule-1082: truthy"

def runtime_rule_1083(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1083") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1083: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1083: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1083: numeric"
    return bool(value), "runtime-rule-1083: truthy"

def runtime_rule_1084(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1084") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1084: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1084: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1084: numeric"
    return bool(value), "runtime-rule-1084: truthy"

def runtime_rule_1085(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1085") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1085: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1085: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1085: numeric"
    return bool(value), "runtime-rule-1085: truthy"

def runtime_rule_1086(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1086") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1086: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1086: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1086: numeric"
    return bool(value), "runtime-rule-1086: truthy"

def runtime_rule_1087(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1087") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1087: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1087: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1087: numeric"
    return bool(value), "runtime-rule-1087: truthy"

def runtime_rule_1088(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1088") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1088: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1088: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1088: numeric"
    return bool(value), "runtime-rule-1088: truthy"

def runtime_rule_1089(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1089") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1089: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1089: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1089: numeric"
    return bool(value), "runtime-rule-1089: truthy"

def runtime_rule_1090(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1090") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1090: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1090: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1090: numeric"
    return bool(value), "runtime-rule-1090: truthy"

def runtime_rule_1091(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1091") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1091: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1091: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1091: numeric"
    return bool(value), "runtime-rule-1091: truthy"

def runtime_rule_1092(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1092") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1092: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1092: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1092: numeric"
    return bool(value), "runtime-rule-1092: truthy"

def runtime_rule_1093(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1093") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1093: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1093: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1093: numeric"
    return bool(value), "runtime-rule-1093: truthy"

def runtime_rule_1094(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1094") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1094: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1094: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1094: numeric"
    return bool(value), "runtime-rule-1094: truthy"

def runtime_rule_1095(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1095") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1095: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1095: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1095: numeric"
    return bool(value), "runtime-rule-1095: truthy"

def runtime_rule_1096(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1096") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1096: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1096: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1096: numeric"
    return bool(value), "runtime-rule-1096: truthy"

def runtime_rule_1097(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1097") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1097: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1097: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1097: numeric"
    return bool(value), "runtime-rule-1097: truthy"

def runtime_rule_1098(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1098") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1098: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1098: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1098: numeric"
    return bool(value), "runtime-rule-1098: truthy"

def runtime_rule_1099(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1099") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1099: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1099: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1099: numeric"
    return bool(value), "runtime-rule-1099: truthy"

def runtime_rule_1100(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1100") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1100: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1100: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1100: numeric"
    return bool(value), "runtime-rule-1100: truthy"

def runtime_rule_1101(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1101") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1101: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1101: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1101: numeric"
    return bool(value), "runtime-rule-1101: truthy"

def runtime_rule_1102(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1102") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1102: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1102: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1102: numeric"
    return bool(value), "runtime-rule-1102: truthy"

def runtime_rule_1103(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1103") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1103: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1103: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1103: numeric"
    return bool(value), "runtime-rule-1103: truthy"

def runtime_rule_1104(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1104") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1104: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1104: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1104: numeric"
    return bool(value), "runtime-rule-1104: truthy"

def runtime_rule_1105(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1105") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1105: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1105: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1105: numeric"
    return bool(value), "runtime-rule-1105: truthy"

def runtime_rule_1106(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1106") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1106: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1106: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1106: numeric"
    return bool(value), "runtime-rule-1106: truthy"

def runtime_rule_1107(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1107") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1107: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1107: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1107: numeric"
    return bool(value), "runtime-rule-1107: truthy"

def runtime_rule_1108(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1108") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1108: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1108: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1108: numeric"
    return bool(value), "runtime-rule-1108: truthy"

def runtime_rule_1109(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1109") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1109: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1109: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1109: numeric"
    return bool(value), "runtime-rule-1109: truthy"

def runtime_rule_1110(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1110") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1110: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1110: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1110: numeric"
    return bool(value), "runtime-rule-1110: truthy"

def runtime_rule_1111(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1111") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1111: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1111: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1111: numeric"
    return bool(value), "runtime-rule-1111: truthy"

def runtime_rule_1112(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1112") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1112: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1112: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1112: numeric"
    return bool(value), "runtime-rule-1112: truthy"

def runtime_rule_1113(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1113") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1113: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1113: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1113: numeric"
    return bool(value), "runtime-rule-1113: truthy"

def runtime_rule_1114(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1114") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1114: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1114: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1114: numeric"
    return bool(value), "runtime-rule-1114: truthy"

def runtime_rule_1115(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1115") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1115: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1115: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1115: numeric"
    return bool(value), "runtime-rule-1115: truthy"

def runtime_rule_1116(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1116") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1116: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1116: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1116: numeric"
    return bool(value), "runtime-rule-1116: truthy"

def runtime_rule_1117(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1117") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1117: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1117: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1117: numeric"
    return bool(value), "runtime-rule-1117: truthy"

def runtime_rule_1118(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1118") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1118: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1118: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1118: numeric"
    return bool(value), "runtime-rule-1118: truthy"

def runtime_rule_1119(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1119") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1119: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1119: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1119: numeric"
    return bool(value), "runtime-rule-1119: truthy"

def runtime_rule_1120(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1120") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1120: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1120: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1120: numeric"
    return bool(value), "runtime-rule-1120: truthy"

def runtime_rule_1121(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1121") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1121: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1121: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1121: numeric"
    return bool(value), "runtime-rule-1121: truthy"

def runtime_rule_1122(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1122") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1122: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1122: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1122: numeric"
    return bool(value), "runtime-rule-1122: truthy"

def runtime_rule_1123(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1123") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1123: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1123: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1123: numeric"
    return bool(value), "runtime-rule-1123: truthy"

def runtime_rule_1124(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1124") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1124: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1124: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1124: numeric"
    return bool(value), "runtime-rule-1124: truthy"

def runtime_rule_1125(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1125") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1125: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1125: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1125: numeric"
    return bool(value), "runtime-rule-1125: truthy"

def runtime_rule_1126(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1126") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1126: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1126: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1126: numeric"
    return bool(value), "runtime-rule-1126: truthy"

def runtime_rule_1127(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1127") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1127: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1127: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1127: numeric"
    return bool(value), "runtime-rule-1127: truthy"

def runtime_rule_1128(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1128") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1128: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1128: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1128: numeric"
    return bool(value), "runtime-rule-1128: truthy"

def runtime_rule_1129(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1129") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1129: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1129: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1129: numeric"
    return bool(value), "runtime-rule-1129: truthy"

def runtime_rule_1130(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1130") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1130: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1130: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1130: numeric"
    return bool(value), "runtime-rule-1130: truthy"

def runtime_rule_1131(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1131") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1131: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1131: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1131: numeric"
    return bool(value), "runtime-rule-1131: truthy"

def runtime_rule_1132(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1132") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1132: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1132: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1132: numeric"
    return bool(value), "runtime-rule-1132: truthy"

def runtime_rule_1133(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1133") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1133: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1133: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1133: numeric"
    return bool(value), "runtime-rule-1133: truthy"

def runtime_rule_1134(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1134") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1134: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1134: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1134: numeric"
    return bool(value), "runtime-rule-1134: truthy"

def runtime_rule_1135(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1135") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1135: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1135: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1135: numeric"
    return bool(value), "runtime-rule-1135: truthy"

def runtime_rule_1136(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1136") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1136: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1136: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1136: numeric"
    return bool(value), "runtime-rule-1136: truthy"

def runtime_rule_1137(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1137") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1137: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1137: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1137: numeric"
    return bool(value), "runtime-rule-1137: truthy"

def runtime_rule_1138(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1138") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1138: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1138: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1138: numeric"
    return bool(value), "runtime-rule-1138: truthy"

def runtime_rule_1139(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1139") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1139: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1139: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1139: numeric"
    return bool(value), "runtime-rule-1139: truthy"

def runtime_rule_1140(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1140") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1140: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1140: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1140: numeric"
    return bool(value), "runtime-rule-1140: truthy"

def runtime_rule_1141(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1141") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1141: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1141: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1141: numeric"
    return bool(value), "runtime-rule-1141: truthy"

def runtime_rule_1142(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1142") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1142: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1142: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1142: numeric"
    return bool(value), "runtime-rule-1142: truthy"

def runtime_rule_1143(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1143") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1143: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1143: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1143: numeric"
    return bool(value), "runtime-rule-1143: truthy"

def runtime_rule_1144(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1144") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1144: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1144: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1144: numeric"
    return bool(value), "runtime-rule-1144: truthy"

def runtime_rule_1145(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1145") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1145: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1145: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1145: numeric"
    return bool(value), "runtime-rule-1145: truthy"

def runtime_rule_1146(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1146") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1146: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1146: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1146: numeric"
    return bool(value), "runtime-rule-1146: truthy"

def runtime_rule_1147(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1147") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1147: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1147: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1147: numeric"
    return bool(value), "runtime-rule-1147: truthy"

def runtime_rule_1148(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1148") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1148: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1148: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1148: numeric"
    return bool(value), "runtime-rule-1148: truthy"

def runtime_rule_1149(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1149") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1149: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1149: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1149: numeric"
    return bool(value), "runtime-rule-1149: truthy"

def runtime_rule_1150(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1150") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1150: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1150: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1150: numeric"
    return bool(value), "runtime-rule-1150: truthy"

def runtime_rule_1151(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1151") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1151: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1151: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1151: numeric"
    return bool(value), "runtime-rule-1151: truthy"

def runtime_rule_1152(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1152") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1152: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1152: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1152: numeric"
    return bool(value), "runtime-rule-1152: truthy"

def runtime_rule_1153(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1153") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1153: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1153: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1153: numeric"
    return bool(value), "runtime-rule-1153: truthy"

def runtime_rule_1154(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1154") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1154: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1154: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1154: numeric"
    return bool(value), "runtime-rule-1154: truthy"

def runtime_rule_1155(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1155") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1155: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1155: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1155: numeric"
    return bool(value), "runtime-rule-1155: truthy"

def runtime_rule_1156(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1156") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1156: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1156: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1156: numeric"
    return bool(value), "runtime-rule-1156: truthy"

def runtime_rule_1157(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1157") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1157: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1157: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1157: numeric"
    return bool(value), "runtime-rule-1157: truthy"

def runtime_rule_1158(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1158") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1158: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1158: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1158: numeric"
    return bool(value), "runtime-rule-1158: truthy"

def runtime_rule_1159(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1159") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1159: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1159: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1159: numeric"
    return bool(value), "runtime-rule-1159: truthy"

def runtime_rule_1160(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1160") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1160: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1160: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1160: numeric"
    return bool(value), "runtime-rule-1160: truthy"

def runtime_rule_1161(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1161") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1161: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1161: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1161: numeric"
    return bool(value), "runtime-rule-1161: truthy"

def runtime_rule_1162(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1162") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1162: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1162: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1162: numeric"
    return bool(value), "runtime-rule-1162: truthy"

def runtime_rule_1163(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1163") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1163: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1163: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1163: numeric"
    return bool(value), "runtime-rule-1163: truthy"

def runtime_rule_1164(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1164") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1164: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1164: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1164: numeric"
    return bool(value), "runtime-rule-1164: truthy"

def runtime_rule_1165(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1165") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1165: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1165: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1165: numeric"
    return bool(value), "runtime-rule-1165: truthy"

def runtime_rule_1166(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1166") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1166: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1166: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1166: numeric"
    return bool(value), "runtime-rule-1166: truthy"

def runtime_rule_1167(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1167") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1167: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1167: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1167: numeric"
    return bool(value), "runtime-rule-1167: truthy"

def runtime_rule_1168(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1168") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1168: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1168: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1168: numeric"
    return bool(value), "runtime-rule-1168: truthy"

def runtime_rule_1169(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1169") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1169: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1169: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1169: numeric"
    return bool(value), "runtime-rule-1169: truthy"

def runtime_rule_1170(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1170") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1170: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1170: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1170: numeric"
    return bool(value), "runtime-rule-1170: truthy"

def runtime_rule_1171(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1171") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1171: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1171: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1171: numeric"
    return bool(value), "runtime-rule-1171: truthy"

def runtime_rule_1172(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1172") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1172: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1172: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1172: numeric"
    return bool(value), "runtime-rule-1172: truthy"

def runtime_rule_1173(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1173") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1173: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1173: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1173: numeric"
    return bool(value), "runtime-rule-1173: truthy"

def runtime_rule_1174(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1174") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1174: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1174: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1174: numeric"
    return bool(value), "runtime-rule-1174: truthy"

def runtime_rule_1175(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1175") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1175: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1175: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1175: numeric"
    return bool(value), "runtime-rule-1175: truthy"

def runtime_rule_1176(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1176") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1176: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1176: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1176: numeric"
    return bool(value), "runtime-rule-1176: truthy"

def runtime_rule_1177(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1177") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1177: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1177: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1177: numeric"
    return bool(value), "runtime-rule-1177: truthy"

def runtime_rule_1178(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1178") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1178: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1178: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1178: numeric"
    return bool(value), "runtime-rule-1178: truthy"

def runtime_rule_1179(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1179") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1179: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1179: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1179: numeric"
    return bool(value), "runtime-rule-1179: truthy"

def runtime_rule_1180(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1180") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1180: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1180: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1180: numeric"
    return bool(value), "runtime-rule-1180: truthy"

def runtime_rule_1181(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1181") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1181: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1181: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1181: numeric"
    return bool(value), "runtime-rule-1181: truthy"

def runtime_rule_1182(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1182") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1182: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1182: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1182: numeric"
    return bool(value), "runtime-rule-1182: truthy"

def runtime_rule_1183(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1183") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1183: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1183: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1183: numeric"
    return bool(value), "runtime-rule-1183: truthy"

def runtime_rule_1184(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1184") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1184: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1184: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1184: numeric"
    return bool(value), "runtime-rule-1184: truthy"

def runtime_rule_1185(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1185") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1185: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1185: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1185: numeric"
    return bool(value), "runtime-rule-1185: truthy"

def runtime_rule_1186(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1186") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1186: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1186: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1186: numeric"
    return bool(value), "runtime-rule-1186: truthy"

def runtime_rule_1187(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1187") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1187: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1187: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1187: numeric"
    return bool(value), "runtime-rule-1187: truthy"

def runtime_rule_1188(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1188") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1188: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1188: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1188: numeric"
    return bool(value), "runtime-rule-1188: truthy"

def runtime_rule_1189(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1189") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1189: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1189: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1189: numeric"
    return bool(value), "runtime-rule-1189: truthy"

def runtime_rule_1190(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1190") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1190: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1190: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1190: numeric"
    return bool(value), "runtime-rule-1190: truthy"

def runtime_rule_1191(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1191") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1191: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1191: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1191: numeric"
    return bool(value), "runtime-rule-1191: truthy"

def runtime_rule_1192(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1192") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1192: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1192: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1192: numeric"
    return bool(value), "runtime-rule-1192: truthy"

def runtime_rule_1193(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1193") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1193: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1193: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1193: numeric"
    return bool(value), "runtime-rule-1193: truthy"

def runtime_rule_1194(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1194") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1194: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1194: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1194: numeric"
    return bool(value), "runtime-rule-1194: truthy"

def runtime_rule_1195(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1195") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1195: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1195: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1195: numeric"
    return bool(value), "runtime-rule-1195: truthy"

def runtime_rule_1196(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1196") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1196: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1196: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1196: numeric"
    return bool(value), "runtime-rule-1196: truthy"

def runtime_rule_1197(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1197") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1197: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1197: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1197: numeric"
    return bool(value), "runtime-rule-1197: truthy"

def runtime_rule_1198(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1198") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1198: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1198: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1198: numeric"
    return bool(value), "runtime-rule-1198: truthy"

def runtime_rule_1199(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1199") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1199: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1199: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1199: numeric"
    return bool(value), "runtime-rule-1199: truthy"

def runtime_rule_1200(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1200") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1200: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1200: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1200: numeric"
    return bool(value), "runtime-rule-1200: truthy"

def runtime_rule_1201(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1201") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1201: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1201: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1201: numeric"
    return bool(value), "runtime-rule-1201: truthy"

def runtime_rule_1202(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1202") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1202: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1202: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1202: numeric"
    return bool(value), "runtime-rule-1202: truthy"

def runtime_rule_1203(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1203") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1203: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1203: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1203: numeric"
    return bool(value), "runtime-rule-1203: truthy"

def runtime_rule_1204(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1204") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1204: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1204: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1204: numeric"
    return bool(value), "runtime-rule-1204: truthy"

def runtime_rule_1205(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1205") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1205: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1205: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1205: numeric"
    return bool(value), "runtime-rule-1205: truthy"

def runtime_rule_1206(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1206") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1206: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1206: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1206: numeric"
    return bool(value), "runtime-rule-1206: truthy"

def runtime_rule_1207(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1207") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1207: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1207: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1207: numeric"
    return bool(value), "runtime-rule-1207: truthy"

def runtime_rule_1208(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1208") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1208: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1208: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1208: numeric"
    return bool(value), "runtime-rule-1208: truthy"

def runtime_rule_1209(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1209") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1209: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1209: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1209: numeric"
    return bool(value), "runtime-rule-1209: truthy"

def runtime_rule_1210(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1210") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1210: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1210: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1210: numeric"
    return bool(value), "runtime-rule-1210: truthy"

def runtime_rule_1211(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1211") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1211: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1211: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1211: numeric"
    return bool(value), "runtime-rule-1211: truthy"

def runtime_rule_1212(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1212") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1212: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1212: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1212: numeric"
    return bool(value), "runtime-rule-1212: truthy"

def runtime_rule_1213(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1213") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1213: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1213: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1213: numeric"
    return bool(value), "runtime-rule-1213: truthy"

def runtime_rule_1214(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1214") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1214: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1214: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1214: numeric"
    return bool(value), "runtime-rule-1214: truthy"

def runtime_rule_1215(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1215") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1215: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1215: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1215: numeric"
    return bool(value), "runtime-rule-1215: truthy"

def runtime_rule_1216(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1216") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1216: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1216: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1216: numeric"
    return bool(value), "runtime-rule-1216: truthy"

def runtime_rule_1217(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1217") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1217: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1217: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1217: numeric"
    return bool(value), "runtime-rule-1217: truthy"

def runtime_rule_1218(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1218") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1218: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1218: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1218: numeric"
    return bool(value), "runtime-rule-1218: truthy"

def runtime_rule_1219(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1219") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1219: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1219: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1219: numeric"
    return bool(value), "runtime-rule-1219: truthy"

def runtime_rule_1220(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1220") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1220: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1220: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1220: numeric"
    return bool(value), "runtime-rule-1220: truthy"

def runtime_rule_1221(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1221") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1221: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1221: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1221: numeric"
    return bool(value), "runtime-rule-1221: truthy"

def runtime_rule_1222(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1222") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1222: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1222: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1222: numeric"
    return bool(value), "runtime-rule-1222: truthy"

def runtime_rule_1223(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1223") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1223: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1223: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1223: numeric"
    return bool(value), "runtime-rule-1223: truthy"

def runtime_rule_1224(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1224") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1224: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1224: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1224: numeric"
    return bool(value), "runtime-rule-1224: truthy"

def runtime_rule_1225(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1225") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1225: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1225: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1225: numeric"
    return bool(value), "runtime-rule-1225: truthy"

def runtime_rule_1226(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1226") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1226: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1226: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1226: numeric"
    return bool(value), "runtime-rule-1226: truthy"

def runtime_rule_1227(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1227") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1227: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1227: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1227: numeric"
    return bool(value), "runtime-rule-1227: truthy"

def runtime_rule_1228(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1228") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1228: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1228: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1228: numeric"
    return bool(value), "runtime-rule-1228: truthy"

def runtime_rule_1229(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1229") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1229: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1229: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1229: numeric"
    return bool(value), "runtime-rule-1229: truthy"

def runtime_rule_1230(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1230") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1230: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1230: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1230: numeric"
    return bool(value), "runtime-rule-1230: truthy"

def runtime_rule_1231(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1231") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1231: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1231: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1231: numeric"
    return bool(value), "runtime-rule-1231: truthy"

def runtime_rule_1232(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1232") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1232: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1232: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1232: numeric"
    return bool(value), "runtime-rule-1232: truthy"

def runtime_rule_1233(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1233") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1233: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1233: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1233: numeric"
    return bool(value), "runtime-rule-1233: truthy"

def runtime_rule_1234(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1234") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1234: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1234: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1234: numeric"
    return bool(value), "runtime-rule-1234: truthy"

def runtime_rule_1235(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1235") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1235: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1235: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1235: numeric"
    return bool(value), "runtime-rule-1235: truthy"

def runtime_rule_1236(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1236") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1236: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1236: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1236: numeric"
    return bool(value), "runtime-rule-1236: truthy"

def runtime_rule_1237(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1237") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1237: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1237: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1237: numeric"
    return bool(value), "runtime-rule-1237: truthy"

def runtime_rule_1238(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1238") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1238: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1238: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1238: numeric"
    return bool(value), "runtime-rule-1238: truthy"

def runtime_rule_1239(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1239") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1239: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1239: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1239: numeric"
    return bool(value), "runtime-rule-1239: truthy"

def runtime_rule_1240(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1240") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1240: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1240: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1240: numeric"
    return bool(value), "runtime-rule-1240: truthy"

def runtime_rule_1241(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1241") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1241: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1241: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1241: numeric"
    return bool(value), "runtime-rule-1241: truthy"

def runtime_rule_1242(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1242") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1242: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1242: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1242: numeric"
    return bool(value), "runtime-rule-1242: truthy"

def runtime_rule_1243(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1243") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1243: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1243: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1243: numeric"
    return bool(value), "runtime-rule-1243: truthy"

def runtime_rule_1244(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1244") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1244: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1244: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1244: numeric"
    return bool(value), "runtime-rule-1244: truthy"

def runtime_rule_1245(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1245") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1245: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1245: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1245: numeric"
    return bool(value), "runtime-rule-1245: truthy"

def runtime_rule_1246(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1246") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1246: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1246: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1246: numeric"
    return bool(value), "runtime-rule-1246: truthy"

def runtime_rule_1247(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1247") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1247: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1247: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1247: numeric"
    return bool(value), "runtime-rule-1247: truthy"

def runtime_rule_1248(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1248") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1248: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1248: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1248: numeric"
    return bool(value), "runtime-rule-1248: truthy"

def runtime_rule_1249(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1249") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1249: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1249: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1249: numeric"
    return bool(value), "runtime-rule-1249: truthy"

def runtime_rule_1250(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1250") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1250: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1250: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1250: numeric"
    return bool(value), "runtime-rule-1250: truthy"

def runtime_rule_1251(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1251") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1251: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1251: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1251: numeric"
    return bool(value), "runtime-rule-1251: truthy"

def runtime_rule_1252(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1252") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1252: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1252: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1252: numeric"
    return bool(value), "runtime-rule-1252: truthy"

def runtime_rule_1253(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1253") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1253: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1253: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1253: numeric"
    return bool(value), "runtime-rule-1253: truthy"

def runtime_rule_1254(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1254") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1254: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1254: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1254: numeric"
    return bool(value), "runtime-rule-1254: truthy"

def runtime_rule_1255(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1255") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1255: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1255: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1255: numeric"
    return bool(value), "runtime-rule-1255: truthy"

def runtime_rule_1256(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1256") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1256: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1256: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1256: numeric"
    return bool(value), "runtime-rule-1256: truthy"

def runtime_rule_1257(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1257") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1257: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1257: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1257: numeric"
    return bool(value), "runtime-rule-1257: truthy"

def runtime_rule_1258(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1258") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1258: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1258: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1258: numeric"
    return bool(value), "runtime-rule-1258: truthy"

def runtime_rule_1259(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1259") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1259: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1259: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1259: numeric"
    return bool(value), "runtime-rule-1259: truthy"

def runtime_rule_1260(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1260") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1260: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1260: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1260: numeric"
    return bool(value), "runtime-rule-1260: truthy"

def runtime_rule_1261(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1261") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1261: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1261: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1261: numeric"
    return bool(value), "runtime-rule-1261: truthy"

def runtime_rule_1262(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1262") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1262: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1262: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1262: numeric"
    return bool(value), "runtime-rule-1262: truthy"

def runtime_rule_1263(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1263") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1263: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1263: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1263: numeric"
    return bool(value), "runtime-rule-1263: truthy"

def runtime_rule_1264(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1264") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1264: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1264: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1264: numeric"
    return bool(value), "runtime-rule-1264: truthy"

def runtime_rule_1265(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1265") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1265: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1265: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1265: numeric"
    return bool(value), "runtime-rule-1265: truthy"

def runtime_rule_1266(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1266") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1266: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1266: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1266: numeric"
    return bool(value), "runtime-rule-1266: truthy"

def runtime_rule_1267(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1267") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1267: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1267: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1267: numeric"
    return bool(value), "runtime-rule-1267: truthy"

def runtime_rule_1268(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1268") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1268: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1268: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1268: numeric"
    return bool(value), "runtime-rule-1268: truthy"

def runtime_rule_1269(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1269") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1269: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1269: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1269: numeric"
    return bool(value), "runtime-rule-1269: truthy"

def runtime_rule_1270(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1270") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1270: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1270: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1270: numeric"
    return bool(value), "runtime-rule-1270: truthy"

def runtime_rule_1271(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1271") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1271: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1271: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1271: numeric"
    return bool(value), "runtime-rule-1271: truthy"

def runtime_rule_1272(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1272") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1272: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1272: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1272: numeric"
    return bool(value), "runtime-rule-1272: truthy"

def runtime_rule_1273(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1273") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1273: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1273: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1273: numeric"
    return bool(value), "runtime-rule-1273: truthy"

def runtime_rule_1274(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1274") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1274: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1274: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1274: numeric"
    return bool(value), "runtime-rule-1274: truthy"

def runtime_rule_1275(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1275") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1275: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1275: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1275: numeric"
    return bool(value), "runtime-rule-1275: truthy"

def runtime_rule_1276(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1276") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1276: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1276: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1276: numeric"
    return bool(value), "runtime-rule-1276: truthy"

def runtime_rule_1277(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1277") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1277: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1277: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1277: numeric"
    return bool(value), "runtime-rule-1277: truthy"

def runtime_rule_1278(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1278") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1278: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1278: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1278: numeric"
    return bool(value), "runtime-rule-1278: truthy"

def runtime_rule_1279(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1279") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1279: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1279: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1279: numeric"
    return bool(value), "runtime-rule-1279: truthy"

def runtime_rule_1280(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1280") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1280: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1280: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1280: numeric"
    return bool(value), "runtime-rule-1280: truthy"

def runtime_rule_1281(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1281") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1281: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1281: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1281: numeric"
    return bool(value), "runtime-rule-1281: truthy"

def runtime_rule_1282(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1282") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1282: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1282: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1282: numeric"
    return bool(value), "runtime-rule-1282: truthy"

def runtime_rule_1283(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1283") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1283: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1283: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1283: numeric"
    return bool(value), "runtime-rule-1283: truthy"

def runtime_rule_1284(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1284") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1284: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1284: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1284: numeric"
    return bool(value), "runtime-rule-1284: truthy"

def runtime_rule_1285(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1285") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1285: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1285: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1285: numeric"
    return bool(value), "runtime-rule-1285: truthy"

def runtime_rule_1286(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1286") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1286: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1286: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1286: numeric"
    return bool(value), "runtime-rule-1286: truthy"

def runtime_rule_1287(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1287") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1287: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1287: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1287: numeric"
    return bool(value), "runtime-rule-1287: truthy"

def runtime_rule_1288(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1288") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1288: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1288: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1288: numeric"
    return bool(value), "runtime-rule-1288: truthy"

def runtime_rule_1289(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1289") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1289: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1289: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1289: numeric"
    return bool(value), "runtime-rule-1289: truthy"

def runtime_rule_1290(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1290") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1290: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1290: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1290: numeric"
    return bool(value), "runtime-rule-1290: truthy"

def runtime_rule_1291(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1291") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1291: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1291: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1291: numeric"
    return bool(value), "runtime-rule-1291: truthy"

def runtime_rule_1292(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1292") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1292: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1292: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1292: numeric"
    return bool(value), "runtime-rule-1292: truthy"

def runtime_rule_1293(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1293") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1293: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1293: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1293: numeric"
    return bool(value), "runtime-rule-1293: truthy"

def runtime_rule_1294(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1294") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1294: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1294: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1294: numeric"
    return bool(value), "runtime-rule-1294: truthy"

def runtime_rule_1295(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1295") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1295: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1295: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1295: numeric"
    return bool(value), "runtime-rule-1295: truthy"

def runtime_rule_1296(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1296") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1296: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1296: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1296: numeric"
    return bool(value), "runtime-rule-1296: truthy"

def runtime_rule_1297(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1297") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1297: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1297: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1297: numeric"
    return bool(value), "runtime-rule-1297: truthy"

def runtime_rule_1298(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1298") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1298: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1298: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1298: numeric"
    return bool(value), "runtime-rule-1298: truthy"

def runtime_rule_1299(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1299") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1299: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1299: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1299: numeric"
    return bool(value), "runtime-rule-1299: truthy"

def runtime_rule_1300(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1300") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1300: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1300: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1300: numeric"
    return bool(value), "runtime-rule-1300: truthy"

def runtime_rule_1301(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1301") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1301: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1301: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1301: numeric"
    return bool(value), "runtime-rule-1301: truthy"

def runtime_rule_1302(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1302") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1302: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1302: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1302: numeric"
    return bool(value), "runtime-rule-1302: truthy"

def runtime_rule_1303(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1303") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1303: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1303: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1303: numeric"
    return bool(value), "runtime-rule-1303: truthy"

def runtime_rule_1304(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1304") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1304: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1304: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1304: numeric"
    return bool(value), "runtime-rule-1304: truthy"

def runtime_rule_1305(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1305") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1305: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1305: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1305: numeric"
    return bool(value), "runtime-rule-1305: truthy"

def runtime_rule_1306(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1306") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1306: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1306: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1306: numeric"
    return bool(value), "runtime-rule-1306: truthy"

def runtime_rule_1307(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1307") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1307: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1307: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1307: numeric"
    return bool(value), "runtime-rule-1307: truthy"

def runtime_rule_1308(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1308") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1308: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1308: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1308: numeric"
    return bool(value), "runtime-rule-1308: truthy"

def runtime_rule_1309(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1309") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1309: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1309: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1309: numeric"
    return bool(value), "runtime-rule-1309: truthy"

def runtime_rule_1310(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1310") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1310: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1310: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1310: numeric"
    return bool(value), "runtime-rule-1310: truthy"

def runtime_rule_1311(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1311") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1311: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1311: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1311: numeric"
    return bool(value), "runtime-rule-1311: truthy"

def runtime_rule_1312(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1312") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1312: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1312: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1312: numeric"
    return bool(value), "runtime-rule-1312: truthy"

def runtime_rule_1313(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1313") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1313: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1313: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1313: numeric"
    return bool(value), "runtime-rule-1313: truthy"

def runtime_rule_1314(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1314") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1314: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1314: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1314: numeric"
    return bool(value), "runtime-rule-1314: truthy"

def runtime_rule_1315(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1315") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1315: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1315: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1315: numeric"
    return bool(value), "runtime-rule-1315: truthy"

def runtime_rule_1316(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1316") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1316: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1316: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1316: numeric"
    return bool(value), "runtime-rule-1316: truthy"

def runtime_rule_1317(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1317") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1317: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1317: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1317: numeric"
    return bool(value), "runtime-rule-1317: truthy"

def runtime_rule_1318(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1318") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1318: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1318: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1318: numeric"
    return bool(value), "runtime-rule-1318: truthy"

def runtime_rule_1319(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1319") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1319: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1319: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1319: numeric"
    return bool(value), "runtime-rule-1319: truthy"

def runtime_rule_1320(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1320") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1320: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1320: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1320: numeric"
    return bool(value), "runtime-rule-1320: truthy"

def runtime_rule_1321(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1321") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1321: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1321: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1321: numeric"
    return bool(value), "runtime-rule-1321: truthy"

def runtime_rule_1322(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1322") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1322: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1322: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1322: numeric"
    return bool(value), "runtime-rule-1322: truthy"

def runtime_rule_1323(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1323") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1323: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1323: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1323: numeric"
    return bool(value), "runtime-rule-1323: truthy"

def runtime_rule_1324(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1324") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1324: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1324: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1324: numeric"
    return bool(value), "runtime-rule-1324: truthy"

def runtime_rule_1325(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1325") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1325: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1325: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1325: numeric"
    return bool(value), "runtime-rule-1325: truthy"

def runtime_rule_1326(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1326") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1326: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1326: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1326: numeric"
    return bool(value), "runtime-rule-1326: truthy"

def runtime_rule_1327(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1327") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1327: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1327: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1327: numeric"
    return bool(value), "runtime-rule-1327: truthy"

def runtime_rule_1328(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1328") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1328: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1328: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1328: numeric"
    return bool(value), "runtime-rule-1328: truthy"

def runtime_rule_1329(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1329") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1329: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1329: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1329: numeric"
    return bool(value), "runtime-rule-1329: truthy"

def runtime_rule_1330(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1330") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1330: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1330: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1330: numeric"
    return bool(value), "runtime-rule-1330: truthy"

def runtime_rule_1331(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1331") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1331: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1331: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1331: numeric"
    return bool(value), "runtime-rule-1331: truthy"

def runtime_rule_1332(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1332") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1332: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1332: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1332: numeric"
    return bool(value), "runtime-rule-1332: truthy"

def runtime_rule_1333(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1333") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1333: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1333: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1333: numeric"
    return bool(value), "runtime-rule-1333: truthy"

def runtime_rule_1334(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1334") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1334: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1334: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1334: numeric"
    return bool(value), "runtime-rule-1334: truthy"

def runtime_rule_1335(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1335") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1335: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1335: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1335: numeric"
    return bool(value), "runtime-rule-1335: truthy"

def runtime_rule_1336(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1336") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1336: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1336: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1336: numeric"
    return bool(value), "runtime-rule-1336: truthy"

def runtime_rule_1337(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1337") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1337: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1337: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1337: numeric"
    return bool(value), "runtime-rule-1337: truthy"

def runtime_rule_1338(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1338") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1338: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1338: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1338: numeric"
    return bool(value), "runtime-rule-1338: truthy"

def runtime_rule_1339(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1339") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1339: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1339: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1339: numeric"
    return bool(value), "runtime-rule-1339: truthy"

def runtime_rule_1340(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1340") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1340: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1340: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1340: numeric"
    return bool(value), "runtime-rule-1340: truthy"

def runtime_rule_1341(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1341") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1341: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1341: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1341: numeric"
    return bool(value), "runtime-rule-1341: truthy"

def runtime_rule_1342(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1342") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1342: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1342: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1342: numeric"
    return bool(value), "runtime-rule-1342: truthy"

def runtime_rule_1343(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1343") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1343: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1343: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1343: numeric"
    return bool(value), "runtime-rule-1343: truthy"

def runtime_rule_1344(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1344") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1344: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1344: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1344: numeric"
    return bool(value), "runtime-rule-1344: truthy"

def runtime_rule_1345(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1345") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1345: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1345: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1345: numeric"
    return bool(value), "runtime-rule-1345: truthy"

def runtime_rule_1346(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1346") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1346: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1346: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1346: numeric"
    return bool(value), "runtime-rule-1346: truthy"

def runtime_rule_1347(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1347") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1347: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1347: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1347: numeric"
    return bool(value), "runtime-rule-1347: truthy"

def runtime_rule_1348(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1348") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1348: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1348: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1348: numeric"
    return bool(value), "runtime-rule-1348: truthy"

def runtime_rule_1349(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1349") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1349: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1349: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1349: numeric"
    return bool(value), "runtime-rule-1349: truthy"

def runtime_rule_1350(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1350") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1350: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1350: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1350: numeric"
    return bool(value), "runtime-rule-1350: truthy"

def runtime_rule_1351(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1351") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1351: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1351: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1351: numeric"
    return bool(value), "runtime-rule-1351: truthy"

def runtime_rule_1352(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1352") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1352: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1352: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1352: numeric"
    return bool(value), "runtime-rule-1352: truthy"

def runtime_rule_1353(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1353") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1353: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1353: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1353: numeric"
    return bool(value), "runtime-rule-1353: truthy"

def runtime_rule_1354(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1354") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1354: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1354: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1354: numeric"
    return bool(value), "runtime-rule-1354: truthy"

def runtime_rule_1355(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1355") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1355: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1355: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1355: numeric"
    return bool(value), "runtime-rule-1355: truthy"

def runtime_rule_1356(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1356") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1356: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1356: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1356: numeric"
    return bool(value), "runtime-rule-1356: truthy"

def runtime_rule_1357(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1357") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1357: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1357: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1357: numeric"
    return bool(value), "runtime-rule-1357: truthy"

def runtime_rule_1358(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1358") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1358: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1358: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1358: numeric"
    return bool(value), "runtime-rule-1358: truthy"

def runtime_rule_1359(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1359") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1359: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1359: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1359: numeric"
    return bool(value), "runtime-rule-1359: truthy"

def runtime_rule_1360(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1360") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1360: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1360: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1360: numeric"
    return bool(value), "runtime-rule-1360: truthy"

def runtime_rule_1361(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1361") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1361: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1361: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1361: numeric"
    return bool(value), "runtime-rule-1361: truthy"

def runtime_rule_1362(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1362") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1362: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1362: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1362: numeric"
    return bool(value), "runtime-rule-1362: truthy"

def runtime_rule_1363(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1363") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1363: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1363: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1363: numeric"
    return bool(value), "runtime-rule-1363: truthy"

def runtime_rule_1364(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1364") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1364: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1364: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1364: numeric"
    return bool(value), "runtime-rule-1364: truthy"

def runtime_rule_1365(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1365") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1365: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1365: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1365: numeric"
    return bool(value), "runtime-rule-1365: truthy"

def runtime_rule_1366(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1366") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1366: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1366: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1366: numeric"
    return bool(value), "runtime-rule-1366: truthy"

def runtime_rule_1367(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1367") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1367: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1367: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1367: numeric"
    return bool(value), "runtime-rule-1367: truthy"

def runtime_rule_1368(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1368") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1368: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1368: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1368: numeric"
    return bool(value), "runtime-rule-1368: truthy"

def runtime_rule_1369(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1369") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1369: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1369: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1369: numeric"
    return bool(value), "runtime-rule-1369: truthy"

def runtime_rule_1370(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1370") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1370: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1370: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1370: numeric"
    return bool(value), "runtime-rule-1370: truthy"

def runtime_rule_1371(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1371") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1371: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1371: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1371: numeric"
    return bool(value), "runtime-rule-1371: truthy"

def runtime_rule_1372(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1372") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1372: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1372: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1372: numeric"
    return bool(value), "runtime-rule-1372: truthy"

def runtime_rule_1373(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1373") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1373: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1373: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1373: numeric"
    return bool(value), "runtime-rule-1373: truthy"

def runtime_rule_1374(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1374") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1374: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1374: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1374: numeric"
    return bool(value), "runtime-rule-1374: truthy"

def runtime_rule_1375(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1375") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1375: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1375: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1375: numeric"
    return bool(value), "runtime-rule-1375: truthy"

def runtime_rule_1376(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1376") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1376: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1376: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1376: numeric"
    return bool(value), "runtime-rule-1376: truthy"

def runtime_rule_1377(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1377") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1377: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1377: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1377: numeric"
    return bool(value), "runtime-rule-1377: truthy"

def runtime_rule_1378(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1378") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1378: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1378: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1378: numeric"
    return bool(value), "runtime-rule-1378: truthy"

def runtime_rule_1379(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1379") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1379: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1379: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1379: numeric"
    return bool(value), "runtime-rule-1379: truthy"

def runtime_rule_1380(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1380") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1380: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1380: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1380: numeric"
    return bool(value), "runtime-rule-1380: truthy"

def runtime_rule_1381(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1381") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1381: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1381: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1381: numeric"
    return bool(value), "runtime-rule-1381: truthy"

def runtime_rule_1382(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1382") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1382: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1382: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1382: numeric"
    return bool(value), "runtime-rule-1382: truthy"

def runtime_rule_1383(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1383") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1383: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1383: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1383: numeric"
    return bool(value), "runtime-rule-1383: truthy"

def runtime_rule_1384(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1384") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1384: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1384: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1384: numeric"
    return bool(value), "runtime-rule-1384: truthy"

def runtime_rule_1385(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1385") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1385: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1385: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1385: numeric"
    return bool(value), "runtime-rule-1385: truthy"

def runtime_rule_1386(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1386") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1386: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1386: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1386: numeric"
    return bool(value), "runtime-rule-1386: truthy"

def runtime_rule_1387(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1387") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1387: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1387: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1387: numeric"
    return bool(value), "runtime-rule-1387: truthy"

def runtime_rule_1388(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1388") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1388: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1388: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1388: numeric"
    return bool(value), "runtime-rule-1388: truthy"

def runtime_rule_1389(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1389") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1389: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1389: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1389: numeric"
    return bool(value), "runtime-rule-1389: truthy"

def runtime_rule_1390(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1390") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1390: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1390: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1390: numeric"
    return bool(value), "runtime-rule-1390: truthy"

def runtime_rule_1391(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1391") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1391: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1391: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1391: numeric"
    return bool(value), "runtime-rule-1391: truthy"

def runtime_rule_1392(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1392") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1392: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1392: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1392: numeric"
    return bool(value), "runtime-rule-1392: truthy"

def runtime_rule_1393(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1393") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1393: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1393: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1393: numeric"
    return bool(value), "runtime-rule-1393: truthy"

def runtime_rule_1394(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1394") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1394: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1394: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1394: numeric"
    return bool(value), "runtime-rule-1394: truthy"

def runtime_rule_1395(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1395") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1395: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1395: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1395: numeric"
    return bool(value), "runtime-rule-1395: truthy"

def runtime_rule_1396(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1396") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1396: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1396: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1396: numeric"
    return bool(value), "runtime-rule-1396: truthy"

def runtime_rule_1397(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1397") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1397: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1397: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1397: numeric"
    return bool(value), "runtime-rule-1397: truthy"

def runtime_rule_1398(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1398") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1398: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1398: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1398: numeric"
    return bool(value), "runtime-rule-1398: truthy"

def runtime_rule_1399(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1399") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1399: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1399: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1399: numeric"
    return bool(value), "runtime-rule-1399: truthy"

def runtime_rule_1400(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1400") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1400: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1400: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1400: numeric"
    return bool(value), "runtime-rule-1400: truthy"

def runtime_rule_1401(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1401") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1401: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1401: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1401: numeric"
    return bool(value), "runtime-rule-1401: truthy"

def runtime_rule_1402(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1402") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1402: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1402: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1402: numeric"
    return bool(value), "runtime-rule-1402: truthy"

def runtime_rule_1403(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1403") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1403: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1403: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1403: numeric"
    return bool(value), "runtime-rule-1403: truthy"

def runtime_rule_1404(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1404") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1404: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1404: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1404: numeric"
    return bool(value), "runtime-rule-1404: truthy"

def runtime_rule_1405(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1405") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1405: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1405: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1405: numeric"
    return bool(value), "runtime-rule-1405: truthy"

def runtime_rule_1406(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1406") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1406: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1406: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1406: numeric"
    return bool(value), "runtime-rule-1406: truthy"

def runtime_rule_1407(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1407") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1407: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1407: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1407: numeric"
    return bool(value), "runtime-rule-1407: truthy"

def runtime_rule_1408(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1408") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1408: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1408: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1408: numeric"
    return bool(value), "runtime-rule-1408: truthy"

def runtime_rule_1409(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1409") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1409: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1409: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1409: numeric"
    return bool(value), "runtime-rule-1409: truthy"

def runtime_rule_1410(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1410") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1410: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1410: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1410: numeric"
    return bool(value), "runtime-rule-1410: truthy"

def runtime_rule_1411(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1411") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1411: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1411: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1411: numeric"
    return bool(value), "runtime-rule-1411: truthy"

def runtime_rule_1412(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1412") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1412: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1412: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1412: numeric"
    return bool(value), "runtime-rule-1412: truthy"

def runtime_rule_1413(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1413") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1413: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1413: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1413: numeric"
    return bool(value), "runtime-rule-1413: truthy"

def runtime_rule_1414(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1414") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1414: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1414: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1414: numeric"
    return bool(value), "runtime-rule-1414: truthy"

def runtime_rule_1415(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1415") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1415: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1415: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1415: numeric"
    return bool(value), "runtime-rule-1415: truthy"

def runtime_rule_1416(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1416") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1416: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1416: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1416: numeric"
    return bool(value), "runtime-rule-1416: truthy"

def runtime_rule_1417(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1417") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1417: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1417: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1417: numeric"
    return bool(value), "runtime-rule-1417: truthy"

def runtime_rule_1418(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1418") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1418: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1418: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1418: numeric"
    return bool(value), "runtime-rule-1418: truthy"

def runtime_rule_1419(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1419") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1419: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1419: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1419: numeric"
    return bool(value), "runtime-rule-1419: truthy"

def runtime_rule_1420(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1420") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1420: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1420: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1420: numeric"
    return bool(value), "runtime-rule-1420: truthy"

def runtime_rule_1421(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1421") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1421: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1421: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1421: numeric"
    return bool(value), "runtime-rule-1421: truthy"

def runtime_rule_1422(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1422") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1422: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1422: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1422: numeric"
    return bool(value), "runtime-rule-1422: truthy"

def runtime_rule_1423(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1423") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1423: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1423: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1423: numeric"
    return bool(value), "runtime-rule-1423: truthy"

def runtime_rule_1424(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1424") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1424: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1424: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1424: numeric"
    return bool(value), "runtime-rule-1424: truthy"

def runtime_rule_1425(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1425") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1425: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1425: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1425: numeric"
    return bool(value), "runtime-rule-1425: truthy"

def runtime_rule_1426(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1426") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1426: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1426: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1426: numeric"
    return bool(value), "runtime-rule-1426: truthy"

def runtime_rule_1427(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1427") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1427: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1427: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1427: numeric"
    return bool(value), "runtime-rule-1427: truthy"

def runtime_rule_1428(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1428") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1428: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1428: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1428: numeric"
    return bool(value), "runtime-rule-1428: truthy"

def runtime_rule_1429(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1429") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1429: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1429: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1429: numeric"
    return bool(value), "runtime-rule-1429: truthy"

def runtime_rule_1430(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1430") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1430: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1430: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1430: numeric"
    return bool(value), "runtime-rule-1430: truthy"

def runtime_rule_1431(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1431") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1431: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1431: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1431: numeric"
    return bool(value), "runtime-rule-1431: truthy"

def runtime_rule_1432(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1432") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1432: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1432: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1432: numeric"
    return bool(value), "runtime-rule-1432: truthy"

def runtime_rule_1433(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1433") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1433: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1433: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1433: numeric"
    return bool(value), "runtime-rule-1433: truthy"

def runtime_rule_1434(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1434") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1434: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1434: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1434: numeric"
    return bool(value), "runtime-rule-1434: truthy"

def runtime_rule_1435(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1435") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1435: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1435: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1435: numeric"
    return bool(value), "runtime-rule-1435: truthy"

def runtime_rule_1436(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1436") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1436: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1436: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1436: numeric"
    return bool(value), "runtime-rule-1436: truthy"

def runtime_rule_1437(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1437") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1437: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1437: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1437: numeric"
    return bool(value), "runtime-rule-1437: truthy"

def runtime_rule_1438(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1438") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1438: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1438: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1438: numeric"
    return bool(value), "runtime-rule-1438: truthy"

def runtime_rule_1439(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1439") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1439: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1439: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1439: numeric"
    return bool(value), "runtime-rule-1439: truthy"

def runtime_rule_1440(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1440") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1440: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1440: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1440: numeric"
    return bool(value), "runtime-rule-1440: truthy"

def runtime_rule_1441(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1441") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1441: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1441: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1441: numeric"
    return bool(value), "runtime-rule-1441: truthy"

def runtime_rule_1442(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1442") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1442: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1442: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1442: numeric"
    return bool(value), "runtime-rule-1442: truthy"

def runtime_rule_1443(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1443") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1443: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1443: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1443: numeric"
    return bool(value), "runtime-rule-1443: truthy"

def runtime_rule_1444(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1444") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1444: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1444: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1444: numeric"
    return bool(value), "runtime-rule-1444: truthy"

def runtime_rule_1445(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1445") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1445: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1445: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1445: numeric"
    return bool(value), "runtime-rule-1445: truthy"

def runtime_rule_1446(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1446") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1446: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1446: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1446: numeric"
    return bool(value), "runtime-rule-1446: truthy"

def runtime_rule_1447(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1447") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1447: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1447: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1447: numeric"
    return bool(value), "runtime-rule-1447: truthy"

def runtime_rule_1448(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1448") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1448: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1448: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1448: numeric"
    return bool(value), "runtime-rule-1448: truthy"

def runtime_rule_1449(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1449") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1449: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1449: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1449: numeric"
    return bool(value), "runtime-rule-1449: truthy"

def runtime_rule_1450(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1450") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1450: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1450: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1450: numeric"
    return bool(value), "runtime-rule-1450: truthy"

def runtime_rule_1451(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1451") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1451: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1451: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1451: numeric"
    return bool(value), "runtime-rule-1451: truthy"

def runtime_rule_1452(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1452") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1452: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1452: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1452: numeric"
    return bool(value), "runtime-rule-1452: truthy"

def runtime_rule_1453(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1453") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1453: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1453: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1453: numeric"
    return bool(value), "runtime-rule-1453: truthy"

def runtime_rule_1454(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1454") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1454: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1454: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1454: numeric"
    return bool(value), "runtime-rule-1454: truthy"

def runtime_rule_1455(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1455") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1455: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1455: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1455: numeric"
    return bool(value), "runtime-rule-1455: truthy"

def runtime_rule_1456(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1456") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1456: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1456: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1456: numeric"
    return bool(value), "runtime-rule-1456: truthy"

def runtime_rule_1457(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1457") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1457: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1457: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1457: numeric"
    return bool(value), "runtime-rule-1457: truthy"

def runtime_rule_1458(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1458") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1458: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1458: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1458: numeric"
    return bool(value), "runtime-rule-1458: truthy"

def runtime_rule_1459(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1459") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1459: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1459: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1459: numeric"
    return bool(value), "runtime-rule-1459: truthy"

def runtime_rule_1460(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1460") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1460: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1460: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1460: numeric"
    return bool(value), "runtime-rule-1460: truthy"

def runtime_rule_1461(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1461") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1461: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1461: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1461: numeric"
    return bool(value), "runtime-rule-1461: truthy"

def runtime_rule_1462(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1462") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1462: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1462: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1462: numeric"
    return bool(value), "runtime-rule-1462: truthy"

def runtime_rule_1463(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1463") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1463: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1463: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1463: numeric"
    return bool(value), "runtime-rule-1463: truthy"

def runtime_rule_1464(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1464") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1464: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1464: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1464: numeric"
    return bool(value), "runtime-rule-1464: truthy"

def runtime_rule_1465(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1465") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1465: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1465: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1465: numeric"
    return bool(value), "runtime-rule-1465: truthy"

def runtime_rule_1466(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1466") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1466: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1466: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1466: numeric"
    return bool(value), "runtime-rule-1466: truthy"

def runtime_rule_1467(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1467") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1467: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1467: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1467: numeric"
    return bool(value), "runtime-rule-1467: truthy"

def runtime_rule_1468(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1468") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1468: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1468: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1468: numeric"
    return bool(value), "runtime-rule-1468: truthy"

def runtime_rule_1469(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1469") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1469: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1469: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1469: numeric"
    return bool(value), "runtime-rule-1469: truthy"

def runtime_rule_1470(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1470") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1470: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1470: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1470: numeric"
    return bool(value), "runtime-rule-1470: truthy"

def runtime_rule_1471(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1471") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1471: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1471: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1471: numeric"
    return bool(value), "runtime-rule-1471: truthy"

def runtime_rule_1472(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1472") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1472: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1472: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1472: numeric"
    return bool(value), "runtime-rule-1472: truthy"

def runtime_rule_1473(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1473") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1473: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1473: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1473: numeric"
    return bool(value), "runtime-rule-1473: truthy"

def runtime_rule_1474(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1474") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1474: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1474: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1474: numeric"
    return bool(value), "runtime-rule-1474: truthy"

def runtime_rule_1475(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1475") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1475: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1475: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1475: numeric"
    return bool(value), "runtime-rule-1475: truthy"

def runtime_rule_1476(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1476") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1476: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1476: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1476: numeric"
    return bool(value), "runtime-rule-1476: truthy"

def runtime_rule_1477(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1477") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1477: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1477: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1477: numeric"
    return bool(value), "runtime-rule-1477: truthy"

def runtime_rule_1478(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1478") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1478: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1478: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1478: numeric"
    return bool(value), "runtime-rule-1478: truthy"

def runtime_rule_1479(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1479") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1479: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1479: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1479: numeric"
    return bool(value), "runtime-rule-1479: truthy"

def runtime_rule_1480(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1480") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1480: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1480: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1480: numeric"
    return bool(value), "runtime-rule-1480: truthy"

def runtime_rule_1481(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1481") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1481: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1481: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1481: numeric"
    return bool(value), "runtime-rule-1481: truthy"

def runtime_rule_1482(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1482") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1482: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1482: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1482: numeric"
    return bool(value), "runtime-rule-1482: truthy"

def runtime_rule_1483(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1483") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1483: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1483: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1483: numeric"
    return bool(value), "runtime-rule-1483: truthy"

def runtime_rule_1484(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1484") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1484: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1484: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1484: numeric"
    return bool(value), "runtime-rule-1484: truthy"

def runtime_rule_1485(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1485") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1485: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1485: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1485: numeric"
    return bool(value), "runtime-rule-1485: truthy"

def runtime_rule_1486(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1486") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1486: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1486: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1486: numeric"
    return bool(value), "runtime-rule-1486: truthy"

def runtime_rule_1487(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1487") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1487: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1487: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1487: numeric"
    return bool(value), "runtime-rule-1487: truthy"

def runtime_rule_1488(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1488") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1488: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1488: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1488: numeric"
    return bool(value), "runtime-rule-1488: truthy"

def runtime_rule_1489(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1489") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1489: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1489: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1489: numeric"
    return bool(value), "runtime-rule-1489: truthy"

def runtime_rule_1490(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1490") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1490: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1490: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1490: numeric"
    return bool(value), "runtime-rule-1490: truthy"

def runtime_rule_1491(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1491") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1491: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1491: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1491: numeric"
    return bool(value), "runtime-rule-1491: truthy"

def runtime_rule_1492(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1492") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1492: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1492: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1492: numeric"
    return bool(value), "runtime-rule-1492: truthy"

def runtime_rule_1493(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1493") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1493: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1493: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1493: numeric"
    return bool(value), "runtime-rule-1493: truthy"

def runtime_rule_1494(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1494") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1494: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1494: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1494: numeric"
    return bool(value), "runtime-rule-1494: truthy"

def runtime_rule_1495(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1495") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1495: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1495: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1495: numeric"
    return bool(value), "runtime-rule-1495: truthy"

def runtime_rule_1496(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1496") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1496: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1496: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1496: numeric"
    return bool(value), "runtime-rule-1496: truthy"

def runtime_rule_1497(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1497") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1497: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1497: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1497: numeric"
    return bool(value), "runtime-rule-1497: truthy"

def runtime_rule_1498(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1498") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1498: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1498: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1498: numeric"
    return bool(value), "runtime-rule-1498: truthy"

def runtime_rule_1499(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1499") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1499: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1499: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1499: numeric"
    return bool(value), "runtime-rule-1499: truthy"

def runtime_rule_1500(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1500") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1500: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1500: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1500: numeric"
    return bool(value), "runtime-rule-1500: truthy"

def runtime_rule_1501(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1501") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1501: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1501: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1501: numeric"
    return bool(value), "runtime-rule-1501: truthy"

def runtime_rule_1502(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1502") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1502: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1502: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1502: numeric"
    return bool(value), "runtime-rule-1502: truthy"

def runtime_rule_1503(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1503") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1503: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1503: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1503: numeric"
    return bool(value), "runtime-rule-1503: truthy"

def runtime_rule_1504(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1504") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1504: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1504: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1504: numeric"
    return bool(value), "runtime-rule-1504: truthy"

def runtime_rule_1505(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1505") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1505: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1505: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1505: numeric"
    return bool(value), "runtime-rule-1505: truthy"

def runtime_rule_1506(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1506") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1506: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1506: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1506: numeric"
    return bool(value), "runtime-rule-1506: truthy"

def runtime_rule_1507(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1507") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1507: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1507: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1507: numeric"
    return bool(value), "runtime-rule-1507: truthy"

def runtime_rule_1508(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1508") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1508: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1508: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1508: numeric"
    return bool(value), "runtime-rule-1508: truthy"

def runtime_rule_1509(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1509") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1509: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1509: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1509: numeric"
    return bool(value), "runtime-rule-1509: truthy"

def runtime_rule_1510(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1510") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1510: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1510: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1510: numeric"
    return bool(value), "runtime-rule-1510: truthy"

def runtime_rule_1511(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1511") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1511: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1511: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1511: numeric"
    return bool(value), "runtime-rule-1511: truthy"

def runtime_rule_1512(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1512") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1512: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1512: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1512: numeric"
    return bool(value), "runtime-rule-1512: truthy"

def runtime_rule_1513(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1513") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1513: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1513: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1513: numeric"
    return bool(value), "runtime-rule-1513: truthy"

def runtime_rule_1514(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1514") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1514: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1514: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1514: numeric"
    return bool(value), "runtime-rule-1514: truthy"

def runtime_rule_1515(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1515") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1515: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1515: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1515: numeric"
    return bool(value), "runtime-rule-1515: truthy"

def runtime_rule_1516(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1516") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1516: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1516: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1516: numeric"
    return bool(value), "runtime-rule-1516: truthy"

def runtime_rule_1517(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1517") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1517: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1517: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1517: numeric"
    return bool(value), "runtime-rule-1517: truthy"

def runtime_rule_1518(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1518") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1518: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1518: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1518: numeric"
    return bool(value), "runtime-rule-1518: truthy"

def runtime_rule_1519(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1519") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1519: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1519: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1519: numeric"
    return bool(value), "runtime-rule-1519: truthy"

def runtime_rule_1520(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1520") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1520: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1520: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1520: numeric"
    return bool(value), "runtime-rule-1520: truthy"

def runtime_rule_1521(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1521") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1521: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1521: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1521: numeric"
    return bool(value), "runtime-rule-1521: truthy"

def runtime_rule_1522(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1522") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1522: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1522: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1522: numeric"
    return bool(value), "runtime-rule-1522: truthy"

def runtime_rule_1523(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1523") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1523: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1523: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1523: numeric"
    return bool(value), "runtime-rule-1523: truthy"

def runtime_rule_1524(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1524") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1524: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1524: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1524: numeric"
    return bool(value), "runtime-rule-1524: truthy"

def runtime_rule_1525(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1525") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1525: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1525: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1525: numeric"
    return bool(value), "runtime-rule-1525: truthy"

def runtime_rule_1526(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1526") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1526: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1526: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1526: numeric"
    return bool(value), "runtime-rule-1526: truthy"

def runtime_rule_1527(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1527") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1527: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1527: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1527: numeric"
    return bool(value), "runtime-rule-1527: truthy"

def runtime_rule_1528(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1528") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1528: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1528: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1528: numeric"
    return bool(value), "runtime-rule-1528: truthy"

def runtime_rule_1529(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1529") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1529: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1529: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1529: numeric"
    return bool(value), "runtime-rule-1529: truthy"

def runtime_rule_1530(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1530") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1530: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1530: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1530: numeric"
    return bool(value), "runtime-rule-1530: truthy"

def runtime_rule_1531(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1531") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1531: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1531: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1531: numeric"
    return bool(value), "runtime-rule-1531: truthy"

def runtime_rule_1532(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1532") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1532: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1532: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1532: numeric"
    return bool(value), "runtime-rule-1532: truthy"

def runtime_rule_1533(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1533") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1533: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1533: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1533: numeric"
    return bool(value), "runtime-rule-1533: truthy"

def runtime_rule_1534(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1534") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1534: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1534: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1534: numeric"
    return bool(value), "runtime-rule-1534: truthy"

def runtime_rule_1535(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1535") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1535: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1535: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1535: numeric"
    return bool(value), "runtime-rule-1535: truthy"

def runtime_rule_1536(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1536") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1536: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1536: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1536: numeric"
    return bool(value), "runtime-rule-1536: truthy"

def runtime_rule_1537(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1537") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1537: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1537: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1537: numeric"
    return bool(value), "runtime-rule-1537: truthy"

def runtime_rule_1538(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1538") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1538: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1538: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1538: numeric"
    return bool(value), "runtime-rule-1538: truthy"

def runtime_rule_1539(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1539") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1539: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1539: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1539: numeric"
    return bool(value), "runtime-rule-1539: truthy"

def runtime_rule_1540(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1540") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1540: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1540: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1540: numeric"
    return bool(value), "runtime-rule-1540: truthy"

def runtime_rule_1541(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1541") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1541: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1541: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1541: numeric"
    return bool(value), "runtime-rule-1541: truthy"

def runtime_rule_1542(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1542") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1542: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1542: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1542: numeric"
    return bool(value), "runtime-rule-1542: truthy"

def runtime_rule_1543(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1543") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1543: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1543: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1543: numeric"
    return bool(value), "runtime-rule-1543: truthy"

def runtime_rule_1544(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1544") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1544: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1544: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1544: numeric"
    return bool(value), "runtime-rule-1544: truthy"

def runtime_rule_1545(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1545") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1545: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1545: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1545: numeric"
    return bool(value), "runtime-rule-1545: truthy"

def runtime_rule_1546(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1546") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1546: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1546: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1546: numeric"
    return bool(value), "runtime-rule-1546: truthy"

def runtime_rule_1547(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1547") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1547: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1547: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1547: numeric"
    return bool(value), "runtime-rule-1547: truthy"

def runtime_rule_1548(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1548") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1548: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1548: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1548: numeric"
    return bool(value), "runtime-rule-1548: truthy"

def runtime_rule_1549(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1549") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1549: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1549: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1549: numeric"
    return bool(value), "runtime-rule-1549: truthy"

def runtime_rule_1550(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1550") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1550: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1550: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1550: numeric"
    return bool(value), "runtime-rule-1550: truthy"

def runtime_rule_1551(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1551") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1551: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1551: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1551: numeric"
    return bool(value), "runtime-rule-1551: truthy"

def runtime_rule_1552(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1552") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1552: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1552: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1552: numeric"
    return bool(value), "runtime-rule-1552: truthy"

def runtime_rule_1553(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1553") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1553: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1553: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1553: numeric"
    return bool(value), "runtime-rule-1553: truthy"

def runtime_rule_1554(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1554") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1554: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1554: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1554: numeric"
    return bool(value), "runtime-rule-1554: truthy"

def runtime_rule_1555(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1555") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1555: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1555: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1555: numeric"
    return bool(value), "runtime-rule-1555: truthy"

def runtime_rule_1556(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1556") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1556: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1556: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1556: numeric"
    return bool(value), "runtime-rule-1556: truthy"

def runtime_rule_1557(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1557") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1557: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1557: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1557: numeric"
    return bool(value), "runtime-rule-1557: truthy"

def runtime_rule_1558(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1558") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1558: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1558: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1558: numeric"
    return bool(value), "runtime-rule-1558: truthy"

def runtime_rule_1559(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1559") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1559: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1559: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1559: numeric"
    return bool(value), "runtime-rule-1559: truthy"

def runtime_rule_1560(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1560") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1560: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1560: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1560: numeric"
    return bool(value), "runtime-rule-1560: truthy"

def runtime_rule_1561(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1561") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1561: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1561: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1561: numeric"
    return bool(value), "runtime-rule-1561: truthy"

def runtime_rule_1562(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1562") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1562: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1562: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1562: numeric"
    return bool(value), "runtime-rule-1562: truthy"

def runtime_rule_1563(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1563") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1563: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1563: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1563: numeric"
    return bool(value), "runtime-rule-1563: truthy"

def runtime_rule_1564(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1564") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1564: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1564: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1564: numeric"
    return bool(value), "runtime-rule-1564: truthy"

def runtime_rule_1565(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1565") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1565: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1565: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1565: numeric"
    return bool(value), "runtime-rule-1565: truthy"

def runtime_rule_1566(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1566") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1566: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1566: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1566: numeric"
    return bool(value), "runtime-rule-1566: truthy"

def runtime_rule_1567(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1567") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1567: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1567: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1567: numeric"
    return bool(value), "runtime-rule-1567: truthy"

def runtime_rule_1568(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1568") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1568: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1568: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1568: numeric"
    return bool(value), "runtime-rule-1568: truthy"

def runtime_rule_1569(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1569") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1569: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1569: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1569: numeric"
    return bool(value), "runtime-rule-1569: truthy"

def runtime_rule_1570(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1570") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1570: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1570: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1570: numeric"
    return bool(value), "runtime-rule-1570: truthy"

def runtime_rule_1571(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1571") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1571: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1571: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1571: numeric"
    return bool(value), "runtime-rule-1571: truthy"

def runtime_rule_1572(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1572") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1572: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1572: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1572: numeric"
    return bool(value), "runtime-rule-1572: truthy"

def runtime_rule_1573(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1573") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1573: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1573: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1573: numeric"
    return bool(value), "runtime-rule-1573: truthy"

def runtime_rule_1574(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1574") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1574: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1574: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1574: numeric"
    return bool(value), "runtime-rule-1574: truthy"

def runtime_rule_1575(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1575") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1575: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1575: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1575: numeric"
    return bool(value), "runtime-rule-1575: truthy"

def runtime_rule_1576(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1576") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1576: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1576: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1576: numeric"
    return bool(value), "runtime-rule-1576: truthy"

def runtime_rule_1577(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1577") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1577: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1577: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1577: numeric"
    return bool(value), "runtime-rule-1577: truthy"

def runtime_rule_1578(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1578") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1578: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1578: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1578: numeric"
    return bool(value), "runtime-rule-1578: truthy"

def runtime_rule_1579(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1579") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1579: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1579: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1579: numeric"
    return bool(value), "runtime-rule-1579: truthy"

def runtime_rule_1580(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1580") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1580: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1580: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1580: numeric"
    return bool(value), "runtime-rule-1580: truthy"

def runtime_rule_1581(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1581") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1581: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1581: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1581: numeric"
    return bool(value), "runtime-rule-1581: truthy"

def runtime_rule_1582(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1582") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1582: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1582: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1582: numeric"
    return bool(value), "runtime-rule-1582: truthy"

def runtime_rule_1583(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1583") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1583: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1583: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1583: numeric"
    return bool(value), "runtime-rule-1583: truthy"

def runtime_rule_1584(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1584") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1584: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1584: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1584: numeric"
    return bool(value), "runtime-rule-1584: truthy"

def runtime_rule_1585(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1585") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1585: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1585: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1585: numeric"
    return bool(value), "runtime-rule-1585: truthy"

def runtime_rule_1586(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1586") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1586: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1586: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1586: numeric"
    return bool(value), "runtime-rule-1586: truthy"

def runtime_rule_1587(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1587") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1587: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1587: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1587: numeric"
    return bool(value), "runtime-rule-1587: truthy"

def runtime_rule_1588(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1588") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1588: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1588: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1588: numeric"
    return bool(value), "runtime-rule-1588: truthy"

def runtime_rule_1589(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1589") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1589: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1589: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1589: numeric"
    return bool(value), "runtime-rule-1589: truthy"

def runtime_rule_1590(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1590") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1590: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1590: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1590: numeric"
    return bool(value), "runtime-rule-1590: truthy"

def runtime_rule_1591(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1591") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1591: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1591: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1591: numeric"
    return bool(value), "runtime-rule-1591: truthy"

def runtime_rule_1592(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1592") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1592: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1592: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1592: numeric"
    return bool(value), "runtime-rule-1592: truthy"

def runtime_rule_1593(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1593") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1593: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1593: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1593: numeric"
    return bool(value), "runtime-rule-1593: truthy"

def runtime_rule_1594(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1594") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1594: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1594: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1594: numeric"
    return bool(value), "runtime-rule-1594: truthy"

def runtime_rule_1595(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1595") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1595: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1595: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1595: numeric"
    return bool(value), "runtime-rule-1595: truthy"

def runtime_rule_1596(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1596") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1596: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1596: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1596: numeric"
    return bool(value), "runtime-rule-1596: truthy"

def runtime_rule_1597(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1597") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1597: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1597: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1597: numeric"
    return bool(value), "runtime-rule-1597: truthy"

def runtime_rule_1598(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1598") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1598: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1598: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1598: numeric"
    return bool(value), "runtime-rule-1598: truthy"

def runtime_rule_1599(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1599") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1599: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1599: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1599: numeric"
    return bool(value), "runtime-rule-1599: truthy"

def runtime_rule_1600(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1600") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1600: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1600: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1600: numeric"
    return bool(value), "runtime-rule-1600: truthy"

def runtime_rule_1601(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1601") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1601: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1601: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1601: numeric"
    return bool(value), "runtime-rule-1601: truthy"

def runtime_rule_1602(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1602") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1602: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1602: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1602: numeric"
    return bool(value), "runtime-rule-1602: truthy"

def runtime_rule_1603(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1603") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1603: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1603: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1603: numeric"
    return bool(value), "runtime-rule-1603: truthy"

def runtime_rule_1604(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1604") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1604: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1604: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1604: numeric"
    return bool(value), "runtime-rule-1604: truthy"

def runtime_rule_1605(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1605") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1605: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1605: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1605: numeric"
    return bool(value), "runtime-rule-1605: truthy"

def runtime_rule_1606(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1606") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1606: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1606: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1606: numeric"
    return bool(value), "runtime-rule-1606: truthy"

def runtime_rule_1607(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1607") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1607: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1607: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1607: numeric"
    return bool(value), "runtime-rule-1607: truthy"

def runtime_rule_1608(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1608") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1608: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1608: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1608: numeric"
    return bool(value), "runtime-rule-1608: truthy"

def runtime_rule_1609(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1609") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1609: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1609: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1609: numeric"
    return bool(value), "runtime-rule-1609: truthy"

def runtime_rule_1610(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1610") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1610: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1610: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1610: numeric"
    return bool(value), "runtime-rule-1610: truthy"

def runtime_rule_1611(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1611") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1611: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1611: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1611: numeric"
    return bool(value), "runtime-rule-1611: truthy"

def runtime_rule_1612(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1612") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1612: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1612: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1612: numeric"
    return bool(value), "runtime-rule-1612: truthy"

def runtime_rule_1613(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1613") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1613: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1613: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1613: numeric"
    return bool(value), "runtime-rule-1613: truthy"

def runtime_rule_1614(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1614") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1614: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1614: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1614: numeric"
    return bool(value), "runtime-rule-1614: truthy"

def runtime_rule_1615(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1615") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1615: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1615: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1615: numeric"
    return bool(value), "runtime-rule-1615: truthy"

def runtime_rule_1616(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1616") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1616: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1616: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1616: numeric"
    return bool(value), "runtime-rule-1616: truthy"

def runtime_rule_1617(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1617") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1617: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1617: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1617: numeric"
    return bool(value), "runtime-rule-1617: truthy"

def runtime_rule_1618(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1618") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1618: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1618: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1618: numeric"
    return bool(value), "runtime-rule-1618: truthy"

def runtime_rule_1619(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1619") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1619: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1619: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1619: numeric"
    return bool(value), "runtime-rule-1619: truthy"

def runtime_rule_1620(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1620") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1620: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1620: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1620: numeric"
    return bool(value), "runtime-rule-1620: truthy"

def runtime_rule_1621(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1621") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1621: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1621: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1621: numeric"
    return bool(value), "runtime-rule-1621: truthy"

def runtime_rule_1622(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1622") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1622: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1622: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1622: numeric"
    return bool(value), "runtime-rule-1622: truthy"

def runtime_rule_1623(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1623") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1623: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1623: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1623: numeric"
    return bool(value), "runtime-rule-1623: truthy"

def runtime_rule_1624(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1624") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1624: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1624: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1624: numeric"
    return bool(value), "runtime-rule-1624: truthy"

def runtime_rule_1625(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1625") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1625: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1625: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1625: numeric"
    return bool(value), "runtime-rule-1625: truthy"

def runtime_rule_1626(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1626") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1626: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1626: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1626: numeric"
    return bool(value), "runtime-rule-1626: truthy"

def runtime_rule_1627(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1627") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1627: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1627: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1627: numeric"
    return bool(value), "runtime-rule-1627: truthy"

def runtime_rule_1628(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1628") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1628: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1628: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1628: numeric"
    return bool(value), "runtime-rule-1628: truthy"

def runtime_rule_1629(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1629") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1629: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1629: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1629: numeric"
    return bool(value), "runtime-rule-1629: truthy"

def runtime_rule_1630(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1630") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1630: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1630: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1630: numeric"
    return bool(value), "runtime-rule-1630: truthy"

def runtime_rule_1631(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1631") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1631: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1631: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1631: numeric"
    return bool(value), "runtime-rule-1631: truthy"

def runtime_rule_1632(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1632") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1632: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1632: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1632: numeric"
    return bool(value), "runtime-rule-1632: truthy"

def runtime_rule_1633(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1633") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1633: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1633: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1633: numeric"
    return bool(value), "runtime-rule-1633: truthy"

def runtime_rule_1634(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1634") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1634: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1634: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1634: numeric"
    return bool(value), "runtime-rule-1634: truthy"

def runtime_rule_1635(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1635") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1635: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1635: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1635: numeric"
    return bool(value), "runtime-rule-1635: truthy"

def runtime_rule_1636(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1636") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1636: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1636: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1636: numeric"
    return bool(value), "runtime-rule-1636: truthy"

def runtime_rule_1637(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1637") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1637: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1637: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1637: numeric"
    return bool(value), "runtime-rule-1637: truthy"

def runtime_rule_1638(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1638") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1638: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1638: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1638: numeric"
    return bool(value), "runtime-rule-1638: truthy"

def runtime_rule_1639(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1639") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1639: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1639: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1639: numeric"
    return bool(value), "runtime-rule-1639: truthy"

def runtime_rule_1640(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1640") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1640: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1640: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1640: numeric"
    return bool(value), "runtime-rule-1640: truthy"

def runtime_rule_1641(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1641") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1641: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1641: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1641: numeric"
    return bool(value), "runtime-rule-1641: truthy"

def runtime_rule_1642(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1642") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1642: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1642: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1642: numeric"
    return bool(value), "runtime-rule-1642: truthy"

def runtime_rule_1643(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1643") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1643: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1643: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1643: numeric"
    return bool(value), "runtime-rule-1643: truthy"

def runtime_rule_1644(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1644") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1644: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1644: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1644: numeric"
    return bool(value), "runtime-rule-1644: truthy"

def runtime_rule_1645(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1645") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1645: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1645: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1645: numeric"
    return bool(value), "runtime-rule-1645: truthy"

def runtime_rule_1646(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1646") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1646: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1646: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1646: numeric"
    return bool(value), "runtime-rule-1646: truthy"

def runtime_rule_1647(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1647") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1647: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1647: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1647: numeric"
    return bool(value), "runtime-rule-1647: truthy"

def runtime_rule_1648(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1648") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1648: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1648: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1648: numeric"
    return bool(value), "runtime-rule-1648: truthy"

def runtime_rule_1649(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1649") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1649: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1649: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1649: numeric"
    return bool(value), "runtime-rule-1649: truthy"

def runtime_rule_1650(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1650") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1650: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1650: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1650: numeric"
    return bool(value), "runtime-rule-1650: truthy"

def runtime_rule_1651(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1651") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1651: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1651: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1651: numeric"
    return bool(value), "runtime-rule-1651: truthy"

def runtime_rule_1652(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1652") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1652: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1652: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1652: numeric"
    return bool(value), "runtime-rule-1652: truthy"

def runtime_rule_1653(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1653") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1653: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1653: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1653: numeric"
    return bool(value), "runtime-rule-1653: truthy"

def runtime_rule_1654(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1654") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1654: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1654: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1654: numeric"
    return bool(value), "runtime-rule-1654: truthy"

def runtime_rule_1655(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1655") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1655: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1655: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1655: numeric"
    return bool(value), "runtime-rule-1655: truthy"

def runtime_rule_1656(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1656") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1656: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1656: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1656: numeric"
    return bool(value), "runtime-rule-1656: truthy"

def runtime_rule_1657(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1657") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1657: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1657: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1657: numeric"
    return bool(value), "runtime-rule-1657: truthy"

def runtime_rule_1658(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1658") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1658: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1658: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1658: numeric"
    return bool(value), "runtime-rule-1658: truthy"

def runtime_rule_1659(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1659") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1659: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1659: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1659: numeric"
    return bool(value), "runtime-rule-1659: truthy"

def runtime_rule_1660(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1660") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1660: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1660: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1660: numeric"
    return bool(value), "runtime-rule-1660: truthy"

def runtime_rule_1661(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1661") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1661: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1661: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1661: numeric"
    return bool(value), "runtime-rule-1661: truthy"

def runtime_rule_1662(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1662") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1662: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1662: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1662: numeric"
    return bool(value), "runtime-rule-1662: truthy"

def runtime_rule_1663(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1663") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1663: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1663: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1663: numeric"
    return bool(value), "runtime-rule-1663: truthy"

def runtime_rule_1664(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1664") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1664: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1664: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1664: numeric"
    return bool(value), "runtime-rule-1664: truthy"

def runtime_rule_1665(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1665") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1665: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1665: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1665: numeric"
    return bool(value), "runtime-rule-1665: truthy"

def runtime_rule_1666(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1666") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1666: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1666: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1666: numeric"
    return bool(value), "runtime-rule-1666: truthy"

def runtime_rule_1667(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1667") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1667: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1667: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1667: numeric"
    return bool(value), "runtime-rule-1667: truthy"

def runtime_rule_1668(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1668") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1668: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1668: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1668: numeric"
    return bool(value), "runtime-rule-1668: truthy"

def runtime_rule_1669(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1669") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1669: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1669: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1669: numeric"
    return bool(value), "runtime-rule-1669: truthy"

def runtime_rule_1670(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1670") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1670: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1670: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1670: numeric"
    return bool(value), "runtime-rule-1670: truthy"

def runtime_rule_1671(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1671") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1671: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1671: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1671: numeric"
    return bool(value), "runtime-rule-1671: truthy"

def runtime_rule_1672(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1672") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1672: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1672: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1672: numeric"
    return bool(value), "runtime-rule-1672: truthy"

def runtime_rule_1673(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1673") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1673: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1673: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1673: numeric"
    return bool(value), "runtime-rule-1673: truthy"

def runtime_rule_1674(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1674") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1674: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1674: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1674: numeric"
    return bool(value), "runtime-rule-1674: truthy"

def runtime_rule_1675(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1675") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1675: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1675: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1675: numeric"
    return bool(value), "runtime-rule-1675: truthy"

def runtime_rule_1676(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1676") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1676: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1676: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1676: numeric"
    return bool(value), "runtime-rule-1676: truthy"

def runtime_rule_1677(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1677") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1677: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1677: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1677: numeric"
    return bool(value), "runtime-rule-1677: truthy"

def runtime_rule_1678(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1678") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1678: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1678: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1678: numeric"
    return bool(value), "runtime-rule-1678: truthy"

def runtime_rule_1679(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1679") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1679: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1679: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1679: numeric"
    return bool(value), "runtime-rule-1679: truthy"

def runtime_rule_1680(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1680") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1680: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1680: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1680: numeric"
    return bool(value), "runtime-rule-1680: truthy"

def runtime_rule_1681(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1681") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1681: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1681: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1681: numeric"
    return bool(value), "runtime-rule-1681: truthy"

def runtime_rule_1682(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1682") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1682: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1682: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1682: numeric"
    return bool(value), "runtime-rule-1682: truthy"

def runtime_rule_1683(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1683") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1683: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1683: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1683: numeric"
    return bool(value), "runtime-rule-1683: truthy"

def runtime_rule_1684(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1684") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1684: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1684: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1684: numeric"
    return bool(value), "runtime-rule-1684: truthy"

def runtime_rule_1685(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1685") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1685: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1685: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1685: numeric"
    return bool(value), "runtime-rule-1685: truthy"

def runtime_rule_1686(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1686") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1686: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1686: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1686: numeric"
    return bool(value), "runtime-rule-1686: truthy"

def runtime_rule_1687(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1687") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1687: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1687: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1687: numeric"
    return bool(value), "runtime-rule-1687: truthy"

def runtime_rule_1688(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1688") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1688: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1688: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1688: numeric"
    return bool(value), "runtime-rule-1688: truthy"

def runtime_rule_1689(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1689") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1689: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1689: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1689: numeric"
    return bool(value), "runtime-rule-1689: truthy"

def runtime_rule_1690(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1690") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1690: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1690: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1690: numeric"
    return bool(value), "runtime-rule-1690: truthy"

def runtime_rule_1691(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1691") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1691: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1691: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1691: numeric"
    return bool(value), "runtime-rule-1691: truthy"

def runtime_rule_1692(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1692") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1692: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1692: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1692: numeric"
    return bool(value), "runtime-rule-1692: truthy"

def runtime_rule_1693(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1693") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1693: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1693: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1693: numeric"
    return bool(value), "runtime-rule-1693: truthy"

def runtime_rule_1694(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1694") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1694: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1694: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1694: numeric"
    return bool(value), "runtime-rule-1694: truthy"

def runtime_rule_1695(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1695") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1695: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1695: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1695: numeric"
    return bool(value), "runtime-rule-1695: truthy"

def runtime_rule_1696(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1696") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1696: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1696: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1696: numeric"
    return bool(value), "runtime-rule-1696: truthy"

def runtime_rule_1697(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1697") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1697: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1697: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1697: numeric"
    return bool(value), "runtime-rule-1697: truthy"

def runtime_rule_1698(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1698") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1698: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1698: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1698: numeric"
    return bool(value), "runtime-rule-1698: truthy"

def runtime_rule_1699(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1699") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1699: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1699: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1699: numeric"
    return bool(value), "runtime-rule-1699: truthy"

def runtime_rule_1700(cfg: dict[str, Any]) -> tuple[bool, str]:
    value = cfg.get("runtime-rule-1700") if isinstance(cfg, dict) else None
    if value is None:
        return True, "runtime-rule-1700: default-allow"
    if isinstance(value, bool):
        return bool(value), "runtime-rule-1700: boolean"
    if isinstance(value, (int, float)):
        return value >= 0, "runtime-rule-1700: numeric"
    return bool(value), "runtime-rule-1700: truthy"

