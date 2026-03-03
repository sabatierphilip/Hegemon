from __future__ import annotations

import http.server
import json
import logging
import os
import platform
import re
import stat
import socketserver
import subprocess
import threading
import time
import hmac
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from sentinel_containment.telemetry.ingestor import TelemetryIngestor

logger = logging.getLogger(__name__)


def discover_live_file_sources(existing: dict[str, Path] | None = None) -> dict[str, Path]:
    existing = existing or {}
    discovered: dict[str, Path] = {}

    env_dirs = os.getenv("TELEMETRY_AUTODISCOVER_DIRS", "")
    candidate_dirs = [Path("data"), Path("/var/log")]
    candidate_dirs.extend(Path(part.strip()) for part in env_dirs.split(",") if part.strip())

    candidates = {
        "cloud_audit": ("cloudtrail.jsonl", "audit.jsonl"),
        "network_flow": ("network_flows.jsonl", "netflow.jsonl"),
        "model_api": ("model_api.jsonl", "model_events.jsonl"),
        "host_osquery": ("osquery_events.jsonl",),
        "host_kernel": ("kernel_events.jsonl",),
        "host_runtime": ("runtime_events.jsonl",),
        "hypervisor": ("hypervisor_events.jsonl",),
        "counterclone": ("counterclone_events.jsonl",),
    }
    known = {str(path.resolve()) for path in existing.values()}
    for source_type, names in candidates.items():
        if source_type in existing:
            continue
        for directory in candidate_dirs:
            for name in names:
                path = directory / name
                try:
                    resolved = str(path.resolve())
                except FileNotFoundError:
                    resolved = str(path.absolute())
                if resolved in known:
                    continue
                if path.exists():
                    discovered[source_type] = path
                    known.add(resolved)
                    break
            if source_type in discovered:
                break
    return discovered


class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = self.request[0].decode("utf-8", errors="replace").strip()
        server: "SyslogUDPServer" = self.server  # type: ignore[assignment]
        payload = parse_syslog_line(data)
        server.ingestor.ingest("syslog", payload)


class SyslogUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True

    def __init__(self, host: str, port: int, ingestor: TelemetryIngestor):
        self.ingestor = ingestor
        super().__init__((host, port), SyslogUDPHandler)


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class PushWebhookHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802 - standard handler name
        server: "PushWebhookServer" = self.server  # type: ignore[assignment]
        if self.path != server.path:
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"error":"invalid_json"}')
            return

        if not isinstance(payload, dict):
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"error":"event_must_be_object"}')
            return

        server.ingestor.ingest(server.source_type, payload)
        if server.on_event:
            try:
                server.on_event(payload)
            except Exception:  # pragma: no cover - never break ingestion on callback failure
                logger.exception("Push webhook callback failed")
        self.send_response(202)
        self.end_headers()
        self.wfile.write(b'{"accepted":true}')

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: A003 - inherited name
        logger.debug("push-webhook %s", fmt % args)


class PushWebhookServer(ThreadingHTTPServer):
    def __init__(
        self,
        host: str,
        port: int,
        ingestor: TelemetryIngestor,
        source_type: str,
        path: str,
        on_event: Callable[[dict[str, Any]], None] | None = None,
    ):
        self.ingestor = ingestor
        self.source_type = source_type
        self.path = path
        self.on_event = on_event
        super().__init__((host, port), PushWebhookHandler)


def parse_syslog_line(line: str) -> dict[str, Any]:
    host = "unknown"
    process = "syslog"
    action = "log"
    message = line

    rfc3164 = re.match(
        r"^(?:<\d+>)?(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<proc>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$",
        line,
    )
    if rfc3164:
        host = rfc3164.group("host") or host
        process = rfc3164.group("proc") or process
        message = rfc3164.group("msg") or ""
        action = "syslog_event"
    else:
        parts = line.split()
        if len(parts) >= 5:
            host = parts[3]
            proc_part = parts[4]
            process = proc_part.rstrip(":")
            message = " ".join(parts[5:]) if len(parts) > 5 else ""
            action = "syslog_event"

    return {
        "host": host,
        "user": "unknown",
        "process": process,
        "action": action,
        "resource": "system",
        "message": message,
        "raw": line,
        "collector_level": "os",
        "telemetry_scope": "syslog",
    }


@dataclass
class JSONLinesFileSource:
    path: Path
    source_type: str
    ingestor: TelemetryIngestor
    poll_interval_seconds: float = 1.0
    integrity_key: str | None = None
    _offset: int = 0

    def _file_guard_verified(self) -> bool:
        try:
            st = self.path.lstat()
        except FileNotFoundError:
            return False
        if stat.S_ISLNK(st.st_mode):
            return False
        if not stat.S_ISREG(st.st_mode):
            return False
        # Reject world-writable telemetry feeds to reduce collector tampering risk.
        if bool(st.st_mode & stat.S_IWOTH):
            return False
        return True

    def _verify_counterclone_integrity(self, payload: dict[str, Any]) -> bool:
        if self.source_type != "counterclone":
            return False
        if not self.integrity_key:
            return False
        signature = str(payload.get("counterclone_file_signature", "")).strip()
        if not signature:
            return False

        candidate = dict(payload)
        candidate.pop("counterclone_file_signature", None)
        candidate.pop("collector_file_guard_verified", None)
        canonical = json.dumps(candidate, sort_keys=True, separators=(",", ":")).encode("utf-8")
        expected = hmac.new(self.integrity_key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)

    def poll_once(self) -> int:
        if not self.path.exists():
            return 0

        processed = 0
        with self.path.open("r", encoding="utf-8") as f:
            f.seek(self._offset)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                    if isinstance(payload, dict):
                        payload["collector_file_guard_verified"] = self._file_guard_verified()
                        if self.source_type == "counterclone":
                            payload["counterclone_integrity_verified"] = self._verify_counterclone_integrity(payload)
                        self.ingestor.ingest(self.source_type, payload)
                        processed += 1
                except json.JSONDecodeError:
                    logger.warning("Invalid JSON line in %s", self.path)
            self._offset = f.tell()
        return processed

    def run_forever(self, stop_check: Callable[[], bool] | None = None) -> None:
        while True:
            if stop_check and stop_check():
                return
            self.poll_once()
            time.sleep(self.poll_interval_seconds)


class IngestionService:
    def __init__(
        self,
        ingestor: TelemetryIngestor,
        syslog_host: str,
        syslog_port: int,
        cloudtrail_path: Path,
        network_flow_path: Path,
        model_api_path: Path,
        extra_sources: dict[str, Path] | None = None,
        kernel_webhook_host: str = "0.0.0.0",
        kernel_webhook_port: int = 5515,
        kernel_webhook_path: str = "/kernel-event",
        on_kernel_event: Callable[[dict[str, Any]], None] | None = None,
        counterclone_integrity_key: str | None = None,
    ):
        self.ingestor = ingestor
        self.syslog_server = SyslogUDPServer(syslog_host, syslog_port, ingestor)
        self.kernel_webhook_server = PushWebhookServer(
            kernel_webhook_host,
            kernel_webhook_port,
            ingestor,
            source_type="host_kernel",
            path=kernel_webhook_path,
            on_event=on_kernel_event,
        )
        self.file_sources = [
            JSONLinesFileSource(cloudtrail_path, "cloud_audit", ingestor),
            JSONLinesFileSource(network_flow_path, "network_flow", ingestor),
            JSONLinesFileSource(model_api_path, "model_api", ingestor),
        ]
        for source_type, path in (extra_sources or {}).items():
            self.file_sources.append(
                JSONLinesFileSource(
                    path,
                    source_type,
                    ingestor,
                    integrity_key=counterclone_integrity_key,
                )
            )
        self._threads: list[threading.Thread] = []
        self._started = False

    def _start_file_source_thread(self, source: JSONLinesFileSource) -> None:
        t = threading.Thread(target=source.run_forever, daemon=True)
        t.start()
        self._threads.append(t)

    def add_file_source(self, source_type: str, path: Path, counterclone_integrity_key: str | None = None) -> bool:
        if any(fs.source_type == source_type and fs.path == path for fs in self.file_sources):
            return False
        source = JSONLinesFileSource(path, source_type, self.ingestor, integrity_key=counterclone_integrity_key)
        self.file_sources.append(source)
        if self._started:
            self._start_file_source_thread(source)
        return True

    def start(self) -> None:
        udp_thread = threading.Thread(target=self.syslog_server.serve_forever, daemon=True)
        udp_thread.start()
        self._threads.append(udp_thread)

        kernel_thread = threading.Thread(target=self.kernel_webhook_server.serve_forever, daemon=True)
        kernel_thread.start()
        self._threads.append(kernel_thread)

        for source in self.file_sources:
            self._start_file_source_thread(source)
        self._started = True

    def stop(self) -> None:
        if self._started:
            self.syslog_server.shutdown()
            self.kernel_webhook_server.shutdown()
        self.syslog_server.server_close()
        self.kernel_webhook_server.server_close()
        self._started = False


class DynamicSystemTelemetrySource:
    """Collects lightweight, real host telemetry snapshots from procfs and platform commands."""

    def __init__(self, ingestor: TelemetryIngestor, poll_interval_seconds: float = 10.0):
        self.ingestor = ingestor
        self.poll_interval_seconds = poll_interval_seconds

    def _safe_run(self, command: list[str]) -> str:
        try:
            result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=3)
            output = result.stdout.strip()
            output = re.sub(r"(?i)(token|secret|password)=[^\s]+", r"\1=<redacted>", output)
            return output[:4000]
        except subprocess.TimeoutExpired:
            return ""
        except FileNotFoundError:
            return ""
        except Exception:
            logger.exception("safe_run failed for command: %s", command)
            return ""

    def poll_once(self) -> None:
        host = platform.node() or "localhost"
        loadavg = ""
        if Path("/proc/loadavg").exists():
            loadavg = Path("/proc/loadavg").read_text(encoding="utf-8").strip()
        meminfo = ""
        if Path("/proc/meminfo").exists():
            meminfo = "\n".join(Path("/proc/meminfo").read_text(encoding="utf-8").splitlines()[:4])

        self.ingestor.ingest(
            "host_runtime",
            {
                "host": host,
                "process": "dynamic-runtime-collector",
                "action": "system_snapshot",
                "resource": "procfs",
                "loadavg": loadavg,
                "meminfo_head": meminfo,
                "collector_level": "runtime",
                "telemetry_scope": "dynamic_system",
            },
        )

        socket_summary = self._safe_run(["ss", "-tunap"]) or self._safe_run(["netstat", "-tunap"])
        self.ingestor.ingest(
            "network_flow",
            {
                "host": host,
                "process": "dynamic-network-collector",
                "action": "socket_inventory",
                "resource": "system_network",
                "socket_table": socket_summary,
                "collector_level": "os",
                "telemetry_scope": "dynamic_network",
            },
        )

    def run_forever(self, stop_check: Callable[[], bool] | None = None) -> None:
        while True:
            if stop_check and stop_check():
                return
            self.poll_once()
            time.sleep(self.poll_interval_seconds)
