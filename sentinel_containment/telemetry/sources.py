from __future__ import annotations

import http.server
import json
import logging
import os
import socketserver
import threading
import time
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
    _offset: int = 0

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
            self.file_sources.append(JSONLinesFileSource(path, source_type, ingestor))
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        udp_thread = threading.Thread(target=self.syslog_server.serve_forever, daemon=True)
        udp_thread.start()
        self._threads.append(udp_thread)

        kernel_thread = threading.Thread(target=self.kernel_webhook_server.serve_forever, daemon=True)
        kernel_thread.start()
        self._threads.append(kernel_thread)

        for source in self.file_sources:
            t = threading.Thread(target=source.run_forever, daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self.syslog_server.shutdown()
        self.syslog_server.server_close()
        self.kernel_webhook_server.shutdown()
        self.kernel_webhook_server.server_close()
