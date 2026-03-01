from __future__ import annotations

import json
import logging
import socketserver
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from sentinel_containment.telemetry.ingestor import TelemetryIngestor

logger = logging.getLogger(__name__)


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
    ):
        self.ingestor = ingestor
        self.syslog_server = SyslogUDPServer(syslog_host, syslog_port, ingestor)
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

        for source in self.file_sources:
            t = threading.Thread(target=source.run_forever, daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self.syslog_server.shutdown()
        self.syslog_server.server_close()
