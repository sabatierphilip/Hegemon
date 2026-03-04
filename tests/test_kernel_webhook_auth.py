import hashlib
import hmac
import http.client
import json
import threading
import time
from pathlib import Path

from sentinel_containment.telemetry.ingestor import TelemetryIngestor
from sentinel_containment.telemetry.sources import PushWebhookServer


def _post_event(port: int, body: bytes, headers: dict[str, str]) -> tuple[int, bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("POST", "/kernel-event", body=body, headers=headers)
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def test_kernel_webhook_requires_valid_hmac_signature(tmp_path: Path):
    ingestor = TelemetryIngestor(tmp_path / "telemetry.jsonl")
    server = PushWebhookServer(
        host="127.0.0.1",
        port=0,
        ingestor=ingestor,
        source_type="host_kernel",
        path="/kernel-event",
        hmac_key="super-secret",
        hmac_required=True,
        hmac_max_skew_seconds=120,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        body = json.dumps({"host": "n1", "action": "kernel_alert", "resource": "kernel", "message": "probe"}).encode("utf-8")

        bad_status, _ = _post_event(server.server_port, body, {"Content-Type": "application/json"})
        assert bad_status == 401
        assert ingestor.read_recent(limit=5) == []

        ts = str(int(time.time()))
        sig = hmac.new(b"super-secret", ts.encode("utf-8") + b"." + body, hashlib.sha256).hexdigest()
        good_status, _ = _post_event(
            server.server_port,
            body,
            {
                "Content-Type": "application/json",
                "X-Hegemon-Timestamp": ts,
                "X-Hegemon-Signature": sig,
            },
        )
        assert good_status == 202
        assert len(ingestor.read_recent(limit=5)) == 1
    finally:
        server.shutdown()
        server.server_close()


def test_kernel_webhook_rejects_replayed_or_stale_timestamp(tmp_path: Path):
    ingestor = TelemetryIngestor(tmp_path / "telemetry.jsonl")
    server = PushWebhookServer(
        host="127.0.0.1",
        port=0,
        ingestor=ingestor,
        source_type="host_kernel",
        path="/kernel-event",
        hmac_key="super-secret",
        hmac_required=True,
        hmac_max_skew_seconds=1,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        body = json.dumps({"host": "n1", "action": "kernel_alert", "resource": "kernel", "message": "probe"}).encode("utf-8")
        stale_ts = str(int(time.time()) - 10)
        stale_sig = hmac.new(b"super-secret", stale_ts.encode("utf-8") + b"." + body, hashlib.sha256).hexdigest()
        status, _ = _post_event(
            server.server_port,
            body,
            {
                "Content-Type": "application/json",
                "X-Hegemon-Timestamp": stale_ts,
                "X-Hegemon-Signature": stale_sig,
            },
        )
        assert status == 401
        assert ingestor.read_recent(limit=5) == []
    finally:
        server.shutdown()
        server.server_close()
