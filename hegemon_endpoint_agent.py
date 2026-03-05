from __future__ import annotations

import argparse
import json
import re
import urllib.error
import urllib.request
from pathlib import Path

from sentinel_containment.controlplane import KILL_CHAIN_STAGES
from sentinel_containment.endpoint_inventory import collect_host_facts, read_recent_auth_telemetry

CONFIG_PATH = Path.home() / ".hegemon" / "agent.json"


def _post_json(url: str, token: str, payload: dict) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _load_config() -> dict:
    if not CONFIG_PATH.exists():
        return {}
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def _save_config(payload: dict) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _extract_kill_chain_events(lines: list[str]) -> list[str]:
    out: list[str] = []
    for line in lines:
        norm = line.lower()
        for stage in KILL_CHAIN_STAGES:
            if re.search(rf"\b{re.escape(stage)}\b", norm):
                out.append(stage)
    return out[-50:]


def enroll_or_heartbeat(hegemon_url: str, token: str) -> dict:
    cfg = _load_config()
    facts = collect_host_facts()
    auth_lines = read_recent_auth_telemetry(limit=50)
    telemetry_events = _extract_kill_chain_events(auth_lines)
    payload = {**facts, "telemetry_events": telemetry_events, "raw_auth_telemetry": auth_lines}

    endpoint_id = cfg.get("endpoint_id")
    if not endpoint_id:
        response = _post_json(f"{hegemon_url.rstrip('/')}/api/endpoints/enroll", token, payload)
        endpoint_id = response.get("endpoint_id")
        cfg["endpoint_id"] = endpoint_id
        _save_config(cfg)
        return response

    response = _post_json(f"{hegemon_url.rstrip('/')}/api/endpoints/heartbeat/{endpoint_id}", token, payload)
    return response


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hegemon-url", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()

    if args.once:
        try:
            enroll_or_heartbeat(args.hegemon_url, args.token)
            return 0
        except urllib.error.URLError:
            return 1

    import time

    while True:
        try:
            enroll_or_heartbeat(args.hegemon_url, args.token)
        except Exception:
            pass
        time.sleep(60)


if __name__ == "__main__":
    raise SystemExit(main())
