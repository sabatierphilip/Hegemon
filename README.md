# Sentinel-Containment

Sentinel-Containment is a defensive, modular cybersecurity system for rapid deployment in cloud, hybrid, or on-prem environments.

## One-command startup (auto-orchestrated)

Start one process and the platform handles the rest automatically:

```bash
python scripts/start_sentinel.py
```

What starts automatically:
- Syslog UDP listener (`5514`)
- JSONL ingestion watchers (`cloudtrail`, `network_flows`, `model_api`)
- Periodic detection/correlation/containment cycles
- Immutable audit logging
- Flask dashboard (`http://localhost:5000`) and `/graph`

## Docker single-command deployment

```bash
./deploy.sh
```

## Real telemetry inputs

Write real events to the configured files (or bind mount/pipe your collector output):
- `data/cloudtrail.jsonl`
- `data/network_flows.jsonl`
- `data/model_api.jsonl`

Send syslog to UDP `5514`.

## Configuration

Main settings are in `config/config.yaml`:
- `refresh_minutes` for automated cycle frequency
- `containment_severity_threshold` for auto containment
- `ingestion.*` for real source locations and ports
- `dashboard_host`/`dashboard_port` for web UI

## Security principles

- Defensive-only containment
- Two-person approval for high-impact actions
- Reversible actions
- Tamper-evident immutable hash-chain log
- No offensive actions

## Tests

```bash
pytest -q
```
