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
- Probabilistic MITRE-aware attack chain extraction
- Learned graph edge novelty with temporal and structural drift scoring
- Credential blast-radius estimation and containment simulation before hard quarantine
- Immutable audit logging with immediate out-of-band mirroring support
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
- `containment_simulation_mode` to stage soft-containment before hard host quarantine
- `hard_quarantine_threshold` to force quarantine only at critical severity
- `ingestion.*` for real source locations and ports
- `honeypot_resources` for decoy assets that should never be accessed
- `audit_out_of_band_path` for append-only out-of-band audit sink
- `approval_identity_store` for canonical approval identity normalization
- `dashboard_host`/`dashboard_port` for web UI


## GitHub zip download + cryptographic sealing

Use the helper script to download a GitHub zipball and unzip it with **automatic sealing during extraction**:

```bash
python scripts/download_and_seal_github_zip.py --repo owner/repo --ref main --output /tmp/repo_extract
```

You can also point it at an existing downloaded zip (sealing still runs automatically during unzip):

```bash
python scripts/download_and_seal_github_zip.py --zip /path/to/repo.zip --output /tmp/repo_extract
```

Notes:
- Extracted files are not modified, so runtime behavior is preserved.
- A `.seal/manifest.enc` file and `.seal/seal_meta.json` are created in the output directory automatically.
- Default sealing key (AES-256-GCM, base64): `uPs8Q_C_nBEGtssLsy5cazP2PghacquTQ76hHL2FMiw=`.
- "AES-800" is not a standardized AES mode/key-size; this tool uses AES-256-GCM.

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
