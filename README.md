# Sentinel-Containment

Sentinel-Containment is a defensive, modular cybersecurity system for rapid deployment in cloud, hybrid, or on-prem environments.

## One-command startup (auto-orchestrated)

Start one process and the platform handles the rest automatically:

```bash
python scripts/start_sentinel.py
```

What starts automatically:
- Syslog UDP listener (`5514`)
- JSONL ingestion watchers (`cloudtrail`, `network_flows`, `model_api`, `osquery`, `kernel`, `runtime`, `hypervisor`, `counterclone`)
- Periodic detection/correlation/containment cycles
- Probabilistic MITRE-aware attack chain extraction
- Learned graph edge novelty with temporal and structural drift scoring
- Credential blast-radius estimation and containment simulation before hard quarantine
- Multi-signal honeypot tripwires with proto-AGI indicator scoring and immediate kill/containment chain
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
- `refresh_minutes` for baseline automated cycle frequency (defaults to 1 minute)
- `burst_cycle_severity_threshold`/`burst_cycle_seconds` for sub-minute burst detection cadence during active incidents
- `containment_severity_threshold` for auto containment
- `containment_simulation_mode` to stage soft-containment before hard host quarantine (defaults to hard containment-first)
- `force_hard_containment_threshold` and `force_hard_containment_blast_radius` to bypass simulation on high confidence/high blast-radius incidents
- `hard_quarantine_threshold` to force quarantine at elevated severity
- `fast_track_containment_threshold`/`fast_track_risk_confidence` for immediate containment based on multi-signal confidence
- `ingestion.*` for real source locations and ports across cloud, host, runtime, hypervisor, and counter-clone feeds
- `approval_quorum` and `automated_approvers` to control single-person fast authorization
- `trusted_hardware_public_keys` and `containment_signature` to require YubiKey/TPM-backed signatures before any containment execution
- `honeypot_resources` for decoy assets that should never be accessed
- `proto_agi_indicators` to tune high-risk autonomous behavior markers that trigger immediate containment
- `audit_out_of_band_path` for append-only out-of-band audit sink
- `approval_identity_store` for canonical approval identity normalization
- `dashboard_host`/`dashboard_port` for web UI
- `graph_horizons_minutes` for multi-horizon rolling graph anomaly summaries that catch patient low-and-slow campaigns
- `web_rate_*` settings for adaptive event-triggered burst throttling that defends dashboard/API endpoints from request-flood DoS


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
- A fresh random AES-256-GCM key is generated for each unzip operation when `--key` is not provided.
- You can optionally pass `--key <base64-key>` to reuse a caller-managed key.

## Security principles

- Defensive-first containment with hard-response acceleration for high-risk incidents
- Configurable approval quorum (default single-user for faster autonomous response)
- Identity-bound execution: containment requires valid signatures from trusted hardware-bound keys (YubiKey/TPM)
- Dynamic peer-to-peer process attestation mesh to continuously verify Hegemon process integrity and detect tampering/subversion attempts
- User-only friendly software enrollment with cryptographic authorization; enrolled friendlies are added to the mesh and protected via patrol telemetry
- Reversible actions where possible with stronger automatic isolation for severe events
- Tamper-evident immutable hash-chain logs plus telemetry event signature-chain verification
- No offensive actions against external infrastructure

## Tests

```bash
pytest -q
```
