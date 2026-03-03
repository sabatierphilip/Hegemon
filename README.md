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
- Hybrid containment execution engine with safe-by-default simulation plus optional live controls (iptables/nft outbound isolation, AWS IAM deny policy push, DNS sinkhole host mapping)
- Multi-signal honeypot tripwires with proto-AGI indicator scoring, adversarial tradecraft profiling, and immediate kill/containment chain
- Level-4 continuously deployed hunting directives that run always-on predictive hunt loops (not trigger-only)
- Level-5 friendly-integrity hunter directives with P2P directive verification, reactive tamper lockout, and all-action broadcast telemetry
- Immutable audit logging with immediate out-of-band mirroring support
- Local-only Flask dashboard (`http://127.0.0.1:5000`) and `/graph` (non-loopback clients are rejected at request level)
- Startup pre-flight trust-anchor validation with hard warning banner when key policy would block containment
- Default autonomous hardware-key bootstrap on startup (dashboard can still toggle/override)

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
- `containment_live_mode` to permit live containment execution hooks (default false for safety)
- `force_hard_containment_threshold` and `force_hard_containment_blast_radius` to bypass simulation on high confidence/high blast-radius incidents
- `hard_quarantine_threshold` to force quarantine at elevated severity
- `fast_track_containment_threshold`/`fast_track_risk_confidence` for immediate containment based on multi-signal confidence
- `ingestion.*` for real source locations and ports across cloud, host, runtime, hypervisor, and counter-clone feeds
- `approval_quorum` and `automated_approvers` to control single-person fast authorization
- `trusted_hardware_public_keys` and `containment_signature` to require YubiKey/TPM-backed signatures before any containment execution
- `honeypot_resources` for decoy assets that should never be accessed
- `proto_agi_indicators` to tune high-risk autonomous behavior markers that trigger immediate containment
- `peer_verification.external_tpm_attestation.*` to enforce hardware TPM quote validation for every mesh peer
- `peer_verification.external_cloud_attestation.*` to enforce cloud-native workload attestation checks
- `peer_verification.checkpoint_*` controls for quorum checkpointing (`checkpoint_quorum`, `checkpoint_signers`, `replication_targets`, nonce age, sequential enforcement)
- `audit_out_of_band_path` for append-only out-of-band audit sink
- `approval_identity_store` for canonical approval identity normalization
- `dashboard_host`/`dashboard_port` for local UI binding (defaults to `127.0.0.1`)
- `graph_horizons_minutes` for multi-horizon rolling graph anomaly summaries that catch patient low-and-slow campaigns
- `web_rate_*` settings for adaptive event-triggered burst throttling that defends dashboard/API endpoints from request-flood DoS
- `auto_configure_hardware_keys_on_startup` defaults to `true` so the runtime can self-bootstrap trust anchors for autonomous containment by default
- `level_four_max_directives`/`level_four_min_dominance_score` to tune continuously deployed level-4 hunting meshes
- `level_five_max_directives`/`level_five_min_hunter_score` to tune level-5 friendly-integrity hunter meshes
- `incident_drill_severity` and `drill_auto_configure_hardware_keys` to run deterministic severe-alert drill simulations through the same approval path


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
- Dynamic peer-to-peer process attestation mesh plus external TPM/cloud attestation verification to prevent self-attesting compromised nodes
- Quorum-signed P2P checkpoints with monotonic sequence/nonce anti-replay, Merkle-root commitments, gossip cross-notarization, and signer revocation/rotation support
- User-only friendly software enrollment with cryptographic authorization; enrolled friendlies are added to the mesh and protected via patrol telemetry
- Reversible actions where possible with stronger automatic isolation for severe events
- Tamper-evident immutable hash-chain logs plus telemetry event signature-chain verification
- No offensive actions against external infrastructure


## Production WSGI load test profile

Run the dashboard with a production WSGI server (example using Gunicorn):

```bash
gunicorn -w 4 --threads 8 -b 127.0.0.1:5000 sentinel_containment.web.app:app
```

Then execute a burst profile against authenticated API endpoints:

```bash
python scripts/run_wsgi_load_profile.py --url http://127.0.0.1:5000/api/health --token <dashboard-token> --concurrency 128 --requests 5000
```

This validates request-throttle and burst-guard behavior under realistic concurrent WSGI traffic, beyond Flask dev-server assumptions.

## Tests

```bash
pytest -q
```


### Rule language upgrades

Rules now support structured matching that goes beyond simple equality/threshold checks:
- Sigma-like selectors under `detection.sigma` (`all_of`, `any_of`, `not`, `contains`, `regex`, `startswith`, `endswith`, `in`)
- YARA-like token sets under `detection.yara_like` with configurable `min_hits` across multiple fields
- Native `regex` and `contains_any` field maps for expressive matching in compact rules
- `long_window_accumulation` for low-and-slow exfil detection over extended windows
- `field_entropy` for covert-channel spotting (encoded/high-entropy payloads in DNS or API fields)
- `windowed_count` + `additional_checks` for low-and-slow DNS tunnel detection across long windows
