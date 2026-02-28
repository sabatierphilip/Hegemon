# Sentinel-Containment

Sentinel-Containment is a defensive, modular cybersecurity system for rapid deployment in cloud, hybrid, or on-prem environments. It focuses on **containment, auditability, and safe reversibility** with no offensive capabilities.

## Features

- **Asset Auto-Mapping**
  - Discovers local hosts, ports, services
  - Uses cloud abstraction adapter (AWS/GCP/Azure style) for instances, IAM roles, buckets, model endpoints
  - Builds a live asset graph with `networkx`
  - Exports topology JSON snapshot
- **Telemetry Ingestion (real sources)**
  - Syslog UDP listener
  - Cloud audit JSONL tailing (CloudTrail-like)
  - Network flow JSONL tailing
  - Model API request/response JSONL tailing
  - Normalizes all events into a common OpenSearch-style schema
- **Detection Engine**
  - Sigma-like YAML rule matching
  - Behavioral baseline anomaly detection (rolling window)
  - Alert correlation and severity scoring
- **Containment Engine (defensive-only)**
  - Safe actions only: traffic block, key rotation, IAM session disable, host quarantine, container pause, forensic metadata
  - Two-person approval gate for high-impact actions
  - Reversible action model and immutable auditing
- **SOAR Workflow**
  - YAML playbooks with conditional steps and human approval gates
- **Immutable Logging**
  - Append-only hash-chained audit log
- **Dashboard + Graph API**
  - Flask dashboard for topology, alerts, and contained hosts
  - `/graph` endpoint for topology JSON visualization

## Project Structure

```text
sentinel_containment/
  asset_mapper/discovery.py
  cloud/provider.py
  telemetry/{schema.py, ingestor.py, sources.py}
  detection/{rule_engine.py, baseline.py, correlator.py}
  containment/engine.py
  soar/workflow.py
  logging_layer/immutable_log.py
  web/app.py
  main.py
scripts/run_ingestion_service.py
config/config.yaml
rules/*.yaml
playbooks/default_playbook.yaml
Dockerfile
deploy.sh
```

## Quick Start (real ingestion)

1. Install dependencies:
   ```bash
   python -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   ```
2. Start ingestion service:
   ```bash
   python scripts/run_ingestion_service.py
   ```
3. Feed logs:
   - Syslog → UDP `5514`
   - Append JSON lines to:
     - `data/cloudtrail.jsonl`
     - `data/network_flows.jsonl`
     - `data/model_api.jsonl`
4. Run detection/containment cycle:
   ```bash
   python -c "from sentinel_containment.config import Settings; from sentinel_containment.main import run_cycle; print(run_cycle(Settings.load()))"
   ```
5. Run dashboard:
   ```bash
   flask --app sentinel_containment.web.app run --host 0.0.0.0 --port 5000
   ```

## Single-command Docker deployment

```bash
./deploy.sh
```

## Security Principles

- Zero Trust and least privilege by default
- No hardcoded secrets (use env vars)
- Containment actions are defensive and reversible
- Tamper-evident immutable audit trail
- No exploitation, counter-attack, destructive action, or external offensive scanning

## Test

```bash
pytest -q
```
