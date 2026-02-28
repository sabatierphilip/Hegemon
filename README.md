# Sentinel-Containment

Sentinel-Containment is a defensive, modular cybersecurity system for rapid deployment in cloud, hybrid, or on-prem environments. It focuses on **containment, auditability, and safe reversibility** with no offensive capabilities.

## Features

- **Asset Auto-Mapping**
  - Discovers local hosts, ports, services
  - Uses cloud abstraction adapter (AWS/GCP/Azure style) for instances, IAM roles, buckets, model endpoints
  - Builds a live asset graph with `networkx`
  - Exports topology JSON snapshot
- **Telemetry Ingestion**
  - Normalizes syslog, cloud audit logs, network flow logs, and model API logs
  - Stores OpenSearch/Elasticsearch-style JSON documents
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
  telemetry/{schema.py, ingestor.py}
  detection/{rule_engine.py, baseline.py, correlator.py}
  containment/engine.py
  soar/workflow.py
  logging_layer/immutable_log.py
  web/app.py
  main.py
config/config.yaml
rules/*.yaml
playbooks/default_playbook.yaml
scripts/simulate_scenario.py
Dockerfile
deploy.sh
```

## Quick Start

1. Create venv and install deps:
   ```bash
   python -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   ```
2. Run simulation:
   ```bash
   python scripts/simulate_scenario.py
   ```
3. Run dashboard:
   ```bash
   flask --app sentinel_containment.web.app run --host 0.0.0.0 --port 5000
   ```
4. Open `http://localhost:5000` and `http://localhost:5000/graph`

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

## Example Test Scenario

```bash
python scripts/simulate_scenario.py
pytest -q
```

