# Sentinel-Containment

Sentinel-Containment is a defensive, modular cybersecurity system for rapid deployment in cloud, hybrid, or on-prem environments.

## One-command startup (auto-orchestrated)

```bash
python scripts/start_sentinel.py
```

This one command automatically starts:
- Real telemetry ingestion (syslog UDP + JSONL file sources)
- Detection cycles with **rule deduplication** (host+rule cooldown)
- Baseline anomaly detection with **training-aware MAD/ratio** logic
- Weighted risk scoring and correlation compression
- Defensive containment and immutable audit logging
- Dashboard at `http://localhost:5000` and `/graph`

## Real telemetry inputs

- Syslog UDP: `5514`
- JSONL files:
  - `data/cloudtrail.jsonl`
  - `data/network_flows.jsonl`
  - `data/model_api.jsonl`

## Risk scoring model

Risk is weighted (not raw sum):

```text
risk_score =
  (model_spike_weight * api_score)
+ (egress_weight * egress_score)
+ (privilege_weight * privilege_score)
+ (correlation_bonus)
```

IAM/privilege changes are intentionally weighted highest by default.

## Docker

```bash
./deploy.sh
```

## Key config (`config/config.yaml`)

- `alert_dedup_seconds`: cooldown to suppress repeated alerts
- `baseline_min_history`: train baseline before anomaly-triggering
- `baseline_training_required`: gate containment until baseline is trained
- `model_spike_weight`, `egress_weight`, `privilege_weight`, `correlation_bonus`

## Tests

```bash
pytest -q
```

## Merge conflict safety

A repository test now fails if any Git merge conflict markers (`<<<<<<<`, `=======`, `>>>>>>>`) are present in tracked text files. Run:

```bash
pytest -q
```

