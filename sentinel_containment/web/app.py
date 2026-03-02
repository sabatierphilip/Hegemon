from __future__ import annotations

import json
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

from flask import Flask, jsonify, render_template_string, request

from sentinel_containment.config import Settings
from sentinel_containment.runtime import SentinelRuntime

app = Flask(__name__)
_runtime: SentinelRuntime | None = None


@dataclass
class _ClientRateState:
    recent_requests: deque[float] = field(default_factory=deque)


class EventTriggeredBurstGuard:
    """Adaptive request guard that hardens limits when a flood burst is detected."""

    def __init__(
        self,
        *,
        base_window_seconds: float = 1.0,
        base_limit: int = 60,
        trigger_window_seconds: float = 5.0,
        trigger_limit: int = 800,
        burst_window_seconds: float = 1.0,
        burst_limit: int = 6,
        burst_duration_seconds: float = 30.0,
        now_fn=time.monotonic,
    ) -> None:
        self.base_window_seconds = base_window_seconds
        self.base_limit = base_limit
        self.trigger_window_seconds = trigger_window_seconds
        self.trigger_limit = trigger_limit
        self.burst_window_seconds = burst_window_seconds
        self.burst_limit = burst_limit
        self.burst_duration_seconds = burst_duration_seconds
        self.now_fn = now_fn
        self._client_state: dict[str, _ClientRateState] = defaultdict(_ClientRateState)
        self._global_recent_requests: deque[float] = deque()
        self._burst_mode_until = 0.0

    def _trim_window(self, timestamps: deque[float], now: float, window: float) -> None:
        lower_bound = now - window
        while timestamps and timestamps[0] < lower_bound:
            timestamps.popleft()

    def allow(self, client_id: str) -> bool:
        now = self.now_fn()
        self._trim_window(self._global_recent_requests, now, self.trigger_window_seconds)

        if len(self._global_recent_requests) >= self.trigger_limit:
            self._burst_mode_until = max(self._burst_mode_until, now + self.burst_duration_seconds)

        in_burst_mode = now < self._burst_mode_until
        state = self._client_state[client_id]
        window = self.burst_window_seconds if in_burst_mode else self.base_window_seconds
        limit = self.burst_limit if in_burst_mode else self.base_limit

        self._trim_window(state.recent_requests, now, window)

        if len(state.recent_requests) >= limit:
            self._global_recent_requests.append(now)
            return False

        state.recent_requests.append(now)
        self._global_recent_requests.append(now)
        return True


def _build_request_guard() -> EventTriggeredBurstGuard:
    settings = Settings.load()
    return EventTriggeredBurstGuard(
        base_window_seconds=float(settings.get("web_rate_base_window_seconds", 1.0)),
        base_limit=int(settings.get("web_rate_base_limit", 60)),
        trigger_window_seconds=float(settings.get("web_rate_trigger_window_seconds", 5.0)),
        trigger_limit=int(settings.get("web_rate_trigger_limit", 800)),
        burst_window_seconds=float(settings.get("web_rate_burst_window_seconds", 1.0)),
        burst_limit=int(settings.get("web_rate_burst_limit", 6)),
        burst_duration_seconds=float(settings.get("web_rate_burst_duration_seconds", 30.0)),
    )


_request_guard = _build_request_guard()


@app.before_request
def enforce_request_throttle():
    client_id = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
    client_id = client_id.split(",")[0].strip()
    if not _request_guard.allow(client_id):
        return jsonify({"error": "rate_limited", "message": "Event-triggered burst protection active"}), 429

HTML = """
<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Sentinel-Containment Command Center</title>
  <style>
    :root {
      --bg: #0b1020;
      --panel: #131a2e;
      --panel-2: #1a2340;
      --text: #d8e2ff;
      --muted: #9fb1dd;
      --critical: #ff4d6d;
      --high: #ff9f1c;
      --medium: #f7d154;
      --low: #4cc9f0;
      --ok: #2dd4bf;
    }
    body { margin: 0; font-family: Inter, Arial, sans-serif; background: linear-gradient(180deg, #0a0e1b, #0b1020); color: var(--text); }
    .wrap { max-width: 1200px; margin: 0 auto; padding: 22px; }
    .title { display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px; }
    .title h1 { margin: 0; font-size: 28px; }
    .badge { background: #20305f; border: 1px solid #2f4383; padding: 6px 10px; border-radius: 20px; color: #cfe0ff; }
    .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 16px; }
    .card { background: var(--panel); border: 1px solid #253155; border-radius: 12px; padding: 14px; box-shadow: 0 8px 16px rgba(0, 0, 0, .25); }
    .kpi { font-size: 26px; font-weight: 700; margin: 6px 0 2px; }
    .muted { color: var(--muted); font-size: 12px; }
    .layout { display: grid; grid-template-columns: 1.7fr 1fr; gap: 14px; }
    .panel { background: var(--panel); border: 1px solid #253155; border-radius: 12px; padding: 14px; margin-bottom: 14px; }
    .panel h3 { margin: 0 0 12px; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { border-bottom: 1px solid #283354; text-align: left; padding: 8px 6px; }
    .sev { font-weight: 700; }
    .sev.high { color: var(--high); }
    .sev.critical { color: var(--critical); }
    .sev.medium { color: var(--medium); }
    .sev.low { color: var(--low); }
    .chain { background: var(--panel-2); border-radius: 10px; padding: 10px; margin-bottom: 8px; }
    .pill { font-size: 11px; border-radius: 999px; padding: 2px 8px; background: #2a3a68; margin-right: 5px; }
    .small { font-size: 12px; }
    .json { max-height: 280px; overflow: auto; background: #0f1528; border: 1px solid #283354; border-radius: 8px; padding: 8px; }
  </style>
</head>
<body>
<div class=\"wrap\">
  <div class=\"title\">
    <h1>🛡️ Sentinel-Containment Command Center</h1>
    <div class=\"badge\">Candidate Severity: {{ candidate_severity }}</div>
  </div>

  <div class=\"panel\">
    <h3>Deployment Control</h3>
    <div class=\"small\" id=\"telemetry-status\">Telemetry permission pending.</div>
    <button id=\"run-btn\" style=\"margin-top:8px;padding:8px 12px;background:#2a3a68;color:#d8e2ff;border:1px solid #3e5393;border-radius:8px;cursor:pointer;\">Run</button>
  </div>

  <div class=\"grid\">
    <div class=\"card\"><div class=\"muted\">Events Processed</div><div class=\"kpi\">{{ events_processed }}</div></div>
    <div class=\"card\"><div class=\"muted\">Rule Alerts</div><div class=\"kpi\">{{ alerts_count }}</div></div>
    <div class=\"card\"><div class=\"muted\">Graph Edge Anomalies</div><div class=\"kpi\">{{ graph_count }}</div></div>
    <div class=\"card\"><div class=\"muted\">Attack Chains</div><div class=\"kpi\">{{ chains_count }}</div></div>
  </div>

  <div class=\"layout\">
    <div>
      <div class=\"panel\">
        <h3>Graph-based Anomaly Detection</h3>
        <table>
          <thead><tr><th>Edge</th><th>Relation</th><th>Novelty</th><th>Severity</th></tr></thead>
          <tbody>
            {% for a in graph_anomalies %}
            <tr>
              <td>{{ a.source }} → {{ a.target }}</td>
              <td>{{ a.relation }}</td>
              <td>{{ a.novelty_score }}</td>
              <td class=\"sev {{ severity_class(a.severity) }}\">{{ a.severity }}</td>
            </tr>
            {% endfor %}
            {% if not graph_anomalies %}<tr><td colspan=\"4\" class=\"small muted\">No novel edges detected in current batch.</td></tr>{% endif %}
          </tbody>
        </table>
      </div>

      <div class=\"panel\">
        <h3>Time-sequence Attack Modeling</h3>
        {% for c in attack_chains %}
        <div class=\"chain\">
          <div><strong>{{ c.host }}</strong> · severity <span class=\"sev {{ severity_class(c.severity) }}\">{{ c.severity }}</span></div>
          <div class=\"small\">{{ c.summary }} (confidence: {{ c.confidence }})</div>
          <div style=\"margin-top: 6px;\">{% for s in c.stages %}<span class=\"pill\">{{ s }}</span>{% endfor %}</div>
        </div>
        {% endfor %}
        {% if not attack_chains %}<div class=\"small muted\">No multi-stage attack chains detected in current time window.</div>{% endif %}
      </div>
    </div>

    <div>
      <div class=\"panel\">
        <h3>Correlated Alert Overview</h3>
        <div class=\"json\"><pre>{{ correlated }}</pre></div>
      </div>
      <div class=\"panel\">
        <h3>Containment</h3>
        <div class=\"small\">Contained Hosts: {{ contained_hosts }}</div>
        <div class=\"small\">SOAR Actions: {{ soar_actions }}</div>
      </div>
      <div class=\"panel\">
        <h3>Topology</h3>
        <div class=\"json\"><pre>{{ topology }}</pre></div>
      </div>
    </div>
  </div>
</div>
<script>
async function startWithPermission(){
  const status=document.getElementById("telemetry-status");
  const resp=await fetch("/api/telemetry/permission",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({granted:true})});
  const body=await resp.json();
  status.textContent = body.completed ? "Dynamic telemetry deployment completed." : "Telemetry permission not granted.";
}
document.getElementById("run-btn")?.addEventListener("click",startWithPermission);
</script>
</body>
</html>
"""


def _load_latest_state() -> dict:
    settings = Settings.load()
    state_path = Path(settings.get("latest_state_path", "data/latest_state.json"))
    if state_path.exists():
        return json.loads(state_path.read_text(encoding="utf-8"))
    return {
        "topology": {},
        "correlated": {},
        "contained_hosts": [],
        "graph_anomalies": [],
        "attack_chains": [],
        "candidate_severity": 0,
    }


def _severity_class(value: int) -> str:
    if value >= 90:
        return "critical"
    if value >= 75:
        return "high"
    if value >= 55:
        return "medium"
    return "low"


@app.get("/")
def dashboard():
    state = _load_latest_state()
    return render_template_string(
        HTML,
        events_processed=state.get("events_processed", 0),
        alerts_count=len(state.get("alerts", [])),
        graph_count=len(state.get("graph_anomalies", [])),
        chains_count=len(state.get("attack_chains", [])),
        candidate_severity=state.get("candidate_severity", 0),
        graph_anomalies=state.get("graph_anomalies", []),
        attack_chains=state.get("attack_chains", []),
        correlated=json.dumps(state.get("correlated", {}), indent=2),
        contained_hosts=json.dumps(state.get("contained_hosts", []), indent=2),
        soar_actions=json.dumps(state.get("soar_actions", []), indent=2),
        topology=json.dumps(state.get("topology", {}), indent=2),
        severity_class=_severity_class,
    )


@app.get("/graph")
def graph():
    state = _load_latest_state()
    return jsonify(state.get("topology", {}))


@app.get("/api/state")
def api_state():
    return jsonify(_load_latest_state())

def set_runtime(runtime: SentinelRuntime) -> None:
    global _runtime
    _runtime = runtime


@app.get("/api/telemetry/permission")
def telemetry_permission_status():
    if _runtime is None:
        return jsonify({"required": True, "granted": False, "completed": False, "details": ["runtime_not_initialized"]}), 503
    return jsonify(_runtime.get_telemetry_setup_notice())


@app.post("/api/telemetry/permission")
def telemetry_permission_apply():
    payload = request.get_json(silent=True) or {}
    granted = bool(payload.get("granted", False))
    if _runtime is None:
        return jsonify({"required": True, "granted": granted, "completed": False, "details": ["runtime_not_initialized"]}), 503
    return jsonify(_runtime.apply_telemetry_permission(granted))

