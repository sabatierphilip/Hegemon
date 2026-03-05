from __future__ import annotations

import json
import logging
import secrets
import time

import hmac
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, g, jsonify, render_template_string, request

from sentinel_containment.config import Settings
from sentinel_containment.controlplane import HegemonControlPlane
from sentinel_containment.runtime import SentinelRuntime

app = Flask(__name__)
logger = logging.getLogger(__name__)
_runtime: SentinelRuntime | None = None
_auth_warning_emitted = False
_control_plane = HegemonControlPlane()


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


def _is_loopback(addr: str | None) -> bool:
    if not addr:
        return False
    return addr in {"127.0.0.1", "::1", "localhost"}


def _is_local_request() -> bool:
    remote = request.remote_addr or ""
    forwarded = (request.headers.get("X-Forwarded-For", "").split(",")[0].strip())
    local_remote = _is_loopback(remote) or (forwarded and _is_loopback(forwarded))
    if not local_remote:
        return False
    origin = request.headers.get("Origin", "").strip()
    if origin:
        host = (urlparse(origin).hostname or "").strip().lower()
        if host not in {"127.0.0.1", "localhost", "::1"}:
            return False
    return True


def _valid_csrf_origin_for_state_change() -> bool:
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return True
    origin = request.headers.get("Origin", "").strip()
    if not origin:
        return False
    host = (urlparse(origin).hostname or "").strip().lower()
    return host in {"127.0.0.1", "localhost", "::1"}


@app.before_request
def enforce_request_throttle():
    g.csp_nonce = secrets.token_urlsafe(16)
    if not _is_local_request():
        return jsonify({"error": "forbidden", "message": "dashboard is restricted to local loopback clients"}), 403
    if not _valid_csrf_origin_for_state_change():
        return jsonify({"error": "forbidden", "message": "state-changing requests require localhost Origin header"}), 403
    client_id = (request.remote_addr or "unknown").strip()
    if not _request_guard.allow(client_id):
        return jsonify({"error": "rate_limited", "message": "Event-triggered burst protection active"}), 429

HTML = """
<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Sentinel-Containment Command Center</title>
  <style nonce="{{ csp_nonce }}">
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
    .header-cues { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
    .cue { font-size:11px; border-radius:999px; padding:4px 10px; border:1px solid #2f4383; background:#1a2340; }
    .cue.ok { border-color:#2f855a; color:#9cf6d2; }
    .cue.warn { border-color:#8b2f45; color:#ffdce5; }
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
    .tabs { display:flex; gap:8px; margin: 12px 0 16px; }
    .tab-btn { background:#1a2340; border:1px solid #2f4383; color:#cfe0ff; padding:8px 12px; border-radius:8px; cursor:pointer; }
    .tab-btn.active { background:#274079; border-color:#5d7fcd; }
    .tab-panel { display:none; }
    .tab-panel.active { display:block; }
    .cp-subtabs{display:flex;gap:10px;flex-wrap:wrap;margin-top:10px;}
    .cp-subtab{background:#1a2340;border:1px solid #35508f;border-radius:10px;padding:8px 10px;min-width:220px;}
    .cp-subtab h4{margin:0;display:flex;align-items:center;justify-content:space-between;font-size:13px;}
    .cp-icon-btn{border:1px solid #4b67a8;background:#223666;color:#d8e2ff;border-radius:8px;cursor:pointer;padding:1px 8px;font-weight:700;}
    .cp-arrow{cursor:pointer;margin-left:6px;}
  </style>
</head>
<body>
<div class="wrap">
  <div class="title">
    <h1>🛡️ Sentinel-Containment Command Center</h1>
    <div class="header-cues">
      <div class="cue {{ 'ok' if readiness.token_ready else 'warn' }}">Auth Token: {{ 'Ready' if readiness.token_ready else 'Missing' }}</div>
      <div class="cue {{ 'ok' if readiness.key_policy_ready else 'warn' }}">Key Policy: {{ 'Ready' if readiness.key_policy_ready else 'Blocked' }}</div>
      <div class="badge">Candidate Severity: {{ candidate_severity }}</div>
    </div>
  </div>

  <div class="tabs">
    <button class="tab-btn active" data-tab="overview">Overview</button>
    <button class="tab-btn" data-tab="control-plane">Control Plane</button>
    <button class="tab-btn" data-tab="kernel-telemetry">Kernel Telemetry</button>
  </div>

  <div id="tab-overview" class="tab-panel active">
  {% if readiness.startup_warning %}
  <div class="panel" style="border-color:#8b2f45;background:#2b1520;">
    <h3 style="color:#ffdce5;">Containment Pre-flight Warning</h3>
    <div class="small">{{ readiness.startup_warning }}</div>
  </div>
  {% endif %}

  <div class="panel">
    <h3>Deployment Control</h3>
    <div class="small" id="human-gate-status">Human-in-the-loop toggle status loading.</div>
    <label class="small" style="display:flex;align-items:center;gap:8px;margin-top:6px;">
      <input id="human-gate-toggle" type="checkbox" />
      Require human confirmation for containment decisions
    </label>
    <div class="small" id="containment-live-status" style="margin-top:6px;">Live containment toggle status loading.</div>
    <label class="small" style="display:flex;align-items:center;gap:8px;margin-top:6px;">
      <input id="containment-live-toggle" type="checkbox" />
      Enable live containment execution hooks
    </label>
    <div class="small" id="telemetry-status">Telemetry permission pending.</div>
    <button id="drill-btn" style="margin-top:8px;padding:8px 12px;background:#4a2b6a;color:#e7d7ff;border:1px solid #6b3f96;border-radius:8px;cursor:pointer;">Run Incident Drill</button>
    <div class="small" id="hardware-key-status" style="margin-top:6px;">Hardware key bootstrap check pending.</div>
    <button id="run-btn" style="margin-top:8px;padding:8px 12px;background:#2a3a68;color:#d8e2ff;border:1px solid #3e5393;border-radius:8px;cursor:pointer;">Run</button>
  </div>

  <div class="panel">
    <h3>Containment Decision Gate</h3>
    <div class="small" id="containment-status">
      {% if containment_decision.pending %}
      Active containment hold on {{ containment_decision.host }}. Review simulation details and choose.
      {% else %}
      No operator decision currently pending.
      {% endif %}
    </div>
    <div class="json" style="margin-top:8px;"><pre id="containment-simulation">{{ containment_decision_json }}</pre></div>
    <div style="margin-top:8px;display:flex;gap:8px;">
      <button id="containment-yes" style="padding:8px 12px;background:#22543d;color:#d8e2ff;border:1px solid #2f855a;border-radius:8px;cursor:pointer;">Yes, Execute</button>
      <button id="containment-no" style="padding:8px 12px;background:#5a1f2b;color:#ffdce5;border:1px solid #8b2f45;border-radius:8px;cursor:pointer;">No, Release Hold</button>
    </div>
  </div>

  <div class=\"grid\">
    <div class=\"card\"><div class=\"muted\">Events Processed</div><div class=\"kpi\">{{ events_processed }}</div></div>
    <div class=\"card\"><div class=\"muted\">Severity Alerts</div><div class=\"kpi\">{{ alerts_count }}</div></div>
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
        <h3>Severity Alert Feed</h3>
        <table>
          <thead><tr><th>Source</th><th>Host</th><th>Title</th><th>Severity</th></tr></thead>
          <tbody>
            {% for a in severity_alerts[:25] %}
            <tr>
              <td>{{ a.source }}</td>
              <td>{{ a.host }}</td>
              <td>{{ a.title }}</td>
              <td class=\"sev {{ severity_class(a.severity) }}\">{{ a.severity }}</td>
            </tr>
            {% endfor %}
            {% if not severity_alerts %}<tr><td colspan=\"4\" class=\"small muted\">No severity alerts in current cycle.</td></tr>{% endif %}
          </tbody>
        </table>
      </div>
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

  <div id="tab-control-plane" class="tab-panel">
    <div class="panel">
      <h3>Control Plane (Friends / Endpoints / Scanning / Patch Review)</h3>
      <label class="small" style="display:flex;align-items:center;gap:8px;margin:6px 0;">
        <input type="checkbox" id="cp-autocomplete-enabled" checked />
        Enable autocomplete suggestions (optional)
      </label>
      <div style="display:flex;gap:8px;flex-wrap:wrap;">
        <input id="cp-scan-endpoint-input" list="cp-endpoint-suggestions" placeholder="endpoint id for scan" style="padding:8px;border-radius:8px;border:1px solid #35508f;background:#0f1528;color:#d8e2ff;" />
        <datalist id="cp-endpoint-suggestions"></datalist>
        <button id="cp-seed-btn" style="padding:8px 12px;background:#2a3a68;color:#d8e2ff;border:1px solid #3e5393;border-radius:8px;cursor:pointer;">Seed Demo Endpoint</button>
              </div>
      <div class="cp-subtabs">
        <div class="cp-subtab">
          <h4>Friends <span><button class="cp-icon-btn" id="cp-add-friend-btn">＋</button><span class="cp-arrow" data-target="cp-friends-list">▾</span></span></h4>
          <div id="cp-friends-list" class="small"></div>
        </div>
        <div class="cp-subtab">
          <h4>Endpoints <span><button class="cp-icon-btn" id="cp-add-endpoint-btn">＋</button><span class="cp-arrow" data-target="cp-endpoints-list">▾</span></span></h4>
          <div id="cp-endpoints-list" class="small"></div>
        </div>
      </div>
      <div class="small" id="cp-status" style="margin-top:8px;">Control-plane data loading. Autonomous scans are active.</div>
    </div>
    <div class="grid">
      <div class="card"><div class="muted">Friends</div><div class="kpi" id="cp-friends">0</div></div>
      <div class="card"><div class="muted">Endpoints</div><div class="kpi" id="cp-endpoints">0</div></div>
      <div class="card"><div class="muted">Findings</div><div class="kpi" id="cp-findings">0</div></div>
      <div class="card"><div class="muted">Patch Proposals</div><div class="kpi" id="cp-proposals">0</div></div>
    </div>
    <div class="panel">
      <h3>Latest Patch Path Before / After + Diff</h3>
      <div class="small" id="cp-path-before">Before: -</div>
      <div class="small" id="cp-path-after">After: -</div>
      <div class="small" id="cp-diff-expl">Diff explanation: -</div>
      <div class="small" id="cp-reasoning">Agent reasoning: -</div>
      <div class="small" id="cp-patch-approval-status" style="margin-top:8px;">Approval status: waiting for proposal selection.</div>
      <div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap;">
        <button id="cp-approve-latest-btn" style="padding:8px 12px;background:#2b4f7a;color:#d8e2ff;border:1px solid #3e6aa3;border-radius:8px;cursor:pointer;">Approve Latest Patch</button>
        <button id="cp-approve-apply-btn" style="padding:8px 12px;background:#22543d;color:#d8e2ff;border:1px solid #2f855a;border-radius:8px;cursor:pointer;">Auto-Apply Approved Patch</button>
      </div>
      <div class="json" style="margin-top:8px;"><pre id="cp-code-diff">No code diff generated yet.</pre></div>
      <div class="json" style="margin-top:8px;"><pre id="cp-patch-terminal">No generated patches yet.</pre></div>
    </div>
    <div class="panel">
      <h3>Autonomous Scan Terminal</h3>
      <div class="small">Detailed loopholes/bug findings from autonomous security scans.</div>
      <div class="json" style="margin-top:8px;"><pre id="cp-scan-terminal">No scan reports generated yet.</pre></div>
    </div>
  </div>

  <div id="tab-kernel-telemetry" class="tab-panel">
    <div class="panel">
      <h3>eBPF Kernel Telemetry Feed</h3>
      <div class="small" id="kernel-telemetry-mode-status">Kernel telemetry mode loading.</div>
      <label class="small" style="display:flex;align-items:center;gap:8px;margin-top:6px;">
        <input id="kernel-telemetry-mode-toggle" type="checkbox" checked />
        Autonomous mode (default). Disable for manual-only staging.
      </label>
      <div class="small" style="margin-top:8px;">Terminal reports</div>
      <div class="json" style="margin-top:8px;"><pre id="kernel-telemetry-terminal">No kernel telemetry reports yet.</pre></div>
    </div>
  </div>
</div>
<script nonce="{{ csp_nonce }}">
async function startWithPermission(){
  const status=document.getElementById("telemetry-status");
  const resp=await fetch("/api/telemetry/permission",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({granted:true})});
  const body=await resp.json();
  status.textContent = body.completed ? "Dynamic telemetry deployment completed." : "Telemetry permission not granted.";
}

function updateDecisionUI(payload){
  const status=document.getElementById("containment-status");
  const sim=document.getElementById("containment-simulation");
  if(status){
    if(payload.pending){
      status.textContent = `Active containment hold on ${payload.host || "unknown"}. Review simulation details and choose.`;
    }else{
      status.textContent = payload.message || "No operator decision currently pending.";
    }
  }
  if(sim){
    sim.textContent = JSON.stringify(payload, null, 2);
  }
}

async function decideContainment(execute){
  const resp=await fetch("/api/containment/decision",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({execute})});
  const body=await resp.json();
  updateDecisionUI(body);
}

async function promptHardwareKeyBootstrap(){
  const status=document.getElementById("hardware-key-status");
  try{
    const statusResp=await fetch("/api/hardware-keys/status");
    const statusPayload=await statusResp.json();
    if(statusPayload.completed){
      if(status){status.textContent=`Hardware key profile already configured (${statusPayload.key_id || "existing"}).`;}
      return;
    }
    const shouldConfigure=window.confirm("Auto-configure local hardware key profile now for high-severity containment operations?");
    const applyResp=await fetch("/api/hardware-keys/auto-configure",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({configure:shouldConfigure})});
    const applyPayload=await applyResp.json();
    if(status){
      status.textContent = applyPayload.completed
        ? `Hardware keys auto-configured with local trust anchor ${applyPayload.key_id || "auto"}.`
        : "Hardware key auto-configuration deferred by operator.";
    }
  }catch(_err){
    if(status){status.textContent="Hardware key bootstrap check unavailable.";}
  }
}

async function loadHumanGateStatus(){
  const status=document.getElementById("human-gate-status");
  const toggle=document.getElementById("human-gate-toggle");
  try{
    const resp=await fetch("/api/human-gate/status");
    const payload=await resp.json();
    if(toggle){toggle.checked=Boolean(payload.human_required);}
    if(status){
      status.textContent = payload.human_required
        ? "Human approval is required before containment execution."
        : "Autonomous mode active: actions auto-approve by default.";
    }
  }catch(_err){
    if(status){status.textContent="Human-gate status unavailable.";}
  }
}


async function loadContainmentLiveStatus(){
  const status=document.getElementById("containment-live-status");
  const toggle=document.getElementById("containment-live-toggle");
  try{
    const resp=await fetch("/api/containment-live-mode/status");
    const payload=await resp.json();
    if(toggle){toggle.checked=Boolean(payload.containment_live_mode);}
    if(status){
      status.textContent = payload.containment_live_mode
        ? "Live containment is enabled: executor hooks run in active mode."
        : "Live containment is disabled: executor hooks run in simulation mode.";
    }
  }catch(_err){
    if(status){status.textContent="Containment live-mode status unavailable.";}
  }
}

async function updateContainmentLiveMode(enabled){
  const status=document.getElementById("containment-live-status");
  const resp=await fetch("/api/containment-live-mode/toggle",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({containment_live_mode:enabled})});
  const payload=await resp.json();
  if(status){
    status.textContent = payload.containment_live_mode
      ? "Live containment is enabled: executor hooks run in active mode."
      : "Live containment is disabled: executor hooks run in simulation mode.";
  }
}

async function runIncidentDrill(){
  const status=document.getElementById("containment-status");
  const resp=await fetch("/api/drill/incident",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({run:true})});
  const payload=await resp.json();
  if(status){
    status.textContent = payload.approved
      ? `Incident drill passed on ${payload.host}: approved containment path verified.`
      : `Incident drill failed: ${payload.message || "containment not approved"}`;
  }
  updateDecisionUI(payload);
}

async function updateHumanGate(required){
  const status=document.getElementById("human-gate-status");
  const resp=await fetch("/api/human-gate/toggle",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({human_required:required})});
  const payload=await resp.json();
  if(status){
    status.textContent = payload.human_required
      ? "Human approval is required before containment execution."
      : "Autonomous mode active: actions auto-approve by default.";
  }
}


const tabButtons=[...document.querySelectorAll('.tab-btn')];
const tabPanels={overview:document.getElementById('tab-overview'),'control-plane':document.getElementById('tab-control-plane'),'kernel-telemetry':document.getElementById('tab-kernel-telemetry')};
for(const btn of tabButtons){
  btn.addEventListener('click',()=>{
    for(const b of tabButtons){b.classList.remove('active');}
    btn.classList.add('active');
    for(const [name,panel] of Object.entries(tabPanels)){ if(panel){panel.classList.toggle('active',name===btn.dataset.tab);} }
  });
}


function setCollapsed(el, collapsed){
  if(!el) return;
  el.style.display = collapsed ? 'none' : 'block';
}

function renderSimpleList(targetId, rows, formatter){
  const node=document.getElementById(targetId);
  if(!node) return;
  if(!rows || !rows.length){ node.textContent='(empty)'; return; }
  node.innerHTML = rows.slice(0,12).map(formatter).join('<br/>');
}

async function autocompleteTerms(kind, q){
  const enabled=document.getElementById('cp-autocomplete-enabled');
  if(enabled && !enabled.checked){ return []; }
  const resp=await fetch(`/api/control-plane/autocomplete?kind=${encodeURIComponent(kind)}&q=${encodeURIComponent(q||'')}`);
  if(!resp.ok){ return []; }
  const data=await resp.json();
  return data.suggestions || [];
}

async function loadControlPlane(){
  try{
    const resp=await fetch('/api/control-plane/overview');
    if(!resp.ok){throw new Error('overview failed');}
    const data=await resp.json();
    document.getElementById('cp-friends').textContent=String(data.friends.length);
    document.getElementById('cp-endpoints').textContent=String(data.endpoints.length);
    document.getElementById('cp-findings').textContent=String(data.findings.length);
    document.getElementById('cp-proposals').textContent=String(data.proposals.length);
    renderSimpleList('cp-friends-list', data.friends, (f)=>`${f.name} (${f.status})`);
    renderSimpleList('cp-endpoints-list', data.endpoints, (e)=>`${e.endpoint_id} · ${e.host_name}`);
    const dl=document.getElementById('cp-endpoint-suggestions');
    if(dl){ dl.innerHTML=(data.endpoints||[]).map((e)=>`<option value="${e.endpoint_id}"></option>`).join(''); }
    const latest=data.proposals[data.proposals.length-1];
    if(latest){
      const before=(latest.graph_path_before||[]).map((n)=>n.node||n).join(' → ');
      const after=(latest.graph_path_after||[]).map((n)=>n.node||n).join(' → ');
      document.getElementById('cp-path-before').textContent='Before: '+before;
      document.getElementById('cp-path-after').textContent='After: '+after;
      document.getElementById('cp-diff-expl').textContent='Diff explanation: '+(latest.diff_explanation||'-');
      document.getElementById('cp-code-diff').textContent=latest.code_diff||'No code diff';
      document.getElementById('cp-reasoning').textContent='Agent reasoning: '+(latest.reasoning||'-');
      document.getElementById('cp-patch-approval-status').textContent=`Approval status: ${latest.status} (${(latest.approvals_received||[]).length}/${latest.approvals_required})`;
    }
    const patchTerminal=document.getElementById('cp-patch-terminal');
    if(patchTerminal){
      const proposals=(data.proposals||[]).slice(-12).map((p)=>`[${p.proposal_id}] status=${p.status} approvals=${(p.approvals_received||[]).length}/${p.approvals_required}\n  summary=${p.summary}\n  plan=${(p.change_plan||[]).join('; ')}`).join('\n\n');
      patchTerminal.textContent = proposals || 'No generated patches yet.';
    }
    document.getElementById('cp-status').textContent='Control-plane synchronized.';
  }catch(_err){
    document.getElementById('cp-status').textContent='Control-plane data unavailable.';
  }
}

async function runAutonomousScan(){
  const endpointInput=document.getElementById('cp-scan-endpoint-input');
  const endpointId=(endpointInput && endpointInput.value.trim()) || 'ep-default-linux';
  const resp=await fetch('/api/control-plane/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({endpoint_id:endpointId, include_global_analysis:true, external_systems:[{system_id:'external-edge-01', host_name:'external-edge-01', network_exposure:'internet', unknown_integrity:true, telemetry_events:['recon','execution','lateral_movement']}]})});
  const data=await resp.json();
  document.getElementById('cp-status').textContent=`Autonomous scan cycle complete. findings=${(data.findings||[]).length}`;
  const terminal=document.getElementById('cp-scan-terminal');
  if(terminal){
    const findings=(data.findings||[]).slice(0,25).map((f)=>({
      cve:f.cve,
      risk_score:f.risk_score,
      cvss:f.cvss,
      exploit_availability:f.exploit_availability,
      endpoint_id:f.endpoint_id,
      reasoning:f.reasoning || 'n/a',
      evidence:(f.evidence||[]).slice(0,3),
      remediations:(f.suggested_remediations||[]),
    }));
    terminal.textContent = JSON.stringify({
      schema:'hegemon.scan_report.v2',
      findings,
      global_weakness_report:data.global_weakness_report || {},
    }, null, 2);
  }
  await loadControlPlane();
}


async function approveLatestPatch(){
  const status=document.getElementById('cp-patch-approval-status');
  const resp=await fetch('/api/control-plane/approve-latest',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({approver:'dashboard-operator'})});
  const payload=await resp.json();
  if(status){
    if(resp.ok){
      status.textContent=`Approval status: ${payload.status} (${payload.approvals_received}/${payload.approvals_required}) for ${payload.proposal_id}`;
    }else{
      status.textContent=`Approval failed: ${payload.message || payload.error || 'unknown_error'}`;
    }
  }
  await loadControlPlane();
}

async function approveAndApplyLatestPatch(){
  const status=document.getElementById('cp-patch-approval-status');
  const resp=await fetch('/api/control-plane/approve-apply-latest',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({autonomous:true})});
  const payload=await resp.json();
  if(status){
    if(resp.ok){
      status.textContent=`Approval status: ${payload.status} (${payload.approvals_received}/${payload.approvals_required}) for ${payload.proposal_id}`;
    }else{
      status.textContent=`Approval failed: ${payload.message || payload.error || 'unknown_error'}`;
    }
  }
  await loadControlPlane();
}

async function loadKernelTelemetryStatus(){
  const modeStatus=document.getElementById('kernel-telemetry-mode-status');
  const terminal=document.getElementById('kernel-telemetry-terminal');
  const toggle=document.getElementById('kernel-telemetry-mode-toggle');
  try{
    const resp=await fetch('/api/kernel-telemetry/status');
    const payload=await resp.json();
    const autonomous=Boolean(payload.autonomous);
    if(toggle){toggle.checked=autonomous;}
    if(modeStatus){modeStatus.textContent=autonomous? 'Autonomous mode: kernel telemetry is forwarded into detection pipeline.' : 'Manual mode: kernel telemetry snapshots are staged only.';}
    if(terminal){
      const reports=Array.isArray(payload.reports)?payload.reports:[];
      terminal.textContent = reports.length ? reports.map((row)=>JSON.stringify(row)).join('\n') : 'No kernel telemetry reports yet.';
    }
  }catch(_err){
    if(modeStatus){modeStatus.textContent='Kernel telemetry status unavailable.';}
  }
}

async function updateKernelTelemetryMode(autonomous){
  const modeStatus=document.getElementById('kernel-telemetry-mode-status');
  const resp=await fetch('/api/kernel-telemetry/mode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({autonomous})});
  const payload=await resp.json();
  if(modeStatus){modeStatus.textContent=payload.autonomous ? 'Autonomous mode: kernel telemetry is forwarded into detection pipeline.' : 'Manual mode: kernel telemetry snapshots are staged only.';}
  await loadKernelTelemetryStatus();
}

document.getElementById('cp-seed-btn')?.addEventListener('click', async()=>{
  const resp=await fetch('/api/control-plane/demo-seed',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({seed:true})});
  const data=await resp.json();
  document.getElementById('cp-status').textContent=data.message||'Seed complete';
  await loadControlPlane();
});


document.querySelectorAll('.cp-arrow').forEach((arrow)=>{
  const target=document.getElementById(arrow.dataset.target);
  let collapsed=false;
  arrow.addEventListener('click',()=>{ collapsed=!collapsed; setCollapsed(target, collapsed); arrow.textContent=collapsed?'▸':'▾'; });
});

document.getElementById('cp-add-friend-btn')?.addEventListener('click', async()=>{
  const name=window.prompt('Friend name');
  if(!name){return;}
  await fetch('/api/control-plane/add-friend',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})});
  await loadControlPlane();
});

document.getElementById('cp-add-endpoint-btn')?.addEventListener('click', async()=>{
  const host=window.prompt('Endpoint host name');
  if(!host){return;}
  await fetch('/api/control-plane/add-endpoint',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({host_name:host})});
  await loadControlPlane();
});

document.getElementById('cp-scan-endpoint-input')?.addEventListener('input', async(event)=>{
  const target=event.target;
  const suggestions=await autocompleteTerms('endpoints', target.value || '');
  const dl=document.getElementById('cp-endpoint-suggestions');
  if(dl){ dl.innerHTML=suggestions.map((s)=>`<option value="${s}"></option>`).join(''); }
});
document.getElementById('cp-approve-latest-btn')?.addEventListener('click', approveLatestPatch);
document.getElementById('cp-approve-apply-btn')?.addEventListener('click', approveAndApplyLatestPatch);

document.getElementById("run-btn")?.addEventListener("click",startWithPermission);
document.getElementById("drill-btn")?.addEventListener("click",runIncidentDrill);
document.getElementById("containment-yes")?.addEventListener("click",()=>decideContainment(true));
document.getElementById("containment-no")?.addEventListener("click",()=>decideContainment(false));
document.getElementById("human-gate-toggle")?.addEventListener("change",(event)=>{
  const target=event.target;
  updateHumanGate(Boolean(target && target.checked));
});
document.getElementById("containment-live-toggle")?.addEventListener("change",(event)=>{
  const target=event.target;
  updateContainmentLiveMode(Boolean(target && target.checked));
});
document.getElementById("kernel-telemetry-mode-toggle")?.addEventListener("change",(event)=>{
  const target=event.target;
  updateKernelTelemetryMode(Boolean(target && target.checked));
});
window.addEventListener("load",()=>{loadHumanGateStatus(); loadContainmentLiveStatus(); promptHardwareKeyBootstrap(); loadControlPlane(); runAutonomousScan(); loadKernelTelemetryStatus(); window.setInterval(runAutonomousScan, 60000); window.setInterval(loadKernelTelemetryStatus, 5000);});
</script>
</body>
</html>
"""


def _api_token() -> str:
    global _auth_warning_emitted
    settings = Settings.load()
    configured = str(settings.get("dashboard_api_token", "")).strip()
    if configured:
        return configured
    env_token = str(settings.env("SENTINEL_DASHBOARD_TOKEN", "")).strip()
    if env_token:
        return env_token
    if not _auth_warning_emitted:
        logger.error("Dashboard API token is not configured. Set dashboard_api_token or SENTINEL_DASHBOARD_TOKEN.")
        _auth_warning_emitted = True
    return ""


def _is_authenticated() -> bool:
    token = _api_token()
    if not token:
        return False
    provided = request.headers.get("Authorization", "")
    if provided.lower().startswith("bearer "):
        provided = provided[7:].strip()
    return bool(provided) and hmac.compare_digest(provided, token)


def _require_auth():
    if _is_authenticated():
        return None
    return jsonify({"error": "unauthorized", "message": "valid bearer token required"}), 401


def _safe_json_payload(max_bytes: int = 65536) -> tuple[dict, tuple | None]:
    if request.content_length is not None and request.content_length > max_bytes:
        return {}, (jsonify({"error": "payload_too_large", "message": f"max payload size is {max_bytes} bytes"}), 413)
    payload = request.get_json(silent=True)
    if payload is None:
        return {}, (jsonify({"error": "invalid_json", "message": "request body must be valid JSON"}), 400)
    if not isinstance(payload, dict):
        return {}, (jsonify({"error": "invalid_payload", "message": "request body must be a JSON object"}), 400)
    return payload, None


@app.after_request
def apply_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    response.headers["Cache-Control"] = "no-store"
    nonce = getattr(g, "csp_nonce", "")
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self' 'nonce-{nonce}'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'none'; "
        "form-action 'self'"
    )
    response.headers["X-CSRF-Protection"] = "token-required-for-state-change"
    return response




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


def _readiness_payload() -> dict[str, object]:
    runtime_payload = _runtime.get_readiness_status() if _runtime is not None else {}
    token_ready = bool(_api_token())
    readiness = {
        "token_ready": token_ready,
        "key_policy_ready": bool(runtime_payload.get("key_policy_ready", False)),
        "containment_ready": bool(runtime_payload.get("containment_ready", False)),
        "containment_live_mode": bool(runtime_payload.get("containment_live_mode", True)),
        "startup_warning": str(runtime_payload.get("startup_warning", "")),
        "blocked_reasons": list(runtime_payload.get("blocked_reasons", [])),
    }
    if not token_ready and not readiness["startup_warning"]:
        readiness["startup_warning"] = "⚠️ HARD WARNING: dashboard API token missing; operator auth is not ready."
    return readiness


@app.get("/")
def dashboard():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    state = _load_latest_state()
    return render_template_string(
        HTML,
        events_processed=state.get("events_processed", 0),
        alerts_count=len(state.get("severity_alerts", state.get("alerts", []))),
        graph_count=len(state.get("graph_anomalies", [])),
        chains_count=len(state.get("attack_chains", [])),
        candidate_severity=state.get("candidate_severity", 0),
        graph_anomalies=state.get("graph_anomalies", []),
        attack_chains=state.get("attack_chains", []),
        severity_alerts=state.get("severity_alerts", []),
        correlated=json.dumps(state.get("correlated", {}), indent=2),
        contained_hosts=json.dumps(state.get("contained_hosts", []), indent=2),
        soar_actions=json.dumps(state.get("soar_actions", []), indent=2),
        topology=json.dumps(state.get("topology", {}), indent=2),
        containment_decision=state.get("containment_decision", {}),
        containment_decision_json=json.dumps(state.get("containment_decision", {}), indent=2),
        severity_class=_severity_class,
        readiness=_readiness_payload(),
        csp_nonce=getattr(g, "csp_nonce", ""),
    )


@app.get("/graph")
def graph():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    state = _load_latest_state()
    topology = state.get("topology", {})
    redacted = {"nodes": len(topology.get("nodes", [])), "edges": len(topology.get("edges", [])), "redacted": True}
    return jsonify(redacted)


@app.get("/api/state")
def api_state():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    return jsonify(_load_latest_state())


@app.get("/api/health")
def api_health():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    state = _load_latest_state()
    fast_lane_status = state.get("fast_lane_status", {"enabled": False, "active": False, "missing_tls_files": []})
    return jsonify({"ok": True, "fast_lane": fast_lane_status})

def set_runtime(runtime: SentinelRuntime) -> None:
    global _runtime
    _runtime = runtime


@app.get("/api/telemetry/permission")
def telemetry_permission_status():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    if _runtime is None:
        return jsonify({"required": True, "granted": False, "completed": False, "details": ["runtime_not_initialized"]}), 503
    return jsonify(_runtime.get_telemetry_setup_notice())


@app.post("/api/telemetry/permission")
def telemetry_permission_apply():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    payload, error = _safe_json_payload()
    if error:
        return error
    granted_value = payload.get("granted", False)
    if not isinstance(granted_value, bool):
        return jsonify({"error": "invalid_payload", "message": "granted must be a boolean"}), 400
    granted = granted_value
    if _runtime is None:
        return jsonify({"required": True, "granted": granted, "completed": False, "details": ["runtime_not_initialized"]}), 503
    return jsonify(_runtime.apply_telemetry_permission(granted))


@app.get("/api/human-gate/status")
def human_gate_status():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    if _runtime is None:
        return jsonify({"human_required": False, "completed": True, "details": ["runtime_not_initialized"]}), 503
    return jsonify(_runtime.get_human_gate_status())


@app.post("/api/human-gate/toggle")
def human_gate_toggle():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    payload, error = _safe_json_payload()
    if error:
        return error
    human_required_value = payload.get("human_required", False)
    if not isinstance(human_required_value, bool):
        return jsonify({"error": "invalid_payload", "message": "human_required must be a boolean"}), 400
    if _runtime is None:
        return jsonify({"human_required": bool(human_required_value), "completed": False, "details": ["runtime_not_initialized"]}), 503
    return jsonify(_runtime.set_human_gate(bool(human_required_value)))


@app.get("/api/containment-live-mode/status")
def containment_live_mode_status():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    if _runtime is None:
        return jsonify({"containment_live_mode": True, "completed": False, "details": ["runtime_not_initialized"]}), 503
    return jsonify(_runtime.get_containment_live_mode_status())


@app.post("/api/containment-live-mode/toggle")
def containment_live_mode_toggle():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    payload, error = _safe_json_payload()
    if error:
        return error
    live_mode_value = payload.get("containment_live_mode", True)
    if not isinstance(live_mode_value, bool):
        return jsonify({"error": "invalid_payload", "message": "containment_live_mode must be a boolean"}), 400
    if _runtime is None:
        return jsonify({"containment_live_mode": bool(live_mode_value), "completed": False, "details": ["runtime_not_initialized"]}), 503
    return jsonify(_runtime.set_containment_live_mode(bool(live_mode_value)))


@app.get("/api/hardware-keys/status")
def hardware_key_status():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    if _runtime is None:
        return jsonify({"required": True, "configured": False, "completed": False, "details": ["runtime_not_initialized"]}), 503
    return jsonify(_runtime.get_hardware_key_setup_notice())


@app.post("/api/hardware-keys/auto-configure")
def hardware_key_auto_configure():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    payload, error = _safe_json_payload()
    if error:
        return error
    configure_value = payload.get("configure", False)
    if not isinstance(configure_value, bool):
        return jsonify({"error": "invalid_payload", "message": "configure must be a boolean"}), 400
    if _runtime is None:
        return jsonify({"required": True, "configured": False, "completed": False, "details": ["runtime_not_initialized"]}), 503
    return jsonify(_runtime.auto_configure_hardware_keys(configure_value))


@app.get("/api/kernel-telemetry/status")
def kernel_telemetry_status():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    if _runtime is None:
        return jsonify({"autonomous": True, "reports": [], "completed": False, "details": ["runtime_not_initialized"]}), 503
    return jsonify(_runtime.get_kernel_telemetry_status())


@app.post("/api/kernel-telemetry/mode")
def kernel_telemetry_mode_toggle():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    payload, error = _safe_json_payload()
    if error:
        return error
    autonomous_value = payload.get("autonomous", True)
    if not isinstance(autonomous_value, bool):
        return jsonify({"error": "invalid_payload", "message": "autonomous must be a boolean"}), 400
    if _runtime is None:
        return jsonify({"autonomous": bool(autonomous_value), "reports": [], "completed": False, "details": ["runtime_not_initialized"]}), 503
    return jsonify(_runtime.set_kernel_telemetry_mode(bool(autonomous_value)))


@app.get("/api/readiness")
def api_readiness():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    return jsonify(_readiness_payload())


@app.post("/api/drill/incident")
def incident_drill():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    payload, error = _safe_json_payload()
    if error:
        return error
    run_value = payload.get("run", False)
    if not isinstance(run_value, bool):
        return jsonify({"error": "invalid_payload", "message": "run must be a boolean"}), 400
    if not run_value:
        return jsonify({"mode": "deterministic_incident_drill", "approved": False, "message": "drill_not_requested"})
    if _runtime is None:
        return jsonify({"mode": "deterministic_incident_drill", "approved": False, "message": "runtime_not_initialized"}), 503
    return jsonify(_runtime.run_incident_drill())


@app.get("/api/containment/decision")
def containment_decision_status():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    if _runtime is None:
        return jsonify({"pending": False, "message": "runtime_not_initialized"}), 503
    return jsonify(_runtime.get_containment_decision_status())


@app.post("/api/containment/decision")
def containment_decision_apply():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    payload, error = _safe_json_payload()
    if error:
        return error
    execute_value = payload.get("execute", False)
    if not isinstance(execute_value, bool):
        return jsonify({"error": "invalid_payload", "message": "execute must be a boolean"}), 400
    execute = execute_value
    if _runtime is None:
        return jsonify({"pending": False, "executed": False, "message": "runtime_not_initialized"}), 503
    return jsonify(_runtime.apply_containment_decision(execute))


@app.get("/api/control-plane/overview")
def control_plane_overview():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    return jsonify(
        {
            "friends": [_control_plane.as_dict(v) for v in _control_plane.friends.values()],
            "endpoints": [_control_plane.as_dict(v) for v in _control_plane.endpoints.values()],
            "findings": [_control_plane.as_dict(v) for v in _control_plane.findings.values()],
            "proposals": [_control_plane.as_dict(v) for v in _control_plane.patch_proposals.values()],
            "stores": [_control_plane.as_dict(v) for v in _control_plane.friendly_stores.values()],
            "apps": [_control_plane.as_dict(v) for v in _control_plane.friendly_apps.values()],
            "ledger_health": _control_plane.ledger_health(),
        }
    )


@app.post("/api/control-plane/demo-seed")
def control_plane_demo_seed():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    if "fr-dashboard-admin" not in _control_plane.friends:
        _control_plane.add_friend(
            {
                "friend_id": "fr-dashboard-admin",
                "name": "Dashboard Admin",
                "identity_type": "user",
                "identity_method": "sso",
                "capabilities": ["approve_firmware"],
                "expiry": "2030-01-01T00:00:00Z",
            },
            actor="dashboard",
        )
        _control_plane.approve_friend("fr-dashboard-admin", "admin-2")
        _control_plane.approve_friend("fr-dashboard-admin", "admin-3")
    if "ep-dashboard-demo" not in _control_plane.endpoints:
        _control_plane.add_endpoint(
            {
                "endpoint_id": "ep-dashboard-demo",
                "host_name": "prod-api-1",
                "endpoint_type": "on-prem",
                "os": "ubuntu",
                "kernel": "6.8",
                "hypervisor": "kvm",
                "firmware_baseline": "1.0.4",
                "sbom_status": "valid",
                "enrollment_method": "mdm",
                "network_exposure": "internet",
                "asset_value": 9.4,
                "trust_level": 6.0,
                "installed_packages": {"openssl": "3.0.2", "glibc": "2.37", "openssh": "9.3"},
            },
            actor="dashboard",
        )
    if "app-dashboard-nginx" not in _control_plane.friendly_apps:
        _control_plane.add_friendly_app(
            {
                "app_id": "app-dashboard-nginx",
                "name": "Nginx",
                "icon": "🌐",
                "store_id": "store-linux",
                "publisher": "NGINX Inc.",
                "version": "1.25.5",
            },
            actor="dashboard",
        )
    return jsonify({"message": "demo control-plane objects seeded"})


@app.post("/api/control-plane/scan")
def control_plane_scan():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    payload, error = _safe_json_payload()
    if error:
        return error
    endpoint_id = str(payload.get("endpoint_id", "")).strip()
    include_global_analysis = bool(payload.get("include_global_analysis", True))
    external_systems_raw = payload.get("external_systems", [])
    external_systems = external_systems_raw if isinstance(external_systems_raw, list) else []
    if not endpoint_id:
        return jsonify({"error": "invalid_payload", "message": "endpoint_id is required"}), 400
    if endpoint_id not in _control_plane.endpoints:
        return jsonify({"error": "not_found", "message": "endpoint not found"}), 404
    findings = _control_plane.run_vulnerability_scan(endpoint_id, actor="dashboard_scanner")
    proposals = [
        _control_plane.as_dict(_control_plane.generate_patch_proposal(finding.finding_id, actor="dashboard_scanner"))
        for finding in findings
    ]
    global_report = _control_plane.analyze_global_attack_surface(external_systems if include_global_analysis else [])
    return jsonify(
        {
            "endpoint_id": endpoint_id,
            "findings": [_control_plane.as_dict(f) for f in findings],
            "proposals": proposals,
            "global_weakness_report": global_report,
        }
    )


@app.post("/api/control-plane/approve-latest")
def control_plane_approve_latest():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    payload, error = _safe_json_payload()
    if error:
        return error
    approver = str(payload.get("approver", "dashboard-operator")).strip() or "dashboard-operator"
    proposals = list(_control_plane.patch_proposals.values())
    if not proposals:
        return jsonify({"error": "not_found", "message": "no patch proposals available"}), 404

    latest = proposals[-1]
    if latest.status == "deployed_canary":
        return jsonify(
            {
                "proposal_id": latest.proposal_id,
                "status": latest.status,
                "approvals_required": latest.approvals_required,
                "approvals_received": len(latest.approvals_received),
                "message": "already_applied",
            }
        )

    latest = _control_plane.approve_patch(latest.proposal_id, approver)
    return jsonify(
        {
            "proposal_id": latest.proposal_id,
            "status": latest.status,
            "approvals_required": latest.approvals_required,
            "approvals_received": len(latest.approvals_received),
            "approver": approver,
        }
    )


@app.post("/api/control-plane/approve-apply-latest")
def control_plane_approve_apply_latest():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    payload, error = _safe_json_payload()
    if error:
        return error
    autonomous = bool(payload.get("autonomous", True))
    proposals = list(_control_plane.patch_proposals.values())
    if not proposals:
        return jsonify({"error": "not_found", "message": "no patch proposals available"}), 404

    latest = proposals[-1]
    if latest.status not in {"approved", "deployed_canary"}:
        _control_plane.approve_patch(latest.proposal_id, "admin-1")
    latest = _control_plane.patch_proposals[latest.proposal_id]
    if autonomous and latest.status not in {"approved", "deployed_canary"}:
        _control_plane.approve_patch(latest.proposal_id, "admin-2")
    latest = _control_plane.patch_proposals[latest.proposal_id]

    if latest.status == "approved":
        latest = _control_plane.apply_patch(latest.proposal_id, actor="dashboard-autonomous")

    return jsonify(
        {
            "proposal_id": latest.proposal_id,
            "status": latest.status,
            "approvals_required": latest.approvals_required,
            "approvals_received": len(latest.approvals_received),
            "autonomous": autonomous,
        }
    )


@app.get("/api/control-plane/autocomplete")
def control_plane_autocomplete():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    kind = str(request.args.get("kind", "")).strip().lower()
    q = str(request.args.get("q", "")).strip().lower()
    if kind == "endpoints":
        pool = [e.endpoint_id for e in _control_plane.endpoints.values()] + [e.host_name for e in _control_plane.endpoints.values()]
    elif kind == "friends":
        pool = [f.name for f in _control_plane.friends.values()]
    else:
        pool = [e.endpoint_id for e in _control_plane.endpoints.values()] + [e.host_name for e in _control_plane.endpoints.values()] + [f.name for f in _control_plane.friends.values()]
    return jsonify({"suggestions": [v for v in pool if q in v.lower()][:15]})


@app.post("/api/control-plane/add-friend")
def control_plane_add_friend():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    payload, error = _safe_json_payload()
    if error:
        return error
    name = str(payload.get("name", "")).strip()
    if not name:
        return jsonify({"error": "invalid_payload", "message": "name required"}), 400
    friend = _control_plane.add_friend(
        {
            "name": name,
            "identity_type": "user",
            "identity_method": "sso",
            "capabilities": ["approve_patches"],
            "expiry": "2030-01-01T00:00:00Z",
        },
        actor="dashboard",
    )
    return jsonify(_control_plane.as_dict(friend)), 201


@app.post("/api/control-plane/add-endpoint")
def control_plane_add_endpoint():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    payload, error = _safe_json_payload()
    if error:
        return error
    host_name = str(payload.get("host_name", "")).strip()
    if not host_name:
        return jsonify({"error": "invalid_payload", "message": "host_name required"}), 400
    endpoint = _control_plane.add_endpoint(
        {
            "host_name": host_name,
            "endpoint_type": "on-prem",
            "os": "linux",
            "kernel": "unknown",
            "sbom_status": "unknown",
            "enrollment_method": "manual",
            "installed_packages": {},
        },
        actor="dashboard",
    )
    return jsonify(_control_plane.as_dict(endpoint)), 201


@app.get("/api/discovery/status")
def discovery_status():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    if _runtime is None:
        return jsonify({"running": False, "message": "runtime_not_initialized"}), 503
    return jsonify(_runtime.discovery_engine.status())


@app.get("/api/discovery/hosts")
def discovery_hosts():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    if _runtime is None:
        return jsonify({"hosts": [], "message": "runtime_not_initialized"}), 503
    return jsonify({"hosts": _runtime.discovery_engine.last_hosts})


@app.get("/api/notifications/history")
def notifications_history():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    if _runtime is None:
        return jsonify({"history": [], "message": "runtime_not_initialized"}), 503
    return jsonify({"history": list(_runtime.notification_history)})


@app.get("/api/peer/ping")
def peer_ping():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    return jsonify({"status": "ok"})


@app.get("/api/peer/registry")
def peer_registry():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    peers = _runtime.peer_mesh.process_ids if _runtime is not None else []
    return jsonify({"peers": peers})


@app.post("/api/peer/verify")
def peer_verify():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    payload, error = _safe_json_payload()
    if error:
        return error
    return jsonify({"valid": bool(payload.get("directive")), "attestor": "local"})
