from __future__ import annotations

import json
import logging
import os
import secrets
import time
import ipaddress

import hmac
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, g, jsonify, make_response, render_template_string, request

from sentinel_containment.config import Settings
from sentinel_containment.controlplane import HEGEMON_SELF_ENDPOINT_ID, HegemonControlPlane
from sentinel_containment.runtime import SentinelRuntime

app = Flask(__name__)
logger = logging.getLogger(__name__)
_runtime: SentinelRuntime | None = None
_auth_warning_emitted = False
_control_plane = HegemonControlPlane()
_AUTOCOMPLETE_CACHE: dict[str, tuple[float, dict]] = {}


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


def _trusted_reverse_proxies() -> set[str]:
    settings = Settings.load()
    configured = settings.get("web_trusted_reverse_proxies", [])
    if isinstance(configured, str):
        configured = [token.strip() for token in configured.split(",") if token.strip()]
    return {str(proxy).strip() for proxy in configured if str(proxy).strip()}


_TRUSTED_REVERSE_PROXIES = _trusted_reverse_proxies()


def _is_loopback(addr: str | None) -> bool:
    if not addr:
        return False
    normalized = addr.strip().lower()
    if normalized in {"localhost"}:
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _is_local_request() -> bool:
    remote = request.remote_addr or ""
    local_remote = _is_loopback(remote)
    if not local_remote and remote in _TRUSTED_REVERSE_PROXIES:
        forwarded = (request.headers.get("X-Forwarded-For", "").split(",")[0].strip())
        local_remote = bool(forwarded and _is_loopback(forwarded))
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
    .drone-network-grid{display:grid;grid-template-columns:220px 1fr;gap:8px;margin-top:8px;}
    .drone-chip{padding:6px 8px;border:1px solid #345098;background:#17213c;border-radius:8px;cursor:pointer;margin-bottom:6px;}
    .drone-link-card{padding:8px;border:1px solid #2f4383;border-radius:8px;background:#131d35;margin-bottom:6px;}
    .drone-link-pill{display:inline-block;padding:2px 6px;border-radius:999px;background:#243868;border:1px solid #38559a;font-size:11px;margin-right:4px;}
  </style>
</head>
<body>
<div class="wrap">
  <div class="title">
    <h1>Sentinel-Containment Command Center</h1>
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
    <button class="tab-btn" data-tab="drones">Drones</button>
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
        <div style="position:relative;min-width:320px;flex:1;">
          <input id="cp-scan-endpoint-input" placeholder="Search apps, packages, endpoints..." style="width:100%;padding:8px;border-radius:8px;border:1px solid #35508f;background:#0f1528;color:#d8e2ff;" />
          <div id="cp-autocomplete-dropdown" style="display:none;position:absolute;z-index:30;left:0;right:0;top:38px;background:#0f1528;border:1px solid #35508f;border-radius:8px;max-height:260px;overflow:auto;"></div>
        </div>
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
      <h3>Add Software to Monitoring</h3>
      <div class="small" id="store-selected">Selected: none</div>
      <div class="small" id="store-detected-root">Detected root: unknown</div>
      <div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap;">
        <select id="store-filter"><option value="">All Stores</option></select>
        <select id="store-exposure"><option value="internal">Internal</option><option value="internet">Internet</option></select>
        <input id="store-asset" type="number" step="0.1" value="7.0" style="width:100px;padding:6px;border-radius:6px;background:#0f1528;color:#d8e2ff;border:1px solid #35508f;" />
        <button id="store-register-scan-btn" style="padding:8px 12px;background:#22543d;color:#d8e2ff;border:1px solid #2f855a;border-radius:8px;cursor:pointer;">Register & Scan</button>
      </div>
    </div>
    <div class="panel">
      <h3>Issues by Language</h3>
      <div class="json"><pre id="cp-lang-breakdown">No scan reports generated yet.</pre></div>
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

  <div id="tab-drones" class="tab-panel">
    <div class="panel">
      <h3>DRONES</h3>
      <div class="small">Visual behaviour builder + compiled blob lifecycle management.</div>
      <div style="display:grid;grid-template-columns:300px 1fr 320px;gap:10px;margin-top:10px;">
        <div>
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <strong>Fleet</strong>
            <button id="new-drone-btn" class="tab-btn">+ New Drone</button>
          </div>
          <select id="sample-drone-select" class="tab-btn" style="margin-top:8px;width:100%;padding:8px;">
            <option value="">Load Sample Drone ▾</option>
          </select>
          <button id="apply-sample-drone-btn" class="tab-btn" style="margin-top:8px;width:100%;">Apply Sample to Builder</button>
          <button id="auto-assemble-drone-btn" class="tab-btn" style="margin-top:8px;width:100%;">Auto-Assemble</button>
          <div id="drone-fleet" style="margin-top:8px;"></div>
        </div>
        <div>
          <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap;">
            <strong>Behaviour Canvas</strong>
            <button id="graph-validate" class="tab-btn">Validate</button>
            <button id="graph-compile" class="tab-btn">Compile & Assemble</button>
            <button id="graph-save-brain" class="tab-btn">Save as Brain...</button>
            <select id="graph-load-brain" class="tab-btn" style="padding:8px;"><option value="">Load Brain ▾</option></select>
          </div>
          <div style="display:grid;grid-template-columns:210px 1fr;gap:8px;">
            <div id="node-palette" class="json" style="max-height:420px;"></div>
            <div id="drone-canvas-wrap" class="json" style="position:relative;height:420px;overflow:hidden;">
              <svg id="drone-edge-svg" style="position:absolute;inset:0;width:100%;height:100%;pointer-events:none;"></svg>
              <div id="drone-canvas" style="position:absolute;inset:0;overflow:hidden;"></div>
            </div>
          </div>
          <div id="graph-errors" class="small" style="color:#ff9f9f;margin-top:8px;"></div>
          <div class="json" style="margin-top:8px;">
            <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;">
              <strong>Adaptive Drone Link Builder</strong>
              <div style="display:flex;gap:8px;">
                <button id="squad-assemble-btn" class="tab-btn">Assemble Squad</button>
                <button id="squad-clear-btn" class="tab-btn">Clear Links</button>
              </div>
            </div>
            <div class="small" style="margin:6px 0 8px;">Select sample drones, connect them visually, and adjust route destinations for each member.</div>
            <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
              <select id="squad-sample-select" class="tab-btn" style="padding:8px;min-width:220px;"><option value="">Select Sample Drone ▾</option></select>
              <input id="squad-drone-destination" placeholder="Destination (host/network/endpoint)" style="padding:8px;border-radius:8px;background:#0f1528;color:#d8e2ff;border:1px solid #2f4383;min-width:280px;" />
              <button id="squad-add-btn" class="tab-btn">Add to Squad</button>
            </div>
            <div class="drone-network-grid">
              <div>
                <div id="squad-drone-list" class="small" style="margin-top:8px;"></div>
                <div id="squad-links" class="small" style="margin-top:8px;"></div>
              </div>
              <div id="squad-canvas-wrap" style="position:relative;height:220px;overflow:hidden;border:1px solid #2f4383;border-radius:8px;background:#0f1528;">
                <svg id="squad-edge-svg" style="position:absolute;inset:0;width:100%;height:100%;pointer-events:none;"></svg>
                <div id="squad-canvas" style="position:absolute;inset:0;"></div>
              </div>
            </div>
          </div>
          <div class="json" style="margin-top:8px;">
            <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;">
              <input id="drone-name" placeholder="Name" value="Scout-Alpha" />
              <select id="drone-tier"><option value="controlled">Controlled</option><option value="tethered">Tethered</option><option value="autonomous">Autonomous</option></select>
              <select id="drone-mission"><option value="scout">scout</option><option value="watch-loop">watch-loop</option><option value="probe">probe</option></select>
              <select id="drone-autonomy"><option value="observe">observe</option><option value="contain">contain</option><option value="enforce">enforce</option></select>
              <input id="drone-target" placeholder="Target host/network" />
              <input id="drone-ttl" type="number" value="3600" />
              <input id="drone-checkin" type="number" value="60" />
            </div>
          </div>
          <div id="drone-build-result" class="small" style="margin-top:8px;"></div>
        </div>
        <div>
          <strong>Node Inspector / Detail</strong>
          <div id="node-inspector" class="json" style="margin-top:8px;">Select a node on the canvas.</div>
          <div class="json" style="margin-top:8px;"><pre id="drone-actions">Loading binary action matrix...</pre></div>
          <div class="json" style="margin-top:8px;"><pre id="drone-comms">Awaiting drone comms telemetry and binary uplink decode.</pre></div>
          <div id="drone-detail" class="json" style="margin-top:8px;">Select a drone card to inspect.</div>
        </div>
      </div>
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
const tabPanels={overview:document.getElementById('tab-overview'),'control-plane':document.getElementById('tab-control-plane'),'kernel-telemetry':document.getElementById('tab-kernel-telemetry'),'drones':document.getElementById('tab-drones')};
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

async function autocompleteTerms(kind, q, storeIds){
  const enabled=document.getElementById('cp-autocomplete-enabled');
  if(enabled && !enabled.checked){ return []; }
  const sid=(storeIds||[]).join(',');
  const resp=await fetch(`/api/control-plane/autocomplete?kind=${encodeURIComponent(kind)}&q=${encodeURIComponent(q||'')}&store_ids=${encodeURIComponent(sid)}`);
  if(!resp.ok){ return []; }
  const data=await resp.json();
  return data.suggestions || [];
}

class HegemonAutocomplete {
  constructor(inputEl, dropdownEl){
    this.inputEl=inputEl; this.dropdownEl=dropdownEl; this.timer=null; this.items=[]; this.active=-1; this.selected=null;
    inputEl.addEventListener('input', ()=>this.schedule());
    inputEl.addEventListener('keydown', (e)=>this.onKey(e));
    document.addEventListener('click', (e)=>{ if(!dropdownEl.contains(e.target) && e.target!==inputEl){ this.hide(); } });
  }
  schedule(){ clearTimeout(this.timer); this.timer=setTimeout(()=>this.fetch(),200); }
  async fetch(){
    const q=(this.inputEl.value||'').trim();
    if(!q){this.hide(); return;}
    this.dropdownEl.style.display='block';
    this.dropdownEl.innerHTML='<div style="padding:8px;opacity:0.7;">Loading…</div>';
    const storeSel=document.getElementById('store-filter');
    const storeIds=storeSel && storeSel.value ? [storeSel.value] : [];
    this.items=await autocompleteTerms('all', q, storeIds);
    this.active=-1;
    if(!this.items.length){ this.dropdownEl.innerHTML='<div style="padding:8px;opacity:0.7;">No results</div>'; return; }
    this.render();
  }
  render(){
    this.dropdownEl.innerHTML=this.items.map((it,idx)=>{
      const badge=it.trust_tier==='verified' ? '<span style="color:#7CFC8A">✓ Verified</span>' : (it.trust_tier? '<span style="color:#f6ad55">Community</span>' : '');
      const icon=(it.icon||'').startsWith('http')?`<img src="${it.icon}" style="width:18px;height:18px;border-radius:4px;"/>`:`<span>${it.icon||'PKG'}</span>`;
      return `<div data-idx="${idx}" style="padding:8px;display:flex;gap:8px;align-items:center;cursor:pointer;background:${idx===this.active?'#1a2342':'transparent'};">
        ${icon}<div style="flex:1;"><div style="font-weight:700;">${it.label}</div><div style="font-size:12px;opacity:0.8;">${it.sublabel||''}</div></div><div style="font-size:12px;">${badge}</div></div>`;
    }).join('');
    this.dropdownEl.querySelectorAll('[data-idx]').forEach((el)=>el.addEventListener('mouseenter',()=>{this.active=Number(el.dataset.idx); this.render();}));
    this.dropdownEl.querySelectorAll('[data-idx]').forEach((el)=>el.addEventListener('click',()=>this.select(Number(el.dataset.idx))));
  }
  onKey(e){
    if(!this.dropdownEl || this.dropdownEl.style.display==='none') return;
    if(e.key==='ArrowDown'){ e.preventDefault(); this.active=Math.min(this.items.length-1,this.active+1); this.render(); }
    if(e.key==='ArrowUp'){ e.preventDefault(); this.active=Math.max(0,this.active-1); this.render(); }
    if(e.key==='Enter'){ if(this.active>=0){ e.preventDefault(); this.select(this.active);} }
    if(e.key==='Escape'){ this.hide(); }
  }
  select(idx){
    const it=this.items[idx];
    if(!it) return;
    this.selected=it;
    this.inputEl.value=it.label;
    this.hide();
    const selected=document.getElementById('store-selected');
    if(selected){ selected.textContent=`Selected: ${it.label} (${it.store_id||it.type})`; }
    const root=document.getElementById('store-detected-root');
    if(root){ root.textContent='Detected root: auto-detect on register'; }
  }
  hide(){ this.dropdownEl.style.display='none'; }
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
      cross_language_analysis_note:data.cross_language_analysis_note || 'potential cross-language hints (not confirmed taint chains)',
      potential_cross_language_hints:(data.potential_cross_language_hints||[]).slice(0, 10),
      lstm_rnn_binary_model:data.lstm_rnn_binary_model || {},
      integrated_flow_model:data.integrated_flow_model || {},
    }, null, 2);
  }

  const langNode=document.getElementById('cp-lang-breakdown');
  if(langNode){
    const lb=data.lang_breakdown || {};
    const rows=Object.entries(lb).map(([k,v])=>`${k.padEnd(10,' ')} ${'█'.repeat(Math.min(10,Number(v)||0))} ${v} issues`);
    langNode.textContent=rows.length? rows.join('\n') : 'No language issues yet.';
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

async function loadStoreFilters(){
  const sel=document.getElementById('store-filter');
  if(!sel) return;
  try{
    const resp=await fetch('/api/control-plane/overview');
    const data=await resp.json();
    const stores=data.friendly_stores||[];
    sel.innerHTML='<option value="">All Stores</option>'+stores.map((s)=>`<option value="${s.store_id}">${s.name}</option>`).join('');
  }catch(_err){}
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

let hegemonAutocomplete=null;
const scanInput=document.getElementById('cp-scan-endpoint-input');
const scanDropdown=document.getElementById('cp-autocomplete-dropdown');
if(scanInput && scanDropdown){ hegemonAutocomplete=new HegemonAutocomplete(scanInput, scanDropdown); }

document.getElementById('store-register-scan-btn')?.addEventListener('click', async()=>{
  const q=(scanInput && scanInput.value || '').trim();
  if(!q){return;}
  const storeId=(document.getElementById('store-filter')?.value)||'';
  const network_exposure=(document.getElementById('store-exposure')?.value)||'internal';
  const asset_value=parseFloat((document.getElementById('store-asset')?.value)||'7.0');
  const resp=await fetch('/api/store/register-endpoint',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({query:q,store_id:storeId,network_exposure,asset_value,actor:'dashboard'})});
  const data=await resp.json();
  if(resp.ok){
    document.getElementById('store-detected-root').textContent=`Detected root: ${data.program_root_detected || 'not found'}`;
    if(scanInput && data.endpoint){ scanInput.value=data.endpoint.endpoint_id; }
    document.getElementById('cp-status').textContent='Store endpoint registered.';
  }else{
    document.getElementById('cp-status').textContent=`Store registration failed: ${data.error||'unknown_error'}`;
  }
  await loadControlPlane();
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
window.addEventListener("load",()=>{loadHumanGateStatus(); loadContainmentLiveStatus(); promptHardwareKeyBootstrap(); loadStoreFilters(); loadControlPlane(); runAutonomousScan(); loadKernelTelemetryStatus(); window.setInterval(runAutonomousScan, 60000); window.setInterval(loadKernelTelemetryStatus, 5000);});

let selectedDroneId=null;
let droneActionMatrix=[];
const graphState={nodes:{},edges:[],selected:null,dragging:null,connecting:null,pan:{x:0,y:0},zoom:1.0};
const squadState={nodes:[],links:[],selectedNodeId:null,linkingFrom:null};
let _brainsCache=[];

let SAMPLE_DRONES=[];

async function loadSampleDrones(){
  try{
    const resp=await fetch('/api/drones/samples');
    if(!resp.ok){return;}
    const rows=await resp.json();
    SAMPLE_DRONES=(rows||[]).map(r=>({
      sample_id:r.sample_id,
      name:r.name,
      tier:r.tier,
      mission:r.mission,
      autonomy_level:r.autonomy_level,
      ttl_seconds:r.ttl_seconds,
      checkin_interval_seconds:r.checkin_interval_seconds,
      target:r.target,
      behaviour_id:r.behaviour_id,
      brain_name:r.brain_name,
      description:r.description,
    }));
  }catch(_e){}
}

const NODE_LIBRARY=[
  {kind:'on_launch',type:'trigger',label:'On Launch'},
  {kind:'ping_host',type:'action',label:'Ping Host'},
  {kind:'port_scan',type:'action',label:'Port Scan'},
  {kind:'subnet_scan',type:'action',label:'Subnet Scan'},
  {kind:'banner_grab',type:'action',label:'Banner Grab'},
  {kind:'local_intel',type:'action',label:'Local Intel'},
  {kind:'send_report',type:'action',label:'Send Report'},
  {kind:'write_deadrop',type:'action',label:'Write Deadrop'},
  {kind:'spawn_child',type:'action',label:'Spawn Child'},
  {kind:'adaptive_wait',type:'action',label:'Adaptive Wait'},
  {kind:'peer_sync',type:'action',label:'Peer Sync'},
  {kind:'self_destruct',type:'action',label:'Self Destruct'},
  {kind:'if_severity',type:'condition',label:'If Severity >='},
  {kind:'if_ttl_expired',type:'condition',label:'If TTL Expired'},
  {kind:'if_findings_gt',type:'condition',label:'If Findings > N'},
  {kind:'wait',type:'control',label:'Wait'},
  {kind:'parallel',type:'control',label:'Parallel'},
  {kind:'repeat',type:'control',label:'Repeat'},
  {kind:'self_terminate',type:'control',label:'Self Terminate'},
];
const NODE_SCHEMAS={
  ping_host:[{key:'host',type:'text',label:'Host',default:''},{key:'message',type:'text',label:'Message payload',default:''},{key:'fallback_port',type:'number',label:'Fallback TCP port',default:443}],
  port_scan:[{key:'host',type:'text',label:'Host',default:''},{key:'port_range',type:'text',label:'Port range',default:'1-1024'},{key:'timeout_ms',type:'number',label:'Timeout ms',default:500}],
  subnet_scan:[{key:'cidr',type:'text',label:'CIDR',default:'10.0.0.0/24'}],
  banner_grab:[{key:'host',type:'text',label:'Host',default:''}],
  local_intel:[{key:'min_confidence',type:'number',label:'Min confidence',default:0.5}],
  send_report:[{key:'include_findings',type:'bool',label:'Include findings',default:true}],
  spawn_child:[{key:'brain_id',type:'brain_select',label:'Child brain'}],
  adaptive_wait:[{key:'base_seconds',type:'number',label:'Base seconds',default:60}],
  wait:[{key:'seconds',type:'number',label:'Seconds',default:60}],
  repeat:[{key:'target_node_id',type:'node_select',label:'Jump to node'},{key:'max_iterations',type:'number',label:'Max iterations',default:3}],
  if_severity:[{key:'operator',type:'select',label:'Operator',options:['>=','<=','==','!='],default:'>='},{key:'value',type:'number',label:'Value',default:1}],
  if_findings_gt:[{key:'value',type:'number',label:'N',default:0}],
};

function _nodeTypeColor(type){return type==='trigger'?'#1a4731':type==='action'?'#1a2e4a':type==='condition'?'#3d2e00':'#1e1e2e';}
function _newNode(kind,x,y){
  const meta=NODE_LIBRARY.find(n=>n.kind===kind)||{type:'action',label:kind};
  const id='node-'+Math.random().toString(16).slice(2,8);
  const schema=NODE_SCHEMAS[kind]||[];
  const params={}; schema.forEach(s=>{if(s.default!==undefined)params[s.key]=s.default;});
  graphState.nodes[id]={id,kind,type:meta.type,label:meta.label,params,x,y,w:170,h:92,edges_out:[],edge_labels:{}};
  return id;
}
function _canvasPoint(clientX,clientY){
  const wrap=document.getElementById('drone-canvas-wrap');
  const r=wrap.getBoundingClientRect();
  return {x:(clientX-r.left-graphState.pan.x)/graphState.zoom,y:(clientY-r.top-graphState.pan.y)/graphState.zoom};
}
function renderPalette(){
  const p=document.getElementById('node-palette'); if(!p)return;
  p.innerHTML=NODE_LIBRARY.map(n=>`<div draggable='true' data-kind='${n.kind}' style='padding:6px;border:1px solid #2a3556;border-radius:6px;margin:4px 0;cursor:grab;'>${n.label}</div>`).join('');
  p.querySelectorAll('[draggable=true]').forEach(el=>el.addEventListener('dragstart',e=>e.dataTransfer.setData('text/node-kind',el.dataset.kind)));
}
function renderCanvas(){
  const c=document.getElementById('drone-canvas'); const svg=document.getElementById('drone-edge-svg'); if(!c||!svg)return;
  c.style.transform=`translate(${graphState.pan.x}px,${graphState.pan.y}px) scale(${graphState.zoom})`;
  c.style.transformOrigin='0 0';
  c.innerHTML='';
  Object.values(graphState.nodes).forEach(n=>{
    const node=document.createElement('div');
    node.className='drone-node'; node.dataset.id=n.id;
    node.style.cssText=`position:absolute;left:${n.x}px;top:${n.y}px;width:${n.w}px;border:1px solid #334369;border-radius:8px;background:#11182b;cursor:move;`;
    node.innerHTML=`<div style='padding:6px;font-weight:700;background:${_nodeTypeColor(n.type)};border-radius:8px 8px 0 0;'>${n.label}</div><div style='padding:6px;font-size:12px;color:#a8b8df;'>${Object.entries(n.params).slice(0,2).map(([k,v])=>`${k}: ${v}`).join('<br/>')||'no params'}</div><div class='node-port in' data-id='${n.id}' style='position:absolute;left:-6px;top:40px;width:10px;height:10px;background:#7aa2ff;border-radius:50%;'></div><div class='node-port out' data-id='${n.id}' style='position:absolute;right:-6px;top:40px;width:10px;height:10px;background:#8cf6c8;border-radius:50%;'></div>`;
    node.addEventListener('mousedown',ev=>{if(ev.button!==0)return;graphState.selected=n.id;const pt=_canvasPoint(ev.clientX,ev.clientY);graphState.dragging={node_id:n.id,start_x:pt.x,start_y:pt.y,orig_x:n.x,orig_y:n.y};renderInspector();renderCanvas();});
    c.appendChild(node);
  });
  svg.innerHTML='';
  const wrap=document.getElementById('drone-canvas-wrap'); const wr=wrap.getBoundingClientRect();
  graphState.edges.forEach(e=>{
    const a=graphState.nodes[e.from_id], b=graphState.nodes[e.to_id]; if(!a||!b)return;
    const x1=(a.x+a.w)*graphState.zoom+graphState.pan.x, y1=(a.y+45)*graphState.zoom+graphState.pan.y;
    const x2=(b.x)*graphState.zoom+graphState.pan.x, y2=(b.y+45)*graphState.zoom+graphState.pan.y;
    const line=document.createElementNS('http://www.w3.org/2000/svg','line');
    line.setAttribute('x1',String(x1));line.setAttribute('y1',String(y1));line.setAttribute('x2',String(x2));line.setAttribute('y2',String(y2));line.setAttribute('stroke','#89a2dd');line.setAttribute('stroke-width','2');
    line.addEventListener('dblclick',()=>{const v=window.prompt('Edge label',e.label||'')||'';e.label=v;const from=graphState.nodes[e.from_id]; if(from){from.edge_labels[e.to_id]=v;} renderCanvas();});
    line.addEventListener('contextmenu',(ev)=>{ev.preventDefault(); graphState.edges=graphState.edges.filter(x=>x.id!==e.id); const f=graphState.nodes[e.from_id]; if(f){f.edges_out=f.edges_out.filter(x=>x!==e.to_id); delete f.edge_labels[e.to_id];} renderCanvas();});
    svg.appendChild(line);
    if(e.label){const t=document.createElementNS('http://www.w3.org/2000/svg','text');t.setAttribute('x',String((x1+x2)/2));t.setAttribute('y',String((y1+y2)/2-4));t.setAttribute('fill','#d5e2ff');t.setAttribute('font-size','11');t.textContent=e.label;svg.appendChild(t);}
  });
  if(graphState.connecting){
    const a=graphState.nodes[graphState.connecting.from_id];
    if(a){const line=document.createElementNS('http://www.w3.org/2000/svg','line');
      line.setAttribute('x1',String((a.x+a.w)*graphState.zoom+graphState.pan.x));line.setAttribute('y1',String((a.y+45)*graphState.zoom+graphState.pan.y));
      line.setAttribute('x2',String(graphState.connecting.mouse_x-wr.left));line.setAttribute('y2',String(graphState.connecting.mouse_y-wr.top));line.setAttribute('stroke','#6cd1ff');line.setAttribute('stroke-dasharray','4 4');svg.appendChild(line);} }
  c.querySelectorAll('.node-port.out').forEach(el=>el.addEventListener('mousedown',(ev)=>{ev.stopPropagation();graphState.connecting={from_id:el.dataset.id,mouse_x:ev.clientX,mouse_y:ev.clientY};}));
  c.querySelectorAll('.node-port.in').forEach(el=>el.addEventListener('mouseup',(ev)=>{if(!graphState.connecting)return;const from=graphState.connecting.from_id,to=el.dataset.id; if(from&&to&&from!==to){const id='edge-'+Math.random().toString(16).slice(2,8);graphState.edges.push({id,from_id:from,to_id:to,label:''});const fn=graphState.nodes[from]; if(fn&&!fn.edges_out.includes(to))fn.edges_out.push(to);} graphState.connecting=null;renderCanvas();}));
}
function renderInspector(){
  const panel=document.getElementById('node-inspector'); if(!panel)return;
  const n=graphState.nodes[graphState.selected];
  if(!n){panel.textContent='Select a node on the canvas.'; return;}
  const schema=NODE_SCHEMAS[n.kind]||[];
  panel.innerHTML=`<div><strong>${n.label}</strong> <span style='opacity:.7'>(${n.kind})</span></div>`+schema.map(s=>{
    const v=n.params[s.key];
    if(s.type==='bool') return `<label style='display:block;margin-top:6px;'>${s.label} <input type='checkbox' data-k='${s.key}' ${v?'checked':''}/></label>`;
    if(s.type==='select') return `<label style='display:block;margin-top:6px;'>${s.label}<select data-k='${s.key}'>${(s.options||[]).map(o=>`<option ${o===v?'selected':''}>${o}</option>`).join('')}</select></label>`;
    if(s.type==='brain_select') return `<label style='display:block;margin-top:6px;'>${s.label}<select data-k='${s.key}'><option value=''>--select--</option>${_brainsCache.map(b=>`<option value='${b.behaviour_id}' ${b.behaviour_id===v?'selected':''}>${b.name}</option>`).join('')}</select></label>`;
    if(s.type==='node_select') return `<label style='display:block;margin-top:6px;'>${s.label}<select data-k='${s.key}'><option value=''>--select--</option>${Object.values(graphState.nodes).map(m=>`<option value='${m.id}' ${m.id===v?'selected':''}>${m.label} (${m.id})</option>`).join('')}</select></label>`;
    return `<label style='display:block;margin-top:6px;'>${s.label}<input data-k='${s.key}' type='${s.type==='number'?'number':'text'}' value='${v??''}'/></label>`;
  }).join('');
  panel.querySelectorAll('input,select').forEach(el=>el.addEventListener('input',()=>{const k=el.dataset.k; if(!k)return; n.params[k]=el.type==='checkbox'?el.checked:(el.type==='number'?Number(el.value):el.value); renderCanvas();}));
}
function validateGraph(){
  const errors=[]; const nodes=Object.values(graphState.nodes);
  if(!nodes.some(n=>n.kind==='on_launch')) errors.push('At least one on_launch node is required.');
  if(!nodes.some(n=>n.kind==='self_terminate'||n.kind==='self_destruct')) errors.push('At least one self_terminate or self_destruct node is required.');
  nodes.forEach(n=>{(NODE_SCHEMAS[n.kind]||[]).forEach(s=>{if(s.type==='text'&&!String(n.params[s.key]||'').trim()) errors.push(`${n.label}: ${s.label} is required.`);});
    if(n.kind==='parallel'&&n.edges_out.length<2) errors.push(`${n.label}: parallel needs at least 2 outgoing edges.`);
    if(n.kind.startsWith('if_')){const labels=Object.values(n.edge_labels||{}); if(!(labels.includes('yes')&&labels.includes('no'))) errors.push(`${n.label}: condition needs yes/no edge labels.`);} 
    if(n.kind==='repeat'&&n.params.target_node_id&&!graphState.nodes[n.params.target_node_id]) errors.push(`${n.label}: repeat target node does not exist.`);
  });
  const panel=document.getElementById('graph-errors'); if(panel) panel.innerHTML=errors.length?errors.map(e=>`• ${e}`).join('<br/>'):'Graph validation passed';
  return {valid:errors.length===0,errors};
}
function graphToBehaviourNodes(){
  return Object.values(graphState.nodes).map(n=>({node_id:n.id,node_type:n.type,kind:n.kind,label:n.label,params:n.params,position:{x:n.x,y:n.y},edges_out:n.edges_out||[],edge_labels:n.edge_labels||{}}));
}

function fillSampleDroneDropdowns(){
  const opts=SAMPLE_DRONES.map(s=>`<option value='${s.sample_id}'>${s.name}</option>`).join('');
  const fleetSel=document.getElementById('sample-drone-select');
  if(fleetSel){fleetSel.innerHTML=`<option value=''>Load Sample Drone ▾</option>${opts}`;}
  const squadSel=document.getElementById('squad-sample-select');
  if(squadSel){squadSel.innerHTML=`<option value=''>Select Sample Drone ▾</option>${opts}`;}
}

function renderSquadBuilder(){
  const list=document.getElementById('squad-drone-list');
  const links=document.getElementById('squad-links');
  const canvas=document.getElementById('squad-canvas');
  const svg=document.getElementById('squad-edge-svg');
  if(list){
    list.innerHTML=squadState.nodes.length? squadState.nodes.map(n=>`<div class='drone-chip' data-node='${n.id}' style='${squadState.selectedNodeId===n.id?'border-color:#6da2ff;background:#1a2a50;':''}'><strong>${n.name}</strong><div class='small'>dest: ${n.destination||'-'}</div><div class='small'>${n.tier.toUpperCase()} / ${n.mission}</div></div>`).join('') : '<div class="small">No sample drones linked yet.</div>';
    list.querySelectorAll('[data-node]').forEach(el=>el.addEventListener('click',()=>{squadState.selectedNodeId=el.dataset.node; renderSquadBuilder();}));
  }
  if(links){
    links.innerHTML=squadState.links.length? squadState.links.map((l,idx)=>`<div class='drone-link-card'><span class='drone-link-pill'>${idx+1}</span>${l.from_name} → ${l.to_name}</div>`).join('') : '<div class="small">No links yet. Click source drone then destination drone to create one.</div>';
  }
  if(canvas && svg){
    canvas.innerHTML=''; svg.innerHTML='';
    squadState.nodes.forEach(n=>{
      const el=document.createElement('button');
      el.className='tab-btn';
      el.style.position='absolute';
      el.style.left=`${n.x}px`;
      el.style.top=`${n.y}px`;
      el.style.padding='6px 10px';
      el.style.borderColor=squadState.selectedNodeId===n.id?'#7daeff':'#2f4383';
      el.textContent=n.name;
      el.onclick=()=>{
        if(squadState.linkingFrom && squadState.linkingFrom!==n.id){
          const from=squadState.nodes.find(x=>x.id===squadState.linkingFrom);
          squadState.links.push({from_id:squadState.linkingFrom,to_id:n.id,from_name:from?.name||squadState.linkingFrom,to_name:n.name});
          squadState.linkingFrom=null;
        }else{
          squadState.selectedNodeId=n.id;
          squadState.linkingFrom=n.id;
        }
        renderSquadBuilder();
      };
      canvas.appendChild(el);
    });
    squadState.links.forEach(link=>{
      const from=squadState.nodes.find(n=>n.id===link.from_id);
      const to=squadState.nodes.find(n=>n.id===link.to_id);
      if(!from||!to) return;
      const line=document.createElementNS('http://www.w3.org/2000/svg','line');
      line.setAttribute('x1',String(from.x+80)); line.setAttribute('y1',String(from.y+16));
      line.setAttribute('x2',String(to.x+8)); line.setAttribute('y2',String(to.y+16));
      line.setAttribute('stroke','#80aaff'); line.setAttribute('stroke-width','2');
      svg.appendChild(line);
    });
  }
}

function applySampleDroneToBuilder(sample){
  if(!sample) return;
  document.getElementById('drone-name').value=sample.name;
  document.getElementById('drone-tier').value=sample.tier;
  document.getElementById('drone-mission').value=sample.mission;
  document.getElementById('drone-autonomy').value=sample.autonomy_level;
  document.getElementById('drone-ttl').value=String(sample.ttl_seconds);
  document.getElementById('drone-checkin').value=String(sample.checkin_interval_seconds);
  document.getElementById('drone-target').value=sample.target;
  const brain=(_brainsCache||[]).find(b=>b.behaviour_id===sample.behaviour_id) || (_brainsCache||[]).find(b=>String(b.name||'').toLowerCase()===String(sample.brain_name||'').toLowerCase());
  if(brain) loadBrainIntoCanvas(brain);
}

async function loadBrains(){
  const resp=await fetch('/api/drones/brains'); if(!resp.ok)return;
  _brainsCache=await resp.json();
  const sel=document.getElementById('graph-load-brain');
  if(sel){sel.innerHTML='<option value="">Load Brain ▾</option>'+_brainsCache.map(b=>`<option value='${b.behaviour_id}'>${b.name}</option>`).join('');}
  fillSampleDroneDropdowns();
}
function loadBrainIntoCanvas(brain){
  graphState.nodes={}; graphState.edges=[]; graphState.selected=null;
  (brain.nodes||[]).forEach(n=>{graphState.nodes[n.node_id]={id:n.node_id,kind:n.kind,type:n.node_type,label:n.label||n.kind,params:n.params||{},x:Number(n.position?.x||50),y:Number(n.position?.y||50),w:170,h:92,edges_out:[...(n.edges_out||[])],edge_labels:{...(n.edge_labels||{})}};});
  Object.values(graphState.nodes).forEach(n=>{(n.edges_out||[]).forEach(to=>graphState.edges.push({id:'edge-'+Math.random().toString(16).slice(2,8),from_id:n.id,to_id:to,label:n.edge_labels?.[to]||''}));});
  renderCanvas(); renderInspector();
}

async function refreshDroneActions(){
  try{const resp=await fetch('/api/drones/actions'); if(!resp.ok){return;} droneActionMatrix=await resp.json();
    const panel=document.getElementById('drone-actions'); if(panel){panel.textContent=droneActionMatrix.map(a=>`${a.binary} -> ${a.action} :: ${a.description}`).join('\n');}
  }catch(_e){}
}
async function refreshDrones(){
  try{
    const resp=await fetch('/api/drones'); if(!resp.ok){return;} const drones=await resp.json(); const fleet=document.getElementById('drone-fleet'); if(!fleet)return; fleet.innerHTML='';
    drones.forEach(d=>{
      const card=document.createElement('div'); card.className='card';
      const ttl=Number(d.ttl_seconds||0), left=Math.max(0,ttl); const pct=ttl>0?Math.max(0,Math.min(100,Math.round((left/ttl)*100))):100;
      const barColor=pct<20?'#ff4d6d':'#4cc9f0';
      card.innerHTML=`<div style='display:flex;justify-content:space-between;'><strong>${d.name}</strong><span>${String(d.tier||'').toUpperCase()}</span></div><div>● ${String(d.status||'').toUpperCase()} PID: ${d.pid||'-'} Blob: ${d.blob_hash||'-'}</div><div>Mission: ${d.mission||'-'} Target: ${d.target_host||d.target_network||d.target_endpoint_id||'-'}</div><div style='margin-top:6px;background:#1a2340;border-radius:8px;overflow:hidden;'><div style='height:8px;width:${pct}%;background:${barColor};'></div></div><div class='small'>Hosts: ${(d.stats||{}).hosts_pinged||0} pinged, ${((d.stats||{}).alive_hosts||[]).length||0} alive</div><div class='small'>Ports: ${(d.stats||{}).ports_scanned||0} Findings: ${(d.stats||{}).findings_count||0}</div><div style='margin-top:6px;display:flex;gap:4px;flex-wrap:wrap;'><button data-id='${d.drone_id}' class='dr-detail'>Detail ▶</button><button data-id='${d.drone_id}' class='dr-term'>Terminate</button><button data-id='${d.drone_id}' class='dr-launch'>Launch</button></div>`;
      fleet.appendChild(card);
    });
    fleet.querySelectorAll('.dr-detail').forEach(b=>b.onclick=()=>loadDroneDetail(b.dataset.id));
    fleet.querySelectorAll('.dr-term').forEach(b=>b.onclick=()=>droneAction(b.dataset.id,'terminate'));
    fleet.querySelectorAll('.dr-launch').forEach(b=>b.onclick=()=>droneAction(b.dataset.id,'launch'));
  }catch(_e){}
}
async function loadDroneDetail(droneId){
  selectedDroneId=droneId; const resp=await fetch(`/api/drones/${droneId}`); if(!resp.ok)return; const d=await resp.json();
  const comms=document.getElementById('drone-comms'); if(comms){comms.textContent=(d.live_output||[]).slice(-50).join('\n') || 'No live comms output yet.';}
  const panel=document.getElementById('drone-detail');
  panel.innerHTML=`<div><strong>${d.name}</strong> (${d.tier}) - ${d.status}</div><div>Mission: ${d.mission} Target: ${d.target_host||d.target_network||d.target_endpoint_id||'-'}</div><div>Blob: ${d.blob_hash||'-'} (${d.blob_size_bytes||0} bytes)</div><div>Child drones: ${(d.child_drone_ids||[]).join(', ')||'-'}</div><div style='margin-top:8px;display:flex;gap:6px;flex-wrap:wrap;'><button id='view-source-btn'>View Source</button><button id='download-blob-btn'>Download Blob</button></div><pre style='max-height:220px;overflow:auto;'>${(d.telemetry||[]).map(t=>`[${t.ts}] ${t.message}`).join('\n')}</pre>`;
  document.getElementById('view-source-btn')?.addEventListener('click',async()=>{const r=await fetch(`/api/drones/${droneId}/source`); const b=await r.json(); window.alert((b.source||'source unavailable').slice(0,3000));});
  document.getElementById('download-blob-btn')?.addEventListener('click',async()=>{const r=await fetch(`/api/drones/${droneId}/blob`); const b=await r.json(); const a=document.createElement('a'); a.href='data:text/plain;base64,'+btoa(b.blob_b64||''); a.download=`drone_${droneId}.hgb`; a.click();});
}
async function droneAction(droneId,action){
  await fetch(`/api/drones/${droneId}/${action}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({actor:'dashboard'})});
  await refreshDrones(); if(selectedDroneId===droneId)await loadDroneDetail(droneId);
}

function wireCanvasEvents(){
  const wrap=document.getElementById('drone-canvas-wrap'); const c=document.getElementById('drone-canvas'); if(!wrap||!c)return;
  wrap.addEventListener('dragover',ev=>ev.preventDefault());
  wrap.addEventListener('drop',ev=>{ev.preventDefault(); const kind=ev.dataTransfer.getData('text/node-kind'); if(!kind)return; const pt=_canvasPoint(ev.clientX,ev.clientY); _newNode(kind,pt.x,pt.y); renderCanvas();});
  wrap.addEventListener('wheel',ev=>{ev.preventDefault(); graphState.zoom=Math.max(0.3,Math.min(3,graphState.zoom+(ev.deltaY<0?0.1:-0.1))); renderCanvas();}, {passive:false});
  wrap.addEventListener('mousedown',ev=>{if(ev.button===1){graphState.panning={x:ev.clientX,y:ev.clientY,ox:graphState.pan.x,oy:graphState.pan.y};}});
  window.addEventListener('mousemove',ev=>{
    if(graphState.dragging){const pt=_canvasPoint(ev.clientX,ev.clientY); const n=graphState.nodes[graphState.dragging.node_id]; if(n){n.x=graphState.dragging.orig_x + (pt.x-graphState.dragging.start_x); n.y=graphState.dragging.orig_y + (pt.y-graphState.dragging.start_y); renderCanvas();}}
    if(graphState.connecting){graphState.connecting.mouse_x=ev.clientX; graphState.connecting.mouse_y=ev.clientY; renderCanvas();}
    if(graphState.panning){graphState.pan.x=graphState.panning.ox+(ev.clientX-graphState.panning.x); graphState.pan.y=graphState.panning.oy+(ev.clientY-graphState.panning.y); renderCanvas();}
  });
  window.addEventListener('mouseup',()=>{graphState.dragging=null; graphState.panning=null; if(graphState.connecting){graphState.connecting=null; renderCanvas();}});
  wrap.addEventListener('click',ev=>{if(ev.target===wrap||ev.target===c){graphState.selected=null; renderInspector();}});
  window.addEventListener('keydown',ev=>{if(ev.key==='Delete'&&graphState.selected){const id=graphState.selected; delete graphState.nodes[id]; graphState.edges=graphState.edges.filter(e=>e.from_id!==id&&e.to_id!==id); Object.values(graphState.nodes).forEach(n=>{n.edges_out=(n.edges_out||[]).filter(x=>x!==id); delete n.edge_labels?.[id];}); graphState.selected=null; renderCanvas(); renderInspector();}});
}

document.getElementById('new-drone-btn')?.addEventListener('click',()=>{document.getElementById('drone-name').value=`Drone-${Math.random().toString(16).slice(2,6).toUpperCase()}`;});
document.getElementById('apply-sample-drone-btn')?.addEventListener('click',()=>{
  const id=document.getElementById('sample-drone-select')?.value||'';
  const sample=SAMPLE_DRONES.find(s=>s.sample_id===id);
  if(sample) applySampleDroneToBuilder(sample);
});
document.getElementById('auto-assemble-drone-btn')?.addEventListener('click', async ()=>{const ep=window.prompt('Endpoint ID for auto-assemble','ep-default-linux')||''; if(!ep)return; await fetch('/api/drones/auto-assemble',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({endpoint_id:ep,actor:'dashboard'})}); await refreshDrones();});
document.getElementById('squad-add-btn')?.addEventListener('click',()=>{
  const sampleId=document.getElementById('squad-sample-select')?.value||'';
  const destination=(document.getElementById('squad-drone-destination')?.value||'').trim();
  const sample=SAMPLE_DRONES.find(s=>s.sample_id===sampleId);
  if(!sample) return;
  const id='sq-'+Math.random().toString(16).slice(2,8);
  const idx=squadState.nodes.length;
  squadState.nodes.push({id,sample_id:sample.sample_id,name:sample.name,tier:sample.tier,mission:sample.mission,destination:destination||sample.target,x:12+(idx%3)*150,y:14+Math.floor(idx/3)*60});
  squadState.selectedNodeId=id;
  squadState.linkingFrom=null;
  renderSquadBuilder();
});
document.getElementById('squad-clear-btn')?.addEventListener('click',()=>{
  squadState.nodes=[];
  squadState.links=[];
  squadState.selectedNodeId=null;
  squadState.linkingFrom=null;
  renderSquadBuilder();
});
document.getElementById('squad-assemble-btn')?.addEventListener('click', async()=>{
  if(!squadState.nodes.length){return;}
  const payload={
    nodes:squadState.nodes.map(n=>({id:n.id,sample_id:n.sample_id,name:n.name,destination:n.destination})),
    links:squadState.links.map(l=>({from_id:l.from_id,to_id:l.to_id})),
    actor:'dashboard',
  };
  const resp=await fetch('/api/drones/squad/assemble',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const data=await resp.json();
  const panel=document.getElementById('drone-build-result');
  if(panel){panel.textContent=resp.ok?`Squad assembled: ${(data.built||[]).map(b=>b.name).join(', ')}`:`Squad assemble failed: ${data.message||data.error||'unknown error'}`;}
  if(resp.ok){await refreshDrones();}
});
document.getElementById('graph-validate')?.addEventListener('click', validateGraph);
document.getElementById('graph-load-brain')?.addEventListener('change',()=>{const id=document.getElementById('graph-load-brain').value; const brain=_brainsCache.find(b=>b.behaviour_id===id); if(brain)loadBrainIntoCanvas(brain);});
document.getElementById('graph-save-brain')?.addEventListener('click', async ()=>{
  const name=window.prompt('Brain name','custom-brain'); if(!name)return;
  await fetch('/api/drones/brains',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,description:'saved from visual builder',nodes:graphToBehaviourNodes()})});
  await loadBrains();
});
document.getElementById('graph-compile')?.addEventListener('click', async ()=>{
  const check=validateGraph(); if(!check.valid)return;
  const payload={
    name:document.getElementById('drone-name').value||'Scout-Alpha',
    tier:document.getElementById('drone-tier').value,
    mission:document.getElementById('drone-mission').value,
    autonomy_level:document.getElementById('drone-autonomy').value,
    ttl_seconds:Number(document.getElementById('drone-ttl').value||3600),
    checkin_interval_seconds:Number(document.getElementById('drone-checkin').value||60),
    target_host:(document.getElementById('drone-target').value||'').trim()||null,
    actor:'dashboard',
    behaviour:{behaviour_id:'brain-'+Math.random().toString(16).slice(2,8),name:'visual-brain',description:'visual builder graph',nodes:graphToBehaviourNodes()},
  };
  const resp=await fetch('/api/drones/assemble',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const data=await resp.json();
  const panel=document.getElementById('drone-build-result');
  if(resp.ok){
    const kb=((data.blob_size_bytes||0)/1024).toFixed(1);
    panel.innerHTML=`Drone assembled: ${data.name} (${data.drone_id})<br/>Blob size: ${kb} KB ${Number(kb)>100?'(large)':''} Hash: ${data.blob_hash||'-'}<br/><button id='launch-now-btn'>Launch Now</button>`;
    document.getElementById('launch-now-btn')?.addEventListener('click',()=>droneAction(data.drone_id,'launch'));
    await refreshDrones();
  }else{panel.textContent=`Assemble failed: ${data.message||data.error||'unknown error'}`;}
});

async function initDroneBuilder(){
  renderPalette(); wireCanvasEvents(); await loadSampleDrones(); await loadBrains(); fillSampleDroneDropdowns(); renderSquadBuilder();
  const a=_newNode('on_launch',40,40), b=_newNode('ping_host',280,40), c=_newNode('send_report',520,40), d=_newNode('self_terminate',760,40);
  graphState.nodes[b].params.host='127.0.0.1';
  graphState.edges.push({id:'edge-a',from_id:a,to_id:b,label:''},{id:'edge-b',from_id:b,to_id:c,label:''},{id:'edge-c',from_id:c,to_id:d,label:''});
  graphState.nodes[a].edges_out=[b]; graphState.nodes[b].edges_out=[c]; graphState.nodes[c].edges_out=[d];
  renderCanvas(); renderInspector();
}

refreshDroneActions();
initDroneBuilder();
setInterval(()=>{if(document.getElementById('tab-drones')?.classList.contains('active')){refreshDrones(); if(selectedDroneId) loadDroneDetail(selectedDroneId);}},3000);

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

    token_file = str(
        settings.env("SENTINEL_DASHBOARD_TOKEN_FILE", settings.get("dashboard_api_token_file", "data/dashboard_api_token"))
    ).strip()
    if token_file:
        token_path = Path(token_file)
        if token_path.exists():
            file_token = token_path.read_text(encoding="utf-8").strip()
            if file_token:
                return file_token
        elif bool(settings.get("dashboard_api_token_auto_configure", True)):
            token_path.parent.mkdir(parents=True, exist_ok=True)
            auto_token = secrets.token_urlsafe(48)
            token_path.write_text(auto_token, encoding="utf-8")
            os.chmod(token_path, 0o600)
            logger.info("Autoconfigured dashboard API token at %s", token_path)
            return auto_token
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
    if bool(provided) and hmac.compare_digest(provided, token):
        return True
    session_token = request.cookies.get("hegemon_session", "")
    return bool(session_token) and hmac.compare_digest(session_token, token)


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
        readiness["startup_warning"] = "HARD WARNING: dashboard API token missing; operator auth is not ready."
    return readiness


@app.get("/")
def dashboard():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    state = _load_latest_state()
    response = make_response(render_template_string(
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
    ))
    response.set_cookie(
        "hegemon_session",
        _api_token(),
        httponly=True,
        secure=request.is_secure,
        samesite="Strict",
        max_age=8 * 60 * 60,
    )
    return response


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
                "installed_packages": {"openssl": "3.0.2", "glibc": "2.37", "openssh": "9.3", "anthropic": "0.34.2"},
            },
            actor="dashboard",
        )
    if "app-dashboard-nginx" not in _control_plane.friendly_apps:
        _control_plane.add_friendly_app(
            {
                "app_id": "app-dashboard-nginx",
                "name": "Nginx",
                "icon": "NET",
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
    endpoint = _control_plane.endpoints.get(endpoint_id)
    structural_report = _control_plane._analyze_program_structure(endpoint.program_root) if endpoint and endpoint.program_root else {}
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
            "potential_cross_language_hints": structural_report.get("potential_cross_language_hints", []),
            "cross_language_analysis_note": structural_report.get("cross_language_analysis_note", "potential cross-language hints (not confirmed taint chains)"),
            "lstm_rnn_binary_model": structural_report.get("lstm_rnn_binary_model", {}),
            "integrated_flow_model": structural_report.get("integrated_flow_model", {}),
        }
    )




@app.post("/api/control-plane/discover-issue")
def control_plane_discover_issue():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    payload, error = _safe_json_payload()
    if error:
        return error

    endpoint_id = str(payload.get("endpoint_id", HEGEMON_SELF_ENDPOINT_ID)).strip() or HEGEMON_SELF_ENDPOINT_ID
    include_external_intel = bool(payload.get("include_external_intel", False))

    if endpoint_id not in _control_plane.endpoints:
        return jsonify({"error": "not_found", "message": "endpoint not found"}), 404

    newly_discovered = _control_plane.discover_new_issues(
        endpoint_id,
        actor="dashboard_autonomous_scanner",
        include_external_intel=include_external_intel,
    )

    if not newly_discovered:
        return jsonify({
            "endpoint_id": endpoint_id,
            "new_issues_discovered": 0,
            "issue": None,
            "message": "no_new_issues",
        })

    highest_risk = sorted(newly_discovered, key=lambda finding: finding.risk_score, reverse=True)[0]
    return jsonify({
        "endpoint_id": endpoint_id,
        "new_issues_discovered": len(newly_discovered),
        "issue": _control_plane.as_dict(highest_risk),
        "message": "autonomous_issue_discovered",
    })

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
    kind = str(request.args.get("kind", "all")).strip().lower()
    q = str(request.args.get("q", "")).strip().lower()
    store_ids_raw = str(request.args.get("store_ids", "")).strip()
    store_ids = [v.strip() for v in store_ids_raw.split(",") if v.strip()] if store_ids_raw else None
    if len(q) < 1 or len(q) > 128 or "../" in q or "\x00" in q:
        return jsonify({"suggestions": [], "total": 0, "from_cache": False, "query": q})
    cache_key = f"{kind}:{q}"
    now = time.monotonic()
    cached = _AUTOCOMPLETE_CACHE.get(cache_key)
    if cached and now - cached[0] <= 0.1:
        out = dict(cached[1])
        out["from_cache"] = True
        return jsonify(out)

    suggestions: list[dict] = []
    if kind in {"endpoints", "all"}:
        for ep in _control_plane.endpoints.values():
            if q in ep.endpoint_id.lower() or q in ep.host_name.lower():
                suggestions.append({"type": "endpoint", "id": ep.endpoint_id, "label": ep.host_name, "sublabel": ep.endpoint_id, "icon": "HOST", "store_id": None, "trust_tier": None, "score": 0.9 if ep.host_name.lower().startswith(q) else 0.7, "meta": {}})
    if kind in {"friends", "all"}:
        for fr in _control_plane.friends.values():
            if q in fr.name.lower():
                suggestions.append({"type": "friend", "id": fr.friend_id, "label": fr.name, "sublabel": fr.identity_method, "icon": "USER", "store_id": None, "trust_tier": None, "score": 0.8 if fr.name.lower().startswith(q) else 0.6, "meta": {}})
    if kind in {"packages", "all"}:
        for hit in _control_plane.store_client.search(q, store_ids, limit=20):
            suggestions.append({"type": "store_app", "id": f"{hit.store_id}:{hit.name}", "label": hit.name, "sublabel": f"{hit.publisher} • {hit.version}", "icon": hit.icon_url or "PKG", "store_id": hit.store_id, "trust_tier": hit.trust_tier, "score": hit.score, "meta": hit.raw})
    suggestions = sorted(suggestions, key=lambda row: float(row.get("score", 0.0)), reverse=True)[:15]
    if kind == "endpoints":
        compact_suggestions = [str(item.get("label", "")) for item in suggestions if str(item.get("label", "")).strip()]
        payload = {"suggestions": compact_suggestions, "total": len(compact_suggestions), "from_cache": False, "query": q}
    else:
        payload = {"suggestions": suggestions, "total": len(suggestions), "from_cache": False, "query": q}
    _AUTOCOMPLETE_CACHE[cache_key] = (now, payload)
    return jsonify(payload)


@app.post("/api/store/register-endpoint")
def api_store_register_endpoint():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    payload, error = _safe_json_payload()
    if error:
        return error
    query = str(payload.get("query", "")).strip()
    store_id = str(payload.get("store_id", "")).strip()
    if not query or not store_id:
        return jsonify({"error": "invalid_payload", "message": "query and store_id required"}), 400
    try:
        result = _control_plane.register_store_endpoint(query=query, store_id=store_id, version=payload.get("version"), network_exposure=str(payload.get("network_exposure", "internal")), asset_value=float(payload.get("asset_value", 7.0)), actor=str(payload.get("actor", "user")))
    except KeyError:
        suggestions = [r.__dict__ for r in _control_plane.store_client.search(query, [store_id], limit=5)]
        return jsonify({"error": "not_found", "suggestions": suggestions}), 404
    return jsonify({"endpoint": _control_plane.as_dict(result["endpoint"]), "friendly_app": _control_plane.as_dict(result["friendly_app"]), "program_root_detected": result["program_root_detected"], "store_metadata": result["store_metadata"].__dict__, "scan_triggered": result["scan_triggered"], "scan_id": result["scan_id"]})


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
            "endpoint_type": str(payload.get("endpoint_type", "on-prem")),
            "os": str(payload.get("os", "linux")),
            "kernel": str(payload.get("kernel", "unknown")),
            "sbom_status": str(payload.get("sbom_status", "unknown")),
            "enrollment_method": str(payload.get("enrollment_method", "manual")),
            "network_exposure": str(payload.get("network_exposure", "internal")),
            "asset_value": float(payload.get("asset_value", 7.0)),
            "trust_level": float(payload.get("trust_level", 6.0)),
            "installed_packages": payload.get("installed_packages", {}) if isinstance(payload.get("installed_packages", {}), dict) else {},
            "telemetry_events": payload.get("telemetry_events", []) if isinstance(payload.get("telemetry_events", []), list) else [],
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




@app.post("/api/peer/advertise")
def peer_advertise():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    payload, error = _safe_json_payload()
    if error:
        return error
    if _runtime is None:
        return jsonify({"status": "ignored", "reason": "runtime_not_initialized"}), 503
    peer_id = str(payload.get("instance_id", "")).strip()
    public_key = str(payload.get("public_key", "")).strip()
    if peer_id and public_key:
        _runtime.peer_mesh.add_or_update_peer(peer_id, public_key)
    return jsonify({"status": "ok", "registered": bool(peer_id and public_key), "peer": peer_id})

@app.post("/api/peer/verify")
def peer_verify():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    payload, error = _safe_json_payload()
    if error:
        return error
    return jsonify({"valid": bool(payload.get("directive")), "attestor": "local"})


@app.post("/api/scan")
def api_scan_unified():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    payload, error = _safe_json_payload()
    if error:
        return error
    result = _control_plane.scan(
        payload.get("target"),
        mode=str(payload.get("mode", "auto")),
        include_external_intel=bool(payload.get("include_external_intel", True)),
        include_ast=bool(payload.get("include_ast", True)),
        program_root=payload.get("program_root"),
        actor="dashboard_scanner",
    )
    return jsonify(_control_plane.as_dict(result))


@app.get("/api/scan/<scan_id>")
def api_scan_by_id(scan_id: str):
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    row = _control_plane.scan_results_by_id.get(scan_id)
    if row is None:
        return jsonify({"error": "not_found"}), 404
    return jsonify(_control_plane.as_dict(row))


@app.get("/api/endpoints/<endpoint_id>/scan_history")
def api_scan_history(endpoint_id: str):
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    history = _control_plane.scan_history.get(endpoint_id, [])[-10:]
    return jsonify([{"scan_id": h.scan_id, "mode": h.mode, "duration_seconds": h.duration_seconds, "findings": len(h.findings), "new_findings": len(h.new_findings)} for h in history])


@app.get("/api/endpoints/<endpoint_id>/lateral_graph")
def api_lateral_graph(endpoint_id: str):
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    graph = _control_plane._build_lateral_movement_graph()
    return jsonify({"origin": endpoint_id, **graph})


@app.get("/api/self/scan_loop")
def api_self_scan_loop_state():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    loop = _control_plane._self_scan_loop
    return jsonify({"running": bool(loop._thread and loop._thread.is_alive()), "last_scan_at": loop.last_scan_at, "last_findings_count": loop.last_findings_count, "scan_interval_seconds": loop.scan_interval_seconds, "consecutive_errors": loop.consecutive_errors, "total_patches_applied": loop.total_patches_applied, "total_rolled_back": loop.total_rolled_back})


@app.post("/api/self/scan_loop/start")
def api_self_scan_loop_start():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    _control_plane._self_scan_loop.start()
    return jsonify({"status": "started"})


@app.post("/api/self/scan_loop/stop")
def api_self_scan_loop_stop():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    _control_plane._self_scan_loop.stop()
    return jsonify({"status": "stopped"})


@app.get("/api/findings/<finding_id>/markov_tree")
def api_finding_markov_tree(finding_id: str):
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    finding = _control_plane.findings.get(finding_id)
    if not finding:
        return jsonify({"error": "not_found"}), 404
    endpoint = _control_plane.endpoints.get(finding.endpoint_id)
    tree = _control_plane._markov_tree_project(endpoint.telemetry_events if endpoint else [])
    return jsonify(tree)


@app.get("/api/findings/<finding_id>/bayesian_posteriors")
def api_finding_posteriors(finding_id: str):
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    finding = _control_plane.findings.get(finding_id)
    if not finding:
        return jsonify({"error": "not_found"}), 404
    return jsonify(finding.bayesian_stage_risk)


@app.get("/api/scan_suppressed")
def api_scan_suppressed():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    return jsonify(_control_plane.suppressed_findings)

@app.get("/api/drones")
def api_drones_list():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    rows = []
    for drone in _control_plane.drones.values():
        rows.append({
            "drone_id": drone.drone_id,
            "name": drone.name,
            "tier": drone.tier,
            "status": drone.status,
            "mission": drone.mission,
            "target_endpoint_id": drone.target_endpoint_id,
            "target_host": drone.target_host,
            "target_network": drone.target_network,
            "ttl_seconds": drone.ttl_seconds,
            "last_checkin_at": drone.last_checkin_at,
            "stats": drone.stats,
            "behaviour_name": drone.behaviour.name,
            "behaviour_id": drone.behaviour.behaviour_id,
        })
    return jsonify(rows)


@app.get("/api/drones/<drone_id>")
def api_drones_get(drone_id: str):
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    drone = _control_plane.drones.get(drone_id)
    if drone is None:
        return jsonify({"error": "not_found"}), 404
    payload = _control_plane.as_dict(drone)
    payload["telemetry"] = payload.get("telemetry", [])[-50:]
    return jsonify(payload)


@app.post("/api/drones/assemble")
def api_drones_assemble():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    payload, error = _safe_json_payload()
    if error:
        return error

    ignored_fields: list[str] = []
    runtime_payload = payload.get("runtime") if isinstance(payload.get("runtime"), dict) else {}
    artifact_format = str(payload.get("artifact_format", "binary_blob") or "binary_blob")

    behaviour = payload.get("behaviour")
    graph_nodes = list(payload.get("nodes", [])) if isinstance(payload.get("nodes"), list) else []
    graph_edges = list(payload.get("edges", [])) if isinstance(payload.get("edges"), list) else []
    if behaviour and isinstance(behaviour, dict):
        behaviour = _control_plane._make_brain(
            behaviour_id=str(behaviour.get("behaviour_id", f"brain-{secrets.token_hex(4)}")),
            name=str(behaviour.get("name", "custom")),
            description=str(behaviour.get("description", "custom behaviour")),
            nodes=list(behaviour.get("nodes", [])),
        )
    elif graph_nodes:
        behaviour = _control_plane._compose_behaviour_from_graph(
            graph_nodes,
            graph_edges,
            behaviour_id=str(payload.get("behaviour_id", f"brain-{secrets.token_hex(4)}")),
            name=str(payload.get("name", "composed-drone")),
            description="composer graph",
        )
    else:
        behaviour = payload.get("brain_id") or "brain-pinger-basic"
    try:
        drone = _control_plane.assemble_drone(
            name=str(payload.get("name", "Drone")),
            tier=str(payload.get("tier", "controlled")),
            mission=str(payload.get("mission", "custom")),
            behaviour=behaviour,
            target_endpoint_id=payload.get("target_endpoint_id"),
            target_host=payload.get("target_host"),
            target_network=payload.get("target_network"),
            autonomy_level=str(payload.get("autonomy_level", "observe")),
            ttl_seconds=int(payload.get("ttl_seconds", 3600)),
            checkin_interval_seconds=int(payload.get("checkin_interval_seconds", 60)),
            payload=payload.get("payload", {}),
            actor=str(payload.get("actor", "user")),
            artifact_format=artifact_format,
            runtime=runtime_payload,
        )
    except ValueError as exc:
        return jsonify({"error": "invalid_request", "message": str(exc)}), 400

    response = _control_plane.as_dict(drone)
    if ignored_fields:
        response["warnings"] = [{
            "code": "ignored_fields",
            "message": "Some payload fields are accepted but not yet consumed by /api/drones/assemble.",
            "fields": ignored_fields,
        }]
    return jsonify(response)






@app.get("/api/drones/<drone_id>/blob")
def api_drones_blob(drone_id: str):
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    drone = _control_plane.drones.get(drone_id)
    if drone is None:
        return jsonify({"error": "not_found"}), 404
    blob_b64 = drone.binary_blob
    if drone.blob_path:
        try:
            blob_b64 = Path(drone.blob_path).read_text(encoding="utf-8").strip()
        except OSError:
            blob_b64 = ""
    return jsonify({"blob_b64": blob_b64, "blob_hash": drone.blob_hash, "blob_size_bytes": drone.blob_size_bytes, "blob_path": drone.blob_path})


@app.get("/api/drones/<drone_id>/source")
def api_drones_source(drone_id: str):
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    drone = _control_plane.drones.get(drone_id)
    if drone is None:
        return jsonify({"error": "not_found"}), 404
    if drone.status not in {"ready", "terminated"}:
        return jsonify({"error": "invalid_state", "message": "source only available when drone is ready or terminated"}), 400
    try:
        source = _control_plane.decode_drone_source(drone_id)
    except Exception as exc:
        return jsonify({"error": "decode_failed", "message": str(exc)}), 400
    return jsonify({"source": source})


@app.post("/api/drones/<drone_id>/deploy-remote")
def api_drones_deploy_remote(drone_id: str):
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    payload, error = _safe_json_payload()
    if error:
        return error
    try:
        result = _control_plane.deploy_drone_remote(
            drone_id=drone_id,
            host=str(payload.get("host", "")),
            ssh_key_path=str(payload.get("ssh_key_path", "")),
            remote_workdir=str(payload.get("remote_workdir", "")),
            actor=str(payload.get("actor", "user")),
        )
    except ValueError as exc:
        return jsonify({"error": "invalid_request", "message": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": "deploy_failed", "message": str(exc)}), 500
    return jsonify(result)


@app.get("/api/drones/<drone_id>/deadrop")
def api_drones_deadrop(drone_id: str):
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    drone = _control_plane.drones.get(drone_id)
    if drone is None:
        return jsonify({"error": "not_found"}), 404
    _control_plane._poll_deadrop(drone_id)
    return jsonify({"findings": drone.findings, "telemetry": drone.telemetry[-200:], "deadrop_path": drone.deadrop_path})


@app.get("/api/drones/actions")
def api_drones_actions():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    return jsonify(_control_plane.available_drone_actions())


@app.get("/api/drones/samples")
def api_drones_samples():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    return jsonify(_control_plane.drone_sample_catalog())


@app.post("/api/drones/samples/<sample_id>/assemble")
def api_drones_samples_assemble(sample_id: str):
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    payload, error = _safe_json_payload()
    if error:
        return error
    try:
        drone = _control_plane.assemble_sample_drone(
            sample_id,
            destination=str(payload.get("destination", "")).strip() or None,
            actor=str(payload.get("actor", "user")),
            name_override=str(payload.get("name", "")).strip() or None,
            payload=payload.get("payload"),
        )
    except ValueError as exc:
        return jsonify({"error": "invalid_request", "message": str(exc)}), 400
    return jsonify(_control_plane.as_dict(drone))


@app.post("/api/drones/squad/assemble")
def api_drones_squad_assemble():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    payload, error = _safe_json_payload()
    if error:
        return error
    try:
        built = _control_plane.assemble_sample_squad(
            list(payload.get("nodes", [])),
            list(payload.get("links", [])),
            actor=str(payload.get("actor", "user")),
        )
    except ValueError as exc:
        return jsonify({"error": "invalid_request", "message": str(exc)}), 400
    return jsonify({"count": len(built), "built": [_control_plane.as_dict(d) for d in built]})


@app.post("/api/drones/preview-build")
def api_drones_preview_build():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    payload, error = _safe_json_payload()
    if error:
        return error
    actor = str(payload.get("actor", "preview-builder"))
    roster = [
        {"name": "Aegis-Scout", "tier": "controlled", "mission": "wide-recon", "brain_id": "brain-ghost-hunter"},
        {"name": "Aegis-Tether", "tier": "tethered", "mission": "honeypot-net", "brain_id": "brain-sentinel-honeypot"},
        {"name": "Aegis-Dark", "tier": "autonomous", "mission": "watch-loop", "brain_id": "brain-watcher"},
    ]
    built = []
    for spec in roster:
        drone = _control_plane.assemble_drone(
            name=spec["name"],
            tier=spec["tier"],
            mission=spec["mission"],
            behaviour=spec["brain_id"],
            autonomy_level="observe",
            ttl_seconds=1800,
            checkin_interval_seconds=45,
            payload={"profile": spec["mission"], "generated_by": "preview-build"},
            actor=actor,
        )
        built.append({
            "drone_id": drone.drone_id,
            "name": drone.name,
            "tier": drone.tier,
            "mission": drone.mission,
            "behaviour_id": drone.behaviour.behaviour_id,
            "binary_blueprint_preview": drone.binary_blueprint[:128],
            "supported_binary_actions": drone.supported_binary_actions,
            "payload_binary_preview": drone.payload_binary[:128],
        })
    return jsonify({"built": built, "count": len(built)})


@app.delete("/api/drones/<drone_id>")
def api_drones_delete(drone_id: str):
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    payload, error = _safe_json_payload()
    if error:
        return error
    try:
        result = _control_plane.delete_drone(drone_id, str(payload.get("actor", "user")))
    except ValueError as exc:
        return jsonify({"error": "invalid_request", "message": str(exc)}), 400
    return jsonify(result)


@app.post("/api/drones/<drone_id>/launch")
def api_drones_launch(drone_id: str):
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    payload, error = _safe_json_payload()
    if error:
        return error
    try:
        drone = _control_plane.launch_drone(drone_id, str(payload.get("actor", "user")))
    except PermissionError as exc:
        return jsonify({"error": "approval_required", "message": str(exc)}), 403
    except ValueError as exc:
        return jsonify({"error": "invalid_request", "message": str(exc)}), 400
    return jsonify(_control_plane.as_dict(drone))


@app.post("/api/drones/<drone_id>/command")
def api_drones_command(drone_id: str):
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    payload, error = _safe_json_payload()
    if error:
        return error
    try:
        queued = _control_plane.send_drone_command(
            drone_id,
            command=str(payload.get("command", "")),
            params=dict(payload.get("params", {})),
            actor=str(payload.get("actor", "user")),
        )
    except ValueError as exc:
        return jsonify({"error": "invalid_request", "message": str(exc)}), 400
    return jsonify(queued)


@app.post("/api/drones/<drone_id>/recall")
def api_drones_recall(drone_id: str):
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    payload, error = _safe_json_payload()
    if error:
        return error
    drone = _control_plane.recall_drone(drone_id, str(payload.get("actor", "user")))
    return jsonify(_control_plane.as_dict(drone))


@app.post("/api/drones/<drone_id>/terminate")
def api_drones_terminate(drone_id: str):
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    payload, error = _safe_json_payload()
    if error:
        return error
    drone = _control_plane.terminate_drone(drone_id, str(payload.get("actor", "user")))
    return jsonify(_control_plane.as_dict(drone))


@app.get("/api/drones/<drone_id>/telemetry")
def api_drones_telemetry(drone_id: str):
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    drone = _control_plane.drones.get(drone_id)
    if drone is None:
        return jsonify({"error": "not_found"}), 404
    limit = int(request.args.get("limit", 100))
    since = request.args.get("since", "").strip()
    rows = drone.telemetry
    if since:
        rows = [r for r in rows if str(r.get("ts", "")) >= since]
    return jsonify({"telemetry": rows[-limit:], "live_output": drone.live_output[-limit:]})


@app.post("/api/drones/auto-assemble")
def api_drones_auto_assemble():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    payload, error = _safe_json_payload()
    if error:
        return error
    drone = _control_plane.auto_assemble_drone(str(payload.get("endpoint_id", "")), str(payload.get("actor", "user")))
    if drone is None:
        return jsonify({"error": "no_drone_applicable"})
    return jsonify(_control_plane.as_dict(drone))


@app.get("/api/drones/brains")
def api_drones_brains():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    return jsonify([_control_plane.as_dict(b) for b in _control_plane.drone_brains.values()])


@app.post("/api/drones/brains")
def api_drones_brains_create():
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    payload, error = _safe_json_payload()
    if error:
        return error
    behaviour_id = f"brain-{secrets.token_hex(4)}"
    brain = _control_plane._make_brain(
        behaviour_id=behaviour_id,
        name=str(payload.get("name", "custom-brain")),
        description=str(payload.get("description", "user saved brain")),
        nodes=list(payload.get("nodes", [])),
    )
    brain.is_brain_preset = False
    brain.author = "user"
    _control_plane.drone_brains[behaviour_id] = brain
    return jsonify(_control_plane.as_dict(brain))


@app.delete("/api/drones/brains/<behaviour_id>")
def api_drones_brains_delete(behaviour_id: str):
    unauthorized = _require_auth()
    if unauthorized:
        return unauthorized
    brain = _control_plane.drone_brains.get(behaviour_id)
    if brain is None:
        return jsonify({"error": "not_found"}), 404
    if brain.is_brain_preset:
        return jsonify({"error": "forbidden"}), 403
    _control_plane.drone_brains.pop(behaviour_id, None)
    return jsonify({"deleted": True})
