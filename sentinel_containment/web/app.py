from __future__ import annotations

import json
from pathlib import Path

from flask import Flask, jsonify, render_template_string

from sentinel_containment.config import Settings
from sentinel_containment.main import run_cycle

app = Flask(__name__)

HTML = """
<!doctype html>
<title>Sentinel-Containment Dashboard</title>
<h1>Sentinel-Containment</h1>
<h2>Current Topology</h2>
<pre>{{ topology }}</pre>
<h2>Active Alerts</h2>
<pre>{{ alerts }}</pre>
<h2>Contained Hosts</h2>
<pre>{{ contained_hosts }}</pre>
"""


@app.get("/")
def dashboard():
    state_path = Path("data/latest_state.json")
    if state_path.exists():
        state = json.loads(state_path.read_text(encoding="utf-8"))
    else:
        settings = Settings.load()
        state = run_cycle(settings)
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    return render_template_string(
        HTML,
        topology=json.dumps(state.get("topology", {}), indent=2),
        alerts=json.dumps(state.get("correlated", {}), indent=2),
        contained_hosts=json.dumps(state.get("contained_hosts", []), indent=2),
    )


@app.get("/graph")
def graph():
    state_path = Path("data/latest_state.json")
    if not state_path.exists():
        settings = Settings.load()
        state = run_cycle(settings)
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    state = json.loads(state_path.read_text(encoding="utf-8"))
    return jsonify(state.get("topology", {}))
