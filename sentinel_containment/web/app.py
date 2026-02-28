from __future__ import annotations

import json
from pathlib import Path

from flask import Flask, jsonify, render_template_string

from sentinel_containment.config import Settings

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


def _load_latest_state() -> dict:
    settings = Settings.load()
    state_path = Path(settings.get("latest_state_path", "data/latest_state.json"))
    if state_path.exists():
        return json.loads(state_path.read_text(encoding="utf-8"))
    return {"topology": {}, "correlated": {}, "contained_hosts": []}


@app.get("/")
def dashboard():
    state = _load_latest_state()
    return render_template_string(
        HTML,
        topology=json.dumps(state.get("topology", {}), indent=2),
        alerts=json.dumps(state.get("correlated", {}), indent=2),
        contained_hosts=json.dumps(state.get("contained_hosts", []), indent=2),
    )


@app.get("/graph")
def graph():
    state = _load_latest_state()
    return jsonify(state.get("topology", {}))
