from __future__ import annotations

import signal
import sys
import threading
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel_containment.config import Settings
from sentinel_containment.runtime import SentinelRuntime
from sentinel_containment.web.app import app, set_runtime


if __name__ == "__main__":
    settings = Settings.load()
    runtime = SentinelRuntime(settings)
    set_runtime(runtime)

    def _shutdown(*_: object) -> None:
        runtime.stop()
        raise SystemExit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    runtime.start()
    runtime.run_once()  # prime state immediately

    dashboard_host = str(settings.get('dashboard_host', '127.0.0.1')).strip()
    if dashboard_host in {'0.0.0.0', '::', '*'}:
        dashboard_host = '127.0.0.1'
    dashboard_url = f"http://{dashboard_host}:{int(settings.get('dashboard_port',5000))}"
    threading.Thread(target=lambda: webbrowser.open(dashboard_url), daemon=True).start()

    app.run(
        host=dashboard_host,
        port=int(settings.get("dashboard_port", 5000)),
        debug=False,
    )
