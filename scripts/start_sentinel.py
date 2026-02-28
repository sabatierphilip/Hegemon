from __future__ import annotations

import signal
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel_containment.config import Settings
from sentinel_containment.runtime import SentinelRuntime
from sentinel_containment.web.app import app


if __name__ == "__main__":
    settings = Settings.load()
    runtime = SentinelRuntime(settings)

    def _shutdown(*_: object) -> None:
        runtime.stop()
        raise SystemExit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    runtime.start()
    runtime.run_once()  # prime state immediately

    app.run(
        host=settings.get("dashboard_host", "0.0.0.0"),
        port=int(settings.get("dashboard_port", 5000)),
        debug=False,
    )
