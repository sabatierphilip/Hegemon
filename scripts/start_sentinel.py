from __future__ import annotations

import signal
import subprocess
import sys
import threading
import webbrowser
from importlib.util import find_spec
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel_containment.config import Settings
from sentinel_containment.runtime import SentinelRuntime
from sentinel_containment.web.app import app, set_runtime


def _ensure_dependencies_installed() -> None:
    required_modules = {
        "flask": "flask",
        "networkx": "networkx",
        "PyYAML": "yaml",
        "cryptography": "cryptography",
        "boto3": "boto3",
    }
    missing = [package for package, module in required_modules.items() if find_spec(module) is None]
    if not missing:
        return

    requirements_file = ROOT / "requirements.txt"
    if not requirements_file.exists():
        raise RuntimeError(
            "Missing required dependencies and requirements.txt was not found. "
            f"Missing packages: {', '.join(missing)}"
        )

    print(
        "[start_sentinel] Missing dependencies detected: "
        f"{', '.join(missing)}. Installing from {requirements_file}..."
    )
    install_cmd = [sys.executable, "-m", "pip", "install", "-r", str(requirements_file)]
    subprocess.run(install_cmd, check=True)


if __name__ == "__main__":
    _ensure_dependencies_installed()
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
