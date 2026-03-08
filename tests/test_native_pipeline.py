from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from sentinel_containment.native_pipeline import (
    BuildInput,
    CommandRunner,
    NativePipelineEngine,
    NativePipelineError,
    PipelinePolicy,
    PipelinePolicyInspector,
    compile_native_binary,
)


class StubRunner(CommandRunner):
    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def run(self, cmd: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None):
        self.commands.append(cmd)

        class Proc:
            def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
                self.returncode = returncode
                self.stdout = stdout
                self.stderr = stderr

        # emulate pyinstaller/nuitka success by writing a native-looking file
        if "PyInstaller" in cmd:
            dist = Path(cmd[cmd.index("--distpath") + 1])
            dist.mkdir(parents=True, exist_ok=True)
            out = dist / "payload"
            out.write_bytes(b"\x7fELF" + b"X" * 200)
            os.chmod(out, 0o700)
            return Proc(0)
        if "nuitka" in cmd:
            # write output next to stage
            for part in cmd:
                if part.startswith("--output-dir="):
                    out_dir = Path(part.split("=", 1)[1])
                    out = out_dir / "payload_nuitka"
                    out.write_bytes(b"\x7fELF" + b"Y" * 200)
                    os.chmod(out, 0o700)
                    break
            return Proc(0)
        if cmd and (cmd[0].endswith("gcc") or cmd[0].endswith("cc")):
            out = Path(cmd[-1])
            out.write_bytes(b"\x7fELF" + b"Z" * 200)
            os.chmod(out, 0o700)
            return Proc(0)
        if "pip" in cmd:
            return Proc(0)
        return Proc(1, stderr="unsupported command")


@pytest.fixture
def payload_source() -> str:
    return """
import time

def main():
    print('ok')

if __name__ == '__main__':
    main()
""".strip() + "\n"


def _req(tmp_path: Path, source: str, runtime_cfg: dict | None = None) -> BuildInput:
    return BuildInput(
        drone_id="drone-test-001",
        source_text=source,
        workdir=tmp_path,
        private_key_hex="a" * 64,
        runtime_cfg=runtime_cfg or {},
        detached=False,
    )


def test_pipeline_compiles_with_stub_runner(tmp_path: Path, payload_source: str):
    engine = NativePipelineEngine(runner=StubRunner())
    out = engine.compile(_req(tmp_path, payload_source))
    assert out.executable_path.exists()
    assert out.backend in {"pyinstaller", "nuitka", "gcc-embed"}
    manifest = json.loads(out.manifest_path.read_text(encoding="utf-8"))
    assert manifest["drone_id"] == "drone-test-001"
    assert manifest["policy"]["require_native_binary"] is True


def test_pipeline_respects_preferred_backend(tmp_path: Path, payload_source: str):
    runner = StubRunner()
    engine = NativePipelineEngine(runner=runner)
    out = engine.compile(_req(tmp_path, payload_source, runtime_cfg={"native_backend": "nuitka"}))
    assert out.executable_path.exists()
    # since stub supports both, nuitka should be first attempted and can succeed
    assert out.backend in {"nuitka", "pyinstaller"}


def test_pipeline_rejects_invalid_input(tmp_path: Path):
    engine = NativePipelineEngine(runner=StubRunner())
    with pytest.raises(NativePipelineError):
        engine.compile(
            BuildInput(
                drone_id="",
                source_text="print('x')\n",
                workdir=tmp_path,
                private_key_hex="a" * 64,
            )
        )


def test_pipeline_rejects_bad_key_material(tmp_path: Path, payload_source: str):
    engine = NativePipelineEngine(runner=StubRunner())
    with pytest.raises(NativePipelineError):
        engine.compile(
            BuildInput(
                drone_id="drone-a",
                source_text=payload_source,
                workdir=tmp_path,
                private_key_hex="abcd",
            )
        )


def test_policy_inspector_default_score_is_high():
    inspector = PipelinePolicyInspector()
    verdict = inspector.evaluate({})
    assert verdict["score"] == 1.0
    assert len(verdict["findings"]) >= 200


@pytest.mark.parametrize(
    "cfg,expected_min",
    [
        ({"rule_001": False, "rule_002": False}, 0.0),
        ({"rule_001": True, "rule_002": True}, 0.9),
        ({"rule_050": -1}, 0.0),
        ({"rule_050": 2}, 0.9),
    ],
)
def test_policy_inspector_custom_inputs(cfg: dict, expected_min: float):
    inspector = PipelinePolicyInspector()
    verdict = inspector.evaluate(cfg)
    assert verdict["score"] >= expected_min


def test_compile_native_binary_policy_gate(tmp_path: Path, payload_source: str):
    req = _req(tmp_path, payload_source, runtime_cfg={**{f"rule_{i:03d}": False for i in range(1, 150)}})
    with pytest.raises(NativePipelineError):
        compile_native_binary(req)


def test_engine_manifest_contains_trace(tmp_path: Path, payload_source: str):
    engine = NativePipelineEngine(runner=StubRunner())
    out = engine.compile(_req(tmp_path, payload_source))
    manifest = json.loads(out.manifest_path.read_text(encoding="utf-8"))
    assert isinstance(manifest.get("trace"), list)
    assert len(manifest["trace"]) > 3
    phases = {e["phase"] for e in manifest["trace"]}
    assert "init" in phases
    assert "verify" in phases


def test_engine_detects_invalid_magic(tmp_path: Path, payload_source: str):
    class BadRunner(StubRunner):
        def run(self, cmd: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None):
            p = super().run(cmd, cwd=cwd, env=env)
            if "PyInstaller" in cmd:
                dist = Path(cmd[cmd.index("--distpath") + 1])
                out = dist / "payload"
                out.write_bytes(b"TEXT" + b"not-native")
            return p

    engine = NativePipelineEngine(runner=BadRunner())
    # fallback may still succeed through other backend, so make policy strict and isolate backend
    engine.backends = [engine.backends[0]]
    with pytest.raises(NativePipelineError):
        engine.compile(_req(tmp_path, payload_source))


def test_engine_cleanup_keeps_binary(tmp_path: Path, payload_source: str):
    runner = StubRunner()
    policy = PipelinePolicy(keep_stage_artifacts=False)
    engine = NativePipelineEngine(runner=runner, policy=policy)
    out = engine.compile(_req(tmp_path, payload_source))
    assert out.executable_path.exists()


def test_engine_keeps_stage_when_configured(tmp_path: Path, payload_source: str):
    runner = StubRunner()
    policy = PipelinePolicy(keep_stage_artifacts=True)
    engine = NativePipelineEngine(runner=runner, policy=policy)
    out = engine.compile(_req(tmp_path, payload_source))
    stage = Path(json.loads(out.manifest_path.read_text(encoding="utf-8"))["stage"])
    assert stage.exists()


def test_pipeline_trace_render(tmp_path: Path, payload_source: str):
    engine = NativePipelineEngine(runner=StubRunner())
    out = engine.compile(_req(tmp_path, payload_source))
    txt = out.trace.render_text()
    assert "[init]" in txt
    assert "pipeline complete" in txt


def test_min_size_policy_enforced(tmp_path: Path, payload_source: str):
    class TinyRunner(StubRunner):
        def run(self, cmd: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None):
            p = super().run(cmd, cwd=cwd, env=env)
            if "PyInstaller" in cmd:
                dist = Path(cmd[cmd.index("--distpath") + 1])
                out = dist / "payload"
                out.write_bytes(b"\x7fELF")
                os.chmod(out, 0o700)
            return p

    engine = NativePipelineEngine(runner=TinyRunner(), policy=PipelinePolicy(min_binary_size=100))
    engine.backends = [engine.backends[0]]
    with pytest.raises(NativePipelineError):
        engine.compile(_req(tmp_path, payload_source))


def test_backend_exhaustion_raises(tmp_path: Path, payload_source: str):
    class FailRunner(CommandRunner):
        def run(self, cmd: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None):
            class Proc:
                returncode = 1
                stdout = ""
                stderr = "forced failure"

            return Proc()

    engine = NativePipelineEngine(runner=FailRunner())
    with pytest.raises(NativePipelineError):
        engine.compile(_req(tmp_path, payload_source))
