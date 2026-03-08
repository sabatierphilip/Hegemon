from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import sysconfig
import textwrap
import time
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

@dataclass(slots=True)
class PipelinePolicy:
    require_native_binary: bool = True
    allow_python_fallback: bool = False
    require_signature_verification: bool = True
    require_file_magic: bool = True
    min_binary_size: int = 64
    max_binary_size: int = 1024 * 1024 * 150
    allow_network_installs: bool = True
    keep_stage_artifacts: bool = False
    strict_env_sanitization: bool = True

@dataclass(slots=True)
class BackendSpec:
    backend_id: str
    module_name: str | None
    executable_hint: str | None
    priority: int = 100
    metadata: dict[str, Any] = field(default_factory=dict)

@dataclass(slots=True)
class BuildEvent:
    ts: float
    phase: str
    detail: str
    data: dict[str, Any] = field(default_factory=dict)

@dataclass(slots=True)
class BuildTrace:
    events: list[BuildEvent] = field(default_factory=list)

    def emit(self, phase: str, detail: str, **data: Any) -> None:
        self.events.append(BuildEvent(ts=time.time(), phase=phase, detail=detail, data=data))

    def render_text(self) -> str:
        rows = []
        for ev in self.events:
            payload = f" {json.dumps(ev.data, sort_keys=True)}" if ev.data else ""
            rows.append(f"[{ev.phase}] {ev.detail}{payload}")
        return "\n".join(rows)

@dataclass(slots=True)
class BuildInput:
    drone_id: str
    source_text: str
    workdir: Path
    private_key_hex: str
    runtime_cfg: dict[str, Any] = field(default_factory=dict)
    detached: bool = False

@dataclass(slots=True)
class BuildOutput:
    executable_path: Path
    backend: str
    manifest_path: Path
    trace: BuildTrace
    build_seconds: float

class NativePipelineError(RuntimeError):
    pass

class CommandRunner:
    def run(self, cmd: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(cmd, cwd=str(cwd) if cwd else None, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

class NativePipelineEngine:
    """Sophisticated multi-stage native compilation pipeline for drones."""

    def __init__(self, *, policy: PipelinePolicy | None = None, runner: CommandRunner | None = None) -> None:
        self.policy = policy or PipelinePolicy()
        self.runner = runner or CommandRunner()
        self.backends: list[BackendSpec] = [
            BackendSpec("pyinstaller", "PyInstaller", None, 10, {"mode": "onefile"}),
            BackendSpec("nuitka", "nuitka", None, 20, {"mode": "onefile"}),
            BackendSpec("gcc-embed", None, "gcc", 30, {"mode": "embed"}),
        ]

    def compile(self, req: BuildInput) -> BuildOutput:
        start = time.time()
        trace = BuildTrace()
        trace.emit("init", "starting native pipeline", drone_id=req.drone_id)
        self._validate_input(req, trace)
        stage = self._create_stage(req, trace)
        backend_order = self._resolve_backend_order(req, trace)
        errors: list[str] = []
        selected_path: Path | None = None
        selected_backend = ""
        for backend in backend_order:
            try:
                trace.emit("backend", "attempt", backend=backend.backend_id)
                out = self._compile_with_backend(stage, req, backend, trace)
                self._verify_compiled_binary(out, trace)
                selected_path = out
                selected_backend = backend.backend_id
                trace.emit("backend", "success", backend=backend.backend_id, binary=str(out))
                break
            except Exception as exc:
                errors.append(f"{backend.backend_id}: {exc}")
                trace.emit("backend", "failure", backend=backend.backend_id, error=str(exc))
        if selected_path is None:
            raise NativePipelineError("native pipeline exhausted: " + " | ".join(errors))
        manifest = self._write_manifest(req=req, stage=stage, backend=selected_backend, binary=selected_path, trace=trace, errors=errors)
        if not self.policy.keep_stage_artifacts:
            self._best_effort_cleanup(stage, selected_path, trace)
        elapsed = time.time() - start
        trace.emit("done", "pipeline complete", backend=selected_backend, seconds=round(elapsed, 3))
        return BuildOutput(executable_path=selected_path, backend=selected_backend, manifest_path=manifest, trace=trace, build_seconds=elapsed)

    def _validate_input(self, req: BuildInput, trace: BuildTrace) -> None:
        if not req.drone_id.strip():
            raise NativePipelineError("empty drone_id")
        if len(req.private_key_hex) < 64:
            raise NativePipelineError("invalid private key material")
        if not req.source_text.strip():
            raise NativePipelineError("empty source")
        req.workdir.mkdir(parents=True, exist_ok=True)
        trace.emit("validate", "input accepted", workdir=str(req.workdir))

    def _create_stage(self, req: BuildInput, trace: BuildTrace) -> Path:
        root = req.workdir / "native_pipeline"
        root.mkdir(parents=True, exist_ok=True)
        stage = root / f"{req.drone_id}_{int(time.time() * 1000)}_{os.getpid()}"
        stage.mkdir(parents=True, exist_ok=True)
        src = stage / "payload.py"
        src.write_text(req.source_text, encoding="utf-8")
        os.chmod(src, 0o600)
        trace.emit("stage", "created", stage=str(stage), source=str(src))
        return stage

    def _resolve_backend_order(self, req: BuildInput, trace: BuildTrace) -> list[BackendSpec]:
        preferred = str((req.runtime_cfg or {}).get("native_backend", "")).strip().lower()
        by_id = {b.backend_id: b for b in self.backends}
        ordered: list[BackendSpec] = []
        if preferred and preferred in by_id:
            ordered.append(by_id[preferred])
        for b in sorted(self.backends, key=lambda x: x.priority):
            if b not in ordered:
                ordered.append(b)
        trace.emit("backend", "resolved", order=[b.backend_id for b in ordered], preferred=preferred or None)
        return ordered

    def _compile_with_backend(self, stage: Path, req: BuildInput, backend: BackendSpec, trace: BuildTrace) -> Path:
        src = (stage / "payload.py").resolve()
        if backend.backend_id == "pyinstaller":
            self._ensure_module("PyInstaller", trace)
            return self._build_pyinstaller(stage, src, req.drone_id, trace)
        if backend.backend_id == "nuitka":
            self._ensure_module("nuitka", trace)
            return self._build_nuitka(stage, src, req.drone_id, trace)
        if backend.backend_id == "gcc-embed":
            return self._build_gcc_embed(stage, src, req.drone_id, trace)
        raise NativePipelineError(f"unsupported backend: {backend.backend_id}")

    def _ensure_module(self, module_name: str, trace: BuildTrace) -> None:
        try:
            __import__(module_name)
            trace.emit("deps", "module present", module=module_name)
            return
        except Exception:
            trace.emit("deps", "module missing", module=module_name)
        if not self.policy.allow_network_installs:
            raise NativePipelineError(f"module {module_name} unavailable and installs disabled")
        proc = self.runner.run([sys.executable, "-m", "pip", "install", module_name])
        if proc.returncode != 0:
            raise NativePipelineError(f"install failed for {module_name}: {proc.stderr}")
        __import__(module_name)
        trace.emit("deps", "module installed", module=module_name)

    def _build_pyinstaller(self, stage: Path, src: Path, drone_id: str, trace: BuildTrace) -> Path:
        dist = (stage / "dist").resolve()
        build = (stage / "build").resolve()
        name = f"drone_{drone_id}_{hashlib.sha1(drone_id.encode()).hexdigest()[:8]}"
        cmd = [sys.executable, "-m", "PyInstaller", "--onefile", "--clean", "--distpath", str(dist), "--workpath", str(build), "--specpath", str(stage.resolve()), "--name", name, str(src)]
        proc = self.runner.run(cmd, cwd=stage)
        trace.emit("compile", "pyinstaller", code=proc.returncode, stderr_tail=proc.stderr[-2000:])
        if proc.returncode != 0:
            raise NativePipelineError("pyinstaller compile failed")
        candidates = [p for p in dist.iterdir() if p.is_file() and os.access(p, os.X_OK)] if dist.exists() else []
        if not candidates:
            raise NativePipelineError("pyinstaller produced no executable")
        return candidates[0]

    def _build_nuitka(self, stage: Path, src: Path, drone_id: str, trace: BuildTrace) -> Path:
        if not shutil.which("python3") and not shutil.which("python"):
            raise NativePipelineError("python executable unavailable")
        name = f"drone_{drone_id}_{hashlib.md5(drone_id.encode()).hexdigest()[:8]}"
        cmd = [sys.executable, "-m", "nuitka", "--onefile", "--assume-yes-for-downloads", f"--output-dir={stage.resolve()}", f"--output-filename={name}", str(src)]
        proc = self.runner.run(cmd, cwd=stage)
        trace.emit("compile", "nuitka", code=proc.returncode, stderr_tail=proc.stderr[-2000:])
        if proc.returncode != 0:
            raise NativePipelineError("nuitka compile failed")
        for p in stage.iterdir():
            if p.is_file() and os.access(p, os.X_OK) and p.name != src.name:
                return p
        raise NativePipelineError("nuitka produced no executable")

    def _build_gcc_embed(self, stage: Path, src: Path, drone_id: str, trace: BuildTrace) -> Path:
        gcc = shutil.which("gcc") or shutil.which("cc")
        if not gcc:
            raise NativePipelineError("gcc/cc not available")
        cfg = sysconfig.get_config_vars()
        include_dir = cfg.get("INCLUDEPY")
        lib_dir = cfg.get("LIBDIR")
        ldlib = str(cfg.get("LDLIBRARY", ""))
        if not include_dir or not lib_dir or not ldlib:
            raise NativePipelineError("python embed vars missing")
        m = re.match(r"^lib(.+?)(?:\.a|\.so(?:\..*)?|\.dylib)$", ldlib)
        lib_name = m.group(1) if m else ("python" + sysconfig.get_python_version())
        blob = zlib.compress(src.read_bytes(), level=9)
        c_bytes = ",".join(str(b) for b in blob)
        c_src = stage / "embed_main.c"
        c_src.write_text(textwrap.dedent(f"""
            #include <Python.h>
            #include <zlib.h>
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>
            static const unsigned char PAYLOAD[] = {{{c_bytes}}};
            static const size_t PAYLOAD_SIZE = sizeof(PAYLOAD);
            static unsigned char* inflate_payload(size_t* out_size) {{
                size_t cap = PAYLOAD_SIZE * 40 + 4096;
                unsigned char* out = (unsigned char*)malloc(cap);
                if (!out) return NULL;
                z_stream s;
                memset(&s, 0, sizeof(s));
                s.next_in = (Bytef*)PAYLOAD;
                s.avail_in = (uInt)PAYLOAD_SIZE;
                if (inflateInit(&s) != Z_OK) {{ free(out); return NULL; }}
                s.next_out = out;
                s.avail_out = (uInt)cap;
                int rc = inflate(&s, Z_FINISH);
                if (rc != Z_STREAM_END) {{ inflateEnd(&s); free(out); return NULL; }}
                *out_size = s.total_out;
                inflateEnd(&s);
                return out;
            }}
            int main(int argc, char** argv) {{
                size_t payload_len = 0;
                unsigned char* payload = inflate_payload(&payload_len);
                if (!payload || payload_len == 0) {{ fprintf(stderr, "inflate failed\n"); return 7; }}
                Py_Initialize();
                PyRun_SimpleString("import sys;sys.argv=[sys.argv[0]]");
                int rc = PyRun_SimpleString((const char*)payload);
                free(payload);
                if (Py_FinalizeEx() < 0) return 120;
                return rc == 0 ? 0 : 1;
            }}
        """).strip()+"\n", encoding="utf-8")
        out = stage / f"drone_{drone_id}_{int(time.time())}.bin"
        cmd = [gcc, "-O2", "-fPIE", "-I", str(include_dir), str(c_src.resolve()), "-L", str(lib_dir), f"-l{lib_name}", "-lz", "-o", str(out.resolve())]
        proc = self.runner.run(cmd, cwd=stage)
        trace.emit("compile", "gcc-embed", code=proc.returncode, stderr_tail=proc.stderr[-2000:])
        if proc.returncode != 0:
            raise NativePipelineError("gcc embed compile failed")
        if not out.exists():
            raise NativePipelineError("gcc output missing")
        return out

    def _verify_compiled_binary(self, path: Path, trace: BuildTrace) -> None:
        if not path.exists():
            raise NativePipelineError("binary path missing")
        size = path.stat().st_size
        if size < self.policy.min_binary_size:
            raise NativePipelineError(f"binary too small: {size}")
        if size > self.policy.max_binary_size:
            raise NativePipelineError(f"binary too large: {size}")
        if not os.access(path, os.X_OK):
            os.chmod(path, path.stat().st_mode | stat.S_IXUSR)
        if self.policy.require_file_magic:
            magic = path.read_bytes()[:4]
            if not self._looks_native_magic(magic):
                raise NativePipelineError(f"binary magic mismatch: {magic!r}")
        trace.emit("verify", "binary verified", path=str(path), size=size, sha256=self._sha256(path))

    def _looks_native_magic(self, magic: bytes) -> bool:
        return any(magic.startswith(prefix) for prefix in [b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"])

    def _sha256(self, path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    def _write_manifest(self, *, req: BuildInput, stage: Path, backend: str, binary: Path, trace: BuildTrace, errors: list[str]) -> Path:
        manifest = req.workdir / "launch_manifest.json"
        payload = {
            "drone_id": req.drone_id,
            "backend": backend,
            "binary_path": str(binary),
            "binary_sha256": self._sha256(binary),
            "binary_size": binary.stat().st_size,
            "policy": dataclasses.asdict(self.policy),
            "stage": str(stage),
            "errors": errors,
            "platform": {"system": platform.system(), "machine": platform.machine(), "python": platform.python_version()},
            "trace": [{"ts": e.ts, "phase": e.phase, "detail": e.detail, "data": e.data} for e in trace.events],
        }
        manifest.write_text(json.dumps(payload, sort_keys=True, indent=2), encoding="utf-8")
        os.chmod(manifest, 0o600)
        return manifest

    def _best_effort_cleanup(self, stage: Path, keep: Path, trace: BuildTrace) -> None:
        for p in stage.glob("**/*"):
            if p.resolve() == keep.resolve():
                continue
            if p.is_file():
                try:
                    p.unlink()
                except Exception:
                    pass
        trace.emit("cleanup", "stage cleanup attempted", stage=str(stage), kept=str(keep))

class PipelinePolicyInspector:
    """Expanded policy validation and explainability layer for runtime configuration."""
    def __init__(self) -> None:
        self._checks: list[Callable[[dict[str, Any]], tuple[bool, str]]] = []
        self._checks.append(self._check_rule_1)
        self._checks.append(self._check_rule_2)
        self._checks.append(self._check_rule_3)
        self._checks.append(self._check_rule_4)
        self._checks.append(self._check_rule_5)
        self._checks.append(self._check_rule_6)
        self._checks.append(self._check_rule_7)
        self._checks.append(self._check_rule_8)
        self._checks.append(self._check_rule_9)
        self._checks.append(self._check_rule_10)
        self._checks.append(self._check_rule_11)
        self._checks.append(self._check_rule_12)
        self._checks.append(self._check_rule_13)
        self._checks.append(self._check_rule_14)
        self._checks.append(self._check_rule_15)
        self._checks.append(self._check_rule_16)
        self._checks.append(self._check_rule_17)
        self._checks.append(self._check_rule_18)
        self._checks.append(self._check_rule_19)
        self._checks.append(self._check_rule_20)
        self._checks.append(self._check_rule_21)
        self._checks.append(self._check_rule_22)
        self._checks.append(self._check_rule_23)
        self._checks.append(self._check_rule_24)
        self._checks.append(self._check_rule_25)
        self._checks.append(self._check_rule_26)
        self._checks.append(self._check_rule_27)
        self._checks.append(self._check_rule_28)
        self._checks.append(self._check_rule_29)
        self._checks.append(self._check_rule_30)
        self._checks.append(self._check_rule_31)
        self._checks.append(self._check_rule_32)
        self._checks.append(self._check_rule_33)
        self._checks.append(self._check_rule_34)
        self._checks.append(self._check_rule_35)
        self._checks.append(self._check_rule_36)
        self._checks.append(self._check_rule_37)
        self._checks.append(self._check_rule_38)
        self._checks.append(self._check_rule_39)
        self._checks.append(self._check_rule_40)
        self._checks.append(self._check_rule_41)
        self._checks.append(self._check_rule_42)
        self._checks.append(self._check_rule_43)
        self._checks.append(self._check_rule_44)
        self._checks.append(self._check_rule_45)
        self._checks.append(self._check_rule_46)
        self._checks.append(self._check_rule_47)
        self._checks.append(self._check_rule_48)
        self._checks.append(self._check_rule_49)
        self._checks.append(self._check_rule_50)
        self._checks.append(self._check_rule_51)
        self._checks.append(self._check_rule_52)
        self._checks.append(self._check_rule_53)
        self._checks.append(self._check_rule_54)
        self._checks.append(self._check_rule_55)
        self._checks.append(self._check_rule_56)
        self._checks.append(self._check_rule_57)
        self._checks.append(self._check_rule_58)
        self._checks.append(self._check_rule_59)
        self._checks.append(self._check_rule_60)
        self._checks.append(self._check_rule_61)
        self._checks.append(self._check_rule_62)
        self._checks.append(self._check_rule_63)
        self._checks.append(self._check_rule_64)
        self._checks.append(self._check_rule_65)
        self._checks.append(self._check_rule_66)
        self._checks.append(self._check_rule_67)
        self._checks.append(self._check_rule_68)
        self._checks.append(self._check_rule_69)
        self._checks.append(self._check_rule_70)
        self._checks.append(self._check_rule_71)
        self._checks.append(self._check_rule_72)
        self._checks.append(self._check_rule_73)
        self._checks.append(self._check_rule_74)
        self._checks.append(self._check_rule_75)
        self._checks.append(self._check_rule_76)
        self._checks.append(self._check_rule_77)
        self._checks.append(self._check_rule_78)
        self._checks.append(self._check_rule_79)
        self._checks.append(self._check_rule_80)
        self._checks.append(self._check_rule_81)
        self._checks.append(self._check_rule_82)
        self._checks.append(self._check_rule_83)
        self._checks.append(self._check_rule_84)
        self._checks.append(self._check_rule_85)
        self._checks.append(self._check_rule_86)
        self._checks.append(self._check_rule_87)
        self._checks.append(self._check_rule_88)
        self._checks.append(self._check_rule_89)
        self._checks.append(self._check_rule_90)
        self._checks.append(self._check_rule_91)
        self._checks.append(self._check_rule_92)
        self._checks.append(self._check_rule_93)
        self._checks.append(self._check_rule_94)
        self._checks.append(self._check_rule_95)
        self._checks.append(self._check_rule_96)
        self._checks.append(self._check_rule_97)
        self._checks.append(self._check_rule_98)
        self._checks.append(self._check_rule_99)
        self._checks.append(self._check_rule_100)
        self._checks.append(self._check_rule_101)
        self._checks.append(self._check_rule_102)
        self._checks.append(self._check_rule_103)
        self._checks.append(self._check_rule_104)
        self._checks.append(self._check_rule_105)
        self._checks.append(self._check_rule_106)
        self._checks.append(self._check_rule_107)
        self._checks.append(self._check_rule_108)
        self._checks.append(self._check_rule_109)
        self._checks.append(self._check_rule_110)
        self._checks.append(self._check_rule_111)
        self._checks.append(self._check_rule_112)
        self._checks.append(self._check_rule_113)
        self._checks.append(self._check_rule_114)
        self._checks.append(self._check_rule_115)
        self._checks.append(self._check_rule_116)
        self._checks.append(self._check_rule_117)
        self._checks.append(self._check_rule_118)
        self._checks.append(self._check_rule_119)
        self._checks.append(self._check_rule_120)
        self._checks.append(self._check_rule_121)
        self._checks.append(self._check_rule_122)
        self._checks.append(self._check_rule_123)
        self._checks.append(self._check_rule_124)
        self._checks.append(self._check_rule_125)
        self._checks.append(self._check_rule_126)
        self._checks.append(self._check_rule_127)
        self._checks.append(self._check_rule_128)
        self._checks.append(self._check_rule_129)
        self._checks.append(self._check_rule_130)
        self._checks.append(self._check_rule_131)
        self._checks.append(self._check_rule_132)
        self._checks.append(self._check_rule_133)
        self._checks.append(self._check_rule_134)
        self._checks.append(self._check_rule_135)
        self._checks.append(self._check_rule_136)
        self._checks.append(self._check_rule_137)
        self._checks.append(self._check_rule_138)
        self._checks.append(self._check_rule_139)
        self._checks.append(self._check_rule_140)
        self._checks.append(self._check_rule_141)
        self._checks.append(self._check_rule_142)
        self._checks.append(self._check_rule_143)
        self._checks.append(self._check_rule_144)
        self._checks.append(self._check_rule_145)
        self._checks.append(self._check_rule_146)
        self._checks.append(self._check_rule_147)
        self._checks.append(self._check_rule_148)
        self._checks.append(self._check_rule_149)
        self._checks.append(self._check_rule_150)
        self._checks.append(self._check_rule_151)
        self._checks.append(self._check_rule_152)
        self._checks.append(self._check_rule_153)
        self._checks.append(self._check_rule_154)
        self._checks.append(self._check_rule_155)
        self._checks.append(self._check_rule_156)
        self._checks.append(self._check_rule_157)
        self._checks.append(self._check_rule_158)
        self._checks.append(self._check_rule_159)
        self._checks.append(self._check_rule_160)
        self._checks.append(self._check_rule_161)
        self._checks.append(self._check_rule_162)
        self._checks.append(self._check_rule_163)
        self._checks.append(self._check_rule_164)
        self._checks.append(self._check_rule_165)
        self._checks.append(self._check_rule_166)
        self._checks.append(self._check_rule_167)
        self._checks.append(self._check_rule_168)
        self._checks.append(self._check_rule_169)
        self._checks.append(self._check_rule_170)
        self._checks.append(self._check_rule_171)
        self._checks.append(self._check_rule_172)
        self._checks.append(self._check_rule_173)
        self._checks.append(self._check_rule_174)
        self._checks.append(self._check_rule_175)
        self._checks.append(self._check_rule_176)
        self._checks.append(self._check_rule_177)
        self._checks.append(self._check_rule_178)
        self._checks.append(self._check_rule_179)
        self._checks.append(self._check_rule_180)
        self._checks.append(self._check_rule_181)
        self._checks.append(self._check_rule_182)
        self._checks.append(self._check_rule_183)
        self._checks.append(self._check_rule_184)
        self._checks.append(self._check_rule_185)
        self._checks.append(self._check_rule_186)
        self._checks.append(self._check_rule_187)
        self._checks.append(self._check_rule_188)
        self._checks.append(self._check_rule_189)
        self._checks.append(self._check_rule_190)
        self._checks.append(self._check_rule_191)
        self._checks.append(self._check_rule_192)
        self._checks.append(self._check_rule_193)
        self._checks.append(self._check_rule_194)
        self._checks.append(self._check_rule_195)
        self._checks.append(self._check_rule_196)
        self._checks.append(self._check_rule_197)
        self._checks.append(self._check_rule_198)
        self._checks.append(self._check_rule_199)
        self._checks.append(self._check_rule_200)

    def evaluate(self, runtime_cfg: dict[str, Any]) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        for idx, fn in enumerate(self._checks, start=1):
            ok, note = fn(runtime_cfg)
            findings.append({"id": idx, "ok": ok, "note": note})
        score = sum(1 for f in findings if f["ok"]) / max(1, len(findings))
        return {"score": round(score, 4), "findings": findings}

    def _check_rule_1(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_001") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_001: default-allow"
        if isinstance(value, bool):
            return value, "rule_001: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_001: numeric threshold"
        return bool(value), "rule_001: truthy policy"

    def _check_rule_2(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_002") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_002: default-allow"
        if isinstance(value, bool):
            return value, "rule_002: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_002: numeric threshold"
        return bool(value), "rule_002: truthy policy"

    def _check_rule_3(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_003") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_003: default-allow"
        if isinstance(value, bool):
            return value, "rule_003: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_003: numeric threshold"
        return bool(value), "rule_003: truthy policy"

    def _check_rule_4(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_004") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_004: default-allow"
        if isinstance(value, bool):
            return value, "rule_004: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_004: numeric threshold"
        return bool(value), "rule_004: truthy policy"

    def _check_rule_5(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_005") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_005: default-allow"
        if isinstance(value, bool):
            return value, "rule_005: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_005: numeric threshold"
        return bool(value), "rule_005: truthy policy"

    def _check_rule_6(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_006") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_006: default-allow"
        if isinstance(value, bool):
            return value, "rule_006: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_006: numeric threshold"
        return bool(value), "rule_006: truthy policy"

    def _check_rule_7(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_007") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_007: default-allow"
        if isinstance(value, bool):
            return value, "rule_007: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_007: numeric threshold"
        return bool(value), "rule_007: truthy policy"

    def _check_rule_8(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_008") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_008: default-allow"
        if isinstance(value, bool):
            return value, "rule_008: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_008: numeric threshold"
        return bool(value), "rule_008: truthy policy"

    def _check_rule_9(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_009") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_009: default-allow"
        if isinstance(value, bool):
            return value, "rule_009: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_009: numeric threshold"
        return bool(value), "rule_009: truthy policy"

    def _check_rule_10(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_010") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_010: default-allow"
        if isinstance(value, bool):
            return value, "rule_010: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_010: numeric threshold"
        return bool(value), "rule_010: truthy policy"

    def _check_rule_11(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_011") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_011: default-allow"
        if isinstance(value, bool):
            return value, "rule_011: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_011: numeric threshold"
        return bool(value), "rule_011: truthy policy"

    def _check_rule_12(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_012") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_012: default-allow"
        if isinstance(value, bool):
            return value, "rule_012: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_012: numeric threshold"
        return bool(value), "rule_012: truthy policy"

    def _check_rule_13(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_013") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_013: default-allow"
        if isinstance(value, bool):
            return value, "rule_013: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_013: numeric threshold"
        return bool(value), "rule_013: truthy policy"

    def _check_rule_14(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_014") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_014: default-allow"
        if isinstance(value, bool):
            return value, "rule_014: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_014: numeric threshold"
        return bool(value), "rule_014: truthy policy"

    def _check_rule_15(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_015") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_015: default-allow"
        if isinstance(value, bool):
            return value, "rule_015: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_015: numeric threshold"
        return bool(value), "rule_015: truthy policy"

    def _check_rule_16(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_016") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_016: default-allow"
        if isinstance(value, bool):
            return value, "rule_016: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_016: numeric threshold"
        return bool(value), "rule_016: truthy policy"

    def _check_rule_17(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_017") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_017: default-allow"
        if isinstance(value, bool):
            return value, "rule_017: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_017: numeric threshold"
        return bool(value), "rule_017: truthy policy"

    def _check_rule_18(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_018") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_018: default-allow"
        if isinstance(value, bool):
            return value, "rule_018: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_018: numeric threshold"
        return bool(value), "rule_018: truthy policy"

    def _check_rule_19(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_019") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_019: default-allow"
        if isinstance(value, bool):
            return value, "rule_019: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_019: numeric threshold"
        return bool(value), "rule_019: truthy policy"

    def _check_rule_20(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_020") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_020: default-allow"
        if isinstance(value, bool):
            return value, "rule_020: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_020: numeric threshold"
        return bool(value), "rule_020: truthy policy"

    def _check_rule_21(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_021") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_021: default-allow"
        if isinstance(value, bool):
            return value, "rule_021: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_021: numeric threshold"
        return bool(value), "rule_021: truthy policy"

    def _check_rule_22(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_022") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_022: default-allow"
        if isinstance(value, bool):
            return value, "rule_022: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_022: numeric threshold"
        return bool(value), "rule_022: truthy policy"

    def _check_rule_23(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_023") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_023: default-allow"
        if isinstance(value, bool):
            return value, "rule_023: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_023: numeric threshold"
        return bool(value), "rule_023: truthy policy"

    def _check_rule_24(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_024") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_024: default-allow"
        if isinstance(value, bool):
            return value, "rule_024: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_024: numeric threshold"
        return bool(value), "rule_024: truthy policy"

    def _check_rule_25(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_025") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_025: default-allow"
        if isinstance(value, bool):
            return value, "rule_025: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_025: numeric threshold"
        return bool(value), "rule_025: truthy policy"

    def _check_rule_26(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_026") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_026: default-allow"
        if isinstance(value, bool):
            return value, "rule_026: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_026: numeric threshold"
        return bool(value), "rule_026: truthy policy"

    def _check_rule_27(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_027") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_027: default-allow"
        if isinstance(value, bool):
            return value, "rule_027: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_027: numeric threshold"
        return bool(value), "rule_027: truthy policy"

    def _check_rule_28(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_028") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_028: default-allow"
        if isinstance(value, bool):
            return value, "rule_028: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_028: numeric threshold"
        return bool(value), "rule_028: truthy policy"

    def _check_rule_29(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_029") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_029: default-allow"
        if isinstance(value, bool):
            return value, "rule_029: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_029: numeric threshold"
        return bool(value), "rule_029: truthy policy"

    def _check_rule_30(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_030") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_030: default-allow"
        if isinstance(value, bool):
            return value, "rule_030: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_030: numeric threshold"
        return bool(value), "rule_030: truthy policy"

    def _check_rule_31(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_031") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_031: default-allow"
        if isinstance(value, bool):
            return value, "rule_031: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_031: numeric threshold"
        return bool(value), "rule_031: truthy policy"

    def _check_rule_32(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_032") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_032: default-allow"
        if isinstance(value, bool):
            return value, "rule_032: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_032: numeric threshold"
        return bool(value), "rule_032: truthy policy"

    def _check_rule_33(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_033") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_033: default-allow"
        if isinstance(value, bool):
            return value, "rule_033: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_033: numeric threshold"
        return bool(value), "rule_033: truthy policy"

    def _check_rule_34(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_034") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_034: default-allow"
        if isinstance(value, bool):
            return value, "rule_034: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_034: numeric threshold"
        return bool(value), "rule_034: truthy policy"

    def _check_rule_35(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_035") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_035: default-allow"
        if isinstance(value, bool):
            return value, "rule_035: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_035: numeric threshold"
        return bool(value), "rule_035: truthy policy"

    def _check_rule_36(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_036") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_036: default-allow"
        if isinstance(value, bool):
            return value, "rule_036: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_036: numeric threshold"
        return bool(value), "rule_036: truthy policy"

    def _check_rule_37(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_037") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_037: default-allow"
        if isinstance(value, bool):
            return value, "rule_037: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_037: numeric threshold"
        return bool(value), "rule_037: truthy policy"

    def _check_rule_38(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_038") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_038: default-allow"
        if isinstance(value, bool):
            return value, "rule_038: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_038: numeric threshold"
        return bool(value), "rule_038: truthy policy"

    def _check_rule_39(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_039") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_039: default-allow"
        if isinstance(value, bool):
            return value, "rule_039: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_039: numeric threshold"
        return bool(value), "rule_039: truthy policy"

    def _check_rule_40(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_040") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_040: default-allow"
        if isinstance(value, bool):
            return value, "rule_040: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_040: numeric threshold"
        return bool(value), "rule_040: truthy policy"

    def _check_rule_41(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_041") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_041: default-allow"
        if isinstance(value, bool):
            return value, "rule_041: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_041: numeric threshold"
        return bool(value), "rule_041: truthy policy"

    def _check_rule_42(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_042") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_042: default-allow"
        if isinstance(value, bool):
            return value, "rule_042: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_042: numeric threshold"
        return bool(value), "rule_042: truthy policy"

    def _check_rule_43(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_043") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_043: default-allow"
        if isinstance(value, bool):
            return value, "rule_043: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_043: numeric threshold"
        return bool(value), "rule_043: truthy policy"

    def _check_rule_44(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_044") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_044: default-allow"
        if isinstance(value, bool):
            return value, "rule_044: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_044: numeric threshold"
        return bool(value), "rule_044: truthy policy"

    def _check_rule_45(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_045") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_045: default-allow"
        if isinstance(value, bool):
            return value, "rule_045: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_045: numeric threshold"
        return bool(value), "rule_045: truthy policy"

    def _check_rule_46(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_046") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_046: default-allow"
        if isinstance(value, bool):
            return value, "rule_046: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_046: numeric threshold"
        return bool(value), "rule_046: truthy policy"

    def _check_rule_47(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_047") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_047: default-allow"
        if isinstance(value, bool):
            return value, "rule_047: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_047: numeric threshold"
        return bool(value), "rule_047: truthy policy"

    def _check_rule_48(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_048") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_048: default-allow"
        if isinstance(value, bool):
            return value, "rule_048: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_048: numeric threshold"
        return bool(value), "rule_048: truthy policy"

    def _check_rule_49(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_049") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_049: default-allow"
        if isinstance(value, bool):
            return value, "rule_049: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_049: numeric threshold"
        return bool(value), "rule_049: truthy policy"

    def _check_rule_50(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_050") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_050: default-allow"
        if isinstance(value, bool):
            return value, "rule_050: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_050: numeric threshold"
        return bool(value), "rule_050: truthy policy"

    def _check_rule_51(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_051") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_051: default-allow"
        if isinstance(value, bool):
            return value, "rule_051: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_051: numeric threshold"
        return bool(value), "rule_051: truthy policy"

    def _check_rule_52(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_052") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_052: default-allow"
        if isinstance(value, bool):
            return value, "rule_052: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_052: numeric threshold"
        return bool(value), "rule_052: truthy policy"

    def _check_rule_53(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_053") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_053: default-allow"
        if isinstance(value, bool):
            return value, "rule_053: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_053: numeric threshold"
        return bool(value), "rule_053: truthy policy"

    def _check_rule_54(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_054") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_054: default-allow"
        if isinstance(value, bool):
            return value, "rule_054: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_054: numeric threshold"
        return bool(value), "rule_054: truthy policy"

    def _check_rule_55(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_055") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_055: default-allow"
        if isinstance(value, bool):
            return value, "rule_055: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_055: numeric threshold"
        return bool(value), "rule_055: truthy policy"

    def _check_rule_56(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_056") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_056: default-allow"
        if isinstance(value, bool):
            return value, "rule_056: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_056: numeric threshold"
        return bool(value), "rule_056: truthy policy"

    def _check_rule_57(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_057") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_057: default-allow"
        if isinstance(value, bool):
            return value, "rule_057: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_057: numeric threshold"
        return bool(value), "rule_057: truthy policy"

    def _check_rule_58(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_058") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_058: default-allow"
        if isinstance(value, bool):
            return value, "rule_058: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_058: numeric threshold"
        return bool(value), "rule_058: truthy policy"

    def _check_rule_59(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_059") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_059: default-allow"
        if isinstance(value, bool):
            return value, "rule_059: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_059: numeric threshold"
        return bool(value), "rule_059: truthy policy"

    def _check_rule_60(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_060") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_060: default-allow"
        if isinstance(value, bool):
            return value, "rule_060: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_060: numeric threshold"
        return bool(value), "rule_060: truthy policy"

    def _check_rule_61(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_061") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_061: default-allow"
        if isinstance(value, bool):
            return value, "rule_061: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_061: numeric threshold"
        return bool(value), "rule_061: truthy policy"

    def _check_rule_62(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_062") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_062: default-allow"
        if isinstance(value, bool):
            return value, "rule_062: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_062: numeric threshold"
        return bool(value), "rule_062: truthy policy"

    def _check_rule_63(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_063") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_063: default-allow"
        if isinstance(value, bool):
            return value, "rule_063: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_063: numeric threshold"
        return bool(value), "rule_063: truthy policy"

    def _check_rule_64(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_064") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_064: default-allow"
        if isinstance(value, bool):
            return value, "rule_064: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_064: numeric threshold"
        return bool(value), "rule_064: truthy policy"

    def _check_rule_65(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_065") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_065: default-allow"
        if isinstance(value, bool):
            return value, "rule_065: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_065: numeric threshold"
        return bool(value), "rule_065: truthy policy"

    def _check_rule_66(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_066") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_066: default-allow"
        if isinstance(value, bool):
            return value, "rule_066: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_066: numeric threshold"
        return bool(value), "rule_066: truthy policy"

    def _check_rule_67(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_067") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_067: default-allow"
        if isinstance(value, bool):
            return value, "rule_067: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_067: numeric threshold"
        return bool(value), "rule_067: truthy policy"

    def _check_rule_68(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_068") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_068: default-allow"
        if isinstance(value, bool):
            return value, "rule_068: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_068: numeric threshold"
        return bool(value), "rule_068: truthy policy"

    def _check_rule_69(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_069") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_069: default-allow"
        if isinstance(value, bool):
            return value, "rule_069: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_069: numeric threshold"
        return bool(value), "rule_069: truthy policy"

    def _check_rule_70(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_070") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_070: default-allow"
        if isinstance(value, bool):
            return value, "rule_070: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_070: numeric threshold"
        return bool(value), "rule_070: truthy policy"

    def _check_rule_71(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_071") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_071: default-allow"
        if isinstance(value, bool):
            return value, "rule_071: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_071: numeric threshold"
        return bool(value), "rule_071: truthy policy"

    def _check_rule_72(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_072") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_072: default-allow"
        if isinstance(value, bool):
            return value, "rule_072: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_072: numeric threshold"
        return bool(value), "rule_072: truthy policy"

    def _check_rule_73(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_073") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_073: default-allow"
        if isinstance(value, bool):
            return value, "rule_073: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_073: numeric threshold"
        return bool(value), "rule_073: truthy policy"

    def _check_rule_74(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_074") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_074: default-allow"
        if isinstance(value, bool):
            return value, "rule_074: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_074: numeric threshold"
        return bool(value), "rule_074: truthy policy"

    def _check_rule_75(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_075") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_075: default-allow"
        if isinstance(value, bool):
            return value, "rule_075: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_075: numeric threshold"
        return bool(value), "rule_075: truthy policy"

    def _check_rule_76(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_076") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_076: default-allow"
        if isinstance(value, bool):
            return value, "rule_076: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_076: numeric threshold"
        return bool(value), "rule_076: truthy policy"

    def _check_rule_77(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_077") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_077: default-allow"
        if isinstance(value, bool):
            return value, "rule_077: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_077: numeric threshold"
        return bool(value), "rule_077: truthy policy"

    def _check_rule_78(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_078") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_078: default-allow"
        if isinstance(value, bool):
            return value, "rule_078: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_078: numeric threshold"
        return bool(value), "rule_078: truthy policy"

    def _check_rule_79(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_079") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_079: default-allow"
        if isinstance(value, bool):
            return value, "rule_079: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_079: numeric threshold"
        return bool(value), "rule_079: truthy policy"

    def _check_rule_80(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_080") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_080: default-allow"
        if isinstance(value, bool):
            return value, "rule_080: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_080: numeric threshold"
        return bool(value), "rule_080: truthy policy"

    def _check_rule_81(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_081") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_081: default-allow"
        if isinstance(value, bool):
            return value, "rule_081: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_081: numeric threshold"
        return bool(value), "rule_081: truthy policy"

    def _check_rule_82(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_082") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_082: default-allow"
        if isinstance(value, bool):
            return value, "rule_082: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_082: numeric threshold"
        return bool(value), "rule_082: truthy policy"

    def _check_rule_83(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_083") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_083: default-allow"
        if isinstance(value, bool):
            return value, "rule_083: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_083: numeric threshold"
        return bool(value), "rule_083: truthy policy"

    def _check_rule_84(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_084") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_084: default-allow"
        if isinstance(value, bool):
            return value, "rule_084: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_084: numeric threshold"
        return bool(value), "rule_084: truthy policy"

    def _check_rule_85(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_085") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_085: default-allow"
        if isinstance(value, bool):
            return value, "rule_085: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_085: numeric threshold"
        return bool(value), "rule_085: truthy policy"

    def _check_rule_86(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_086") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_086: default-allow"
        if isinstance(value, bool):
            return value, "rule_086: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_086: numeric threshold"
        return bool(value), "rule_086: truthy policy"

    def _check_rule_87(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_087") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_087: default-allow"
        if isinstance(value, bool):
            return value, "rule_087: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_087: numeric threshold"
        return bool(value), "rule_087: truthy policy"

    def _check_rule_88(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_088") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_088: default-allow"
        if isinstance(value, bool):
            return value, "rule_088: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_088: numeric threshold"
        return bool(value), "rule_088: truthy policy"

    def _check_rule_89(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_089") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_089: default-allow"
        if isinstance(value, bool):
            return value, "rule_089: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_089: numeric threshold"
        return bool(value), "rule_089: truthy policy"

    def _check_rule_90(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_090") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_090: default-allow"
        if isinstance(value, bool):
            return value, "rule_090: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_090: numeric threshold"
        return bool(value), "rule_090: truthy policy"

    def _check_rule_91(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_091") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_091: default-allow"
        if isinstance(value, bool):
            return value, "rule_091: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_091: numeric threshold"
        return bool(value), "rule_091: truthy policy"

    def _check_rule_92(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_092") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_092: default-allow"
        if isinstance(value, bool):
            return value, "rule_092: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_092: numeric threshold"
        return bool(value), "rule_092: truthy policy"

    def _check_rule_93(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_093") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_093: default-allow"
        if isinstance(value, bool):
            return value, "rule_093: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_093: numeric threshold"
        return bool(value), "rule_093: truthy policy"

    def _check_rule_94(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_094") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_094: default-allow"
        if isinstance(value, bool):
            return value, "rule_094: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_094: numeric threshold"
        return bool(value), "rule_094: truthy policy"

    def _check_rule_95(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_095") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_095: default-allow"
        if isinstance(value, bool):
            return value, "rule_095: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_095: numeric threshold"
        return bool(value), "rule_095: truthy policy"

    def _check_rule_96(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_096") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_096: default-allow"
        if isinstance(value, bool):
            return value, "rule_096: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_096: numeric threshold"
        return bool(value), "rule_096: truthy policy"

    def _check_rule_97(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_097") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_097: default-allow"
        if isinstance(value, bool):
            return value, "rule_097: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_097: numeric threshold"
        return bool(value), "rule_097: truthy policy"

    def _check_rule_98(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_098") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_098: default-allow"
        if isinstance(value, bool):
            return value, "rule_098: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_098: numeric threshold"
        return bool(value), "rule_098: truthy policy"

    def _check_rule_99(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_099") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_099: default-allow"
        if isinstance(value, bool):
            return value, "rule_099: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_099: numeric threshold"
        return bool(value), "rule_099: truthy policy"

    def _check_rule_100(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_100") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_100: default-allow"
        if isinstance(value, bool):
            return value, "rule_100: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_100: numeric threshold"
        return bool(value), "rule_100: truthy policy"

    def _check_rule_101(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_101") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_101: default-allow"
        if isinstance(value, bool):
            return value, "rule_101: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_101: numeric threshold"
        return bool(value), "rule_101: truthy policy"

    def _check_rule_102(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_102") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_102: default-allow"
        if isinstance(value, bool):
            return value, "rule_102: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_102: numeric threshold"
        return bool(value), "rule_102: truthy policy"

    def _check_rule_103(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_103") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_103: default-allow"
        if isinstance(value, bool):
            return value, "rule_103: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_103: numeric threshold"
        return bool(value), "rule_103: truthy policy"

    def _check_rule_104(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_104") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_104: default-allow"
        if isinstance(value, bool):
            return value, "rule_104: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_104: numeric threshold"
        return bool(value), "rule_104: truthy policy"

    def _check_rule_105(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_105") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_105: default-allow"
        if isinstance(value, bool):
            return value, "rule_105: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_105: numeric threshold"
        return bool(value), "rule_105: truthy policy"

    def _check_rule_106(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_106") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_106: default-allow"
        if isinstance(value, bool):
            return value, "rule_106: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_106: numeric threshold"
        return bool(value), "rule_106: truthy policy"

    def _check_rule_107(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_107") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_107: default-allow"
        if isinstance(value, bool):
            return value, "rule_107: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_107: numeric threshold"
        return bool(value), "rule_107: truthy policy"

    def _check_rule_108(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_108") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_108: default-allow"
        if isinstance(value, bool):
            return value, "rule_108: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_108: numeric threshold"
        return bool(value), "rule_108: truthy policy"

    def _check_rule_109(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_109") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_109: default-allow"
        if isinstance(value, bool):
            return value, "rule_109: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_109: numeric threshold"
        return bool(value), "rule_109: truthy policy"

    def _check_rule_110(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_110") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_110: default-allow"
        if isinstance(value, bool):
            return value, "rule_110: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_110: numeric threshold"
        return bool(value), "rule_110: truthy policy"

    def _check_rule_111(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_111") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_111: default-allow"
        if isinstance(value, bool):
            return value, "rule_111: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_111: numeric threshold"
        return bool(value), "rule_111: truthy policy"

    def _check_rule_112(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_112") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_112: default-allow"
        if isinstance(value, bool):
            return value, "rule_112: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_112: numeric threshold"
        return bool(value), "rule_112: truthy policy"

    def _check_rule_113(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_113") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_113: default-allow"
        if isinstance(value, bool):
            return value, "rule_113: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_113: numeric threshold"
        return bool(value), "rule_113: truthy policy"

    def _check_rule_114(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_114") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_114: default-allow"
        if isinstance(value, bool):
            return value, "rule_114: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_114: numeric threshold"
        return bool(value), "rule_114: truthy policy"

    def _check_rule_115(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_115") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_115: default-allow"
        if isinstance(value, bool):
            return value, "rule_115: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_115: numeric threshold"
        return bool(value), "rule_115: truthy policy"

    def _check_rule_116(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_116") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_116: default-allow"
        if isinstance(value, bool):
            return value, "rule_116: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_116: numeric threshold"
        return bool(value), "rule_116: truthy policy"

    def _check_rule_117(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_117") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_117: default-allow"
        if isinstance(value, bool):
            return value, "rule_117: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_117: numeric threshold"
        return bool(value), "rule_117: truthy policy"

    def _check_rule_118(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_118") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_118: default-allow"
        if isinstance(value, bool):
            return value, "rule_118: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_118: numeric threshold"
        return bool(value), "rule_118: truthy policy"

    def _check_rule_119(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_119") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_119: default-allow"
        if isinstance(value, bool):
            return value, "rule_119: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_119: numeric threshold"
        return bool(value), "rule_119: truthy policy"

    def _check_rule_120(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_120") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_120: default-allow"
        if isinstance(value, bool):
            return value, "rule_120: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_120: numeric threshold"
        return bool(value), "rule_120: truthy policy"

    def _check_rule_121(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_121") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_121: default-allow"
        if isinstance(value, bool):
            return value, "rule_121: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_121: numeric threshold"
        return bool(value), "rule_121: truthy policy"

    def _check_rule_122(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_122") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_122: default-allow"
        if isinstance(value, bool):
            return value, "rule_122: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_122: numeric threshold"
        return bool(value), "rule_122: truthy policy"

    def _check_rule_123(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_123") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_123: default-allow"
        if isinstance(value, bool):
            return value, "rule_123: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_123: numeric threshold"
        return bool(value), "rule_123: truthy policy"

    def _check_rule_124(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_124") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_124: default-allow"
        if isinstance(value, bool):
            return value, "rule_124: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_124: numeric threshold"
        return bool(value), "rule_124: truthy policy"

    def _check_rule_125(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_125") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_125: default-allow"
        if isinstance(value, bool):
            return value, "rule_125: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_125: numeric threshold"
        return bool(value), "rule_125: truthy policy"

    def _check_rule_126(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_126") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_126: default-allow"
        if isinstance(value, bool):
            return value, "rule_126: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_126: numeric threshold"
        return bool(value), "rule_126: truthy policy"

    def _check_rule_127(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_127") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_127: default-allow"
        if isinstance(value, bool):
            return value, "rule_127: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_127: numeric threshold"
        return bool(value), "rule_127: truthy policy"

    def _check_rule_128(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_128") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_128: default-allow"
        if isinstance(value, bool):
            return value, "rule_128: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_128: numeric threshold"
        return bool(value), "rule_128: truthy policy"

    def _check_rule_129(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_129") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_129: default-allow"
        if isinstance(value, bool):
            return value, "rule_129: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_129: numeric threshold"
        return bool(value), "rule_129: truthy policy"

    def _check_rule_130(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_130") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_130: default-allow"
        if isinstance(value, bool):
            return value, "rule_130: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_130: numeric threshold"
        return bool(value), "rule_130: truthy policy"

    def _check_rule_131(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_131") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_131: default-allow"
        if isinstance(value, bool):
            return value, "rule_131: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_131: numeric threshold"
        return bool(value), "rule_131: truthy policy"

    def _check_rule_132(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_132") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_132: default-allow"
        if isinstance(value, bool):
            return value, "rule_132: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_132: numeric threshold"
        return bool(value), "rule_132: truthy policy"

    def _check_rule_133(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_133") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_133: default-allow"
        if isinstance(value, bool):
            return value, "rule_133: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_133: numeric threshold"
        return bool(value), "rule_133: truthy policy"

    def _check_rule_134(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_134") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_134: default-allow"
        if isinstance(value, bool):
            return value, "rule_134: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_134: numeric threshold"
        return bool(value), "rule_134: truthy policy"

    def _check_rule_135(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_135") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_135: default-allow"
        if isinstance(value, bool):
            return value, "rule_135: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_135: numeric threshold"
        return bool(value), "rule_135: truthy policy"

    def _check_rule_136(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_136") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_136: default-allow"
        if isinstance(value, bool):
            return value, "rule_136: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_136: numeric threshold"
        return bool(value), "rule_136: truthy policy"

    def _check_rule_137(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_137") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_137: default-allow"
        if isinstance(value, bool):
            return value, "rule_137: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_137: numeric threshold"
        return bool(value), "rule_137: truthy policy"

    def _check_rule_138(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_138") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_138: default-allow"
        if isinstance(value, bool):
            return value, "rule_138: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_138: numeric threshold"
        return bool(value), "rule_138: truthy policy"

    def _check_rule_139(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_139") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_139: default-allow"
        if isinstance(value, bool):
            return value, "rule_139: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_139: numeric threshold"
        return bool(value), "rule_139: truthy policy"

    def _check_rule_140(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_140") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_140: default-allow"
        if isinstance(value, bool):
            return value, "rule_140: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_140: numeric threshold"
        return bool(value), "rule_140: truthy policy"

    def _check_rule_141(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_141") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_141: default-allow"
        if isinstance(value, bool):
            return value, "rule_141: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_141: numeric threshold"
        return bool(value), "rule_141: truthy policy"

    def _check_rule_142(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_142") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_142: default-allow"
        if isinstance(value, bool):
            return value, "rule_142: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_142: numeric threshold"
        return bool(value), "rule_142: truthy policy"

    def _check_rule_143(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_143") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_143: default-allow"
        if isinstance(value, bool):
            return value, "rule_143: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_143: numeric threshold"
        return bool(value), "rule_143: truthy policy"

    def _check_rule_144(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_144") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_144: default-allow"
        if isinstance(value, bool):
            return value, "rule_144: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_144: numeric threshold"
        return bool(value), "rule_144: truthy policy"

    def _check_rule_145(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_145") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_145: default-allow"
        if isinstance(value, bool):
            return value, "rule_145: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_145: numeric threshold"
        return bool(value), "rule_145: truthy policy"

    def _check_rule_146(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_146") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_146: default-allow"
        if isinstance(value, bool):
            return value, "rule_146: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_146: numeric threshold"
        return bool(value), "rule_146: truthy policy"

    def _check_rule_147(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_147") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_147: default-allow"
        if isinstance(value, bool):
            return value, "rule_147: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_147: numeric threshold"
        return bool(value), "rule_147: truthy policy"

    def _check_rule_148(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_148") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_148: default-allow"
        if isinstance(value, bool):
            return value, "rule_148: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_148: numeric threshold"
        return bool(value), "rule_148: truthy policy"

    def _check_rule_149(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_149") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_149: default-allow"
        if isinstance(value, bool):
            return value, "rule_149: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_149: numeric threshold"
        return bool(value), "rule_149: truthy policy"

    def _check_rule_150(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_150") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_150: default-allow"
        if isinstance(value, bool):
            return value, "rule_150: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_150: numeric threshold"
        return bool(value), "rule_150: truthy policy"

    def _check_rule_151(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_151") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_151: default-allow"
        if isinstance(value, bool):
            return value, "rule_151: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_151: numeric threshold"
        return bool(value), "rule_151: truthy policy"

    def _check_rule_152(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_152") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_152: default-allow"
        if isinstance(value, bool):
            return value, "rule_152: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_152: numeric threshold"
        return bool(value), "rule_152: truthy policy"

    def _check_rule_153(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_153") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_153: default-allow"
        if isinstance(value, bool):
            return value, "rule_153: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_153: numeric threshold"
        return bool(value), "rule_153: truthy policy"

    def _check_rule_154(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_154") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_154: default-allow"
        if isinstance(value, bool):
            return value, "rule_154: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_154: numeric threshold"
        return bool(value), "rule_154: truthy policy"

    def _check_rule_155(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_155") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_155: default-allow"
        if isinstance(value, bool):
            return value, "rule_155: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_155: numeric threshold"
        return bool(value), "rule_155: truthy policy"

    def _check_rule_156(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_156") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_156: default-allow"
        if isinstance(value, bool):
            return value, "rule_156: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_156: numeric threshold"
        return bool(value), "rule_156: truthy policy"

    def _check_rule_157(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_157") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_157: default-allow"
        if isinstance(value, bool):
            return value, "rule_157: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_157: numeric threshold"
        return bool(value), "rule_157: truthy policy"

    def _check_rule_158(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_158") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_158: default-allow"
        if isinstance(value, bool):
            return value, "rule_158: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_158: numeric threshold"
        return bool(value), "rule_158: truthy policy"

    def _check_rule_159(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_159") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_159: default-allow"
        if isinstance(value, bool):
            return value, "rule_159: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_159: numeric threshold"
        return bool(value), "rule_159: truthy policy"

    def _check_rule_160(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_160") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_160: default-allow"
        if isinstance(value, bool):
            return value, "rule_160: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_160: numeric threshold"
        return bool(value), "rule_160: truthy policy"

    def _check_rule_161(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_161") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_161: default-allow"
        if isinstance(value, bool):
            return value, "rule_161: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_161: numeric threshold"
        return bool(value), "rule_161: truthy policy"

    def _check_rule_162(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_162") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_162: default-allow"
        if isinstance(value, bool):
            return value, "rule_162: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_162: numeric threshold"
        return bool(value), "rule_162: truthy policy"

    def _check_rule_163(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_163") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_163: default-allow"
        if isinstance(value, bool):
            return value, "rule_163: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_163: numeric threshold"
        return bool(value), "rule_163: truthy policy"

    def _check_rule_164(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_164") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_164: default-allow"
        if isinstance(value, bool):
            return value, "rule_164: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_164: numeric threshold"
        return bool(value), "rule_164: truthy policy"

    def _check_rule_165(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_165") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_165: default-allow"
        if isinstance(value, bool):
            return value, "rule_165: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_165: numeric threshold"
        return bool(value), "rule_165: truthy policy"

    def _check_rule_166(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_166") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_166: default-allow"
        if isinstance(value, bool):
            return value, "rule_166: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_166: numeric threshold"
        return bool(value), "rule_166: truthy policy"

    def _check_rule_167(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_167") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_167: default-allow"
        if isinstance(value, bool):
            return value, "rule_167: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_167: numeric threshold"
        return bool(value), "rule_167: truthy policy"

    def _check_rule_168(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_168") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_168: default-allow"
        if isinstance(value, bool):
            return value, "rule_168: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_168: numeric threshold"
        return bool(value), "rule_168: truthy policy"

    def _check_rule_169(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_169") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_169: default-allow"
        if isinstance(value, bool):
            return value, "rule_169: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_169: numeric threshold"
        return bool(value), "rule_169: truthy policy"

    def _check_rule_170(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_170") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_170: default-allow"
        if isinstance(value, bool):
            return value, "rule_170: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_170: numeric threshold"
        return bool(value), "rule_170: truthy policy"

    def _check_rule_171(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_171") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_171: default-allow"
        if isinstance(value, bool):
            return value, "rule_171: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_171: numeric threshold"
        return bool(value), "rule_171: truthy policy"

    def _check_rule_172(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_172") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_172: default-allow"
        if isinstance(value, bool):
            return value, "rule_172: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_172: numeric threshold"
        return bool(value), "rule_172: truthy policy"

    def _check_rule_173(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_173") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_173: default-allow"
        if isinstance(value, bool):
            return value, "rule_173: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_173: numeric threshold"
        return bool(value), "rule_173: truthy policy"

    def _check_rule_174(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_174") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_174: default-allow"
        if isinstance(value, bool):
            return value, "rule_174: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_174: numeric threshold"
        return bool(value), "rule_174: truthy policy"

    def _check_rule_175(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_175") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_175: default-allow"
        if isinstance(value, bool):
            return value, "rule_175: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_175: numeric threshold"
        return bool(value), "rule_175: truthy policy"

    def _check_rule_176(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_176") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_176: default-allow"
        if isinstance(value, bool):
            return value, "rule_176: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_176: numeric threshold"
        return bool(value), "rule_176: truthy policy"

    def _check_rule_177(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_177") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_177: default-allow"
        if isinstance(value, bool):
            return value, "rule_177: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_177: numeric threshold"
        return bool(value), "rule_177: truthy policy"

    def _check_rule_178(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_178") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_178: default-allow"
        if isinstance(value, bool):
            return value, "rule_178: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_178: numeric threshold"
        return bool(value), "rule_178: truthy policy"

    def _check_rule_179(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_179") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_179: default-allow"
        if isinstance(value, bool):
            return value, "rule_179: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_179: numeric threshold"
        return bool(value), "rule_179: truthy policy"

    def _check_rule_180(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_180") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_180: default-allow"
        if isinstance(value, bool):
            return value, "rule_180: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_180: numeric threshold"
        return bool(value), "rule_180: truthy policy"

    def _check_rule_181(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_181") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_181: default-allow"
        if isinstance(value, bool):
            return value, "rule_181: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_181: numeric threshold"
        return bool(value), "rule_181: truthy policy"

    def _check_rule_182(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_182") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_182: default-allow"
        if isinstance(value, bool):
            return value, "rule_182: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_182: numeric threshold"
        return bool(value), "rule_182: truthy policy"

    def _check_rule_183(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_183") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_183: default-allow"
        if isinstance(value, bool):
            return value, "rule_183: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_183: numeric threshold"
        return bool(value), "rule_183: truthy policy"

    def _check_rule_184(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_184") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_184: default-allow"
        if isinstance(value, bool):
            return value, "rule_184: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_184: numeric threshold"
        return bool(value), "rule_184: truthy policy"

    def _check_rule_185(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_185") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_185: default-allow"
        if isinstance(value, bool):
            return value, "rule_185: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_185: numeric threshold"
        return bool(value), "rule_185: truthy policy"

    def _check_rule_186(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_186") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_186: default-allow"
        if isinstance(value, bool):
            return value, "rule_186: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_186: numeric threshold"
        return bool(value), "rule_186: truthy policy"

    def _check_rule_187(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_187") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_187: default-allow"
        if isinstance(value, bool):
            return value, "rule_187: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_187: numeric threshold"
        return bool(value), "rule_187: truthy policy"

    def _check_rule_188(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_188") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_188: default-allow"
        if isinstance(value, bool):
            return value, "rule_188: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_188: numeric threshold"
        return bool(value), "rule_188: truthy policy"

    def _check_rule_189(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_189") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_189: default-allow"
        if isinstance(value, bool):
            return value, "rule_189: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_189: numeric threshold"
        return bool(value), "rule_189: truthy policy"

    def _check_rule_190(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_190") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_190: default-allow"
        if isinstance(value, bool):
            return value, "rule_190: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_190: numeric threshold"
        return bool(value), "rule_190: truthy policy"

    def _check_rule_191(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_191") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_191: default-allow"
        if isinstance(value, bool):
            return value, "rule_191: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_191: numeric threshold"
        return bool(value), "rule_191: truthy policy"

    def _check_rule_192(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_192") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_192: default-allow"
        if isinstance(value, bool):
            return value, "rule_192: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_192: numeric threshold"
        return bool(value), "rule_192: truthy policy"

    def _check_rule_193(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_193") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_193: default-allow"
        if isinstance(value, bool):
            return value, "rule_193: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_193: numeric threshold"
        return bool(value), "rule_193: truthy policy"

    def _check_rule_194(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_194") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_194: default-allow"
        if isinstance(value, bool):
            return value, "rule_194: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_194: numeric threshold"
        return bool(value), "rule_194: truthy policy"

    def _check_rule_195(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_195") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_195: default-allow"
        if isinstance(value, bool):
            return value, "rule_195: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_195: numeric threshold"
        return bool(value), "rule_195: truthy policy"

    def _check_rule_196(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_196") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_196: default-allow"
        if isinstance(value, bool):
            return value, "rule_196: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_196: numeric threshold"
        return bool(value), "rule_196: truthy policy"

    def _check_rule_197(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_197") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_197: default-allow"
        if isinstance(value, bool):
            return value, "rule_197: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_197: numeric threshold"
        return bool(value), "rule_197: truthy policy"

    def _check_rule_198(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_198") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_198: default-allow"
        if isinstance(value, bool):
            return value, "rule_198: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_198: numeric threshold"
        return bool(value), "rule_198: truthy policy"

    def _check_rule_199(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_199") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_199: default-allow"
        if isinstance(value, bool):
            return value, "rule_199: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_199: numeric threshold"
        return bool(value), "rule_199: truthy policy"

    def _check_rule_200(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        value = cfg.get("rule_200") if isinstance(cfg, dict) else None
        if value is None:
            return True, "rule_200: default-allow"
        if isinstance(value, bool):
            return value, "rule_200: boolean gate"
        if isinstance(value, (int, float)):
            return value >= 0, "rule_200: numeric threshold"
        return bool(value), "rule_200: truthy policy"

def compile_native_binary(req: BuildInput, *, policy: PipelinePolicy | None = None) -> BuildOutput:
    inspector = PipelinePolicyInspector()
    verdict = inspector.evaluate(req.runtime_cfg if isinstance(req.runtime_cfg, dict) else {})
    if verdict["score"] < 0.45:
        raise NativePipelineError("runtime policy score too low for native compile")
    return NativePipelineEngine(policy=policy).compile(req)
