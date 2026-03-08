from pathlib import Path

from sentinel_containment.action_runtime import RuntimeActionEngine, RuntimeContext, RuntimeRulebook


def _engine(tmp_path: Path) -> RuntimeActionEngine:
    return RuntimeActionEngine(RuntimeContext(drone_id="drone-x", base_dir=tmp_path / "runtime", autonomy_level="enforce"))


def test_registry_watch_and_rotate_credentials(tmp_path: Path):
    eng = _engine(tmp_path)
    r1 = eng.registry_watch("HKLM", "Software\\Test")
    r2 = eng.rotate_credentials("db")
    assert r1.ok and r2.ok
    assert (tmp_path / "runtime" / "registry_watch.json").exists()
    assert (tmp_path / "runtime" / "rotated_credentials.json").exists()


def test_sinkhole_isolation_snapshot_contact_report(tmp_path: Path):
    eng = _engine(tmp_path)
    s = eng.sinkhole_clone("10.0.0.9")
    i = eng.isolate_source_ip("10.0.0.9")
    v = eng.snapshot_vss("C:\\")
    c = eng.establish_contact()
    rp = eng.send_report({"hello": "world"})
    assert s.ok and v.ok and rp.ok
    assert (tmp_path / "runtime" / "sinkhole" / "routes.json").exists()
    assert (tmp_path / "runtime" / "blocked_ips.json").exists()
    assert (tmp_path / "runtime" / "reports" / "latest.json").exists()
    assert c.action == "establish_contact"
    assert i.action == "isolate_source_ip"


def test_peer_sync_and_rulebook(tmp_path: Path):
    eng = _engine(tmp_path)
    p = tmp_path / "d1" / "deadrop"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("x", encoding="utf-8")
    r = eng.peer_sync([tmp_path])
    assert r.ok
    assert r.artifacts["merged"] >= 1

    rb = RuntimeRulebook()
    assert len(rb.rules) >= 1700
    assert rb.score({}) == 1.0
