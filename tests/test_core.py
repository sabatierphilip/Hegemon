from sentinel_containment.cloud.provider import CloudProviderAdapter
from sentinel_containment.asset_mapper.discovery import AssetMapper
from sentinel_containment.detection.rule_engine import RuleEngine
from sentinel_containment.logging_layer.immutable_log import ImmutableAuditLog
from sentinel_containment.containment.engine import ContainmentEngine
from sentinel_containment.config import Settings
from sentinel_containment.main import run_cycle


def test_asset_snapshot_contains_nodes(tmp_path):
    mapper = AssetMapper(CloudProviderAdapter(simulated=True), snapshot_path=tmp_path / "topology.json")
    snap = mapper.snapshot()
    assert snap["nodes"]


def test_rule_engine_detects_excessive_calls():
    engine = RuleEngine()
    alerts = engine.evaluate({"action": "model_invoke", "api_call_count": 900})
    assert any("Excessive Model API Calls" == a.rule for a in alerts)


def test_containment_two_person_approval(tmp_path):
    audit = ImmutableAuditLog(tmp_path / "audit.log")
    engine = ContainmentEngine(audit)
    denied = engine.execute("h1", 90, ["quarantine_host"], ["alice"])
    assert not denied.approved
    allowed = engine.execute("h1", 90, ["quarantine_host"], ["alice", "bob"])
    assert allowed.approved


def test_run_cycle_generates_correlated_alert_and_containment():
    state = run_cycle(Settings.load())
    assert state["correlated"] is not None
    assert state["correlated"]["severity"] >= 70
    assert state["containment"] is not None
