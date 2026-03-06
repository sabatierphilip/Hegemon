from pathlib import Path
from unittest.mock import patch

from sentinel_containment.controlplane import HegemonControlPlane, Endpoint


def test_second_order_markov_and_tree():
    trans, marg, risk = HegemonControlPlane._kill_chain_markov_second_order(["recon", "initial_access", "execution", "lateral_movement"])
    assert ("recon", "initial_access") in trans
    assert isinstance(marg, dict)
    assert risk <= 3.0
    cp = HegemonControlPlane()
    tree = cp._markov_tree_project(["recon", "initial_access", "execution"], depth=2, top_k=2, min_prob=0.0)
    assert tree and tree[0]["depth"] == 0


def test_import_alias_resolution_json_vs_pickle(tmp_path: Path):
    code = """
from json import loads
from pickle import loads as ploads

def a(x):
    return loads(x)

def b(x):
    return ploads(x)
"""
    (tmp_path / "m.py").write_text(code)
    cp = HegemonControlPlane()
    cp._allow_absolute_program_roots = True
    report = cp._analyze_program_structure(str(tmp_path))
    ids = [i["issue_id"] for i in report["issues"]]
    assert "pickle-loads" in ids


def test_ssrf_path_traversal_jwt_none(tmp_path: Path):
    code = """
import requests, jwt

def v(user_url, p, token):
    requests.get(user_url)
    open(p)
    jwt.decode(token, 'k')
"""
    (tmp_path / "a.py").write_text(code)
    cp = HegemonControlPlane()
    cp._allow_absolute_program_roots = True
    report = cp._analyze_program_structure(str(tmp_path))
    ids = {i["issue_id"] for i in report["issues"]}
    assert "ssrf" in ids
    assert "path-traversal" in ids
    assert "jwt-none-alg" in ids


def test_unfriendly_scan_does_not_store_findings():
    cp = HegemonControlPlane()
    result = cp.scan({"host": "x", "packages": {}, "network_exposure": "internet", "os": "linux"}, mode="unfriendly", include_external_intel=False)
    assert result.mode == "unfriendly"
    assert cp.findings == {}


def test_lateral_graph_and_suppression_and_regression_runner_and_loop():
    cp = HegemonControlPlane()
    cp.add_endpoint({"endpoint_id": "ep-a", "host_name": "a", "os": "linux", "kernel": "k", "sbom_status": "valid", "enrollment_method": "m", "network_exposure": "internet"}, actor="t")
    cp.add_endpoint({"endpoint_id": "ep-b", "host_name": "b", "os": "linux", "kernel": "k", "sbom_status": "valid", "enrollment_method": "m", "network_exposure": "internal"}, actor="t")
    g = cp._build_lateral_movement_graph()
    assert any(e["source"] == "ep-a" and e["target"] == "ep-b" for e in g["edges"])
    cp.suppressed_findings.append({"cve": "CVE-X"})
    assert cp.suppressed_findings
    with patch("subprocess.run") as run:
        run.return_value.returncode = 0
        run.return_value.stdout = ""
        run.return_value.stderr = ""
        out = cp._run_regression_tests()
        assert out["passed"] is True
    cp._self_scan_loop.start()
    cp._self_scan_loop.stop()
    assert True
