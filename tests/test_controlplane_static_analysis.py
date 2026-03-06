from pathlib import Path

from sentinel_containment.controlplane import HegemonControlPlane


def test_js_analyzer_tracks_taint_flow_and_sanitization(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    js_path = tmp_path / "sample.js"
    js_path.write_text(
        """
        function passthrough(v) { return v; }
        const userInput = window.location.search;
        const safe = DOMPurify.sanitize(userInput);
        document.body.innerHTML = safe;
        const alias = passthrough(userInput);
        document.body.innerHTML = alias;
        eval(alias);
        """,
        encoding="utf-8",
    )

    issues = cp._analyze_js_file(js_path, "sample.js")
    ids = [i["issue_id"] for i in issues]
    assert "js-dom-xss" in ids
    assert "js-dynamic-exec" in ids

    dom_issues = [i for i in issues if i["issue_id"] == "js-dom-xss"]
    assert len(dom_issues) == 1
    assert "sink-context" in dom_issues[0]["reasoning_details"]


def test_js_analyzer_tracks_property_and_jquery_sinks(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    js_path = tmp_path / "jquery.js"
    js_path.write_text(
        """
        const req = { body: { html: "<img src=x onerror=alert(1)>" } };
        let model = {};
        model.payload = req.body.html;
        $('#target').html(model.payload);
        """,
        encoding="utf-8",
    )

    issues = cp._analyze_js_file(js_path, "jquery.js")
    assert any(i["issue_id"] == "js-dom-xss" for i in issues)


def test_cross_language_hints_are_potential_with_evidence_and_sorted(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    hints = cp._build_cross_language_taint_chains(
        [
            {
                "lang": "python",
                "severity": "critical",
                "issue_id": "path-traversal",
                "file": "service.py",
                "reasoning": "writes to /tmp/cache/out.js",
                "dataflow_path": ["/tmp/cache/out.js"],
            },
            {
                "lang": "javascript",
                "severity": "high",
                "issue_id": "js-dom-xss",
                "file": "out.js",
                "reasoning": "reads /tmp/cache/out.js",
                "dataflow_path": ["/tmp/cache/out.js"],
            },
            {
                "lang": "shell",
                "severity": "medium",
                "issue_id": "shell-curl-pipe-exec",
                "file": "run.sh",
                "reasoning": "reads /tmp/out.sh",
                "dataflow_path": ["/tmp/out.sh"],
            },
        ]
    )
    assert hints
    assert hints[0]["type"] == "potential_cross_language_hint"
    assert hints[0]["confirmed"] is False
    assert "evidence" in hints[0]
    assert hints[0]["confidence"] >= hints[-1]["confidence"]


def test_binary_analysis_uses_objdump_when_available(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    binary_path = tmp_path / "prog.bin"
    binary_path.write_bytes(b"\x7fELF" + b"A" * 2048)

    issues, _packed, backend = cp._analyze_binary_file(binary_path, "prog.bin")
    assert backend in {None, "objdump"}
    assert isinstance(issues, list)


def test_structural_report_exposes_potential_cross_language_note(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "a.py").write_text("import os\n", encoding="utf-8")

    report = cp._analyze_program_structure(str(proj))
    assert "potential_cross_language_hints" in report
    assert report["cross_language_analysis_note"].startswith("potential cross-language hints")
    assert "integrated_flow_model" in report


def test_lstm_rnn_binary_model_is_built_from_markov_graph_context(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    model = cp._build_lightweight_lstm_rnn_binary_model(
        ["recon", "initial_access", "execution", "impact"],
        {"execution": {"impact": 0.8, "persistence": 0.2}},
        {"call_edges": 120.0, "functions": 40.0, "modules": 8.0},
    )
    assert model["model"] == "lightweight-lstm-rnn-binary-v1"
    assert model["timesteps"] == 4
    assert 0.0 <= model["sequence_anomaly"] <= 1.0
    assert 0.0 <= model["confidence"] <= 1.0


def test_scan_populates_markov_rnn_bayesian_posteriors(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    project = tmp_path / "project"
    project.mkdir()
    (project / "mini.py").write_text("print('hi')\n", encoding="utf-8")

    endpoint = cp.add_endpoint(
        {
            "endpoint_id": "ep-rnn-test",
            "host_name": "rnn-host",
            "endpoint_type": "on-prem",
            "os": "linux",
            "kernel": "6.1",
            "sbom_status": "valid",
            "enrollment_method": "manual",
            "program_root": str(project),
            "telemetry_events": ["recon", "initial_access", "execution", "impact"],
        },
        actor="tester",
    )

    result = cp.scan(endpoint.endpoint_id, include_external_intel=False, actor="tester")
    assert "markov_rnn_sequence_anomaly" in result.bayesian_posteriors
    assert "markov_rnn_confidence" in result.bayesian_posteriors
    assert "fusion_risk" in result.bayesian_posteriors
    assert result.scan_confidence > 0.0


def test_integrated_markov_mtre_graph_model_fuses_signals(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    model = cp._integrated_markov_mtre_graph_model(
        ["recon", "initial_access", "execution", "impact"],
        {
            "program_graph": {"call_edges": 200.0, "functions": 60.0, "tainted_return_functions": 4.0},
            "lstm_rnn_binary_model": {"sequence_anomaly": 0.3, "confidence": 0.7},
            "potential_cross_language_hints": [{"type": "potential_cross_language_hint"}],
        },
    )
    assert model["model"] == "markov-mtre-graph-rnn-fusion-v1"
    assert 0.0 <= model["fusion_risk"] <= 0.99
    assert 0.0 <= model["fusion_confidence"] <= 0.99
    assert model["cross_language_hint_count"] == 1
