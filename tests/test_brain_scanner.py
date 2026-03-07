import json
from pathlib import Path

from sentinel_containment.brain_scanner import MultiByteThreatScanner


def test_mbt_scanner_detects_languages_and_binary(tmp_path: Path):
    (tmp_path / "a.py").write_text("import os\nexec('print(1)')\n", encoding="utf-8")
    (tmp_path / "b.js").write_text("eval('alert(1)')\n", encoding="utf-8")
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01\x02\x03" * 30)

    scanner = MultiByteThreatScanner()
    result = scanner.scan_path(tmp_path, max_files=20)

    assert result["scanned_files"] == 3
    assert result["binary_file_count"] == 1
    assert result["language_counts"]["python"] == 1
    assert result["language_counts"]["javascript"] == 1
    assert result["language_counts"]["binary"] == 1

    top = result["high_risk_findings"][0]
    assert "mbt_score" in top
    assert isinstance(top["indicators"], list)


def test_mbt_scanner_single_file_details(tmp_path: Path):
    payload = "#!/usr/bin/env python3\nimport subprocess\nsubprocess.call('echo hi', shell=True)\n"
    p = tmp_path / "scanner"
    p.write_text(payload, encoding="utf-8")

    scanner = MultiByteThreatScanner()
    finding = scanner.scan_file(p, base=tmp_path)

    assert finding.path == "scanner"
    assert finding.language == "python"
    assert "subprocess" in finding.indicators
