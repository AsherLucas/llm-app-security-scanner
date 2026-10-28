import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from llm_scanner.scanner import scan_path


def test_vulnerable_example_flagged_and_fixed_passes_gate():
    root = Path(__file__).resolve().parents[1]
    vuln = scan_path(root / "examples" / "vulnerable")
    assert vuln.gate_failures("high"), "vulnerable example must fail the default gate"
    assert any(f.check_id == "SECRET001" for f in vuln.findings)
    fixed = scan_path(root / "examples" / "fixed")
    assert fixed.gate_failures("high") == [], f"fixed example must pass gate, got {fixed.findings}"


def test_suppression_file(tmp_path):
    (tmp_path / "bad.py").write_text('KEY = "sk-abcdefghijklmnopqrstuvwxyz1234567890"\n')
    (tmp_path / ".llm-scan-suppress").write_text("SECRET001:bad.py\n")
    result = scan_path(tmp_path)
    assert result.suppressed >= 1
    assert not any(f.check_id == "SECRET001" for f in result.findings)


def test_gate_only_high_confidence_by_default(tmp_path):
    (tmp_path / "m.py").write_text('password = "hunter2-hunter2"\n')
    result = scan_path(tmp_path)
    # SECRET002 is medium confidence, so it must not fail the default gate.
    assert result.gate_failures("high") == []
    assert result.gate_failures("medium") == []  # still high-confidence only
