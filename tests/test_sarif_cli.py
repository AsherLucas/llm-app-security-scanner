import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from llm_scanner.cli import main
from llm_scanner.sarif import to_sarif
from llm_scanner.scanner import scan_path


def test_sarif_shape(tmp_path):
    (tmp_path / "bad.py").write_text('KEY = "sk-abcdefghijklmnopqrstuvwxyz1234567890"\n')
    result = scan_path(tmp_path)
    sarif = to_sarif(result)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]
    assert sarif["runs"][0]["results"][0]["ruleId"] == "SECRET001"


def test_cli_exit_codes(tmp_path, capsys):
    (tmp_path / "bad.py").write_text('KEY = "sk-abcdefghijklmnopqrstuvwxyz1234567890"\n')
    assert main(["scan", str(tmp_path)]) == 1
    (tmp_path / "bad.py").write_text("x = 1\n")
    assert main(["scan", str(tmp_path)]) == 0


def test_cli_sarif_output(tmp_path, capsys):
    (tmp_path / "bad.py").write_text('KEY = "sk-abcdefghijklmnopqrstuvwxyz1234567890"\n')
    assert main(["scan", str(tmp_path), "--format", "sarif"]) == 1
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["runs"][0]["results"][0]["level"] == "error"


def test_adversarial_command(tmp_path):
    root = Path(__file__).resolve().parents[1]
    assert main(["adversarial", "--cases", str(root / "examples" / "adversarial" / "cases.yaml")]) == 0
