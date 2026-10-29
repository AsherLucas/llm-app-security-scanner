
def test_js_checks(tmp_path):
    from llm_scanner.checks import scan_file
    p = tmp_path / "vuln.js"
    p.write_text("eval(userInput);\nconst { exec } = require('child_process');\nrequire('child_process').exec(cmd);\nnew Function('x', 'return x');\n")
    ids = [f.check_id for f in scan_file(p)]
    assert "JS001" in ids and "JS002" in ids and "JS003" in ids
