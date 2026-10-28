"""SARIF 2.1.0 output for GitHub code scanning."""
from __future__ import annotations

import json

from .models import ScanResult

LEVEL = {"high": "error", "medium": "warning", "low": "note"}


def to_sarif(result: ScanResult, tool_name: str = "llm-app-security-scanner") -> dict:
    rules: dict[str, dict] = {}
    for f in result.findings:
        rules.setdefault(f.check_id, {
            "id": f.check_id,
            "name": f.check_id,
            "shortDescription": {"text": f.message},
            "defaultConfiguration": {"level": LEVEL.get(f.severity, "warning")},
        })
    results = []
    for f in result.findings:
        results.append({
            "ruleId": f.check_id,
            "level": LEVEL.get(f.severity, "warning"),
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": f.line, "snippet": {"text": f.snippet}},
                }
            }],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": tool_name, "version": "0.1.0", "rules": list(rules.values())}},
            "results": results,
        }],
    }


def sarif_json(result: ScanResult) -> str:
    return json.dumps(to_sarif(result), indent=2)
