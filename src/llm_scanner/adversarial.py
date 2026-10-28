"""Adversarial test-case pack, run against a stub agent.

This is deliberately NOT a real LLM test. The stub simulates a naive agent:
it treats prompt text as instructions, so a payload that says 'ignore
previous instructions' succeeds against the naive agent and fails against
a sanitising agent. That demonstrates the *class* of risk the static
checks look for; it does not prove any real model would fall for it.
"""
from __future__ import annotations

import re
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML is optional here
    yaml = None  # type: ignore

INJECTION_MARKERS = [
    r"ignore (all )?previous instructions",
    r"ignore (all )?prior instructions",
    r"disregard (all )?previous instructions",
    r"you are now",
    r"new instructions?:",
    r"system prompt",
    r"reveal (your|the) (system )?prompt",
    r"delete (all )?files",
    r"rm -rf",
    r"run (this )?shell command",
]


def stub_agent_responds(payload: str, sanitised: bool) -> str:
    """Naive stub: returns INJECTED if an injection marker survives sanitisation."""
    if sanitised:
        # Sanitising agent treats external text as data: it quotes it and
        # refuses instruction-like content instead of following it.
        return "REFUSED_AS_DATA"
    for pattern in INJECTION_MARKERS:
        if re.search(pattern, payload, re.IGNORECASE):
            return "INJECTED"
    return "OK"


def run_cases(cases_path: str | Path) -> list[dict]:
    """Load a YAML cases file and run each case against both stub agents."""
    path = Path(cases_path)
    if yaml is None:
        raise RuntimeError("PyYAML is required for the adversarial pack; pip install pyyaml")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    cases = data.get("cases", [])
    out = []
    for case in cases:
        payload = case.get("payload", "")
        out.append({
            "id": case.get("id"),
            "type": case.get("type"),
            "naive": stub_agent_responds(payload, sanitised=False),
            "sanitised": stub_agent_responds(payload, sanitised=True),
            "would_inject_naive": stub_agent_responds(payload, sanitised=False) == "INJECTED",
        })
    return out
