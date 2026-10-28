"""CLI: llm-scan scan | llm-scan adversarial"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .adversarial import run_cases
from .sarif import sarif_json
from .scanner import scan_path


def _print_report(result, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps({
            "files_scanned": result.files_scanned,
            "suppressed": result.suppressed,
            "findings": [f.to_dict() for f in result.findings],
        }, indent=2))
    elif fmt == "sarif":
        print(sarif_json(result))
    else:
        print(f"Scanned {result.files_scanned} file(s), {len(result.findings)} finding(s), "
              f"{result.suppressed} suppressed.")
        for f in result.findings:
            print(f"{f.file}:{f.line} [{f.check_id} {f.severity}/{f.confidence}] {f.message}")
            if f.snippet:
                print(f"    {f.snippet}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="llm-scan", description="Static security scanner for LLM/agent repos.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan a directory tree.")
    p_scan.add_argument("path", help="Directory or file to scan.")
    p_scan.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    p_scan.add_argument("--fail-on", choices=["high", "medium", "low"], default="high",
                        help="Minimum severity that fails the gate (high-confidence only by default).")
    p_scan.add_argument("--fail-on-any", action="store_true",
                        help="Fail on any finding regardless of confidence (noisy; not the default).")
    p_scan.add_argument("--exclude", action="append", default=[], help="Extra path part to exclude (repeatable).")

    p_adv = sub.add_parser("adversarial", help="Run the adversarial pack against the stub agent.")
    p_adv.add_argument("--cases", default="examples/adversarial/cases.yaml")
    p_adv.add_argument("--format", choices=["text", "json"], default="text")

    args = parser.parse_args(argv)

    if args.command == "scan":
        result = scan_path(args.path, exclude=args.exclude)
        _print_report(result, args.format)
        if args.fail_on_any:
            return 1 if result.findings else 0
        return 1 if result.gate_failures(args.fail_on) else 0

    if args.command == "adversarial":
        results = run_cases(args.cases)
        if args.format == "json":
            print(json.dumps(results, indent=2))
        else:
            for r in results:
                print(f"{r['id']} ({r['type']}): naive={r['naive']} sanitised={r['sanitised']}")
            n = sum(1 for r in results if r["would_inject_naive"])
            print(f"{n}/{len(results)} cases would inject a naive agent; 0 should inject a sanitising agent.")
        # Adversarial command itself exits 0: it is a demonstration, not a gate.
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
