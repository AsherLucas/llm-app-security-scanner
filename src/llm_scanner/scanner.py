"""Directory scanner + suppression handling."""
from __future__ import annotations

import fnmatch
from pathlib import Path

from .checks import scan_file
from .models import ScanResult

DEFAULT_EXCLUDES = {".git", "__pycache__", ".venv", "venv", "node_modules", ".pytest_cache", "dist", "build", "*.egg-info"}


def load_suppressions(root: Path) -> list[dict]:
    """Read .llm-scan-suppress (one rule per line: CHECK_ID:glob or CHECK_ID:file:line).

    Lines starting with # are comments. A rule matches when the check id
    matches and the file path matches the glob (or file:line matches exactly).
    """
    suppress_file = root / ".llm-scan-suppress"
    rules: list[dict] = []
    if not suppress_file.exists():
        return rules
    for raw in suppress_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) == 2:
            rules.append({"check": parts[0].strip(), "glob": parts[1].strip()})
        elif len(parts) == 3:
            rules.append({"check": parts[0].strip(), "file": parts[1].strip(), "line": parts[2].strip()})
    return rules


def _suppressed(finding, rules, root: Path) -> bool:
    rel = str(Path(finding.file).relative_to(root)) if str(finding.file).startswith(str(root)) else finding.file
    for rule in rules:
        if rule["check"] != finding.check_id:
            continue
        if "glob" in rule and fnmatch.fnmatch(rel, rule["glob"]):
            return True
        if "file" in rule and rule["file"] == rel and str(finding.line) == rule["line"]:
            return True
    return False


def scan_path(root: str | Path, exclude: list[str] | None = None) -> ScanResult:
    """Scan a directory tree (Python + JS/TS files, plus .env/.cfg/.ini/.yaml/.yml for secrets)."""
    root = Path(root)
    excludes = set(DEFAULT_EXCLUDES) | set(exclude or [])
    files: list[Path] = []
    if root.is_file():
        files = [root]
        scan_root = root.parent
    else:
        scan_root = root
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            if any(part in excludes for part in path.parts):
                continue
            if path.suffix in (".py", ".env", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx") or path.name in (".env",) or path.suffix in (".cfg", ".ini", ".yaml", ".yml", ".toml"):
                # Secret checks only apply to non-Python config files; AST checks are .py only.
                files.append(path)
    rules = load_suppressions(scan_root)
    result = ScanResult()
    for path in files:
        findings = scan_file(path)
        for f in findings:
            if _suppressed(f, rules, scan_root):
                result.suppressed += 1
            else:
                result.findings.append(f)
    result.files_scanned = len(files)
    return result
