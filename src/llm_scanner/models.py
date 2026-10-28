from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Finding:
    """One scanner finding. Severity is impact; confidence is how sure the check is.

    The CI gate fails by default only on high severity + high confidence,
    so a heuristic medium/low finding does not block every merge.
    """

    check_id: str
    severity: str  # high | medium | low
    confidence: str  # high | medium | low
    file: str
    line: int
    message: str
    snippet: str = ""

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "file": self.file,
            "line": self.line,
            "message": self.message,
            "snippet": self.snippet,
        }


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    suppressed: int = 0

    def gate_failures(self, fail_on: str = "high") -> list[Finding]:
        """Findings that fail the gate. ``fail_on`` is the minimum severity
        that counts, but only high-confidence findings count by default:
        pass ``fail_on="medium"`` with ``require_high_confidence=False``
        via the CLI only if you accept more false positives."""
        order = {"low": 0, "medium": 1, "high": 2}
        threshold = order.get(fail_on, 2)
        return [
            f
            for f in self.findings
            if order.get(f.severity, 0) >= threshold and f.confidence == "high"
        ]
