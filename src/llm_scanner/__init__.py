"""llm-app-security-scanner: static security checks for LLM/agent repos."""

from .models import Finding, ScanResult
from .scanner import scan_path

__version__ = "0.1.0"
__all__ = ["Finding", "ScanResult", "scan_path"]
