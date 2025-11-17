"""
Secret Scanner - Professional Web Application Security Scanner

A comprehensive tool for detecting exposed secrets, API keys, tokens, and credentials
in web applications including HTML pages, JavaScript files, and client-side storage.
"""

__version__ = "1.0.0"
__author__ = "Secret Scanner Team"
__license__ = "MIT"

from .core.scanner import SecretScanner
from .core.config import ScanConfig
from .core.models import ScanResult, Finding

__all__ = [
    "SecretScanner",
    "ScanConfig", 
    "ScanResult",
    "Finding",
    "__version__"
]