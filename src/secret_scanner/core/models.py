"""Data models for Secret Scanner."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Any
from enum import Enum


class Severity(Enum):
    """Severity levels for findings."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(Enum):
    """Confidence levels for detections."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class RiskLevel(Enum):
    """Overall risk assessment levels."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


@dataclass
class SourceLocation:
    """Location information for a finding."""
    type: str
    url: str
    line: Optional[int] = None
    col: Optional[int] = None
    tag: Optional[str] = None
    attr: Optional[str] = None
    storage: Optional[str] = None
    key: Optional[str] = None


@dataclass
class Finding:
    """Represents a detected secret or credential."""
    id: str
    type: str
    severity: Severity
    description: str
    match: str
    match_length: int
    context: str
    snippet: str
    remediation: str
    confidence: Confidence
    source: SourceLocation
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "id": self.id,
            "type": self.type,
            "severity": self.severity.value,
            "description": self.description,
            "match": self.match,
            "match_length": self.match_length,
            "context": self.context,
            "snippet": self.snippet,
            "remediation": self.remediation,
            "confidence": self.confidence.value,
            "source": {
                "type": self.source.type,
                "url": self.source.url,
                "line": self.source.line,
                "col": self.source.col,
                "tag": self.source.tag,
                "attr": self.source.attr,
                "storage": self.source.storage,
                "key": self.source.key
            },
            "timestamp": self.timestamp.isoformat() + "Z"
        }


@dataclass
class ScanStatistics:
    """Statistics about the scan execution."""
    pages_scanned: int = 0
    js_files_scanned: int = 0
    total_findings: int = 0
    high_severity_findings: int = 0
    medium_severity_findings: int = 0
    low_severity_findings: int = 0
    info_findings: int = 0
    errors_encountered: int = 0

    def to_dict(self) -> Dict[str, int]:
        """Convert statistics to dictionary."""
        return {
            "pages_scanned": self.pages_scanned,
            "js_files_scanned": self.js_files_scanned,
            "total_findings": self.total_findings,
            "high_severity_findings": self.high_severity_findings,
            "medium_severity_findings": self.medium_severity_findings,
            "low_severity_findings": self.low_severity_findings,
            "info_findings": self.info_findings,
            "errors_encountered": self.errors_encountered
        }


@dataclass
class RiskAssessment:
    """Risk assessment for the scan results."""
    overall_risk: RiskLevel
    critical_findings: int
    total_secrets_found: int
    unique_secret_types: int
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert risk assessment to dictionary."""
        return {
            "overall_risk": self.overall_risk.value,
            "critical_findings": self.critical_findings,
            "total_secrets_found": self.total_secrets_found,
            "unique_secret_types": self.unique_secret_types,
            "recommendations": self.recommendations
        }


@dataclass
class ScanInfo:
    """Information about the scan execution."""
    target_url: str
    scan_id: str
    scanned_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    scanner_version: str = "1.0.0"
    scan_parameters: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert scan info to dictionary."""
        return {
            "target_url": self.target_url,
            "scan_id": self.scan_id,
            "scanned_at": self.scanned_at.isoformat() + "Z",
            "completed_at": self.completed_at.isoformat() + "Z" if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "scanner_version": self.scanner_version,
            "scan_parameters": self.scan_parameters
        }


@dataclass
class ScanResult:
    """Complete scan result containing all findings and metadata."""
    scan_info: ScanInfo
    scan_statistics: ScanStatistics
    risk_assessment: RiskAssessment
    findings: List[Finding] = field(default_factory=list)
    pages: List[Dict[str, Any]] = field(default_factory=list)
    js_files: List[Dict[str, Any]] = field(default_factory=list)
    client_storage: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary."""
        # Calculate summary
        summary = {}
        for finding in self.findings:
            summary[finding.type] = summary.get(finding.type, 0) + 1

        return {
            "scan_info": self.scan_info.to_dict(),
            "scan_statistics": self.scan_statistics.to_dict(),
            "risk_assessment": self.risk_assessment.to_dict(),
            "summary": summary,
            "pages": self.pages,
            "js_files": self.js_files,
            "client_storage": self.client_storage,
            # Legacy fields for backward compatibility
            "url": self.scan_info.target_url,
            "scanned_at": self.scan_info.scanned_at.isoformat() + "Z"
        }