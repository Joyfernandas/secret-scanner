"""Main scanner class for Secret Scanner."""

import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import time

from .models import ScanResult, ScanInfo, ScanStatistics, RiskAssessment, RiskLevel, Finding
from .config import ScanConfig
from ..detectors.pattern_detector import PatternDetector
from ..detectors.base64_detector import Base64Detector
from ..utils.network_utils import fetch_url_with_retry
from ..utils.file_utils import ensure_directory_exists


class SecretScanner:
    """Main scanner class for detecting secrets in web applications."""
    
    def __init__(self, config: Optional[ScanConfig] = None):
        """Initialize scanner with configuration."""
        self.config = config or ScanConfig()
        self.logger = self._setup_logging()
        self.pattern_detector = PatternDetector()
        self.base64_detector = Base64Detector(self.config.min_token_length)
        
        # Scan state
        self._visited_urls = set()
        self._all_findings = []
        self._scan_start_time = None
    
    def scan(self, target_url: str) -> ScanResult:
        """Perform comprehensive scan of target URL."""
        self.logger.info(f"Starting scan of {target_url}")
        self._scan_start_time = datetime.now(timezone.utc)
        
        # Validate URL
        self._validate_url(target_url)
        
        # Initialize scan result
        scan_info = ScanInfo(
            target_url=target_url,
            scan_id=f"scan_{int(self._scan_start_time.timestamp())}",
            scanned_at=self._scan_start_time,
            scan_parameters=self.config.to_dict()
        )
        
        scan_result = ScanResult(
            scan_info=scan_info,
            scan_statistics=ScanStatistics(),
            risk_assessment=RiskAssessment(
                overall_risk=RiskLevel.NONE,
                critical_findings=0,
                total_secrets_found=0,
                unique_secret_types=0
            )
        )
        
        try:
            # Perform scanning
            self._crawl_and_scan(target_url, scan_result)
            
            # Finalize scan
            self._finalize_scan(scan_result)
            
            self.logger.info(f"Scan completed. Found {len(self._all_findings)} secrets.")
            return scan_result
            
        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}")
            scan_result.scan_statistics.errors_encountered += 1
            raise
    
    def _validate_url(self, url: str) -> None:
        """Validate target URL."""
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError("Invalid URL: missing scheme or netloc")
        except Exception as e:
            raise ValueError(f"Invalid URL: {str(e)}")
    
    def _crawl_and_scan(self, target_url: str, scan_result: ScanResult) -> None:
        """Crawl website and scan for secrets."""
        to_visit = [(target_url, 0)]
        base_domain = urlparse(target_url).netloc
        
        while to_visit and len(self._visited_urls) < self.config.max_pages:
            current_url, depth = to_visit.pop(0)
            
            if current_url in self._visited_urls or depth > self.config.depth:
                continue
            
            self._visited_urls.add(current_url)
            self.logger.debug(f"Scanning URL: {current_url} (depth: {depth})")
            
            # Add delay between requests
            if self.config.request_delay > 0:
                time.sleep(self.config.request_delay)
            
            try:
                # Fetch and scan page
                page_data = self._scan_page(current_url)
                scan_result.pages.append(page_data)
                scan_result.scan_statistics.pages_scanned += 1
                
                # Extract and queue new URLs
                if depth < self.config.depth:
                    new_urls = self._extract_urls(page_data.get('content', ''), current_url, base_domain)
                    for new_url in new_urls:
                        if new_url not in self._visited_urls:
                            to_visit.append((new_url, depth + 1))
                
            except Exception as e:
                self.logger.warning(f"Error scanning {current_url}: {str(e)}")
                scan_result.scan_statistics.errors_encountered += 1
        
        # Scan JavaScript files
        self._scan_javascript_files(scan_result)
        
        # Scan client-side storage if enabled
        if self.config.enable_playwright:
            self._scan_client_storage(target_url, scan_result)
    
    def _scan_page(self, url: str) -> Dict[str, Any]:
        """Scan a single page for secrets."""
        response = fetch_url_with_retry(url, self.config)
        
        page_data = {
            "url": url,
            "status": response.get("status"),
            "headers": response.get("headers", {}),
            "content": response.get("content", ""),
            "findings": [],
            "scripts": []
        }
        
        if response.get("content"):
            # Scan page content
            source_info = {"type": "page", "url": url}
            findings = self._detect_secrets(response["content"], source_info)
            page_data["findings"] = [f.to_dict() for f in findings]
            self._all_findings.extend(findings)
            
            # Extract script references
            page_data["scripts"] = self._extract_scripts(response["content"], url)
        
        return page_data
    
    def _detect_secrets(self, text: str, source_info: Dict[str, Any]) -> List[Finding]:
        """Detect secrets in text using all available detectors."""
        findings = []
        
        # Pattern-based detection
        pattern_findings = self.pattern_detector.detect(text, source_info)
        findings.extend(pattern_findings)
        
        # Base64 detection
        base64_findings = self.base64_detector.detect(text, source_info)
        findings.extend(base64_findings)
        
        return findings
    
    def _extract_scripts(self, html: str, base_url: str) -> List[Dict[str, Any]]:
        """Extract script references from HTML."""
        # Implementation would use BeautifulSoup to extract scripts
        # Simplified for brevity
        return []
    
    def _extract_urls(self, html: str, base_url: str, base_domain: str) -> List[str]:
        """Extract URLs from HTML content."""
        # Implementation would use BeautifulSoup to extract links
        # Simplified for brevity
        return []
    
    def _scan_javascript_files(self, scan_result: ScanResult) -> None:
        """Scan JavaScript files for secrets."""
        # Implementation would scan JS files found in pages
        pass
    
    def _scan_client_storage(self, target_url: str, scan_result: ScanResult) -> None:
        """Scan client-side storage using Playwright."""
        # Implementation would use Playwright to inspect storage
        pass
    
    def _finalize_scan(self, scan_result: ScanResult) -> None:
        """Finalize scan results and calculate statistics."""
        scan_end_time = datetime.now(timezone.utc)
        scan_result.scan_info.completed_at = scan_end_time
        scan_result.scan_info.duration_seconds = (scan_end_time - self._scan_start_time).total_seconds()
        
        # Update statistics
        self._update_statistics(scan_result)
        
        # Calculate risk assessment
        self._calculate_risk_assessment(scan_result)
    
    def _update_statistics(self, scan_result: ScanResult) -> None:
        """Update scan statistics based on findings."""
        stats = scan_result.scan_statistics
        stats.total_findings = len(self._all_findings)
        
        for finding in self._all_findings:
            if finding.severity.value == "HIGH":
                stats.high_severity_findings += 1
            elif finding.severity.value == "MEDIUM":
                stats.medium_severity_findings += 1
            elif finding.severity.value == "LOW":
                stats.low_severity_findings += 1
            else:
                stats.info_findings += 1
    
    def _calculate_risk_assessment(self, scan_result: ScanResult) -> None:
        """Calculate overall risk assessment."""
        stats = scan_result.scan_statistics
        risk = scan_result.risk_assessment
        
        risk.critical_findings = stats.high_severity_findings
        risk.total_secrets_found = stats.total_findings
        risk.unique_secret_types = len(set(f.type for f in self._all_findings))
        
        # Determine overall risk level
        if stats.high_severity_findings > 0:
            risk.overall_risk = RiskLevel.HIGH
        elif stats.medium_severity_findings > 0:
            risk.overall_risk = RiskLevel.MEDIUM
        elif stats.total_findings > 0:
            risk.overall_risk = RiskLevel.LOW
        else:
            risk.overall_risk = RiskLevel.NONE
        
        # Generate recommendations
        risk.recommendations = self._generate_recommendations(stats)
    
    def _generate_recommendations(self, stats: ScanStatistics) -> List[str]:
        """Generate actionable recommendations based on findings."""
        recommendations = []
        
        if stats.high_severity_findings > 0:
            recommendations.append("URGENT: High-severity credentials detected. Rotate immediately.")
        
        # Check for specific types in findings
        finding_types = set(f.type for f in self._all_findings)
        
        if any("aws" in t for t in finding_types):
            recommendations.append("AWS credentials found. Check CloudTrail for unauthorized access.")
        
        if any("jwt" in t for t in finding_types):
            recommendations.append("JWT tokens detected. Verify token expiration and scope.")
        
        if any("github" in t for t in finding_types):
            recommendations.append("GitHub tokens found. Review repository access permissions.")
        
        if stats.total_findings > 10:
            recommendations.append("Multiple secrets detected. Implement secrets scanning in CI/CD.")
        
        if recommendations:
            recommendations.append("Review all findings and implement proper secrets management.")
        else:
            recommendations.append("No secrets detected. Continue monitoring for exposed credentials.")
        
        return recommendations
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration."""
        logger = logging.getLogger(__name__)
        
        if not logger.handlers:
            level = logging.DEBUG if self.config.verbose_logging else logging.INFO
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(level)
        
        return logger