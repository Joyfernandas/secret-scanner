"""Configuration management for Secret Scanner."""

from dataclasses import dataclass, field
from typing import Dict, Set, List
import re


@dataclass
class ScanConfig:
    """Configuration for scan execution."""
    
    # Scanning parameters
    depth: int = 2
    min_token_length: int = 30
    request_delay: float = 0.5
    timeout: int = 12
    max_pages: int = 100
    
    # Feature flags
    enable_playwright: bool = True
    enable_html_report: bool = False
    verbose_logging: bool = False
    
    # Output configuration
    output_format: str = "json"  # json, html, both
    output_path: str = "Results/secret_scanner.json"
    
    # Network configuration
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 SecretScanner/1.0"
    verify_ssl: bool = True
    
    # Exclusions
    excluded_extensions: Set[str] = field(default_factory=lambda: {
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.zip', '.rar', '.tar', '.gz', '.7z',
        '.mp3', '.mp4', '.avi', '.mov', '.wmv',
        '.exe', '.dll', '.so', '.dylib'
    })
    
    excluded_content_types: Set[str] = field(default_factory=lambda: {
        'image/', 'video/', 'audio/', 'application/pdf',
        'application/zip', 'application/octet-stream'
    })
    
    # Patterns to ignore (reduce false positives)
    ignore_patterns: List[str] = field(default_factory=lambda: [
        r'^[0-9]+$',  # Pure numbers
        r'^[a-f0-9]{32}$',  # MD5 hashes
        r'^[a-f0-9]{40}$',  # SHA1 hashes
        r'^[a-f0-9]{64}$',  # SHA256 hashes
    ])

    def to_dict(self) -> Dict:
        """Convert config to dictionary."""
        return {
            "depth": self.depth,
            "playwright_enabled": self.enable_playwright,
            "min_token_length": self.min_token_length,
            "request_delay": self.request_delay
        }


# Secret detection patterns
SECRET_PATTERNS = {
    # Authentication tokens
    "bearer_token_header": re.compile(r"Bearer\s+([A-Za-z0-9\-\._~\+/]+=*)", re.I),
    "jwt_like": re.compile(r"\beyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z\-_]{10,}\.[0-9A-Za-z\-_]{10,}\b"),
    "basic_auth_inline": re.compile(r"https?://[^:@\s]+:[^@\s]+@"),
    "bearer_in_url": re.compile(r"(?:access_token|token|bearer)=([A-Za-z0-9\-_\.]+)", re.I),
    
    # AWS credentials
    "aws_access_key": re.compile(r"\b(AKIA|ASIA|A3T|AGPA)[A-Z0-9]{16}\b"),
    "aws_secret_key_like": re.compile(r"(?i)aws(.{0,20})?(secret|key|secretaccesskey).{0,20}([A-Za-z0-9/+]{40,})"),
    "aws_session_token": re.compile(r"(?i)(aws.{0,20})?session.{0,20}token.{0,20}([A-Za-z0-9/+=]{100,})"),
    
    # Cloud provider keys
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "google_oauth_key": re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    "azure_client_secret": re.compile(r"\b[A-Za-z0-9~._-]{34}\b"),
    
    # Payment processors
    "stripe_secret": re.compile(r"\b(sk_live|sk_test)_[0-9a-zA-Z]{24,}\b"),
    "stripe_publishable": re.compile(r"\b(pk_live|pk_test)_[0-9a-zA-Z]{24,}\b"),
    "paypal_client_id": re.compile(r"\bA[A-Za-z0-9_-]{79}\b"),
    
    # Communication platforms
    "slack_token": re.compile(r"xox[baprs]-[0-9A-Za-z-]+"),
    "discord_token": re.compile(r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}"),
    "telegram_bot_token": re.compile(r"\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b"),
    
    # Version control
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b"),
    "github_classic_token": re.compile(r"\bghp_[A-Za-z0-9_]{36}\b"),
    "gitlab_token": re.compile(r"\bglpat-[A-Za-z0-9_-]{20}\b"),
    
    # Database connections
    "mongodb_uri": re.compile(r"mongodb://[^\s]+:[^\s]+@[^\s]+"),
    "postgres_uri": re.compile(r"postgres://[^\s]+:[^\s]+@[^\s]+"),
    "mysql_uri": re.compile(r"mysql://[^\s]+:[^\s]+@[^\s]+"),
    
    # Generic patterns
    "generic_key": re.compile(r"(?i)(api[_-]?key|apikey|secret|client_secret|access_token|auth_token|password|passwd|token)[\"'\s:=]{1,5}([A-Za-z0-9\-_=+./]{8,200})"),
    "password_param": re.compile(r"password=([^&\s]+)", re.I),
    "private_key": re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----"),
    "ssh_private_key": re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----"),
}

# Base64-like pattern for fallback detection
BASE64_PATTERN = re.compile(r"\b[A-Za-z0-9\-_+/=]{32,}\b")

# I18N key suffixes to ignore
I18N_SUFFIXES = ("_label", "_message", "_title", "_placeholder", "_text", "_noData", "_error")