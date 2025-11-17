#!/usr/bin/env python3
"""
Configuration settings for Secret Scanner
"""

# Request settings
DEFAULT_TIMEOUT = 12
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 SecretScanner/1.0"

# Scanning settings
DEFAULT_DEPTH = 2
DEFAULT_MIN_TOKEN_LENGTH = 30
MAX_CRAWL_PAGES = 100  # Safety limit

# Playwright settings
PLAYWRIGHT_TIMEOUT = 20000
PLAYWRIGHT_HEADLESS = True

# Output settings
DEFAULT_OUTPUT_DIR = "Results"
DEFAULT_OUTPUT_FILE = "secret_scanner.json"

# Rate limiting
REQUEST_DELAY = 0.5  # Seconds between requests
MAX_RETRIES = 3

# File size limits (in bytes)
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
MAX_RESPONSE_SIZE = 5 * 1024 * 1024  # 5MB

# Exclusions
EXCLUDED_EXTENSIONS = {
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.rar', '.tar', '.gz', '.7z',
    '.mp3', '.mp4', '.avi', '.mov', '.wmv',
    '.exe', '.dll', '.so', '.dylib'
}

EXCLUDED_CONTENT_TYPES = {
    'image/', 'video/', 'audio/', 'application/pdf',
    'application/zip', 'application/octet-stream'
}

# Patterns to ignore (reduce false positives)
IGNORE_PATTERNS = [
    r'^[0-9]+$',  # Pure numbers
    r'^[a-f0-9]{32}$',  # MD5 hashes
    r'^[a-f0-9]{40}$',  # SHA1 hashes
    r'^[a-f0-9]{64}$',  # SHA256 hashes
]