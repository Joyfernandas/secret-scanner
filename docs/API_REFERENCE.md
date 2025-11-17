# 🔧 API Reference

## Command Line Interface

### Basic Usage
```bash
python secrets_scanner.py <URL> [OPTIONS]
```

### Required Arguments
- `URL` - Target URL to scan (must include protocol: http:// or https://)

### Optional Arguments

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--depth N` | integer | 2 | Crawl depth for same-domain links (0-10) |
| `--output FILE` | string | Results/secret_scanner.json | Output file path |
| `--no-playwright` | flag | False | Disable client-side storage scanning |
| `--min-token-length N` | integer | 30 | Minimum length for base64-like tokens (10-100) |
| `--verbose, -v` | flag | False | Enable verbose logging |
| `--delay N` | float | 0.5 | Delay between requests in seconds (0.1-10.0) |
| `--html-report` | flag | False | Generate HTML report in addition to JSON |
| `--format {json,html,both}` | choice | json | Output format |

### Exit Codes
- `0` - Success
- `1` - Invalid arguments or URL
- `2` - Network/connection errors
- `3` - Permission/access errors

## Python API

### Core Functions

#### `crawl_and_scan(url, **kwargs)`
Main scanning function that performs comprehensive analysis.

**Parameters:**
- `url` (str): Target URL to scan
- `depth` (int, optional): Crawl depth (default: 2)
- `do_playwright` (bool, optional): Enable browser automation (default: True)
- `min_token_length` (int, optional): Minimum token length (default: 30)
- `request_delay` (float, optional): Delay between requests (default: 0.5)

**Returns:**
- `dict`: Complete scan results in JSON format

**Example:**
```python
from secrets_scanner import crawl_and_scan

results = crawl_and_scan(
    url="https://example.com",
    depth=3,
    do_playwright=True,
    min_token_length=25,
    request_delay=1.0
)
```

#### `scan_text_for_patterns(text, source_info, min_token_length=40)`
Scans text content for secret patterns.

**Parameters:**
- `text` (str): Text content to scan
- `source_info` (dict): Source metadata
- `min_token_length` (int, optional): Minimum token length

**Returns:**
- `list`: List of finding dictionaries

**Example:**
```python
from secrets_scanner import scan_text_for_patterns

source = {"type": "test", "url": "https://example.com"}
findings = scan_text_for_patterns(
    "const apiKey = 'sk_test_1234567890abcdef';",
    source,
    min_token_length=20
)
```

#### `generate_html_report(json_data, output_path=None)`
Generates HTML report from scan results.

**Parameters:**
- `json_data` (dict or str): Scan results or path to JSON file
- `output_path` (str, optional): Output HTML file path

**Returns:**
- `str`: Path to generated HTML file

**Example:**
```python
from report_generator import generate_html_report

html_path = generate_html_report(
    scan_results,
    "my_report.html"
)
```

### Utility Functions

#### `fetch_url(url, delay=None)`
Fetches URL content with rate limiting and error handling.

#### `extract_script_urls(html, base_url)`
Extracts JavaScript URLs from HTML content.

#### `is_suspicious_token(s, min_len=40)`
Determines if a string is a suspicious token using heuristics.

#### `get_secret_severity(secret_type)`
Returns severity level for a given secret type.

#### `get_remediation_advice(secret_type)`
Returns remediation advice for a secret type.

## Configuration API

### Pattern Management

#### Adding Custom Patterns
```python
from secrets_scanner import PATTERNS
import re

# Add new pattern
PATTERNS["custom_token"] = re.compile(r"\\bcustom_[A-Za-z0-9]{32}\\b")
```

#### Modifying Exclusions
```python
from config import EXCLUDED_EXTENSIONS, EXCLUDED_CONTENT_TYPES

# Add new exclusions
EXCLUDED_EXTENSIONS.add('.custom')
EXCLUDED_CONTENT_TYPES.add('application/custom')
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SCANNER_TIMEOUT` | Request timeout in seconds | 12 |
| `SCANNER_USER_AGENT` | Custom user agent string | Default UA |
| `SCANNER_MAX_PAGES` | Maximum pages to crawl | 100 |
| `PLAYWRIGHT_BROWSERS_PATH` | Playwright browser path | System default |

## Integration Examples

### CI/CD Integration
```yaml
# GitLab CI example
security_scan:
  script:
    - python secrets_scanner.py $TARGET_URL --format json --output security_scan.json
  artifacts:
    reports:
      security: security_scan.json
```

### Python Script Integration
```python
#!/usr/bin/env python3
import json
from secrets_scanner import crawl_and_scan

def security_scan(url):
    """Perform security scan and return summary."""
    results = crawl_and_scan(url, depth=2)
    
    return {
        'url': url,
        'risk_level': results['risk_assessment']['overall_risk'],
        'total_findings': results['scan_statistics']['total_findings'],
        'high_severity': results['scan_statistics']['high_severity_findings'],
        'recommendations': results['risk_assessment']['recommendations']
    }

# Usage
summary = security_scan("https://example.com")
print(json.dumps(summary, indent=2))
```

### Batch Scanning
```python
import concurrent.futures
from secrets_scanner import crawl_and_scan

def scan_multiple_urls(urls, max_workers=3):
    """Scan multiple URLs concurrently."""
    results = {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {
            executor.submit(crawl_and_scan, url, depth=1): url 
            for url in urls
        }
        
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                results[url] = future.result()
            except Exception as exc:
                results[url] = {'error': str(exc)}
    
    return results
```

## Error Handling

### Common Exceptions
- `requests.exceptions.ConnectionError` - Network connectivity issues
- `requests.exceptions.Timeout` - Request timeout
- `requests.exceptions.SSLError` - SSL certificate problems
- `ValueError` - Invalid input parameters
- `ImportError` - Missing dependencies

### Error Response Format
```json
{
  "error": "Connection timeout",
  "url": "https://example.com",
  "timestamp": "2024-01-15T10:30:00Z",
  "details": {
    "error_type": "timeout",
    "retry_suggested": true
  }
}
```

## Performance Tuning

### Memory Optimization
```python
# For large sites, reduce memory usage
results = crawl_and_scan(
    url="https://large-site.com",
    depth=1,                    # Shallow crawl
    do_playwright=False,        # Skip browser automation
    request_delay=1.0           # Slower requests
)
```

### Speed Optimization
```python
# For faster scanning
results = crawl_and_scan(
    url="https://fast-site.com",
    depth=3,
    do_playwright=True,
    request_delay=0.1,          # Faster requests
    min_token_length=20         # Lower threshold
)
```

## Security Considerations

### Safe Usage Patterns
```python
# Always validate URLs
from urllib.parse import urlparse

def safe_scan(url):
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("Invalid URL")
    
    # Only scan authorized domains
    authorized_domains = ['example.com', 'test.example.com']
    if parsed.netloc not in authorized_domains:
        raise ValueError("Unauthorized domain")
    
    return crawl_and_scan(url)
```

### Result Sanitization
```python
def sanitize_results(results):
    """Remove sensitive data from results before logging."""
    sanitized = results.copy()
    
    # Truncate actual secret values
    for page in sanitized.get('pages', []):
        for finding in page.get('findings', []):
            if len(finding['match']) > 10:
                finding['match'] = finding['match'][:10] + "..."
    
    return sanitized
```

This API reference provides comprehensive guidance for integrating Secret Scanner into various workflows and applications.