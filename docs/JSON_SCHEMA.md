# 📋 JSON Output Schema Documentation

## Overview
Secret Scanner generates structured JSON output with comprehensive metadata, risk assessment, and actionable findings. This document describes the complete schema and field definitions.

## Root Schema Structure

```json
{
  "scan_info": { ... },           // Scan metadata and parameters
  "scan_statistics": { ... },     // Numerical scan statistics
  "risk_assessment": { ... },     // Risk analysis and recommendations
  "summary": { ... },             // Finding counts by type
  "pages": [ ... ],               // Page-level findings
  "js_files": [ ... ],            // JavaScript file findings
  "client_storage": { ... },      // Client-side storage findings
  "url": "string",                // Target URL (legacy)
  "scanned_at": "ISO8601"         // Scan timestamp (legacy)
}
```

## Detailed Field Definitions

### 📊 scan_info
Contains metadata about the scan execution.

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `target_url` | string | The primary URL that was scanned | `"https://example.com"` |
| `scan_id` | string | Unique identifier for this scan | `"scan_1705312200"` |
| `scanned_at` | ISO8601 | When the scan started | `"2024-01-15T10:30:00.000Z"` |
| `completed_at` | ISO8601 | When the scan finished | `"2024-01-15T10:35:45.123Z"` |
| `duration_seconds` | number | Total scan duration | `345.123` |
| `scanner_version` | string | Version of the scanner used | `"1.0.0"` |
| `scan_parameters` | object | Configuration used for the scan | See below |

#### scan_parameters Object
```json
{
  "depth": 3,                     // Crawl depth setting
  "playwright_enabled": true,     // Whether browser automation was used
  "min_token_length": 30,         // Minimum token length for detection
  "request_delay": 0.5            // Delay between requests in seconds
}
```

### 📈 scan_statistics
Numerical summary of scan results.

| Field | Type | Description |
|-------|------|-------------|
| `pages_scanned` | integer | Number of HTML pages analyzed |
| `js_files_scanned` | integer | Number of JavaScript files analyzed |
| `total_findings` | integer | Total number of secrets found |
| `high_severity_findings` | integer | Count of HIGH severity findings |
| `medium_severity_findings` | integer | Count of MEDIUM severity findings |
| `low_severity_findings` | integer | Count of LOW severity findings |
| `info_findings` | integer | Count of INFO level findings |
| `errors_encountered` | integer | Number of errors during scanning |

### 🎯 risk_assessment
Risk analysis and actionable recommendations.

| Field | Type | Description |
|-------|------|-------------|
| `overall_risk` | enum | Overall risk level: `"HIGH"`, `"MEDIUM"`, `"LOW"`, `"NONE"` |
| `critical_findings` | integer | Number of critical/high-severity findings |
| `total_secrets_found` | integer | Total secrets detected |
| `unique_secret_types` | integer | Number of different secret types found |
| `recommendations` | array[string] | Actionable recommendations for remediation |

### 📋 summary
Count of findings by secret type.

```json
{
  "aws_access_key": 2,
  "jwt_like": 3,
  "github_token": 1,
  "stripe_secret": 2,
  "base64_like": 1
}
```

### 📄 pages Array
Each page object contains:

| Field | Type | Description |
|-------|------|-------------|
| `url` | string | Page URL |
| `status` | integer | HTTP status code |
| `headers` | object | HTTP response headers |
| `findings` | array[Finding] | Secrets found on this page |
| `scripts` | array[Script] | JavaScript references found |

#### Script Object
```json
{
  "type": "external|inline",      // Script type
  "src": "string",                // URL for external scripts
  "content_snippet": "string"    // Preview for inline scripts
}
```

### 📜 js_files Array
Each JavaScript file object contains:

| Field | Type | Description |
|-------|------|-------------|
| `url` | string | JavaScript file URL |
| `status` | integer | HTTP status code |
| `headers` | object | HTTP response headers |
| `findings` | array[Finding] | Secrets found in this file |

### 💾 client_storage Object
Client-side storage analysis results.

| Field | Type | Description |
|-------|------|-------------|
| `cookies` | array[Cookie] | Browser cookies |
| `localStorage` | object | localStorage key-value pairs |
| `sessionStorage` | object | sessionStorage key-value pairs |
| `localStorage_findings` | array[Finding] | Secrets in localStorage |
| `sessionStorage_findings` | array[Finding] | Secrets in sessionStorage |
| `indexedDB` | array | IndexedDB database names |
| `indexedDB_error` | string | Error message if IndexedDB scan failed |

#### Cookie Object
```json
{
  "name": "string",               // Cookie name
  "value": "string",              // Cookie value
  "domain": "string",             // Cookie domain
  "path": "string",               // Cookie path
  "secure": boolean,              // Secure flag
  "httpOnly": boolean             // HttpOnly flag
}
```

## Finding Object Schema

Each finding (secret detection) contains comprehensive metadata:

### Core Fields
| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `id` | string | Unique finding identifier | `"aws_access_key_1234"` |
| `type` | string | Secret pattern type | `"aws_access_key"` |
| `severity` | enum | Risk level | `"HIGH"`, `"MEDIUM"`, `"LOW"`, `"INFO"` |
| `description` | string | Human-readable explanation | `"AWS Access Key - Provides access to AWS services"` |

### Detection Details
| Field | Type | Description |
|-------|------|-------------|
| `match` | string | The detected secret (truncated for security) |
| `match_length` | integer | Full length of the detected secret |
| `context` | string | Surrounding text for context |
| `snippet` | string | Code snippet showing the finding |
| `confidence` | enum | Detection confidence: `"HIGH"`, `"MEDIUM"`, `"LOW"` |

### Remediation
| Field | Type | Description |
|-------|------|-------------|
| `remediation` | string | Specific steps to fix the issue |

### Location Information
| Field | Type | Description |
|-------|------|-------------|
| `source` | object | Detailed location information |
| `timestamp` | ISO8601 | When this finding was detected |

#### Source Object
```json
{
  "type": "page|js|html-attr|client-storage|inline-js",
  "url": "string",                // Source URL
  "line": integer,                // Line number (if applicable)
  "col": integer,                 // Column number (if applicable)
  "tag": "string",                // HTML tag (for html-attr type)
  "attr": "string",               // HTML attribute (for html-attr type)
  "storage": "localStorage|sessionStorage", // Storage type (for client-storage)
  "key": "string"                 // Storage key (for client-storage)
}
```

## Secret Types and Severity Levels

### High Severity Secrets
- `aws_access_key` - AWS Access Keys
- `aws_secret_key_like` - AWS Secret Keys
- `private_key` - Private cryptographic keys
- `ssh_private_key` - SSH private keys

### Medium Severity Secrets
- `jwt_like` - JSON Web Tokens
- `github_token` - GitHub Personal Access Tokens
- `stripe_secret` - Stripe API keys
- `google_api_key` - Google API keys
- `slack_token` - Slack tokens
- `discord_token` - Discord tokens

### Low Severity Secrets
- `bearer_token_header` - Bearer tokens in headers
- `basic_auth_inline` - Basic auth in URLs
- `generic_key` - Generic API keys

### Info Level
- `base64_like` - Suspicious base64-encoded strings

## Usage Examples

### Parsing Risk Assessment
```python
import json

with open('scan_results.json', 'r') as f:
    data = json.load(f)

risk_level = data['risk_assessment']['overall_risk']
critical_count = data['risk_assessment']['critical_findings']
recommendations = data['risk_assessment']['recommendations']

print(f"Risk Level: {risk_level}")
print(f"Critical Issues: {critical_count}")
for rec in recommendations:
    print(f"- {rec}")
```

### Filtering High Severity Findings
```python
high_severity_findings = []

# Check all sources for high severity findings
for page in data['pages']:
    for finding in page['findings']:
        if finding['severity'] == 'HIGH':
            high_severity_findings.append(finding)

for js_file in data['js_files']:
    for finding in js_file['findings']:
        if finding['severity'] == 'HIGH':
            high_severity_findings.append(finding)

# Check client storage
for finding in data['client_storage'].get('localStorage_findings', []):
    if finding['severity'] == 'HIGH':
        high_severity_findings.append(finding)
```

### Generating Summary Report
```python
def generate_summary(scan_data):
    stats = scan_data['scan_statistics']
    risk = scan_data['risk_assessment']
    
    return {
        'scan_duration': scan_data['scan_info']['duration_seconds'],
        'pages_analyzed': stats['pages_scanned'],
        'total_secrets': stats['total_findings'],
        'risk_level': risk['overall_risk'],
        'needs_immediate_attention': stats['high_severity_findings'] > 0
    }
```

This schema provides a comprehensive structure for automated processing, reporting, and integration with security tools and workflows.