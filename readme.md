# 🔍 Secret Scanner

[![GitLab CI](https://gitlab.com/Joyfernandas/secret-scanner/badges/main/pipeline.svg)](https://gitlab.com/Joyfernandas/secret-scanner/-/pipelines)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)

A comprehensive web application security scanner that detects exposed secrets, API keys, tokens, and credentials in web applications. Scan websites directly from your browser using GitLab Codespaces!

## 🚀 Quick Start with GitLab Codespaces

### Option 1: One-Click Launch
[![Open in GitLab Codespaces](https://img.shields.io/badge/GitLab-Codespaces-orange?logo=gitlab)](https://gitlab.com/Joyfernandas/secret-scanner/-/tree/main?vscode=true)

1. Click the "Open in GitLab Codespaces" button above
2. Wait for the environment to load (2-3 minutes)
3. Open the integrated terminal
4. Run your first scan:
   ```bash
   python secrets_scanner.py https://httpbin.org/html --depth 1
   ```

### Option 2: Manual Setup in Codespaces
1. Go to your GitLab project
2. Click **Web IDE** → **VS Code for the Web**
3. Open terminal and run:
   ```bash
   # Install dependencies
   pip install -r requirements.txt
   
   # Optional: Install Playwright for client-side scanning
   pip install playwright
   playwright install chromium
   
   # Run a test scan
   python secrets_scanner.py https://example.com --depth 2 --html-report
   ```

## 🌟 Features

- **🔍 Multi-source scanning**: HTML pages, JavaScript files, and client-side storage
- **🎯 Pattern-based detection**: 25+ secret types including AWS keys, JWT tokens, API keys
- **🌐 Client-side analysis**: Uses Playwright to inspect localStorage, sessionStorage, and cookies
- **🕷️ Smart crawling**: Recursively scans linked pages within the same domain
- **📊 Detailed reporting**: JSON and HTML reports with risk assessment
- **⚡ Real-time results**: Live feedback during scanning process
- **🛡️ Ethical scanning**: Built-in rate limiting and respectful crawling

## 🔐 Supported Secret Types

| Category | Secret Types |
|----------|-------------|
| **Cloud Providers** | AWS Access Keys, Google API Keys, Azure Client Secrets |
| **Version Control** | GitHub Tokens, GitLab Tokens |
| **Payment** | Stripe Keys, PayPal Client IDs |
| **Communication** | Slack Tokens, Discord Tokens, Telegram Bot Tokens |
| **Authentication** | JWT Tokens, Bearer Tokens, Basic Auth |
| **Databases** | MongoDB URIs, PostgreSQL URIs, MySQL URIs |
| **Cryptographic** | Private Keys, SSH Keys |
| **Generic** | API Keys, Secrets, Base64-encoded strings |

## 📋 Installation

### Local Installation
```bash
# Clone the repository
git clone https://gitlab.com/Joyfernandas/secret-scanner.git
cd secret-scanner

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Optional: Install Playwright for enhanced scanning
pip install playwright
playwright install chromium

# Verify installation
python test_installation.py
```

### Docker Installation
```bash
# Build the image
docker build -t secret-scanner .

# Run a scan
docker run --rm secret-scanner https://example.com
```

## 🎮 Usage Examples

### Basic Scanning
```bash
# Simple scan
python secrets_scanner.py https://example.com

# Deep scan with custom depth
python secrets_scanner.py https://example.com --depth 5

# Quick scan without client-side analysis
python secrets_scanner.py https://example.com --no-playwright --depth 1
```

### Advanced Options
```bash
# Generate HTML report
python secrets_scanner.py https://example.com --html-report

# Verbose logging with custom output
python secrets_scanner.py https://example.com --verbose --output my_scan.json

# Both JSON and HTML reports
python secrets_scanner.py https://example.com --format both

# Custom token detection threshold
python secrets_scanner.py https://example.com --min-token-length 20

# Slower scanning for rate-limited sites
python secrets_scanner.py https://example.com --delay 2.0
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `url` | Target URL to scan (required) | - |
| `--depth N` | Crawl depth for same-domain links | 2 |
| `--output FILE` | Output file path | Results/secret_scanner.json |
| `--no-playwright` | Disable client-side storage scanning | False |
| `--min-token-length N` | Minimum length for base64-like tokens | 30 |
| `--verbose, -v` | Enable verbose logging | False |
| `--delay N` | Delay between requests in seconds | 0.5 |
| `--html-report` | Generate HTML report in addition to JSON | False |
| `--format {json,html,both}` | Output format | json |

## 📊 Output Formats

### Enhanced JSON Report
```json
{
  "scan_info": {
    "target_url": "https://example.com",
    "scan_id": "scan_1705312200",
    "scanned_at": "2024-01-15T10:30:00Z",
    "completed_at": "2024-01-15T10:32:15Z",
    "duration_seconds": 135.4,
    "scanner_version": "1.0.0"
  },
  "scan_statistics": {
    "pages_scanned": 5,
    "js_files_scanned": 3,
    "total_findings": 8,
    "high_severity_findings": 2,
    "medium_severity_findings": 4,
    "low_severity_findings": 2
  },
  "risk_assessment": {
    "overall_risk": "HIGH",
    "critical_findings": 2,
    "total_secrets_found": 8,
    "recommendations": [
      "URGENT: High-severity credentials detected. Rotate immediately.",
      "AWS credentials found. Check CloudTrail for unauthorized access."
    ]
  }
}
```

### Interactive HTML Report
- 📊 Visual risk assessment dashboard
- 📑 Tabbed interface for different finding types
- 🔧 Detailed remediation guidance
- 🎨 Color-coded severity levels
- 📤 Exportable format for sharing

### Finding Details
Each finding includes comprehensive metadata:
- **🆔 ID**: Unique identifier
- **🏷️ Type**: Pattern type that matched
- **⚠️ Severity**: Risk level (HIGH/MEDIUM/LOW/INFO)
- **📝 Description**: Human-readable explanation
- **🔍 Match**: The detected secret (truncated for security)
- **🔧 Remediation**: Specific steps to fix the issue
- **🎯 Confidence**: Detection confidence level
- **📍 Location**: File, line, and column information
- **⏰ Timestamp**: When the finding was detected

## 🛠️ GitLab Integration

### GitLab CI/CD Pipeline
The project includes a comprehensive `.gitlab-ci.yml` for automated testing:

```yaml
stages:
  - test
  - security
  - deploy

test:
  stage: test
  image: python:3.9
  script:
    - pip install -r requirements.txt
    - python test_installation.py
    - python secrets_scanner.py --help

security_scan:
  stage: security
  image: python:3.9
  script:
    - pip install bandit safety
    - bandit -r . -f json -o bandit-report.json || true
    - safety check --json --output safety-report.json || true
  artifacts:
    reports:
      security: bandit-report.json
    paths:
      - bandit-report.json
      - safety-report.json
    expire_in: 1 week
```

### GitLab Codespaces Configuration
The repository includes `.devcontainer/devcontainer.json` for seamless Codespaces integration:

```json
{
  "name": "Secret Scanner",
  "image": "python:3.9",
  "features": {
    "ghcr.io/devcontainers/features/common-utils:2": {},
    "ghcr.io/devcontainers/features/python:1": {}
  },
  "postCreateCommand": "pip install -r requirements.txt && pip install playwright && playwright install chromium",
  "customizations": {
    "vscode": {
      "extensions": [
        "ms-python.python",
        "ms-python.flake8"
      ]
    }
  }
}
```

## 🔒 Security & Ethics

### ⚠️ Ethical Use Policy
This tool is intended for **authorized security testing only**:

- ✅ Only scan systems you own or have explicit written permission to test
- ✅ Follow all applicable laws and regulations
- ✅ Respect robots.txt and rate limits
- ✅ Use findings responsibly with coordinated disclosure
- ❌ Do not use for malicious purposes
- ❌ Do not scan systems without permission

### 🛡️ Built-in Safety Features
- **Rate Limiting**: Configurable delays between requests
- **Respectful Crawling**: Honors robots.txt and server responses
- **SSL Verification**: Proper certificate validation
- **Error Handling**: Graceful failure handling
- **Content Filtering**: Skips binary and irrelevant files

## 🚨 What to Do If You Find Secrets

1. **🛑 Stop**: Don't share or publish the secrets
2. **🔒 Secure**: Store findings securely and limit access
3. **📞 Contact**: Reach out to the affected organization
4. **⏰ Timeline**: Follow responsible disclosure (typically 90 days)
5. **📋 Document**: Provide clear, actionable information
6. **🔄 Follow-up**: Verify remediation

## 🔧 Troubleshooting

### Timeout Errors in Codespaces
If you encounter connection timeout errors in GitLab Codespaces:

```bash
# The scanner now includes automatic retry logic with increased timeouts
# If issues persist, try these options:

# 1. Increase delay between requests
python secrets_scanner.py https://example.com --delay 2.0

# 2. Reduce crawl depth
python secrets_scanner.py https://example.com --depth 1

# 3. Disable Playwright for faster scanning
python secrets_scanner.py https://example.com --no-playwright

# 4. Test with a reliable site first
python secrets_scanner.py https://httpbin.org/html --depth 1
```

### Common Issues

**Issue**: `playwright not available`
**Solution**: Install Playwright: `pip install playwright && playwright install chromium`

**Issue**: Connection timeouts
**Solution**: The scanner now retries failed requests automatically (3 attempts with exponential backoff)

**Issue**: SSL certificate errors
**Solution**: Ensure the target site has valid SSL certificates

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup
```bash
# Clone and setup
git clone https://gitlab.com/Joyfernandas/secret-scanner.git
cd secret-scanner

# Setup development environmentnment
make setup-dev

# Run tests
make test

# Run linting
make lint
```

### Adding New Secret Patterns
```python
# Add to PATTERNS dictionary in secrets_scanner.py
"new_service_token": re.compile(r"\\bnst_[A-Za-z0-9]{32}\\b"),
```

## 📈 Performance Tips

- **Adjust depth**: Use `--depth 1` for quick scans
- **Skip Playwright**: Use `--no-playwright` for faster scanning
- **Increase delays**: Use `--delay 1.0` for rate-limited sites
- **Filter results**: Adjust `--min-token-length` to reduce false positives

## 🐛 Troubleshooting

### Common Issues

**Playwright Installation**
```bash
pip install playwright
playwright install chromium
```

**SSL Certificate Errors**
```bash
# Skip SSL verification (not recommended for production)
python secrets_scanner.py https://example.com --no-ssl-verify
```

**Memory Issues with Large Sites**
```bash
# Reduce depth and enable delays
python secrets_scanner.py https://example.com --depth 1 --delay 1.0
```

## 📚 Documentation

- [Installation Guide](docs/installation.md)
- [Usage Examples](docs/examples.md)
- [API Reference](docs/api.md)
- [Contributing Guide](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)

## 🏷️ Versioning

We use [Semantic Versioning](https://semver.org/). See [CHANGELOG.md](CHANGELOG.md) for release history.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [OWASP](https://owasp.org/) for security best practices
- [Playwright](https://playwright.dev/) for browser automation
- [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/) for HTML parsing
- The security research community for pattern contributions

## 📞 Support

- 🐛 **Bug Reports**: [GitLab Issues](https://gitlab.com/Joyfernandas/secret-scanner/-/issues)
- 💡 **Feature Requests**: [GitLab Issues](https://gitlab.com/Joyfernandas/secret-scanner/-/issues)
- 🔒 **Security Issues**: See [SECURITY.md](SECURITY.md)
- 💬 **Discussions**: [GitLab Discussions](https://gitlab.com/Joyfernandas/secret-scanner/-/issues)

---

**⚠️ Disclaimer**: This tool is provided for educational and authorized testing purposes only. Users are responsible for ensuring they have proper authorization before scanning any systems. The authors are not responsible for any misuse of this tool.

**🌟 Star this repository if you find it useful!**