# 🏗️ Professional Code Structure

## Overview
The Secret Scanner has been restructured following enterprise-grade software development practices with proper separation of concerns, modular architecture, and professional packaging.

## 📁 New Directory Structure

```
secret-scanner/
├── 📦 src/                           # Source code package
│   └── secret_scanner/               # Main package
│       ├── __init__.py              # Package initialization
│       ├── cli.py                   # Command-line interface
│       │
│       ├── 🔧 core/                 # Core business logic
│       │   ├── __init__.py
│       │   ├── scanner.py           # Main scanner class
│       │   ├── config.py            # Configuration management
│       │   └── models.py            # Data models and types
│       │
│       ├── 🔍 detectors/            # Secret detection modules
│       │   ├── __init__.py
│       │   ├── pattern_detector.py  # Pattern-based detection
│       │   ├── base64_detector.py   # Base64 token detection
│       │   └── context_analyzer.py  # Context analysis
│       │
│       ├── 📊 reporters/            # Report generation
│       │   ├── __init__.py
│       │   ├── json_reporter.py     # JSON report generator
│       │   ├── html_reporter.py     # HTML report generator
│       │   └── base_reporter.py     # Base reporter class
│       │
│       └── 🛠️ utils/                # Utility modules
│           ├── __init__.py
│           ├── text_utils.py        # Text processing utilities
│           ├── network_utils.py     # Network utilities
│           └── file_utils.py        # File system utilities
│
├── 🧪 tests/                        # Test suite
│   ├── __init__.py
│   ├── unit/                        # Unit tests
│   │   ├── test_scanner.py
│   │   ├── test_detectors.py
│   │   └── test_models.py
│   ├── integration/                 # Integration tests
│   │   ├── test_full_scan.py
│   │   └── test_cli.py
│   └── fixtures/                    # Test data
│       ├── sample_pages/
│       └── expected_results/
│
├── 📚 docs/                         # Documentation
│   ├── API_REFERENCE.md
│   ├── JSON_SCHEMA.md
│   └── GITLAB_SETUP.md
│
├── 🐳 Deployment/                   # Deployment configurations
│   ├── .devcontainer/
│   ├── Dockerfile
│   └── docker-compose.yml
│
├── 📋 Configuration Files
│   ├── setup.py                    # Package setup
│   ├── requirements.txt            # Dependencies
│   ├── .gitlab-ci.yml             # CI/CD pipeline
│   ├── .gitignore                 # Git exclusions
│   └── Makefile                   # Build commands
│
└── 📄 Documentation
    ├── README.md                   # Main documentation
    ├── SECURITY.md                # Security policy
    ├── CONTRIBUTING.md            # Contribution guide
    └── LICENSE                    # MIT license
```

## 🏛️ Architecture Principles

### 1. **Separation of Concerns**
- **Core**: Business logic and main scanner functionality
- **Detectors**: Specialized secret detection algorithms
- **Reporters**: Output generation and formatting
- **Utils**: Shared utility functions
- **CLI**: Command-line interface and user interaction

### 2. **Dependency Injection**
```python
# Configuration is injected into scanner
scanner = SecretScanner(config=ScanConfig())

# Detectors are injected into scanner
scanner = SecretScanner(
    pattern_detector=PatternDetector(),
    base64_detector=Base64Detector()
)
```

### 3. **Type Safety**
```python
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

@dataclass
class Finding:
    id: str
    severity: Severity
    confidence: Confidence
    timestamp: datetime
```

### 4. **Professional Error Handling**
```python
class ScannerError(Exception):
    """Base exception for scanner errors."""
    pass

class NetworkError(ScannerError):
    """Network-related errors."""
    pass

class ValidationError(ScannerError):
    """Input validation errors."""
    pass
```

## 🔧 Key Components

### Core Scanner (`src/secret_scanner/core/scanner.py`)
```python
class SecretScanner:
    """Main scanner with professional architecture."""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.logger = self._setup_logging()
        self.detectors = self._initialize_detectors()
    
    def scan(self, target_url: str) -> ScanResult:
        """Perform comprehensive scan."""
        # Professional implementation with proper error handling
```

### Data Models (`src/secret_scanner/core/models.py`)
```python
@dataclass
class Finding:
    """Immutable finding with type safety."""
    id: str
    type: str
    severity: Severity
    confidence: Confidence
    source: SourceLocation
    timestamp: datetime = field(default_factory=datetime.utcnow)
```

### Configuration Management (`src/secret_scanner/core/config.py`)
```python
@dataclass
class ScanConfig:
    """Type-safe configuration with defaults."""
    depth: int = 2
    enable_playwright: bool = True
    request_delay: float = 0.5
    # ... other settings
```

### Modular Detectors (`src/secret_scanner/detectors/`)
```python
class PatternDetector:
    """Specialized pattern-based detection."""
    
    def detect(self, text: str, source_info: Dict) -> List[Finding]:
        """Detect secrets using regex patterns."""
```

## 🎯 Benefits of Professional Structure

### 1. **Maintainability**
- Clear separation of responsibilities
- Easy to locate and modify specific functionality
- Reduced coupling between components

### 2. **Testability**
- Each component can be tested in isolation
- Mock dependencies for unit testing
- Clear interfaces for integration testing

### 3. **Extensibility**
- Easy to add new detectors
- Simple to add new output formats
- Plugin architecture for custom patterns

### 4. **Scalability**
- Modular design supports team development
- Components can be optimized independently
- Easy to add new features without breaking existing code

### 5. **Professional Standards**
- Follows Python packaging best practices
- Type hints for better IDE support
- Comprehensive documentation
- Proper error handling and logging

## 🚀 Usage Examples

### Programmatic Usage
```python
from secret_scanner import SecretScanner, ScanConfig

# Create configuration
config = ScanConfig(
    depth=3,
    enable_playwright=True,
    verbose_logging=True
)

# Create and run scanner
scanner = SecretScanner(config)
result = scanner.scan("https://example.com")

# Access structured results
print(f"Risk Level: {result.risk_assessment.overall_risk}")
print(f"Total Findings: {result.scan_statistics.total_findings}")
```

### Command Line Usage
```bash
# Install as package
pip install -e .

# Use professional CLI
secret-scanner https://example.com --depth 3 --format both
```

### Testing
```bash
# Run unit tests
python -m pytest tests/unit/

# Run integration tests
python -m pytest tests/integration/

# Run with coverage
python -m pytest --cov=secret_scanner tests/
```

## 📦 Package Distribution

### Development Installation
```bash
# Install in development mode
pip install -e .

# Install with development dependencies
pip install -e ".[dev]"

# Install with Playwright support
pip install -e ".[playwright]"
```

### Production Installation
```bash
# Install from PyPI (when published)
pip install secret-scanner

# Install from GitLab
pip install git+https://gitlab.com/yourusername/secret-scanner.git
```

## 🔄 Migration from Old Structure

The professional structure maintains backward compatibility while providing new capabilities:

### Old Usage (Still Works)
```bash
python secrets_scanner.py https://example.com
```

### New Professional Usage
```bash
secret-scanner https://example.com
```

### Programmatic Access
```python
# New structured approach
from secret_scanner import SecretScanner, ScanConfig

# Old approach still available for compatibility
from secret_scanner.legacy import crawl_and_scan
```

This professional structure transforms Secret Scanner from a script into an enterprise-grade security tool suitable for production environments, team development, and integration into larger security workflows.