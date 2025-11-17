# 📁 Secret Scanner - Project Structure

## Root Directory Structure
```
secret-scanner/
├── 📄 Core Files
│   ├── secrets_scanner.py          # Main scanner application
│   ├── config.py                   # Configuration settings
│   ├── report_generator.py         # HTML report generator
│   └── test_installation.py        # Installation validator
│
├── 📋 Configuration
│   ├── requirements.txt            # Python dependencies
│   ├── setup.py                   # Package setup configuration
│   ├── Makefile                   # Build and development commands
│   └── .gitignore                 # Git ignore patterns
│
├── 🐳 Containerization
│   ├── Dockerfile                 # Docker image configuration
│   └── docker-compose.yml         # Multi-service deployment
│
├── 🦊 GitLab Integration
│   ├── .gitlab-ci.yml             # CI/CD pipeline configuration
│   └── .devcontainer/             # Codespaces configuration
│       ├── devcontainer.json      # Development environment setup
│       └── setup.sh               # Automated setup script
│
├── 📚 Documentation
│   ├── README.md                  # Main project documentation
│   ├── SECURITY.md                # Security policy and guidelines
│   ├── CONTRIBUTING.md            # Contribution guidelines
│   ├── CHANGELOG.md               # Version history
│   ├── LICENSE                    # MIT license
│   └── docs/                      # Additional documentation
│       └── GITLAB_SETUP.md        # GitLab setup guide
│
├── 🧪 Testing & Quality
│   └── .github/                   # GitHub templates (if needed)
│       ├── workflows/             # GitHub Actions
│       └── ISSUE_TEMPLATE/        # Issue templates
│
├── 📊 Output & Results
│   ├── Results/                   # Scan output directory
│   ├── enhanced_example_output.json # Sample enhanced output
│   └── example_output.json        # Basic sample output
│
└── 📦 Dependencies
    └── env/                       # Virtual environment (local)
```

## File Descriptions

### 🔧 Core Application Files

| File | Purpose | Key Features |
|------|---------|--------------|
| `secrets_scanner.py` | Main scanner engine | Pattern detection, crawling, reporting |
| `config.py` | Configuration management | Settings, patterns, exclusions |
| `report_generator.py` | HTML report creation | Interactive dashboards, visualizations |
| `test_installation.py` | Installation validation | Dependency checks, pattern testing |

### ⚙️ Configuration Files

| File | Purpose | Contents |
|------|---------|----------|
| `requirements.txt` | Python dependencies | requests, beautifulsoup4, playwright |
| `setup.py` | Package configuration | Metadata, entry points, classifiers |
| `Makefile` | Development commands | install, test, lint, clean |
| `.gitignore` | Version control exclusions | Results/, logs/, cache files |

### 🐳 Deployment Files

| File | Purpose | Features |
|------|---------|----------|
| `Dockerfile` | Container image | Multi-stage build, security hardening |
| `docker-compose.yml` | Service orchestration | Scanner, web UI, caching |

### 🦊 GitLab Integration

| File | Purpose | Capabilities |
|------|---------|--------------|
| `.gitlab-ci.yml` | CI/CD pipeline | Testing, security scans, deployment |
| `.devcontainer/` | Codespaces setup | Automated environment, extensions |

### 📚 Documentation

| File | Purpose | Content |
|------|---------|---------|
| `README.md` | Main documentation | Usage, installation, examples |
| `SECURITY.md` | Security guidelines | Ethical use, vulnerability reporting |
| `CONTRIBUTING.md` | Contribution guide | Development setup, guidelines |

## Directory Functions

### 📊 Results Directory
```
Results/
├── secret_scanner.json           # Default JSON output
├── secret_scanner.html           # HTML report (if generated)
├── scan_[timestamp].json         # Timestamped scans
└── reports/                      # Organized report storage
    ├── daily/
    ├── weekly/
    └── archived/
```

### 🔧 Development Structure
```
.devcontainer/
├── devcontainer.json             # VS Code configuration
├── setup.sh                     # Environment setup script
└── workspace-cache/              # Cached dependencies
```

### 📋 Configuration Hierarchy
```
config.py                         # Base configuration
├── DEFAULT_TIMEOUT = 12
├── PATTERNS = {...}
├── EXCLUDED_EXTENSIONS = {...}
└── IGNORE_PATTERNS = [...]
```

## Key Features by File

### 🎯 secrets_scanner.py
- Multi-source scanning (HTML, JS, storage)
- 25+ secret pattern detection
- Risk assessment and severity classification
- Configurable crawling depth
- Rate limiting and ethical scanning

### 📊 report_generator.py
- Interactive HTML reports
- Risk assessment dashboards
- Tabbed interface for findings
- Color-coded severity levels
- Export capabilities

### ⚙️ config.py
- Centralized settings management
- Pattern definitions
- Exclusion rules
- Performance tuning parameters

### 🧪 test_installation.py
- Dependency validation
- Pattern testing
- Basic functionality checks
- Environment verification

This structured approach ensures maintainability, scalability, and ease of deployment across different environments.