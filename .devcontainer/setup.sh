#!/bin/bash

# Secret Scanner Development Environment Setup Script
echo "🔍 Setting up Secret Scanner development environment..."

# Update system packages
echo "📦 Updating system packages..."
sudo apt-get update && sudo apt-get upgrade -y

# Install additional system dependencies
echo "🛠️ Installing system dependencies..."
sudo apt-get install -y \
    curl \
    wget \
    git \
    vim \
    htop \
    tree \
    jq \
    unzip \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev

# Upgrade pip and install Python dependencies
echo "🐍 Setting up Python environment..."
python -m pip install --upgrade pip setuptools wheel

# Install project dependencies
echo "📋 Installing project dependencies..."
pip install -r requirements.txt

# Install development dependencies
echo "🔧 Installing development dependencies..."
pip install \
    flake8 \
    black \
    pylint \
    bandit \
    safety \
    pytest \
    pytest-cov \
    mypy

# Install Playwright and browsers
echo "🎭 Installing Playwright..."
pip install playwright
playwright install chromium
playwright install firefox
playwright install webkit

# Create necessary directories
echo "📁 Creating project directories..."
mkdir -p Results
mkdir -p logs
mkdir -p .cache
mkdir -p /workspace-cache/playwright

# Set up git configuration (if not already set)
echo "🔧 Configuring Git..."
if [ -z "$(git config --global user.name)" ]; then
    echo "Please set your Git username:"
    read -p "Enter your name: " git_name
    git config --global user.name "$git_name"
fi

if [ -z "$(git config --global user.email)" ]; then
    echo "Please set your Git email:"
    read -p "Enter your email: " git_email
    git config --global user.email "$git_email"
fi

# Set up pre-commit hooks
echo "🪝 Setting up pre-commit hooks..."
pip install pre-commit
cat > .pre-commit-config.yaml << EOF
repos:
  - repo: https://github.com/psf/black
    rev: 23.1.0
    hooks:
      - id: black
        args: [--line-length=120]
  - repo: https://github.com/pycqa/flake8
    rev: 6.0.0
    hooks:
      - id: flake8
        args: [--max-line-length=120, --ignore=E501,W503]
  - repo: https://github.com/pycqa/bandit
    rev: 1.7.4
    hooks:
      - id: bandit
        args: [-ll]
EOF

pre-commit install

# Create useful aliases
echo "⚡ Setting up aliases..."
cat >> ~/.zshrc << EOF

# Secret Scanner aliases
alias ss='python secrets_scanner.py'
alias ss-test='python test_installation.py'
alias ss-help='python secrets_scanner.py --help'
alias ss-demo='python secrets_scanner.py https://httpbin.org/html --depth 1'
alias ss-report='python report_generator.py'

# Development aliases
alias lint='flake8 secrets_scanner.py --max-line-length=120'
alias format='black secrets_scanner.py --line-length=120'
alias security='bandit -r . -ll'
alias test='python -m pytest'

# Useful shortcuts
alias ll='ls -la'
alias la='ls -la'
alias ..='cd ..'
alias ...='cd ../..'
alias grep='grep --color=auto'
EOF

# Create a welcome script
echo "📝 Creating welcome message..."
cat > welcome.py << EOF
#!/usr/bin/env python3
"""
Welcome script for Secret Scanner development environment
"""

print("""
🔍 Welcome to Secret Scanner Development Environment!

Quick Start Commands:
  ss-demo                    # Run a demo scan
  ss-test                    # Test installation
  ss --help                  # Show help
  
Development Commands:
  lint                       # Run linting
  format                     # Format code
  security                   # Security scan
  test                       # Run tests

Example Scans:
  ss https://httpbin.org/html --depth 1
  ss https://example.com --html-report
  ss https://httpbin.org/html --format both --verbose

Happy scanning! 🚀
""")
EOF

chmod +x welcome.py

# Run installation test
echo "🧪 Running installation test..."
python test_installation.py

# Display welcome message
python welcome.py

echo "✅ Development environment setup complete!"
echo "🎉 You can now start using Secret Scanner!"
echo ""
echo "Try running: ss-demo"