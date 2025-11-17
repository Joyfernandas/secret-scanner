# 🦊 GitLab Setup Guide

This guide will help you set up Secret Scanner on GitLab with Codespaces integration.

## 🚀 Quick Setup

### Step 1: Create GitLab Repository
1. Go to GitLab and click **New project**
2. Choose **Create blank project**
3. Fill in project details:
   - **Project name**: `secret-scanner`
   - **Visibility**: Choose based on your needs
4. Click **Create project**

### Step 2: Upload Files
1. Clone the repository locally
2. Add all Secret Scanner files
3. Commit and push to GitLab

### Step 3: Enable GitLab Codespaces
1. Go to your project
2. Click **Web IDE** → **VS Code for the Web**
3. The environment will automatically load

## 🛠️ Using in Codespaces

### Quick Commands
```bash
# Demo scan
python secrets_scanner.py https://httpbin.org/html --depth 1

# Full scan with HTML report
python secrets_scanner.py https://example.com --html-report

# Verbose scan
python secrets_scanner.py https://example.com --verbose --format both
```

### Available Aliases (after setup)
```bash
ss-demo                    # Demo scan
ss-test                    # Test installation
ss-help                    # Show help
lint                       # Run linting
format                     # Format code
security                   # Security scan
```

## 📊 Viewing Results

1. **JSON Results**: Open `Results/secret_scanner.json` in VS Code
2. **HTML Reports**: Right-click HTML file → **Open with Live Server**
3. **Download**: Right-click files → **Download**

## 🔒 Security Best Practices

- Only scan websites you own or have permission to test
- Don't commit scan results with real secrets
- Use private repositories for scanning projects
- Clear results before committing code

## 🐛 Troubleshooting

### Playwright Issues
```bash
pip install playwright
playwright install chromium
```

### Permission Issues
```bash
chmod +x .devcontainer/setup.sh
```

### Memory Issues
```bash
python secrets_scanner.py https://example.com --depth 1 --no-playwright
```

## 📈 Performance Tips

1. Use shallow scans: `--depth 1`
2. Skip Playwright: `--no-playwright`
3. Increase delays: `--delay 2.0`
4. Process in batches for multiple URLs

Happy scanning with GitLab Codespaces! 🚀