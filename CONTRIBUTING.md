# Contributing to Secret Scanner

Thank you for your interest in contributing to Secret Scanner! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help maintain a welcoming environment for all contributors

## How to Contribute

### Reporting Issues

1. Check existing issues to avoid duplicates
2. Use the issue template if available
3. Provide clear reproduction steps
4. Include system information (OS, Python version, etc.)

### Submitting Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes
4. Add tests if applicable
5. Ensure code follows the existing style
6. Update documentation if needed
7. Submit a pull request

### Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/secret-scanner.git
cd secret-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # If available

# Install Playwright (optional)
playwright install chromium
```

### Adding New Secret Patterns

When adding new secret detection patterns:

1. Add the pattern to the `PATTERNS` dictionary in `secrets_scanner.py`
2. Use descriptive names for pattern keys
3. Test the pattern with known examples
4. Consider false positive rates
5. Add documentation for the new pattern type

Example:
```python
"new_service_token": re.compile(r"\\bnst_[A-Za-z0-9]{32}\\b"),
```

### Testing

- Test your changes with various websites (with permission)
- Verify that new patterns don't cause excessive false positives
- Test both with and without Playwright
- Ensure the tool handles edge cases gracefully

### Documentation

- Update README.md if adding new features
- Add docstrings to new functions
- Update help text for new command-line options
- Include examples in documentation

## Security Considerations

- Never include real secrets or credentials in code or tests
- Use placeholder values in examples
- Be mindful of the ethical implications of security tools
- Follow responsible disclosure practices

## Pull Request Guidelines

- Keep changes focused and atomic
- Write clear commit messages
- Include tests for new functionality
- Update documentation as needed
- Ensure CI passes (if available)

## Questions?

Feel free to open an issue for questions about contributing or reach out to the maintainers.

Thank you for helping make Secret Scanner better!