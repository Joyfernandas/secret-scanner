# Changelog

All notable changes to Secret Scanner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-01-15

### Added
- Initial release of Secret Scanner
- Web application secret detection capabilities
- Support for multiple secret types:
  - JWT tokens
  - AWS credentials
  - Google API keys
  - Stripe keys
  - GitHub tokens
  - Discord tokens
  - Database connection strings
  - Private keys
  - Generic API keys and secrets
- Client-side storage scanning with Playwright
- Recursive crawling of same-domain links
- HTML attribute scanning
- JavaScript file analysis
- Detailed JSON reporting with context and location information
- Command-line interface with multiple options
- Comprehensive documentation and examples

### Security
- Ethical use guidelines and warnings
- Rate limiting and respectful scanning practices
- SSL certificate verification
- Proper error handling for network issues

### Documentation
- Complete README with usage examples
- Contributing guidelines
- Security policy
- Example output format
- MIT license

## [Unreleased]

### Planned
- Configuration file support
- Plugin system for custom patterns
- HTML report generation
- Integration with CI/CD pipelines
- Performance optimizations
- Additional secret pattern types
- Improved false positive reduction