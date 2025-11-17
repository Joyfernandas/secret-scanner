# Secret Scanner Makefile

.PHONY: help install test clean lint format setup-dev

help:
	@echo "Available commands:"
	@echo "  install     - Install dependencies"
	@echo "  install-dev - Install development dependencies"
	@echo "  test        - Run tests"
	@echo "  lint        - Run linting"
	@echo "  format      - Format code"
	@echo "  clean       - Clean up temporary files"
	@echo "  setup-dev   - Setup development environment"

install:
	pip install -r requirements.txt

install-dev: install
	pip install flake8 black bandit safety
	pip install playwright
	playwright install chromium

test:
	python test_installation.py

lint:
	flake8 secrets_scanner.py --max-line-length=120 --ignore=E501,W503
	bandit -r . -f json -o bandit-report.json || true

format:
	black secrets_scanner.py config.py test_installation.py --line-length=120

clean:
	rm -rf __pycache__/
	rm -rf *.pyc
	rm -rf .pytest_cache/
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -f bandit-report.json
	rm -rf Results/

setup-dev: install-dev
	@echo "Development environment setup complete!"
	@echo "Run 'make test' to verify installation"

# Example usage targets
example-basic:
	python secrets_scanner.py https://httpbin.org/html --depth 1 --no-playwright

example-full:
	python secrets_scanner.py https://httpbin.org/html --depth 2 --verbose