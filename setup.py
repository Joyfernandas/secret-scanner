#!/usr/bin/env python3

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_path.exists():
    requirements = [
        line.strip() 
        for line in requirements_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="secret-scanner",
    version="1.0.0",
    author="Joyfernandas",
    author_email="cyphersilhouette@gmail.com",
    description="A comprehensive web application security scanner for detecting exposed secrets and credentials",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Joyfernandas/secret-scanner",
    project_urls={
        "Bug Reports": "https://github.com/Joyfernandas/secret-scanner/issues",
        "Source": "https://github.com/Joyfernandas/secret-scanner",
        "Documentation": "https://github.com/Joyfernandas/secret-scanner/blob/main/README.md",
    },
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Testing",
        "Topic :: System :: Systems Administration",
        "Environment :: Console",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.0",
            "black>=22.0",
            "flake8>=4.0",
            "mypy>=0.900",
            "bandit>=1.7",
            "safety>=2.0",
        ],
        "playwright": [
            "playwright>=1.30.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "secret-scanner=secret_scanner.cli:main",
            "secrets-scanner=secret_scanner.cli:main",  # Alternative name
        ],
    },
    keywords=[
        "security", "secrets", "scanner", "web", "api-keys", 
        "tokens", "credentials", "vulnerability", "pentest"
    ],
    include_package_data=True,
    zip_safe=False,
)