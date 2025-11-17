"""Command-line interface for Secret Scanner."""

import argparse
import sys
import json
import os
from pathlib import Path
from typing import Optional

from .core.scanner import SecretScanner
from .core.config import ScanConfig
from .reporters.json_reporter import JsonReporter
from .reporters.html_reporter import HtmlReporter
from .utils.file_utils import ensure_directory_exists


class SecretScannerCLI:
    """Command-line interface for Secret Scanner."""
    
    def __init__(self):
        self.parser = self._create_parser()
    
    def run(self, args: Optional[list] = None) -> int:
        """Run the CLI with given arguments."""
        try:
            parsed_args = self.parser.parse_args(args)
            return self._execute_scan(parsed_args)
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
            return 130
        except Exception as e:
            print(f"[!] Error: {str(e)}")
            return 1
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser."""
        parser = argparse.ArgumentParser(
            prog="secret-scanner",
            description="Secret Scanner - Web Application Security Scanner",
            epilog="Use responsibly and only on systems you are authorized to test.",
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        
        # Required arguments
        parser.add_argument(
            "url",
            help="Target URL to scan (must include protocol: http:// or https://)"
        )
        
        # Scanning options
        parser.add_argument(
            "--depth",
            type=int,
            default=2,
            metavar="N",
            help="Crawl depth for same-domain links (default: 2)"
        )
        
        parser.add_argument(
            "--min-token-length",
            type=int,
            default=30,
            metavar="N",
            help="Minimum length for base64-like tokens (default: 30)"
        )
        
        parser.add_argument(
            "--delay",
            type=float,
            default=0.5,
            metavar="N",
            help="Delay between requests in seconds (default: 0.5)"
        )
        
        # Feature flags
        parser.add_argument(
            "--no-playwright",
            action="store_true",
            help="Disable client-side storage scanning"
        )
        
        parser.add_argument(
            "--verbose", "-v",
            action="store_true",
            help="Enable verbose logging"
        )
        
        # Output options
        parser.add_argument(
            "--output",
            metavar="FILE",
            help="Output file path (default: Results/secret_scanner.json)"
        )
        
        parser.add_argument(
            "--format",
            choices=["json", "html", "both"],
            default="json",
            help="Output format (default: json)"
        )
        
        parser.add_argument(
            "--html-report",
            action="store_true",
            help="Generate HTML report in addition to JSON"
        )
        
        # Version
        parser.add_argument(
            "--version",
            action="version",
            version="Secret Scanner 1.0.0"
        )
        
        return parser
    
    def _execute_scan(self, args) -> int:
        """Execute the scan with parsed arguments."""
        # Create configuration
        config = self._create_config(args)
        
        # Create scanner
        scanner = SecretScanner(config)
        
        # Perform scan
        print(f"[+] Starting scan of {args.url}")
        print(f"    Depth: {config.depth}")
        print(f"    Playwright: {'enabled' if config.enable_playwright else 'disabled'}")
        print(f"    Output format: {config.output_format}")
        
        scan_result = scanner.scan(args.url)
        
        # Generate reports
        self._generate_reports(scan_result, config)
        
        # Print summary
        self._print_summary(scan_result)
        
        return 0
    
    def _create_config(self, args) -> ScanConfig:
        """Create scan configuration from arguments."""
        # Determine output path
        if args.output:
            output_path = args.output
        else:
            ensure_directory_exists("Results")
            output_path = "Results/secret_scanner.json"
        
        # Determine output format
        output_format = args.format
        if args.html_report:
            output_format = "both"
        
        return ScanConfig(
            depth=args.depth,
            min_token_length=args.min_token_length,
            request_delay=args.delay,
            enable_playwright=not args.no_playwright,
            verbose_logging=args.verbose,
            output_path=output_path,
            output_format=output_format
        )
    
    def _generate_reports(self, scan_result, config: ScanConfig) -> None:
        """Generate output reports."""
        output_path = Path(config.output_path)
        
        # Generate JSON report
        if config.output_format in ["json", "both"]:
            json_reporter = JsonReporter()
            json_path = output_path.with_suffix('.json')
            json_reporter.generate(scan_result, str(json_path))
            print(f"[+] JSON report written to {json_path}")
        
        # Generate HTML report
        if config.output_format in ["html", "both"]:
            html_reporter = HtmlReporter()
            html_path = output_path.with_suffix('.html')
            html_reporter.generate(scan_result, str(html_path))
            print(f"[+] HTML report written to {html_path}")
    
    def _print_summary(self, scan_result) -> None:
        """Print scan summary to console."""
        stats = scan_result.scan_statistics
        risk = scan_result.risk_assessment
        
        print(f"\n{'='*50}")
        print("SCAN SUMMARY")
        print(f"{'='*50}")
        print(f"Target URL: {scan_result.scan_info.target_url}")
        print(f"Scan Duration: {scan_result.scan_info.duration_seconds:.1f} seconds")
        print(f"Pages Scanned: {stats.pages_scanned}")
        print(f"JS Files Scanned: {stats.js_files_scanned}")
        print(f"\nFINDINGS:")
        print(f"  Total Secrets: {stats.total_findings}")
        print(f"  High Severity: {stats.high_severity_findings}")
        print(f"  Medium Severity: {stats.medium_severity_findings}")
        print(f"  Low Severity: {stats.low_severity_findings}")
        print(f"\nRISK ASSESSMENT: {risk.overall_risk.value}")
        
        if risk.recommendations:
            print(f"\nRECOMMENDATIONS:")
            for i, rec in enumerate(risk.recommendations, 1):
                print(f"  {i}. {rec}")
        
        if stats.errors_encountered > 0:
            print(f"\nWarning: {stats.errors_encountered} errors encountered during scan")


def main():
    """Main entry point for CLI."""
    cli = SecretScannerCLI()
    sys.exit(cli.run())


if __name__ == "__main__":
    main()