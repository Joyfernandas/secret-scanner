#!/usr/bin/env python3
"""
HTML Report Generator for Secret Scanner
Converts JSON results to a readable HTML report
"""

import json
import os
from datetime import datetime

def generate_html_report(json_data, output_path=None):
    """Generate an HTML report from scan results."""
    
    if isinstance(json_data, str):
        with open(json_data, 'r', encoding='utf-8') as f:
            data = json.load(f)
    else:
        data = json_data
    
    html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secret Scanner Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }
        .risk-high { color: #d32f2f; font-weight: bold; }
        .risk-medium { color: #f57c00; font-weight: bold; }
        .risk-low { color: #388e3c; font-weight: bold; }
        .risk-none { color: #666; }
        .finding { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .finding-high { border-left: 5px solid #d32f2f; background-color: #ffebee; }
        .finding-medium { border-left: 5px solid #f57c00; background-color: #fff3e0; }
        .finding-low { border-left: 5px solid #388e3c; background-color: #e8f5e8; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }
        .code { background: #f4f4f4; padding: 10px; border-radius: 3px; font-family: monospace; overflow-x: auto; }
        .recommendations { background: #e3f2fd; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .tab-container { margin: 20px 0; }
        .tab-buttons { display: flex; border-bottom: 1px solid #ddd; }
        .tab-button { padding: 10px 20px; background: #f8f9fa; border: none; cursor: pointer; border-bottom: 2px solid transparent; }
        .tab-button.active { background: white; border-bottom-color: #007bff; }
        .tab-content { display: none; padding: 20px 0; }
        .tab-content.active { display: block; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Secret Scanner Report</h1>
            <p><strong>Target:</strong> {target_url}</p>
            <p><strong>Scan ID:</strong> {scan_id}</p>
            <p><strong>Completed:</strong> {completed_at}</p>
            <p><strong>Duration:</strong> {duration} seconds</p>
        </div>

        <div class="stats">
            <div class="stat-card">
                <h3>Overall Risk</h3>
                <div class="risk-{overall_risk_class}">{overall_risk}</div>
            </div>
            <div class="stat-card">
                <h3>Total Findings</h3>
                <div style="font-size: 24px; font-weight: bold;">{total_findings}</div>
            </div>
            <div class="stat-card">
                <h3>Critical Issues</h3>
                <div class="risk-high">{high_severity}</div>
            </div>
            <div class="stat-card">
                <h3>Pages Scanned</h3>
                <div>{pages_scanned}</div>
            </div>
        </div>

        {recommendations_section}

        <div class="tab-container">
            <div class="tab-buttons">
                <button class="tab-button active" onclick="showTab('summary')">Summary</button>
                <button class="tab-button" onclick="showTab('pages')">Pages</button>
                <button class="tab-button" onclick="showTab('javascript')">JavaScript</button>
                <button class="tab-button" onclick="showTab('storage')">Client Storage</button>
            </div>

            <div id="summary" class="tab-content active">
                <h2>Findings Summary</h2>
                {summary_content}
            </div>

            <div id="pages" class="tab-content">
                <h2>Page Findings</h2>
                {pages_content}
            </div>

            <div id="javascript" class="tab-content">
                <h2>JavaScript Findings</h2>
                {js_content}
            </div>

            <div id="storage" class="tab-content">
                <h2>Client Storage Findings</h2>
                {storage_content}
            </div>
        </div>
    </div>

    <script>
        function showTab(tabName) {{
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
            document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
            
            // Show selected tab
            document.getElementById(tabName).classList.add('active');
            event.target.classList.add('active');
        }}
    </script>
</body>
</html>
"""

    # Extract data
    scan_info = data.get('scan_info', {})
    stats = data.get('scan_statistics', {})
    risk = data.get('risk_assessment', {})
    
    # Format data
    target_url = scan_info.get('target_url', data.get('url', 'Unknown'))
    scan_id = scan_info.get('scan_id', 'Unknown')
    completed_at = scan_info.get('completed_at', data.get('scanned_at', 'Unknown'))
    duration = scan_info.get('duration_seconds', 0)
    
    overall_risk = risk.get('overall_risk', 'UNKNOWN')
    overall_risk_class = overall_risk.lower()
    
    # Generate recommendations section
    recommendations = risk.get('recommendations', [])
    recommendations_section = ""
    if recommendations:
        recommendations_section = '<div class="recommendations"><h3>🎯 Recommendations</h3><ul>'
        for rec in recommendations:
            recommendations_section += f'<li>{rec}</li>'
        recommendations_section += '</ul></div>'
    
    # Generate summary content
    summary_content = generate_summary_section(data)
    
    # Generate pages content
    pages_content = generate_pages_section(data.get('pages', []))
    
    # Generate JS content
    js_content = generate_js_section(data.get('js_files', []))
    
    # Generate storage content
    storage_content = generate_storage_section(data.get('client_storage', {}))
    
    # Fill template
    html_content = html_template.format(
        target_url=target_url,
        scan_id=scan_id,
        completed_at=completed_at,
        duration=duration,
        overall_risk=overall_risk,
        overall_risk_class=overall_risk_class,
        total_findings=stats.get('total_findings', 0),
        high_severity=stats.get('high_severity_findings', 0),
        pages_scanned=stats.get('pages_scanned', 0),
        recommendations_section=recommendations_section,
        summary_content=summary_content,
        pages_content=pages_content,
        js_content=js_content,
        storage_content=storage_content
    )
    
    # Write to file
    if not output_path:
        output_path = 'secret_scanner_report.html'
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return output_path

def generate_summary_section(data):
    """Generate the summary section HTML."""
    summary = data.get('summary', {})
    if not summary:
        return '<p>No secrets detected.</p>'
    
    content = '<table style="width: 100%; border-collapse: collapse;">'
    content += '<tr style="background: #f8f9fa;"><th style="padding: 10px; border: 1px solid #ddd;">Secret Type</th><th style="padding: 10px; border: 1px solid #ddd;">Count</th></tr>'
    
    for secret_type, count in summary.items():
        content += f'<tr><td style="padding: 10px; border: 1px solid #ddd;">{secret_type}</td><td style="padding: 10px; border: 1px solid #ddd; text-align: center;">{count}</td></tr>'
    
    content += '</table>'
    return content

def generate_pages_section(pages):
    """Generate the pages section HTML."""
    if not pages:
        return '<p>No pages scanned.</p>'
    
    content = ''
    for page in pages:
        findings = page.get('findings', [])
        if findings:
            content += f'<h3>📄 {page.get("url", "Unknown URL")}</h3>'
            content += f'<p><strong>Status:</strong> {page.get("status", "Unknown")}</p>'
            
            for finding in findings:
                content += generate_finding_html(finding)
    
    if not content:
        content = '<p>No secrets found in pages.</p>'
    
    return content

def generate_js_section(js_files):
    """Generate the JavaScript section HTML."""
    if not js_files:
        return '<p>No JavaScript files scanned.</p>'
    
    content = ''
    for js_file in js_files:
        findings = js_file.get('findings', [])
        if findings:
            content += f'<h3>📜 {js_file.get("url", "Unknown URL")}</h3>'
            content += f'<p><strong>Status:</strong> {js_file.get("status", "Unknown")}</p>'
            
            for finding in findings:
                content += generate_finding_html(finding)
    
    if not content:
        content = '<p>No secrets found in JavaScript files.</p>'
    
    return content

def generate_storage_section(client_storage):
    """Generate the client storage section HTML."""
    content = ''
    
    # localStorage findings
    ls_findings = client_storage.get('localStorage_findings', [])
    if ls_findings:
        content += '<h3>💾 localStorage Findings</h3>'
        for finding in ls_findings:
            content += generate_finding_html(finding)
    
    # sessionStorage findings
    ss_findings = client_storage.get('sessionStorage_findings', [])
    if ss_findings:
        content += '<h3>🔄 sessionStorage Findings</h3>'
        for finding in ss_findings:
            content += generate_finding_html(finding)
    
    if not content:
        content = '<p>No secrets found in client storage.</p>'
    
    return content

def generate_finding_html(finding):
    """Generate HTML for a single finding."""
    severity = finding.get('severity', 'INFO').lower()
    severity_class = f'finding-{severity}' if severity in ['high', 'medium', 'low'] else 'finding'
    
    html = f'<div class="finding {severity_class}">'
    html += f'<h4>🚨 {finding.get("type", "Unknown")} <span class="risk-{severity}">({finding.get("severity", "INFO")})</span></h4>'
    html += f'<p><strong>Description:</strong> {finding.get("description", "No description")}</p>'
    html += f'<p><strong>Match:</strong> <code>{finding.get("match", "")}</code></p>'
    html += f'<p><strong>Location:</strong> Line {finding.get("source", {}).get("line", "?")} Column {finding.get("source", {}).get("col", "?")}</p>'
    html += f'<div class="code"><strong>Context:</strong><br>{finding.get("snippet", "No context available")}</div>'
    html += f'<p><strong>🔧 Remediation:</strong> {finding.get("remediation", "Review and rotate if necessary")}</p>'
    html += f'<p><strong>Confidence:</strong> {finding.get("confidence", "UNKNOWN")}</p>'
    html += '</div>'
    
    return html

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        json_file = sys.argv[1]
        output_file = sys.argv[2] if len(sys.argv) > 2 else None
        report_path = generate_html_report(json_file, output_file)
        print(f"HTML report generated: {report_path}")
    else:
        print("Usage: python report_generator.py <json_file> [output_file]")