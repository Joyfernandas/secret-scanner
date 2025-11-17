#!/usr/bin/env python3
"""
Secret Scanner - Web Application Security Scanner

A comprehensive tool for detecting exposed secrets, API keys, tokens, and credentials
in web applications including HTML pages, JavaScript files, and client-side storage.

Usage:
    python secrets_scanner.py <url> [--no-playwright] [--depth N] [--output out.json] [--min-token-length N]

Requirements:
 - requests, beautifulsoup4
 - Optional: playwright (for client-side storage scanning)

Ethical Use Only:
 - Only use on systems you own or have explicit permission to test
 - Follow responsible disclosure practices
 - Respect rate limits and robots.txt
"""
import re
import sys
import json
import argparse
import requests
import os
import tempfile
import time
import logging
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from collections import defaultdict
from datetime import datetime, timezone

# Import configuration
try:
    from config import *
except ImportError:
    # Fallback values if config.py is not available
    DEFAULT_TIMEOUT = 30
    DEFAULT_USER_AGENT = "Mozilla/5.0 (SecretScanner/1.0)"
    REQUEST_DELAY = 0.5
    MAX_CRAWL_PAGES = 100

# Optional Playwright imports done lazily
PLAYWRIGHT_AVAILABLE = True
try:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    PLAYWRIGHT_AVAILABLE = True
except Exception:
    PLAYWRIGHT_AVAILABLE = False

REQUESTS_TIMEOUT = DEFAULT_TIMEOUT if 'DEFAULT_TIMEOUT' in globals() else 30

# Comprehensive patterns for known keys/tokens
PATTERNS = {
    # Authentication tokens
    "bearer_token_header": re.compile(r"Bearer\s+([A-Za-z0-9\-\._~\+/]+=*)", re.I),
    "jwt_like": re.compile(r"\beyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z\-_]{10,}\.[0-9A-Za-z\-_]{10,}\b"),
    "basic_auth_inline": re.compile(r"https?://[^:@\s]+:[^@\s]+@"),
    "bearer_in_url": re.compile(r"(?:access_token|token|bearer)=([A-Za-z0-9\-_\.]+)", re.I),
    
    # AWS credentials
    "aws_access_key": re.compile(r"\b(AKIA|ASIA|A3T|AGPA)[A-Z0-9]{16}\b"),
    "aws_secret_key_like": re.compile(r"(?i)aws(.{0,20})?(secret|key|secretaccesskey).{0,20}([A-Za-z0-9/+]{40,})"),
    "aws_session_token": re.compile(r"(?i)(aws.{0,20})?session.{0,20}token.{0,20}([A-Za-z0-9/+=]{100,})"),
    
    # Cloud provider keys
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "google_oauth_key": re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    "azure_client_secret": re.compile(r"\b[A-Za-z0-9~._-]{34}\b"),
    
    # Payment processors
    "stripe_secret": re.compile(r"\b(sk_live|sk_test)_[0-9a-zA-Z]{24,}\b"),
    "stripe_publishable": re.compile(r"\b(pk_live|pk_test)_[0-9a-zA-Z]{24,}\b"),
    "paypal_client_id": re.compile(r"\bA[A-Za-z0-9_-]{79}\b"),
    
    # Communication platforms
    "slack_token": re.compile(r"xox[baprs]-[0-9A-Za-z-]+"),
    "discord_token": re.compile(r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}"),
    "telegram_bot_token": re.compile(r"\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b"),
    
    # Version control
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b"),
    "github_classic_token": re.compile(r"\bghp_[A-Za-z0-9_]{36}\b"),
    "gitlab_token": re.compile(r"\bglpat-[A-Za-z0-9_-]{20}\b"),
    
    # Database connections
    "mongodb_uri": re.compile(r"mongodb://[^\s]+:[^\s]+@[^\s]+"),
    "postgres_uri": re.compile(r"postgres://[^\s]+:[^\s]+@[^\s]+"),
    "mysql_uri": re.compile(r"mysql://[^\s]+:[^\s]+@[^\s]+"),
    
    # Generic patterns
    "generic_key": re.compile(r"(?i)(api[_-]?key|apikey|secret|client_secret|access_token|auth_token|password|passwd|token)[\"'\s:=]{1,5}([A-Za-z0-9\-_=+./]{8,200})"),
    "password_param": re.compile(r"password=([^&\s]+)", re.I),
    "private_key": re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----"),
    "ssh_private_key": re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----"),
}

# fallback base64-like pattern (we apply heuristics before reporting)
BASE64_LIKE = re.compile(r"\b[A-Za-z0-9\-_+/=]{32,}\b")
I18N_KEY_SUFFIXES = ("_label", "_message", "_title", "_placeholder", "_text", "_noData", "_error")

def setup_logging(verbose=False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    return logging.getLogger(__name__)

def fetch_url(url, delay=None, max_retries=3):
    """Fetch URL content with proper error handling, rate limiting, and retry logic."""
    if delay is None:
        delay = REQUEST_DELAY if 'REQUEST_DELAY' in globals() else 0.5
    
    # Rate limiting
    time.sleep(delay)
    
    user_agent = DEFAULT_USER_AGENT if 'DEFAULT_USER_AGENT' in globals() else "Mozilla/5.0 (SecretScanner/1.0)"
    headers = {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    }
    
    for attempt in range(max_retries):
        try:
            try:
                logging.debug(f"Fetching URL: {url} (attempt {attempt + 1}/{max_retries})")
            except:
                pass  # Logging not set up yet
            r = requests.get(url, headers=headers, timeout=REQUESTS_TIMEOUT, allow_redirects=True, verify=True)
            
            # Check content type to avoid processing binary files
            content_type = r.headers.get('content-type', '').lower()
            if 'EXCLUDED_CONTENT_TYPES' in globals():
                for excluded in EXCLUDED_CONTENT_TYPES:
                    if content_type.startswith(excluded):
                        try:
                            logging.debug(f"Skipping {url} due to content type: {content_type}")
                        except:
                            pass
                        return None, None, {"error": f"Excluded content type: {content_type}"}
            
            return r.status_code, r.text, dict(r.headers or {})
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            if attempt < max_retries - 1:
                wait_time = (attempt + 1) * 2
                try:
                    logging.warning(f"Retry {attempt + 1}/{max_retries} for {url} after {wait_time}s")
                except:
                    pass
                time.sleep(wait_time)
                continue
            raise
    except requests.exceptions.SSLError as e:
        try:
            logging.warning(f"SSL Error for {url}: {str(e)}")
        except:
            pass
        return None, None, {"error": f"SSL Error: {str(e)}"}
    except requests.exceptions.Timeout as e:
        try:
            logging.warning(f"Timeout for {url}: {str(e)}")
        except:
            pass
        return None, None, {"error": f"Timeout: {str(e)}"}
    except requests.exceptions.ConnectionError as e:
        try:
            logging.warning(f"Connection Error for {url}: {str(e)}")
        except:
            pass
        return None, None, {"error": f"Connection Error: {str(e)}"}
    except Exception as e:
        try:
            logging.error(f"Unexpected error for {url}: {str(e)}")
        except:
            pass
        return None, None, {"error": str(e)}

def extract_script_urls(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    scripts = []
    for s in soup.find_all("script"):
        src = s.get("src")
        if src:
            full = urljoin(base_url, src)
            scripts.append(("external", full))
        else:
            content = s.string or ""
            scripts.append(("inline", content))
    for link in soup.find_all("link", {"rel": "preload"}):
        if link.get("as") == "script" and link.get("href"):
            scripts.append(("external", urljoin(base_url, link["href"])))
    return scripts

def looks_like_i18n_key(s: str) -> bool:
    if any(s.endswith(suf) for suf in I18N_KEY_SUFFIXES):
        return True
    if s.count("_") >= 3 and re.fullmatch(r"[A-Za-z0-9_]+", s):
        return True
    return False

def is_suspicious_token(s: str, min_len: int = 40) -> bool:
    if not s or len(s) < min_len:
        return False
    ss = s.strip("\"'` ")
    if looks_like_i18n_key(ss):
        return False
    # require digits or base64 characters, plus letters, or mixed-case + digits
    if (re.search(r"[0-9]", ss) or re.search(r"[+/=]", ss)) and re.search(r"[A-Za-z]", ss):
        return True
    if re.search(r"[A-Z]", ss) and re.search(r"[a-z]", ss) and re.search(r"[0-9]", ss):
        return True
    return False

def line_col_from_index(text: str, index: int):
    before = text[:index]
    line = before.count("\n") + 1
    col = index - before.rfind("\n") if "\n" in before else index + 1
    return line, col

def get_secret_severity(secret_type):
    """Determine severity level based on secret type."""
    high_risk = ['aws_access_key', 'aws_secret_key_like', 'private_key', 'ssh_private_key']
    medium_risk = ['jwt_like', 'github_token', 'stripe_secret', 'google_api_key']
    low_risk = ['bearer_token_header', 'basic_auth_inline', 'generic_key']
    
    if secret_type in high_risk:
        return 'HIGH'
    elif secret_type in medium_risk:
        return 'MEDIUM'
    elif secret_type in low_risk:
        return 'LOW'
    else:
        return 'INFO'

def get_secret_description(secret_type):
    """Get human-readable description of the secret type."""
    descriptions = {
        'jwt_like': 'JSON Web Token - May contain sensitive user data or authentication info',
        'aws_access_key': 'AWS Access Key - Provides access to AWS services and resources',
        'aws_secret_key_like': 'AWS Secret Key - Critical credential for AWS authentication',
        'github_token': 'GitHub Personal Access Token - Grants access to GitHub repositories',
        'stripe_secret': 'Stripe Secret Key - Allows processing payments and accessing customer data',
        'google_api_key': 'Google API Key - Provides access to Google Cloud services',
        'private_key': 'Private Key - Critical cryptographic key for authentication/encryption',
        'ssh_private_key': 'SSH Private Key - Allows server access and authentication',
        'bearer_token_header': 'Bearer Token - Authentication token found in headers',
        'basic_auth_inline': 'Basic Authentication - Username/password in URL',
        'generic_key': 'Generic API Key/Secret - Potentially sensitive credential',
        'base64_like': 'Base64-encoded String - May contain encoded credentials'
    }
    return descriptions.get(secret_type, 'Unknown secret type detected')

def get_remediation_advice(secret_type):
    """Get remediation advice for the secret type."""
    advice = {
        'jwt_like': 'Revoke and regenerate JWT tokens. Implement proper token expiration.',
        'aws_access_key': 'URGENT: Rotate AWS keys immediately. Review CloudTrail logs for unauthorized access.',
        'aws_secret_key_like': 'URGENT: Rotate AWS credentials immediately. Check for unauthorized resource usage.',
        'github_token': 'Revoke token in GitHub settings. Generate new token with minimal required permissions.',
        'stripe_secret': 'Rotate Stripe keys immediately. Review transaction logs for unauthorized activity.',
        'google_api_key': 'Regenerate API key. Restrict key usage to specific IPs/domains if possible.',
        'private_key': 'Replace private key immediately. Update all systems using this key.',
        'ssh_private_key': 'Replace SSH key pair. Remove old public key from all authorized_keys files.',
        'bearer_token_header': 'Invalidate current tokens. Implement proper token rotation.',
        'basic_auth_inline': 'Remove credentials from URLs. Use proper authentication headers.',
        'generic_key': 'Rotate the credential. Review access logs for unauthorized usage.',
        'base64_like': 'Verify if this contains sensitive data. Rotate if it\'s a credential.'
    }
    return advice.get(secret_type, 'Review and rotate this credential if sensitive.')

def scan_text_for_patterns(text, source_info, min_token_length=40):
    """
    Scan `text` for PATTERNS and fallback base64-like tokens.
    Each finding includes enhanced metadata for actionable results.
    """
    findings = []
    if not text:
        return findings
    
    for name, regex in PATTERNS.items():
        for m in regex.finditer(text):
            matched = None
            groups = m.groups()
            if groups:
                matched = next((g for g in groups if g), m.group(0))
            else:
                matched = m.group(0)
            
            start = m.start()
            line, col = line_col_from_index(text, start)
            context = text[max(0, start - 80): m.end() + 80].replace("\n", " ")
            
            # Enhanced finding with actionable data
            f = {
                "id": f"{name}_{hash(matched + str(start)) % 10000}",
                "type": name,
                "severity": get_secret_severity(name),
                "description": get_secret_description(name),
                "match": matched[:50] + "..." if len(matched) > 50 else matched,  # Truncate long matches
                "match_length": len(matched),
                "context": context,
                "snippet": context[:200],
                "remediation": get_remediation_advice(name),
                "confidence": "HIGH" if name != "base64_like" else "MEDIUM",
                "source": dict(source_info, line=line, col=col),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            findings.append(f)
    
    # Enhanced base64-like detection with better heuristics
    for m in BASE64_LIKE.finditer(text):
        piece = m.group(0)
        if is_suspicious_token(piece, min_len=min_token_length):
            start = m.start()
            line, col = line_col_from_index(text, start)
            context = text[max(0, start - 80): m.end() + 80].replace("\n", " ")
            
            # Determine confidence based on context
            confidence = "LOW"
            if any(keyword in context.lower() for keyword in ['key', 'token', 'secret', 'auth', 'api']):
                confidence = "MEDIUM"
            if any(keyword in context.lower() for keyword in ['password', 'credential', 'private']):
                confidence = "HIGH"
            
            f = {
                "id": f"base64_{hash(piece + str(start)) % 10000}",
                "type": "base64_like",
                "severity": "INFO" if confidence == "LOW" else "MEDIUM",
                "description": get_secret_description("base64_like"),
                "match": piece[:50] + "..." if len(piece) > 50 else piece,
                "match_length": len(piece),
                "context": context,
                "snippet": context[:200],
                "remediation": get_remediation_advice("base64_like"),
                "confidence": confidence,
                "source": dict(source_info, line=line, col=col),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            findings.append(f)
    
    return findings

def unique_keep_order(seq):
    seen = set()
    out = []
    for item in seq:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out

def inspect_client_with_playwright(target_url, timeout=20000):
    data = {}
    if not PLAYWRIGHT_AVAILABLE:
        return {"error": "playwright not installed"}
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()
            page.goto(target_url, timeout=timeout)
            try:
                page.wait_for_load_state("networkidle", timeout=timeout)
            except Exception:
                pass
            data["cookies"] = context.cookies()
            data["localStorage"] = page.evaluate("""() => {
                const r = {};
                for (let i=0;i<localStorage.length;i++){
                    const k = localStorage.key(i);
                    r[k] = localStorage.getItem(k);
                }
                return r;
            }""")
            data["sessionStorage"] = page.evaluate("""() => {
                const r = {};
                for (let i=0;i<sessionStorage.length;i++){
                    const k = sessionStorage.key(i);
                    r[k] = sessionStorage.getItem(k);
                }
                return r;
            }""")
            try:
                idx = page.evaluate("""() => {
                    if (!window.indexedDB) return [];
                    if (indexedDB.databases) {
                        return indexedDB.databases().then(dbs => dbs.map(x => x.name));
                    }
                    return [];
                }""")
                data["indexedDB"] = idx
            except Exception as e:
                data["indexedDB_error"] = f"could not enumerate indexedDB: {e}"
            browser.close()
    except Exception as e:
        # Playwright errors can be transient or environment-based
        data["error"] = str(e)
    return data

def crawl_and_scan(url, depth=2, do_playwright=True, min_token_length=30, request_delay=0.5):
    scan_start_time = datetime.now(timezone.utc)
    results = {
        "scan_info": {
            "target_url": url,
            "scan_id": f"scan_{int(scan_start_time.timestamp())}",
            "scanned_at": scan_start_time.isoformat(),
            "scanner_version": "1.0.0",
            "scan_parameters": {
                "depth": depth,
                "playwright_enabled": do_playwright,
                "min_token_length": min_token_length,
                "request_delay": request_delay
            }
        },
        "url": url,
        "scanned_at": scan_start_time.isoformat(),
        "pages": [],
        "js_files": [],
        "client_storage": {},
        "scan_statistics": {
            "pages_scanned": 0,
            "js_files_scanned": 0,
            "total_findings": 0,
            "high_severity_findings": 0,
            "medium_severity_findings": 0,
            "low_severity_findings": 0,
            "errors_encountered": 0
        }
    }
    visited = set()
    to_fetch = [(url, 0)]
    max_pages = MAX_CRAWL_PAGES if 'MAX_CRAWL_PAGES' in globals() else 100
    
    while to_fetch and len(visited) < max_pages:
        cur_url, level = to_fetch.pop(0)
        if cur_url in visited or level > depth:
            continue
        visited.add(cur_url)
        
        try:
            status, html, headers = fetch_url(cur_url, request_delay)
        except Exception as e:
            # Handle any unexpected errors in fetch_url
            status, html, headers = None, None, {"error": str(e)}
            
        page_res = {"url": cur_url, "status": status, "headers": dict(headers or {}), "findings": [], "scripts": []}
        
        if html:
            try:
                page_res["findings"].extend(scan_text_for_patterns(html, {"type": "page", "url": cur_url}, min_token_length))
                scripts = extract_script_urls(html, cur_url)
                for kind, s in scripts:
                    if kind == "external":
                        page_res["scripts"].append({"type": "external", "src": s})
                    else:
                        snippet = (s[:200] + "...") if len(s) > 200 else s
                        page_res["scripts"].append({"type": "inline", "content_snippet": snippet})
                        
                # Scan for inline script content
                for script_info in scripts:
                    if script_info[0] == "inline" and script_info[1]:
                        page_res["findings"].extend(scan_text_for_patterns(script_info[1], {"type": "inline-js", "url": cur_url}, min_token_length))
                        
                soup = BeautifulSoup(html, "html.parser")
                anchors = soup.find_all("a", href=True)
                base_host = urlparse(url).netloc
                for a in anchors:
                    href = a["href"]
                    full = urljoin(cur_url, href)
                    parsed_full = urlparse(full)
                    if (parsed_full.netloc == base_host and 
                        full not in visited and 
                        len(to_fetch) < max_pages and
                        not any(full.lower().endswith(ext) for ext in getattr(globals().get('EXCLUDED_EXTENSIONS', set()), '__iter__', lambda: []))):
                        to_fetch.append((full, level + 1))
            except Exception as e:
                # Handle parsing errors gracefully
                page_res["error"] = f"Error processing page: {str(e)}"
                
        results["pages"].append(page_res)
        results["scan_statistics"]["pages_scanned"] += 1

    # fetch + scan external JS files
    js_urls = []
    for p in results["pages"]:
        for s in p["scripts"]:
            if s["type"] == "external":
                js_urls.append(s["src"])
    js_urls = unique_keep_order(js_urls)
    
    for js in js_urls:
        try:
            status, text, headers = fetch_url(js, request_delay)
            js_res = {"url": js, "status": status, "headers": dict(headers or {}), "findings": []}
            if text:
                js_res["findings"].extend(scan_text_for_patterns(text, {"type": "js", "url": js}, min_token_length))
            results["js_files"].append(js_res)
        except Exception as e:
            # Handle JS file fetch errors
            js_res = {"url": js, "status": None, "headers": {}, "findings": [], "error": str(e)}
            results["js_files"].append(js_res)

    # inspect HTML attributes / meta / hidden inputs with tag+attr source info
    for p in results["pages"]:
        try:
            if p.get("status") and p["status"] < 400:
                # Re-use the HTML we already fetched instead of fetching again
                html_content = None
                
                # Try to get HTML from the page we already processed
                if "error" not in p:
                    try:
                        status, html_content, _ = fetch_url(p["url"], request_delay)
                    except:
                        continue
                        
                if html_content:
                    soup = BeautifulSoup(html_content, "html.parser")
                    
                    # Scan meta tags
                    for meta in soup.find_all("meta"):
                        for attr in ["content", "name", "value"]:
                            v = meta.get(attr)
                            if v and len(str(v).strip()) > 3:
                                source = {"type": "html-attr", "url": p["url"], "tag": "meta", "attr": attr}
                                p["findings"].extend(scan_text_for_patterns(str(v), source, min_token_length))
                    
                    # Scan interesting attributes
                    for tag in soup.find_all(True):
                        for k, v in tag.attrs.items():
                            if isinstance(v, (list, tuple)):
                                v = " ".join(str(x) for x in v)
                            if (v and len(str(v).strip()) > 3 and 
                                (k.lower().startswith("data-") or 
                                 k.lower() in ["value", "content", "placeholder", "alt", "title", "href", "src"])):
                                source = {"type": "html-attr", "url": p["url"], "tag": tag.name, "attr": k}
                                p["findings"].extend(scan_text_for_patterns(str(v), source, min_token_length))
                    
                    # Scan hidden inputs
                    for hidden in soup.find_all("input", {"type": "hidden"}):
                        val = hidden.get("value")
                        if val and len(str(val).strip()) > 3:
                            source = {"type": "html-attr", "url": p["url"], "tag": "input", "attr": "value"}
                            p["findings"].extend(scan_text_for_patterns(str(val), source, min_token_length))
        except Exception as e:
            # Add error info but don't crash
            p["attr_scan_error"] = str(e)

    # client-side storage checks with Playwright
    if do_playwright:
        if not PLAYWRIGHT_AVAILABLE:
            results["client_storage"]["error"] = "playwright not available"
        else:
            try:
                client_data = inspect_client_with_playwright(url)
                results["client_storage"].update(client_data)
                
                if "error" not in client_data:
                    ls = client_data.get("localStorage") or {}
                    ss = client_data.get("sessionStorage") or {}
                    ls_findings = []
                    ss_findings = []
                    
                    for k, v in ls.items():
                        if v and len(str(v).strip()) > 3:
                            src = {"type": "client-storage", "url": url, "storage": "localStorage", "key": k}
                            ls_findings.extend(scan_text_for_patterns(str(v), src, min_token_length))
                    
                    for k, v in ss.items():
                        if v and len(str(v).strip()) > 3:
                            src = {"type": "client-storage", "url": url, "storage": "sessionStorage", "key": k}
                            ss_findings.extend(scan_text_for_patterns(str(v), src, min_token_length))
                    
                    results["client_storage"]["localStorage_findings"] = ls_findings
                    results["client_storage"]["sessionStorage_findings"] = ss_findings
            except Exception as e:
                results["client_storage"]["error"] = f"Playwright scan failed: {str(e)}"

    # Calculate comprehensive statistics and summary
    summary = defaultdict(int)
    severity_counts = defaultdict(int)
    all_findings = []
    
    try:
        # Collect all findings
        for p in results["pages"]:
            for f in p.get("findings", []):
                if "type" in f:
                    summary[f["type"]] += 1
                    severity_counts[f.get("severity", "UNKNOWN")] += 1
                    all_findings.append(f)
        
        for j in results["js_files"]:
            for f in j.get("findings", []):
                if "type" in f:
                    summary[f["type"]] += 1
                    severity_counts[f.get("severity", "UNKNOWN")] += 1
                    all_findings.append(f)
        
        for key in ("localStorage_findings", "sessionStorage_findings"):
            if key in results["client_storage"]:
                for f in results["client_storage"][key]:
                    if "type" in f:
                        summary[f["type"]] += 1
                        severity_counts[f.get("severity", "UNKNOWN")] += 1
                        all_findings.append(f)
        
        # Update statistics
        results["scan_statistics"]["total_findings"] = len(all_findings)
        results["scan_statistics"]["high_severity_findings"] = severity_counts.get("HIGH", 0)
        results["scan_statistics"]["medium_severity_findings"] = severity_counts.get("MEDIUM", 0)
        results["scan_statistics"]["low_severity_findings"] = severity_counts.get("LOW", 0)
        
        # Add scan completion info
        scan_end_time = datetime.now(timezone.utc)
        results["scan_info"]["completed_at"] = scan_end_time.isoformat()
        results["scan_info"]["duration_seconds"] = (scan_end_time - scan_start_time).total_seconds()
        
        # Enhanced summary with risk assessment
        results["summary"] = dict(summary)
        results["risk_assessment"] = {
            "overall_risk": "HIGH" if severity_counts.get("HIGH", 0) > 0 else 
                           "MEDIUM" if severity_counts.get("MEDIUM", 0) > 0 else 
                           "LOW" if len(all_findings) > 0 else "NONE",
            "critical_findings": severity_counts.get("HIGH", 0),
            "total_secrets_found": len(all_findings),
            "unique_secret_types": len(summary),
            "recommendations": generate_recommendations(all_findings)
        }
        
    except Exception as e:
        results["summary_error"] = str(e)
    
    return results

def generate_recommendations(findings):
    """Generate actionable recommendations based on findings."""
    recommendations = []
    
    if not findings:
        return ["No secrets detected. Continue monitoring for exposed credentials."]
    
    high_severity = [f for f in findings if f.get("severity") == "HIGH"]
    if high_severity:
        recommendations.append("URGENT: High-severity credentials detected. Rotate immediately.")
    
    aws_findings = [f for f in findings if "aws" in f.get("type", "")]
    if aws_findings:
        recommendations.append("AWS credentials found. Check CloudTrail for unauthorized access.")
    
    jwt_findings = [f for f in findings if "jwt" in f.get("type", "")]
    if jwt_findings:
        recommendations.append("JWT tokens detected. Verify token expiration and scope.")
    
    github_findings = [f for f in findings if "github" in f.get("type", "")]
    if github_findings:
        recommendations.append("GitHub tokens found. Review repository access permissions.")
    
    if len(findings) > 10:
        recommendations.append("Multiple secrets detected. Implement secrets scanning in CI/CD.")
    
    recommendations.append("Review all findings and implement proper secrets management.")
    return recommendations

def main():
    parser = argparse.ArgumentParser(
        description="Secret Scanner - Web Application Security Scanner",
        epilog="Use responsibly and only on systems you are authorized to test."
    )
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--no-playwright", action="store_true", help="Disable Playwright client-side checks")
    parser.add_argument("--depth", type=int, default=2, help="Same-host crawl depth (default: 2)")
    parser.add_argument("--output", default=None, help="Write JSON output to file (default: Results/secret_scanner.json)")
    parser.add_argument("--min-token-length", type=int, default=30, help="Minimum length for base64-like token heuristic (default: 30)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests in seconds (default: 0.5)")
    parser.add_argument("--html-report", action="store_true", help="Generate HTML report in addition to JSON")
    parser.add_argument("--format", choices=["json", "html", "both"], default="json", help="Output format (default: json)")
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging(args.verbose)

    do_playwright = not args.no_playwright and PLAYWRIGHT_AVAILABLE
    if not PLAYWRIGHT_AVAILABLE and not args.no_playwright:
        print("[!] Playwright not available; client-side checks will be skipped unless you install Playwright.")

    logger.info(f"Starting scan of {args.url} (depth={args.depth}, playwright={do_playwright})")
    
    # Validate URL
    try:
        parsed = urlparse(args.url)
        if not parsed.scheme or not parsed.netloc:
            logger.error("Invalid URL provided")
            sys.exit(1)
    except Exception as e:
        logger.error(f"Error parsing URL: {e}")
        sys.exit(1)
    
    print(f"[+] Scanning {args.url} (depth={args.depth})  playwright={do_playwright}")
    res = crawl_and_scan(args.url, depth=args.depth, do_playwright=do_playwright, min_token_length=args.min_token_length, request_delay=args.delay)

    # print summary
    print("\nSummary findings:")
    for k, v in res.get("summary", {}).items():
        print(f" - {k}: {v}")

    # per-page findings (safe snippet fallback already guaranteed)
    for p in res["pages"]:
        if p.get("findings"):
            print(f"\n[PAGE] {p['url']} (status={p.get('status')})")
            for f in p["findings"]:
                src = f.get("source", {})
                loc = f"{src.get('type')} @ {src.get('url')}"
                if src.get("tag"):
                    loc += f" tag={src.get('tag')}"
                if src.get("attr"):
                    loc += f" attr={src.get('attr')}"
                if src.get("line"):
                    loc += f" line={src.get('line')} col={src.get('col')}"
                snippet = f.get("snippet", (f.get("context") or "")[:200])
                print(f"  * {f.get('type')} -> {f.get('match')}\n    location: {loc}\n    snippet: {snippet}\n")

    # JS files
    for j in res["js_files"]:
        if j.get("findings"):
            print(f"\n[JS] {j['url']} (status={j.get('status')})")
            for f in j["findings"]:
                src = f.get("source", {})
                loc = f"{src.get('type')} @ {src.get('url')}"
                if src.get("line"):
                    loc += f" line={src.get('line')} col={src.get('col')}"
                snippet = f.get("snippet", (f.get("context") or "")[:200])
                print(f"  * {f.get('type')} -> {f.get('match')}\n    location: {loc}\n    snippet: {snippet}\n")

    # client storage summary + findings
    if res.get("client_storage"):
        print("\nClient storage inspection:")
        cs = res["client_storage"]
        if "cookies" in cs:
            print(f"  cookies: {len(cs['cookies'])} entries")
        if "localStorage" in cs:
            try:
                keys = list(cs["localStorage"].keys())
                print(f"  localStorage keys: {keys[:10]}{'...' if len(keys) > 10 else ''}")
            except Exception:
                print("  localStorage: present")
        if "sessionStorage" in cs:
            try:
                keys = list(cs["sessionStorage"].keys())
                print(f"  sessionStorage keys: {keys[:10]}{'...' if len(keys) > 10 else ''}")
            except Exception:
                print("  sessionStorage: present")
        if cs.get("localStorage_findings"):
            print("  localStorage findings:")
            for f in cs["localStorage_findings"]:
                snippet = f.get("snippet", (f.get("context") or "")[:200])
                print(f"   * {f.get('type')} -> key={f['source'].get('key')} snippet={snippet}")
        if cs.get("sessionStorage_findings"):
            print("  sessionStorage findings:")
            for f in cs["sessionStorage_findings"]:
                snippet = f.get("snippet", (f.get("context") or "")[:200])
                print(f"   * {f.get('type')} -> key={f['source'].get('key')} snippet={snippet}")

    # write JSON output (atomic write). If --output provided, use it; otherwise write to Results/secrect_scanner.json
    if args.output:
        out_path = args.output
    else:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        results_dir = os.path.join(script_dir, "Results")
        try:
            os.makedirs(results_dir, exist_ok=True)
        except Exception as e:
            print("[!] Could not create Results directory:", e)
            results_dir = script_dir  # fallback
        out_path = os.path.join(results_dir, "secret_scanner.json")

    try:
        # Write JSON output
        dir_for_temp = os.path.dirname(out_path) or "."
        with tempfile.NamedTemporaryFile("w", delete=False, dir=dir_for_temp, encoding="utf-8") as tmpf:
            json.dump(res, tmpf, indent=2, ensure_ascii=False, default=str)
            tmp_name = tmpf.name
        os.replace(tmp_name, out_path)
        print(f"\n[+] JSON output written to {out_path}")
        
        # Generate HTML report if requested
        if args.html_report or args.format in ["html", "both"]:
            try:
                from report_generator import generate_html_report
                html_path = out_path.replace('.json', '.html')
                generate_html_report(res, html_path)
                print(f"[+] HTML report written to {html_path}")
            except ImportError:
                print("[!] HTML report generation requires report_generator.py")
            except Exception as e:
                print(f"[!] Could not generate HTML report: {e}")
                
    except Exception as e:
        print("[!] Could not write output file:", e)

if __name__ == "__main__":
    main()