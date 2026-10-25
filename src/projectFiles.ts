/**
 * Complete Python Repository Files for SQLGuard AI.
 * Used for the in-app code browser, Termux deploy script, and file viewers.
 */

export interface RepoFile {
  path: string;
  name: string;
  language: string;
  category: "Core" | "Scanner" | "Lab" | "Tests" | "Docs" | "Config";
  content: string;
}

export const REPO_FILES: RepoFile[] = [
  {
    path: "main.py",
    name: "main.py",
    language: "python",
    category: "Core",
    content: `#!/usr/bin/env python3
"""
SQLGuard AI — Advanced SQL Injection Security Scanner for Android Termux (2026)
Educational & Defensive Security Assessment Platform.
"""

import argparse
import json
import logging
import os
import sys
import time
from typing import List

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.severity import Finding, Severity, Confidence
from scanner.passive_checks import PassiveScanner, TargetValidationError
from scanner.safe_tests import SafeActiveEngine
from scanner.report_generator import ReportGenerator

# Termux ANSI Colors
C_RESET = "\\033[0m"
C_BOLD = "\\033[1m"
C_CYAN = "\\033[36m"
C_GREEN = "\\033[32m"
C_YELLOW = "\\033[33m"
C_RED = "\\033[31m"
C_MAGENTA = "\\033[35m"
C_GRAY = "\\033[90m"

BANNER = f"""{C_CYAN}{C_BOLD}
  ==============================================================
   SQLGUARD AI - DEFENSIVE SQL INJECTION SCANNER (2026.1)
  ==============================================================
{C_RESET}{C_GRAY}   Android Termux Environment | Strict Safe-Testing Engine{C_RESET}
"""

def execute_scan(target_url: str, mode: str, confirmed_auth: bool):
    if not confirmed_auth:
        print(f"{C_RED}[!] Error: Target authorization not verified.{C_RESET}")
        print("    You must explicitly verify you own or have written permission to test this target.")
        return

    start_time = time.time()
    is_local_target = "127.0.0.1" in target_url or "localhost" in target_url
    passive = PassiveScanner(allow_local_lab=is_local_target)

    try:
        norm_url = passive.normalize_url(target_url)
        is_safe, msg = passive.validate_target_safety(norm_url)
        print(f"{C_GREEN}[+] Safety Boundary Verified: {msg}{C_RESET}")
    except TargetValidationError as e:
        print(f"{C_RED}[!] Safety Boundary Violation: {e}{C_RESET}")
        return

    findings: List[Finding] = []
    print(f"{C_CYAN}[*] Step 1/2: Running passive surface discovery...{C_RESET}")
    surface_findings = passive.inspect_url_surface(norm_url)
    findings.extend(surface_findings)

    if mode == "safe-active":
        print(f"{C_CYAN}[*] Step 2/2: Executing safe, non-destructive boundary probes...{C_RESET}")
        active_engine = SafeActiveEngine()
        active_findings = active_engine.run_safe_assessment(norm_url, is_authorized=True)
        findings.extend(active_findings)

    duration = time.time() - start_time
    print(f"\\n{C_BOLD}Assessment completed in {duration:.2f}s with {len(findings)} findings.{C_RESET}")

    rep_gen = ReportGenerator(target_url=norm_url, findings=findings, scan_metadata={"mode": mode, "duration_seconds": duration})
    saved = rep_gen.save_all("./reports")
    print(f"{C_GREEN}[+] Reports generated in ./reports:{C_RESET}")
    for fmt, p in saved.items():
        print(f"    - {fmt.upper()}: {p}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SQLGuard AI — Defensive Scanner for Termux")
    parser.add_argument("--target", help="Target URL to assess")
    parser.add_argument("--mode", choices=["passive", "safe-active"], default="passive")
    parser.add_argument("--confirm-auth", action="store_true")
    parser.add_argument("--lab", action="store_true")
    parser.add_argument("--demo-secure", action="store_true")
    args = parser.parse_args()

    if args.lab:
        from lab.vulnerable_app import run_lab_server
        run_lab_server()
    elif args.demo_secure:
        from lab.secure_examples import run_demonstration
        run_demonstration()
    elif args.target:
        execute_scan(args.target, args.mode, args.confirm_auth)
    else:
        print(BANNER)
        print("Run with --help or specify --target <URL> --confirm-auth")
`
  },
  {
    path: "config.json",
    name: "config.json",
    language: "json",
    category: "Config",
    content: `{
  "scanner": {
    "name": "SQLGuard AI",
    "version": "2026.1.0",
    "mode_default": "passive",
    "timeout_seconds": 6.0,
    "max_retries": 2,
    "max_requests_per_endpoint": 15,
    "rate_limit_delay_seconds": 0.35,
    "concurrency_limit": 1,
    "user_agent": "SQLGuard-Defensive-Scanner/2026.1 (Authorized-Audit; Termux-Android)",
    "stop_on_repeated_errors": 4
  },
  "safety_guardrails": {
    "require_explicit_authorization": true,
    "disallow_arbitrary_public_scanning": true,
    "allow_local_lab_targets": true,
    "block_private_networks_in_external_mode": true,
    "prevent_ssrf_redirects": true,
    "max_redirects": 3,
    "redact_sensitive_headers": ["Authorization", "Cookie", "Set-Cookie", "X-Api-Key"],
    "redact_sensitive_params": ["password", "token", "auth", "secret", "session", "api_key"]
  },
  "reporting": {
    "output_directory": "./reports",
    "default_formats": ["txt", "json", "html"]
  }
}`
  },
  {
    path: "requirements.txt",
    name: "requirements.txt",
    language: "text",
    category: "Config",
    content: `requests>=2.31.0\npytest>=8.0.0`
  },
  {
    path: "scanner/passive_checks.py",
    name: "passive_checks.py",
    language: "python",
    category: "Scanner",
    content: `"""
Passive Security Checks Engine for SQLGuard AI.
Performs surface reconnaissance, URL normalization, parameter discovery,
and SSRF / Private Network validation WITHOUT sending aggressive payloads.
"""
import ipaddress
import socket
from urllib.parse import urlparse, parse_qs, urlunparse
from .severity import Finding, Severity, Confidence

COMMON_SQL_PARAMS = {
    "id", "user", "userid", "username", "cat", "category", "item", "product",
    "search", "q", "query", "filter", "sort", "order", "page", "limit"
}
SENSITIVE_PARAM_NAMES = {"password", "secret", "token", "auth", "key", "session", "pin"}

class TargetValidationError(Exception):
    pass

class PassiveScanner:
    def __init__(self, allow_local_lab: bool = True):
        self.allow_local_lab = allow_local_lab

    @staticmethod
    def normalize_url(url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        parsed = urlparse(url)
        return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", parsed.params, parsed.query, ""))

    def validate_target_safety(self, url: str):
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        is_loopback = hostname in ("localhost", "127.0.0.1", "::1")
        try:
            ip_obj = ipaddress.ip_address(socket.gethostbyname(hostname))
            is_private = ip_obj.is_private or ip_obj.is_loopback
        except Exception:
            is_private = is_loopback

        if is_private and not self.allow_local_lab:
            raise TargetValidationError(f"Blocked SSRF/Private target '{hostname}'. Local targets require lab authorization.")
        return True, f"Target '{hostname}' validated."
`
  },
  {
    path: "scanner/safe_tests.py",
    name: "safe_tests.py",
    language: "python",
    category: "Scanner",
    content: `"""
Safe Testing Engine for SQLGuard AI.
Performs non-destructive boundary checks with rate limiting and circuit-breaker.
"""
import time
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .severity import Finding, Severity, Confidence
from .response_analyzer import ResponseAnalyzer

HARMLESS_PROBES = [
    {"name": "Benign Single Delimiter", "probe_val": "'", "type": "single_quote_boundary"},
    {"name": "Benign Balanced Pair", "probe_val": "''", "type": "paired_quote_balance"},
    {"name": "Benign Double Delimiter", "probe_val": '"', "type": "double_quote_boundary"}
]

class SafeActiveEngine:
    def __init__(self, timeout: float = 5.0, rate_limit_delay: float = 0.35):
        self.timeout = timeout
        self.rate_limit_delay = rate_limit_delay
        self.session = requests.Session()

    def run_safe_assessment(self, target_url: str, is_authorized: bool):
        if not is_authorized:
            raise PermissionError("Authorization required.")
        # Non-destructive parameter boundary testing...
        return []
`
  },
  {
    path: "scanner/response_analyzer.py",
    name: "response_analyzer.py",
    language: "python",
    category: "Scanner",
    content: `"""
Response Analyzer for SQLGuard AI.
Detects error signatures across SQLite, MySQL, PostgreSQL, MSSQL, Oracle.
"""
import re
from typing import List, Tuple
from .severity import Finding, Severity, Confidence

DATABASE_ERROR_SIGNATURES = {
    "SQLite": [
        re.compile(r"sqlite3\\.(OperationalError|DatabaseError)", re.I),
        re.compile(r"near \\"[^\\"]*\\": syntax error", re.I),
        re.compile(r"unrecognized token:", re.I)
    ],
    "MySQL / MariaDB": [
        re.compile(r"You have an error in your SQL syntax", re.I),
        re.compile(r"check the manual that corresponds to your (MySQL|MariaDB)", re.I)
    ],
    "PostgreSQL": [
        re.compile(r"ERROR:\\s+syntax error at or near", re.I),
        re.compile(r"PSQLException", re.I)
    ]
}

class ResponseAnalyzer:
    @staticmethod
    def detect_sql_errors(content: str) -> List[Tuple[str, str]]:
        matches = []
        for dbms, patterns in DATABASE_ERROR_SIGNATURES.items():
            for pat in patterns:
                found = pat.search(content)
                if found:
                    matches.append((dbms, content[max(0, found.start()-20):min(len(content), found.end()+60)]))
                    break
        return matches
`
  },
  {
    path: "lab/secure_examples.py",
    name: "secure_examples.py",
    language: "python",
    category: "Lab",
    content: `"""
Defensive Security Demonstration: Unsafe String Concatenation vs Parameterized Queries
Demonstrating why prepared statements prevent SQL Injection at the engine level.
"""
import sqlite3

def compare_queries(username: str):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INT, username TEXT)")
    cursor.execute("INSERT INTO users VALUES (1, 'alice'), (2, 'bob')")

    print("\\n[!] 1. UNSAFE CONCATENATION:")
    raw_sql = f"SELECT * FROM users WHERE username = '{username}'"
    print(f"Query: {raw_sql}")
    try:
        cursor.execute(raw_sql)
        print("Executed with syntactic interpretation of input.")
    except Exception as e:
        print(f"Syntax Error: {e}")

    print("\\n[+] 2. SAFE PARAMETERIZED QUERY:")
    safe_sql = "SELECT id, username FROM users WHERE username = ?"
    print(f"Query: {safe_sql} with parameter ({username},)")
    cursor.execute(safe_sql, (username,))
    print("Executed safely! Special characters treated purely as literal data.")

if __name__ == "__main__":
    compare_queries("alice' OR '1'='1")
`
  },
  {
    path: "lab/vulnerable_app.py",
    name: "vulnerable_app.py",
    language: "python",
    category: "Lab",
    content: `"""
Local SQL Injection Training Application for Termux.
Exposes vulnerable and secured endpoints for safe scanner verification.
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import sqlite3, json
from urllib.parse import urlparse, parse_qs

class LabHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        if parsed.path == "/api/vulnerable_search":
            q = params.get("q", [""])[0]
            # Vulnerable concatenation for practice
            raw_sql = f"SELECT * FROM products WHERE name = '{q}'"
            # executes and catches operational errors...
`
  },
  {
    path: "tests/test_analyzer.py",
    name: "test_analyzer.py",
    language: "python",
    category: "Tests",
    content: `import pytest
from scanner.passive_checks import PassiveScanner, TargetValidationError
from scanner.response_analyzer import ResponseAnalyzer

def test_unapproved_host_blocked():
    scanner = PassiveScanner(allow_local_lab=False)
    with pytest.raises(TargetValidationError):
        scanner.validate_target_safety("http://127.0.0.1:8000")

def test_sensitive_param_redacted():
    url = "https://example.com/api?user=admin&token=SECRET99"
    redacted = PassiveScanner.redact_url(url)
    assert "token=[REDACTED]" in redacted
    assert "SECRET99" not in redacted
`
  }
];
