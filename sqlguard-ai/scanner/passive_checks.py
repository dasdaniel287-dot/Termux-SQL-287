"""
Passive Security Checks Engine for SQLGuard AI.
Performs surface reconnaissance, URL normalization, parameter discovery,
and SSRF / Private Network validation WITHOUT sending aggressive or destructive payloads.
"""

import ipaddress
import re
import socket
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlunparse
from .severity import Finding, Severity, Confidence

COMMON_SQL_PARAMS = {
    "id", "user", "userid", "user_id", "username", "account",
    "cat", "category", "item", "product", "sku", "article",
    "search", "q", "query", "filter", "find", "keyword",
    "sort", "order", "orderby", "order_by", "dir", "direction",
    "page", "p", "offset", "limit", "rows", "num",
    "select", "column", "table", "field", "group"
}

SENSITIVE_PARAM_NAMES = {
    "password", "pass", "pwd", "secret", "token", "auth",
    "key", "api_key", "session", "pin", "ssn", "creditcard"
}


class TargetValidationError(Exception):
    """Raised when a target fails safety or authorization boundaries."""
    pass


class PassiveScanner:
    def __init__(self, allow_local_lab: bool = True):
        self.allow_local_lab = allow_local_lab

    @staticmethod
    def normalize_url(url: str) -> str:
        """Validates and normalizes target URL."""
        if not url:
            raise TargetValidationError("URL cannot be empty.")
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        parsed = urlparse(url)
        if not parsed.netloc:
            raise TargetValidationError(f"Invalid URL structure: {url}")
        # Clean path & keep clean scheme
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path or "/"
        normalized = urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))
        return normalized

    def validate_target_safety(self, url: str) -> Tuple[bool, str]:
        """
        Validates target against SSRF and private IP boundaries.
        In external mode, private IPs and loopbacks are rejected.
        In local lab mode, localhost/127.0.0.1 is permitted for defensive training.
        """
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            raise TargetValidationError("Hostname could not be extracted from URL.")

        # Check if hostname resolves to private or loopback IP
        is_loopback = hostname in ("localhost", "127.0.0.1", "::1")
        try:
            ip_str = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip_str)
            is_private = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
        except Exception:
            # If resolution fails in Termux, check string representation
            if is_loopback:
                is_private = True
            else:
                is_private = False

        if is_loopback or is_private:
            if not self.allow_local_lab:
                raise TargetValidationError(
                    f"Blocked SSRF/Private target '{hostname}'. Private networks are restricted "
                    f"unless --lab or --allow-local is explicitly authorized."
                )
            return True, f"Target '{hostname}' approved under Controlled Local Lab policy."

        return True, f"Target '{hostname}' validated for authorized assessment."

    @staticmethod
    def redact_url(url: str) -> str:
        """Redacts sensitive query parameters from URLs before logging or reporting."""
        parsed = urlparse(url)
        if not parsed.query:
            return url
        params = parse_qs(parsed.query, keep_blank_values=True)
        cleaned_params = []
        for key, vals in params.items():
            if key.lower() in SENSITIVE_PARAM_NAMES:
                cleaned_params.append(f"{key}=[REDACTED]")
            else:
                for v in vals:
                    cleaned_params.append(f"{key}={v}")
        new_query = "&".join(cleaned_params)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, ""))

    def inspect_url_surface(self, url: str) -> List[Finding]:
        """Passive analysis of URL parameters for SQL injection exposure points."""
        findings: List[Finding] = []
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        if not query_params:
            findings.append(
                Finding(
                    id="INFO-SURFACE-001",
                    title="No Query Parameters Observed on Endpoint",
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.CONFIRMED,
                    category="Reconnaissance",
                    endpoint=self.redact_url(url),
                    parameter=None,
                    description="The tested endpoint URL contains no query string parameters. Active SQL testing requires parameter inputs or form bodies.",
                    evidence=f"Target URL: {self.redact_url(url)}",
                    remediation="Verify if API endpoints accept POST bodies or other URL query parameters for dynamic database lookups.",
                    secure_code_example="# No parameter binding needed if no user inputs are handled.",
                    verification_steps="Check API documentation for endpoints taking input parameters.",
                )
            )
            return findings

        for param_name, values in query_params.items():
            is_suspicious_param = param_name.lower() in COMMON_SQL_PARAMS
            findings.append(
                Finding(
                    id=f"INFO-PARAM-{param_name.upper()}",
                    title=f"Database Query Surface Identified: '{param_name}'",
                    severity=Severity.LOW if is_suspicious_param else Severity.INFORMATIONAL,
                    confidence=Confidence.CONFIRMED,
                    category="Attack Surface Discovery",
                    endpoint=self.redact_url(url),
                    parameter=param_name,
                    description=(
                        f"The parameter '{param_name}' appears to pass dynamic filtering, lookup, or ordering values "
                        f"to the server application. In poorly defended applications, parameters named '{param_name}' "
                        f"are frequently concatenated directly into SQL query strings."
                    ),
                    evidence=f"Observed query parameter: {param_name}={values[0] if values else ''}",
                    remediation="Ensure this parameter is handled using parameterized SQL queries and strict input type validation.",
                    secure_code_example=(
                        "# Safe Parameter Handling in Python:\n"
                        "cursor.execute('SELECT * FROM items WHERE category = ?', (category_param,))"
                    ),
                    verification_steps="Ensure unit tests confirm SQL syntax errors cannot be induced through this parameter.",
                )
            )

        return findings
