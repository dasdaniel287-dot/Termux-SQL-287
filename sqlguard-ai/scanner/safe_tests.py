"""
Safe Testing Engine for SQLGuard AI.
Performs strictly controlled, harmless, non-destructive security checks.
Enforces strict rate limits, redirect boundaries, timeouts, and error circuit-breakers.
"""

import time
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import Dict, Any, List, Optional, Tuple, Callable
from .severity import Finding, Severity, Confidence
from .response_analyzer import ResponseAnalyzer
from .passive_checks import PassiveScanner, TargetValidationError

# Non-destructive test probes designed ONLY to test parser boundary integrity
HARMLESS_PROBES = [
    {
        "name": "Benign Single Delimiter Probe",
        "probe_val": "'",
        "type": "single_quote_boundary",
        "description": "Tests if unescaped single quote breaks query syntax tree."
    },
    {
        "name": "Benign Balanced Literal Probe",
        "probe_val": "''",
        "type": "paired_quote_balance",
        "description": "Tests if doubling the quote literal balances SQL syntax."
    },
    {
        "name": "Benign Double Delimiter Probe",
        "probe_val": "\"",
        "type": "double_quote_boundary",
        "description": "Tests identifier quote handling in ANSI SQL engines."
    }
]


class SafeActiveEngine:
    def __init__(
        self,
        timeout: float = 5.0,
        rate_limit_delay: float = 0.35,
        max_requests_per_endpoint: int = 12,
        stop_on_repeated_errors: int = 3,
        user_agent: Optional[str] = None
    ):
        self.timeout = timeout
        self.rate_limit_delay = rate_limit_delay
        self.max_requests_per_endpoint = max_requests_per_endpoint
        self.stop_on_repeated_errors = stop_on_repeated_errors
        self.user_agent = user_agent or "SQLGuard-AI-Defensive-Scanner/2026.1 (Android-Termux)"
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml,application/json;q=0.9,*/*;q=0.8"
        })

    def _safe_request(
        self,
        url: str,
        initial_host: str,
        progress_callback: Optional[Callable[[str], None]] = None
    ) -> requests.Response:
        """
        Executes HTTP request with SSRF redirect verification and timeouts.
        Re-validates each redirect hop to guarantee requests cannot leave the authorized target.
        """
        # We manually manage redirects to prevent SSRF
        current_url = url
        for redirect_count in range(4):
            parsed_current = urlparse(current_url)
            if parsed_current.netloc.lower() != initial_host.lower():
                raise TargetValidationError(
                    f"Redirect blocked: Destination '{parsed_current.netloc}' deviates from authorized host '{initial_host}'."
                )

            time.sleep(self.rate_limit_delay)
            resp = self.session.get(
                current_url,
                timeout=self.timeout,
                allow_redirects=False
            )

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location")
                if not location:
                    break
                # Handle relative redirects
                if not location.startswith(("http://", "https://")):
                    location = f"{parsed_current.scheme}://{parsed_current.netloc}/{location.lstrip('/')}"
                current_url = location
                if progress_callback:
                    progress_callback(f"Following authorized redirect hop #{redirect_count + 1}...")
                continue
            else:
                return resp

        return resp

    def run_safe_assessment(
        self,
        target_url: str,
        is_authorized: bool,
        progress_callback: Optional[Callable[[str], None]] = None
    ) -> List[Finding]:
        """
        Executes non-destructive, safe testing against authorized URL parameters.
        """
        if not is_authorized:
            raise PermissionError("Assessment aborted: Explicit target ownership or written authorization is required.")

        findings: List[Finding] = []
        normalized_url = PassiveScanner.normalize_url(target_url)
        initial_host = urlparse(normalized_url).netloc

        if progress_callback:
            progress_callback(f"Establishing baseline response for {PassiveScanner.redact_url(normalized_url)}...")

        # Step 1: Establish baseline
        try:
            baseline_resp = self._safe_request(normalized_url, initial_host, progress_callback)
            baseline_status = baseline_resp.status_code
            baseline_text = baseline_resp.text
            baseline_len = len(baseline_text)
        except Exception as e:
            if progress_callback:
                progress_callback(f"Failed to establish baseline: {str(e)}")
            raise ConnectionError(f"Could not connect to target: {e}")

        parsed = urlparse(normalized_url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            if progress_callback:
                progress_callback("No URL parameters available for active boundary probing.")
            return findings

        consecutive_errors = 0
        total_requests = 1

        for param_name, current_values in params.items():
            original_val = current_values[0] if current_values else ""
            if progress_callback:
                progress_callback(f"Reviewing parameter '{param_name}' with safe non-destructive probes...")

            probe_results = {}

            for probe in HARMLESS_PROBES:
                if total_requests >= self.max_requests_per_endpoint:
                    if progress_callback:
                        progress_callback(f"Reached safety request limit ({self.max_requests_per_endpoint}) for this endpoint.")
                    break

                if consecutive_errors >= self.stop_on_repeated_errors:
                    if progress_callback:
                        progress_callback(f"Circuit breaker tripped: Stopped testing due to {consecutive_errors} consecutive failures.")
                    break

                test_val = f"{original_val}{probe['probe_val']}"
                modified_params = dict(params)
                modified_params[param_name] = [test_val]
                encoded_query = urlencode(modified_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, encoded_query, ""))

                try:
                    total_requests += 1
                    resp = self._safe_request(test_url, initial_host, progress_callback)
                    probe_results[probe["type"]] = resp
                    consecutive_errors = 0
                except Exception as e:
                    consecutive_errors += 1
                    if progress_callback:
                        progress_callback(f"Probe request warning: {e}")
                    continue

                # Analyze response for errors or behavioral divergence
                finding = ResponseAnalyzer.analyze_differential(
                    baseline_status=baseline_status,
                    baseline_length=baseline_len,
                    baseline_content=baseline_text,
                    probe_status=resp.status_code,
                    probe_length=len(resp.text),
                    probe_content=resp.text,
                    param_name=param_name,
                    probe_type=probe["type"],
                    target_url=PassiveScanner.redact_url(normalized_url)
                )

                if finding:
                    # Check if balanced probe healed the syntax error (conclusive verification)
                    if probe["type"] == "single_quote_boundary" and "paired_quote_balance" in probe_results:
                        paired_resp = probe_results["paired_quote_balance"]
                        paired_errors = ResponseAnalyzer.detect_sql_errors(paired_resp.text)
                        if not paired_errors and paired_resp.status_code == baseline_status:
                            finding.confidence = Confidence.CONFIRMED
                            finding.evidence += " | Confirmatory probe: doubling quote delimiter successfully restored valid SQL syntax."

                    findings.append(finding)
                    if progress_callback:
                        progress_callback(f"[!] Finding identified on parameter '{param_name}': {finding.title}")
                    # Once a high-confidence finding is documented for a parameter, avoid redundant requests
                    break

        return findings
