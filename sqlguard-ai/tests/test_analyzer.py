"""
Unit tests for SQLGuard AI URL safety, response analyzer, and defensive controls.
"""

import pytest
from scanner.passive_checks import PassiveScanner, TargetValidationError
from scanner.response_analyzer import ResponseAnalyzer
from scanner.severity import Severity, Confidence


def test_url_normalization():
    # Adding scheme if missing
    norm = PassiveScanner.normalize_url("example.com/search?q=test")
    assert norm.startswith("http://")
    assert "example.com" in norm

    # Preserving https
    norm2 = PassiveScanner.normalize_url("https://secure.internal/api?id=1")
    assert norm2.startswith("https://")


def test_unapproved_private_host_blocked_in_external_mode():
    scanner = PassiveScanner(allow_local_lab=False)
    with pytest.raises(TargetValidationError) as exc:
        scanner.validate_target_safety("http://127.0.0.1:8000/api")
    assert "Blocked SSRF/Private target" in str(exc.value)

    with pytest.raises(TargetValidationError):
        scanner.validate_target_safety("http://localhost:3000")


def test_local_host_allowed_in_lab_mode():
    scanner = PassiveScanner(allow_local_lab=True)
    is_safe, msg = scanner.validate_target_safety("http://127.0.0.1:8000/api")
    assert is_safe is True
    assert "Controlled Local Lab" in msg


def test_sensitive_value_redaction():
    url = "https://app.test/login?user=admin&password=SuperSecretPassword123&token=eyJhbGciOi"
    redacted = PassiveScanner.redact_url(url)
    assert "SuperSecretPassword123" not in redacted
    assert "password=[REDACTED]" in redacted
    assert "token=[REDACTED]" in redacted
    assert "user=admin" in redacted


def test_sqlite_syntax_error_detection():
    error_response = '{"error": "sqlite3.OperationalError: near \\"\'\\": syntax error"}'
    errors = ResponseAnalyzer.detect_sql_errors(error_response)
    assert len(errors) > 0
    assert errors[0][0] == "SQLite"
    assert "syntax error" in errors[0][1]


def test_mysql_syntax_error_detection():
    mysql_response = "Warning: mysql_fetch_array() expects parameter 1: You have an error in your SQL syntax near ''"
    errors = ResponseAnalyzer.detect_sql_errors(mysql_response)
    assert len(errors) > 0
    assert "MySQL" in errors[0][0]


def test_postgres_syntax_error_detection():
    pg_response = "ERROR: syntax error at or near \"'\" at character 45"
    errors = ResponseAnalyzer.detect_sql_errors(pg_response)
    assert len(errors) > 0
    assert errors[0][0] == "PostgreSQL"


def test_differential_analysis_identifies_vulnerability():
    finding = ResponseAnalyzer.analyze_differential(
        baseline_status=200,
        baseline_length=512,
        baseline_content="Clean product results",
        probe_status=500,
        probe_length=320,
        probe_content='{"error": "sqlite3.OperationalError: unrecognized token: \\"\'\\""}',
        param_name="search",
        probe_type="single_quote_boundary",
        target_url="http://127.0.0.1:8000/api/search"
    )
    assert finding is not None
    assert finding.severity == Severity.HIGH
    assert finding.confidence == Confidence.CONFIRMED
    assert finding.parameter == "search"
    assert "SQLite" in finding.evidence


def test_clean_response_yields_no_finding():
    finding = ResponseAnalyzer.analyze_differential(
        baseline_status=200,
        baseline_length=500,
        baseline_content="Product results",
        probe_status=200,
        probe_length=498,
        probe_content="Product results (empty)",
        param_name="id",
        probe_type="single_quote_boundary",
        target_url="http://127.0.0.1:8000/api/products"
    )
    assert finding is None
