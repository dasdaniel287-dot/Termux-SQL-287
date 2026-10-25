"""
Response Analyzer for SQLGuard AI.
Performs signature matching for database errors, differential analysis,
and evidence extraction without revealing sensitive database credentials.
"""

import re
from typing import Dict, Any, List, Optional, Tuple
from .severity import Finding, Severity, Confidence

# Fingerprints for SQL syntax errors across major Relational Database engines
DATABASE_ERROR_SIGNATURES: Dict[str, List[re.Pattern]] = {
    "SQLite": [
        re.compile(r"sqlite3\.(OperationalError|DatabaseError)", re.IGNORECASE),
        re.compile(r"near \"[^\"]*\": syntax error", re.IGNORECASE),
        re.compile(r"unrecognized token: \"[^\"]*\"", re.IGNORECASE),
        re.compile(r"incomplete input", re.IGNORECASE),
        re.compile(r"no such table: [a-zA-Z0-9_]+", re.IGNORECASE),
        re.compile(r"no such column: [a-zA-Z0-9_]+", re.IGNORECASE),
    ],
    "MySQL / MariaDB": [
        re.compile(r"You have an error in your SQL syntax", re.IGNORECASE),
        re.compile(r"check the manual that corresponds to your (MySQL|MariaDB) server version", re.IGNORECASE),
        re.compile(r"Warning: mysql_", re.IGNORECASE),
        re.compile(r"Warning: mysqli_", re.IGNORECASE),
        re.compile(r"MySqlException \(0x[0-9a-fA-F]+\)", re.IGNORECASE),
        re.compile(r"com\.mysql\.jdbc\.exceptions", re.IGNORECASE),
    ],
    "PostgreSQL": [
        re.compile(r"ERROR:\s+syntax error at or near", re.IGNORECASE),
        re.compile(r"psycopg2\.(errors\.)?[A-Za-z]+", re.IGNORECASE),
        re.compile(r"pg_query\(\):\s+Query failed:", re.IGNORECASE),
        re.compile(r"org\.postgresql\.util\.PSQLException", re.IGNORECASE),
        re.compile(r"PostgreSQL query failed", re.IGNORECASE),
    ],
    "Microsoft SQL Server": [
        re.compile(r"Unclosed quotation mark after the character string", re.IGNORECASE),
        re.compile(r"Microsoft OLE DB Provider for SQL Server", re.IGNORECASE),
        re.compile(r"Line \d+: Incorrect syntax near", re.IGNORECASE),
        re.compile(r"System\.Data\.SqlClient\.SqlException", re.IGNORECASE),
    ],
    "Oracle Database": [
        re.compile(r"ORA-00933:\s*SQL command not properly ended", re.IGNORECASE),
        re.compile(r"ORA-00907:\s*missing right parenthesis", re.IGNORECASE),
        re.compile(r"ORA-01756:\s*quoted string not properly terminated", re.IGNORECASE),
        re.compile(r"Oracle error", re.IGNORECASE),
    ]
}


class ResponseAnalyzer:
    """Analyzes server HTTP responses for SQL injection indicators."""

    @staticmethod
    def detect_sql_errors(content: str) -> List[Tuple[str, str]]:
        """
        Scans response text for known database error strings.
        Returns list of tuples: (dbms_name, matched_error_snippet).
        """
        matches: List[Tuple[str, str]] = []
        if not content:
            return matches

        for dbms, patterns in DATABASE_ERROR_SIGNATURES.items():
            for pat in patterns:
                found = pat.search(content)
                if found:
                    # Extract surrounding context (up to 120 chars) safely
                    start = max(0, found.start() - 20)
                    end = min(len(content), found.end() + 60)
                    snippet = content[start:end].strip().replace("\n", " ")
                    matches.append((dbms, snippet))
                    break  # One finding per DBMS family is sufficient
        return matches

    @staticmethod
    def analyze_differential(
        baseline_status: int,
        baseline_length: int,
        baseline_content: str,
        probe_status: int,
        probe_length: int,
        probe_content: str,
        param_name: str,
        probe_type: str,
        target_url: str
    ) -> Optional[Finding]:
        """
        Performs safe differential comparison between baseline and benign probe responses.
        Identifies whether user-supplied delimiters alter SQL control flow or elicit syntax errors.
        """
        # Step 1: Check for explicit database error signatures
        errors = ResponseAnalyzer.detect_sql_errors(probe_content)
        if errors:
            dbms, snippet = errors[0]
            return Finding(
                id=f"VULN-SQLI-ERR-{param_name.upper()}",
                title=f"Error-Based SQL Injection Detected in '{param_name}' ({dbms})",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                category="SQL Injection (Error-Based / Syntax Leakage)",
                endpoint=target_url,
                parameter=param_name,
                description=(
                    f"Submitting a harmless delimiter probe on parameter '{param_name}' resulted in an unhandled "
                    f"{dbms} database syntax error leaked directly in the HTTP response. "
                    f"This indicates that the parameter value is concatenated into the SQL statement without parameter binding."
                ),
                evidence=f"DBMS Detected: {dbms} | Error snippet: \"{snippet}\"",
                remediation=(
                    "Implement parameterized queries (prepared statements) using parameter placeholders (e.g. ? or :name). "
                    "Disable verbose server error messages and database stack traces in production."
                ),
                secure_code_example=(
                    "# Secure Parameterized Query (Python SQLite):\n"
                    "cursor.execute('SELECT * FROM records WHERE search_term = ?', (user_input,))\n\n"
                    "# ORM Equivalent (SQLAlchemy):\n"
                    "session.query(Record).filter(Record.search_term == user_input).all()"
                ),
                verification_steps=(
                    "1. Replace query concatenation with parameter binding.\n"
                    "2. Re-run SQLGuard scanner: ensure HTTP 200/400 is returned with clean error handling and zero SQL exceptions.\n"
                    "3. Verify unit tests with special characters (' \" \\ ;)."
                ),
                dbms_detected=dbms,
                technical_details={
                    "probe_type": probe_type,
                    "baseline_status": baseline_status,
                    "probe_status": probe_status,
                    "length_delta": probe_length - baseline_length
                }
            )

        # Step 2: Check for 500 Internal Server Error triggered specifically by benign quote probe
        if baseline_status == 200 and probe_status >= 500:
            return Finding(
                id=f"VULN-SQLI-ANOMALY-{param_name.upper()}",
                title=f"Potential SQL Syntax Sensitivity Detected in '{param_name}'",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category="SQL Injection (Behavioral Anomaly)",
                endpoint=target_url,
                parameter=param_name,
                description=(
                    f"The parameter '{param_name}' produced a server failure (HTTP {probe_status}) when tested with a harmless "
                    f"quote delimiter, whereas the baseline request succeeded (HTTP {baseline_status}). "
                    f"While no verbose database stack trace was exposed, this abrupt failure pattern is characteristic of unhandled syntax exceptions."
                ),
                evidence=f"Baseline HTTP {baseline_status} ({baseline_length} bytes) vs Probe HTTP {probe_status} ({probe_length} bytes)",
                remediation=(
                    "Audit server-side SQL statement construction for parameter '{param_name}'. Ensure input validation, "
                    "parameterized queries, and structured application-level error handling."
                ),
                secure_code_example=(
                    "# Defensive Query Binding:\n"
                    "cursor.execute('SELECT id, name FROM items WHERE code = ?', (param_value,))"
                ),
                verification_steps="Audit backend log files for SQL syntax errors triggered during the test timeframe.",
                technical_details={
                    "probe_type": probe_type,
                    "baseline_status": baseline_status,
                    "probe_status": probe_status,
                }
            )

        return None
