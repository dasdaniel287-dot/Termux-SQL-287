"""
Unit tests for SQLGuard AI report generator across TXT, JSON, and HTML formats.
"""

import json
from scanner.report_generator import ReportGenerator
from scanner.severity import Finding, Severity, Confidence


def create_sample_finding():
    return Finding(
        id="TEST-001",
        title="Error-Based SQL Injection in 'cat_id'",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        category="SQL Injection",
        endpoint="http://127.0.0.1:8000/items?cat_id=1",
        parameter="cat_id",
        description="Delimiter probe leaked SQLite syntax error.",
        evidence="DBMS: SQLite | sqlite3.OperationalError: syntax error",
        remediation="Use parameterized queries with placeholder '?'",
        secure_code_example="cursor.execute('SELECT * FROM items WHERE cat_id = ?', (cat_id,))",
        verification_steps="Send delimiter and verify HTTP 200 with zero SQL errors."
    )


def test_json_report_generation():
    finding = create_sample_finding()
    gen = ReportGenerator(
        target_url="http://127.0.0.1:8000/items",
        findings=[finding],
        scan_metadata={"mode": "safe-active", "duration_seconds": 1.25}
    )
    json_str = gen.generate_json()
    data = json.loads(json_str)

    assert data["target"] == "http://127.0.0.1:8000/items"
    assert data["summary"]["total_findings"] == 1
    assert data["summary"]["severity_breakdown"]["High"] == 1
    assert len(data["remediation_checklist"]) > 0


def test_txt_report_generation():
    finding = create_sample_finding()
    gen = ReportGenerator(
        target_url="http://127.0.0.1:8000/items",
        findings=[finding],
        scan_metadata={"mode": "safe-active", "duration_seconds": 1.25}
    )
    txt = gen.generate_txt()
    assert "SQLGUARD AI — DEFENSIVE SQL INJECTION ASSESSMENT REPORT" in txt
    assert "Finding #1: [HIGH]" in txt
    assert "FINAL DEFENSIVE SECURITY CHECKLIST" in txt


def test_html_report_generation():
    finding = create_sample_finding()
    gen = ReportGenerator(
        target_url="http://127.0.0.1:8000/items",
        findings=[finding],
        scan_metadata={"mode": "safe-active", "duration_seconds": 1.25}
    )
    html = gen.generate_html()
    assert "<!doctype html>" in html
    assert "Error-Based SQL Injection in &#39;cat_id&#39;" in html or "Error-Based SQL Injection in 'cat_id'" in html
    assert "Defensive Verification Checklist" in html
