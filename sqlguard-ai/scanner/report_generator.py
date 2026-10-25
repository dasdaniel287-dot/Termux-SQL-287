"""
Multi-Format Report Generator for SQLGuard AI.
Produces audit reports in TXT, JSON, and responsive standalone HTML.
Adheres to strict redaction policies: no credentials or secrets included.
"""

import json
import os
import datetime
from typing import List, Dict, Any
from .severity import Finding, Severity


class ReportGenerator:
    def __init__(self, target_url: str, findings: List[Finding], scan_metadata: Dict[str, Any]):
        self.target_url = target_url
        self.findings = findings
        self.scan_metadata = scan_metadata
        self.timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def get_summary_stats(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    def generate_json(self) -> str:
        """Generates structured JSON report."""
        report_data = {
            "report_name": "SQLGuard AI Assessment Report",
            "generated_at": self.timestamp,
            "target": self.target_url,
            "metadata": self.scan_metadata,
            "summary": {
                "total_findings": len(self.findings),
                "severity_breakdown": self.get_summary_stats(),
            },
            "findings": [f.to_dict() for f in self.findings],
            "limitations": [
                "Assessment was restricted to harmless, non-destructive boundary probes.",
                "Second-order SQL injection and asynchronous database tasks are not assessed in this scope.",
                "WAF rules or network throttling may suppress or alter error disclosures."
            ],
            "remediation_checklist": [
                "Migrate all dynamic SQL statements to parameterized queries / prepared statements.",
                "Enforce strict input validation using allowlists for table/column names.",
                "Disable verbose database error display and stack traces in production environments.",
                "Configure database users with least privilege access permissions.",
                "Implement automated CI/CD static security code analysis."
            ]
        }
        return json.dumps(report_data, indent=2)

    def generate_txt(self) -> str:
        """Generates clear, human-readable plain text audit report."""
        stats = self.get_summary_stats()
        lines = [
            "=" * 78,
            "SQLGUARD AI — DEFENSIVE SQL INJECTION ASSESSMENT REPORT",
            "=" * 78,
            f"Generated:       {self.timestamp}",
            f"Assessment Scope: {self.target_url}",
            f"Mode:            {self.scan_metadata.get('mode', 'N/A')}",
            f"Duration:        {self.scan_metadata.get('duration_seconds', 0):.2f}s",
            f"Total Findings:  {len(self.findings)}",
            "-" * 78,
            "SEVERITY BREAKDOWN:",
            f"  [!] Critical:      {stats.get(Severity.CRITICAL.value, 0)}",
            f"  [*] High:          {stats.get(Severity.HIGH.value, 0)}",
            f"  [+] Medium:        {stats.get(Severity.MEDIUM.value, 0)}",
            f"  [-] Low:           {stats.get(Severity.LOW.value, 0)}",
            f"  [i] Informational: {stats.get(Severity.INFORMATIONAL.value, 0)}",
            "=" * 78,
            "\n1. EXECUTIVE SUMMARY",
            "-" * 78,
            "SQLGuard AI performed an authorized, non-destructive security evaluation",
            "to assess SQL injection exposure. Testing prioritized safe boundary parsing",
            "and database error analysis without data tampering or exfiltration.",
            "\n2. DETAILED FINDINGS & EVIDENCE",
            "-" * 78,
        ]

        if not self.findings:
            lines.append("No SQL injection vulnerabilities or error leakages detected in this scope.")
        else:
            for idx, f in enumerate(self.findings, 1):
                lines.extend([
                    f"Finding #{idx}: [{f.severity.value.upper()}] {f.title}",
                    f"  Category:    {f.category}",
                    f"  Confidence:  {f.confidence.value}",
                    f"  Endpoint:    {f.endpoint}",
                    f"  Parameter:   {f.parameter or 'N/A'}",
                    f"  Description: {f.description}",
                    f"  Evidence:    {f.evidence}",
                    f"  Remediation: {f.remediation}",
                    "  Secure Code Example:",
                ])
                for code_line in f.secure_code_example.splitlines():
                    lines.append(f"    {code_line}")
                lines.extend([
                    f"  Verification Steps:\n    {f.verification_steps}",
                    "-" * 78,
                ])

        lines.extend([
            "\n3. ASSESSMENT LIMITATIONS",
            "-" * 78,
            "- Testing was strictly harmless and non-destructive; no payloads or exfiltration attempted.",
            "- Only specified parameters and endpoints were reviewed.",
            "- Out-of-band and blind asynchronous database interactions were not in scope.",
            "\n4. FINAL DEFENSIVE SECURITY CHECKLIST",
            "-" * 78,
            "[ ] 1. Parameterize all SQL queries using prepared statement placeholders.",
            "[ ] 2. Audit backend database connection accounts for least privilege.",
            "[ ] 3. Suppress all database error details in production HTTP responses.",
            "[ ] 4. Add automated unit and integration regression tests for special characters.",
            "=" * 78,
            "End of SQLGuard AI Assessment Report."
        ])
        return "\n".join(lines)

    def generate_html(self) -> str:
        """Generates styled standalone HTML report."""
        stats = self.get_summary_stats()
        findings_html = ""
        for idx, f in enumerate(self.findings, 1):
            badge_color = {
                "Critical": "#ef4444",
                "High": "#f97316",
                "Medium": "#eab308",
                "Low": "#3b82f6",
                "Informational": "#64748b"
            }.get(f.severity.value, "#64748b")

            code_snippet = f.secure_code_example.replace("<", "&lt;").replace(">", "&gt;")
            evidence_snippet = f.evidence.replace("<", "&lt;").replace(">", "&gt;")

            findings_html += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <span class="finding-badge" style="background: {badge_color};">{f.severity.value}</span>
                    <span class="finding-title">#{idx} {f.title}</span>
                </div>
                <div class="finding-meta">
                    <strong>Parameter:</strong> <code>{f.parameter or 'N/A'}</code> &bull;
                    <strong>Confidence:</strong> {f.confidence.value} &bull;
                    <strong>Category:</strong> {f.category}
                </div>
                <p><strong>Description:</strong> {f.description}</p>
                <div class="evidence-box">
                    <strong>Evidence:</strong> <code>{evidence_snippet}</code>
                </div>
                <p><strong>Remediation:</strong> {f.remediation}</p>
                <div class="code-box"><pre><code>{code_snippet}</code></pre></div>
                <p><strong>Verification:</strong> {f.verification_steps}</p>
            </div>
            """

        html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SQLGuard AI Assessment Report - {self.target_url}</title>
<style>
    :root {{
        --bg: #090d16;
        --card: #111827;
        --border: #1f2937;
        --text: #f3f4f6;
        --muted: #9ca3af;
        --accent: #0ea5e9;
    }}
    body {{
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace, sans-serif;
        background: var(--bg);
        color: var(--text);
        padding: 30px;
        line-height: 1.6;
    }}
    .container {{
        max-width: 960px;
        margin: 0 auto;
    }}
    header {{
        border-bottom: 1px solid var(--border);
        padding-bottom: 20px;
        margin-bottom: 30px;
    }}
    h1 {{ color: var(--accent); margin: 0 0 10px 0; font-size: 26px; }}
    .stats-grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
        gap: 12px;
        margin-bottom: 30px;
    }}
    .stat-card {{
        background: var(--card);
        border: 1px solid var(--border);
        padding: 14px;
        border-radius: 8px;
        text-align: center;
    }}
    .stat-val {{ font-size: 24px; font-weight: bold; }}
    .stat-lbl {{ font-size: 11px; text-transform: uppercase; color: var(--muted); }}
    .finding-card {{
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 20px;
        margin-bottom: 20px;
    }}
    .finding-header {{
        display: flex;
        align-items: center;
        gap: 10px;
        margin-bottom: 10px;
    }}
    .finding-badge {{
        color: #fff;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: bold;
        text-transform: uppercase;
    }}
    .finding-title {{ font-size: 17px; font-weight: 600; color: #fff; }}
    .finding-meta {{ color: var(--muted); font-size: 13px; margin-bottom: 12px; }}
    .evidence-box, .code-box {{
        background: #030712;
        border: 1px solid #1f2937;
        padding: 12px;
        border-radius: 6px;
        margin: 10px 0;
        overflow-x: auto;
    }}
    code {{ color: #38bdf8; font-family: monospace; font-size: 13px; }}
    pre code {{ color: #a7f3d0; }}
    ul {{ padding-left: 20px; }}
</style>
</head>
<body>
<div class="container">
    <header>
        <h1>SQLGuard AI &mdash; Security Assessment Report</h1>
        <p style="color:var(--muted); margin:0;">
            Target: <code>{self.target_url}</code> &bull; Generated: {self.timestamp} &bull; Mode: {self.scan_metadata.get('mode', 'N/A')}
        </p>
    </header>

    <div class="stats-grid">
        <div class="stat-card"><div class="stat-val" style="color:#ef4444;">{stats.get(Severity.CRITICAL.value, 0)}</div><div class="stat-lbl">Critical</div></div>
        <div class="stat-card"><div class="stat-val" style="color:#f97316;">{stats.get(Severity.HIGH.value, 0)}</div><div class="stat-lbl">High</div></div>
        <div class="stat-card"><div class="stat-val" style="color:#eab308;">{stats.get(Severity.MEDIUM.value, 0)}</div><div class="stat-lbl">Medium</div></div>
        <div class="stat-card"><div class="stat-val" style="color:#3b82f6;">{stats.get(Severity.LOW.value, 0)}</div><div class="stat-lbl">Low</div></div>
        <div class="stat-card"><div class="stat-val" style="color:#94a3b8;">{stats.get(Severity.INFORMATIONAL.value, 0)}</div><div class="stat-lbl">Info</div></div>
    </div>

    <h2>Findings &amp; Remediation</h2>
    {findings_html if findings_html else '<p>No vulnerabilities identified.</p>'}

    <h2>Defensive Verification Checklist</h2>
    <ul>
        <li>Migrate all query assembly to parameterized bindings / prepared statements.</li>
        <li>Enable production database exception wrapping to prevent stack trace leakage.</li>
        <li>Review database user credentials to guarantee least-privilege operations.</li>
        <li>Add unit tests verifying query behavior with quotes and delimiters.</li>
    </ul>
</div>
</body>
</html>
"""
        return html

    def save_all(self, output_dir: str = "./reports") -> Dict[str, str]:
        """Saves reports to TXT, JSON, and HTML."""
        os.makedirs(output_dir, exist_ok=True)
        timestamp_slug = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        paths = {
            "json": os.path.join(output_dir, f"sqlguard_report_{timestamp_slug}.json"),
            "txt": os.path.join(output_dir, f"sqlguard_report_{timestamp_slug}.txt"),
            "html": os.path.join(output_dir, f"sqlguard_report_{timestamp_slug}.html"),
        }
        with open(paths["json"], "w", encoding="utf-8") as f:
            f.write(self.generate_json())
        with open(paths["txt"], "w", encoding="utf-8") as f:
            f.write(self.generate_txt())
        with open(paths["html"], "w", encoding="utf-8") as f:
            f.write(self.generate_html())
        return paths
