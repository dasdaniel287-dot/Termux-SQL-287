/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useRef } from "react";
import {
  Terminal,
  Shield,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Database,
  Code2,
  FileText,
  Smartphone,
  Play,
  CheckCircle2,
  XCircle,
  Copy,
  Download,
  ExternalLink,
  Info,
  RefreshCw,
  Search,
  Lock,
  ChevronRight,
  Sliders,
  Server,
  Layers,
  FileCode,
  BookOpen,
} from "lucide-react";
import {
  FindingItem,
  DBMS_ERROR_SIGNATURES,
  COMMON_SQL_PARAMS,
  redactSensitiveUrl,
  validateTargetSafety,
} from "./scannerEngine";
import { REPO_FILES, RepoFile } from "./projectFiles";

// Preset targets for rapid safe testing
const TARGET_PRESETS = [
  {
    name: "Local Lab - Vulnerable Search Endpoint",
    url: "http://127.0.0.1:8000/api/vulnerable_search?q=Termux",
    isLab: true,
    description: "SQLite backend with direct string concatenation. Leaks syntax errors upon quote delimiter.",
  },
  {
    name: "Local Lab - Defended Parameterized Endpoint",
    url: "http://127.0.0.1:8000/api/secure_search?q=Termux",
    isLab: true,
    description: "SQLite backend using cursor.execute(query, (q,)). Safe against syntax breaks.",
  },
  {
    name: "Authorized External Target (Custom)",
    url: "https://shop.authorized-audit.org/api/products?category=hardware&sort=price",
    isLab: false,
    description: "Requires explicit owner consent declaration. Private networks strictly filtered.",
  },
];

export default function App() {
  const [activeTab, setActiveTab] = useState<
    "terminal" | "scanner" | "lab" | "advisor" | "reports" | "codebase"
  >("scanner");

  // Terminal State
  const [terminalLogs, setTerminalLogs] = useState<string[]>([
    "\u001b[36m\u001b[1m  ____   ___  _      ____                     _      _    ___ \u001b[0m",
    "\u001b[36m\u001b[1m / ___| / _ \\| |    / ___|_   _  __ _ _ __ __| |    / \\  |_ _|\u001b[0m",
    "\u001b[36m\u001b[1m \\___ \\| | | | |   | |  _| | | |/ _` | '__/ _` |   / _ \\  | | \u001b[0m",
    "\u001b[36m\u001b[1m  ___) | |_| | |___| |_| | |_| | (_| | | | (_| |  / ___ \\ | | \u001b[0m",
    "\u001b[36m\u001b[1m |____/ \\__\\_\\_____|\\____|\\__,_|\\__,_|_|  \\__,_| /_/   \\_\\___|\u001b[0m",
    "\u001b[90m   SQLGuard AI — Defensive SQL Injection Scanner for Termux [2026.1]\u001b[0m",
    "\u001b[90m   Android Termux Environment initialized. Ready for authorized assessment.\u001b[0m",
    "\u001b[32mtermux@sqlguard:~$ \u001b[0mType 'python main.py' or select a quick action below.",
  ]);
  const [terminalInput, setTerminalInput] = useState("");
  const terminalEndRef = useRef<HTMLDivElement>(null);

  // Scanner State
  const [targetUrl, setTargetUrl] = useState("http://127.0.0.1:8000/api/vulnerable_search?q=Termux");
  const [scanMode, setScanMode] = useState<"passive" | "safe-active">("safe-active");
  const [isAuthorized, setIsAuthorized] = useState(true);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState<string[]>([]);
  const [findings, setFindings] = useState<FindingItem[]>([
    {
      id: "VULN-SQLI-ERR-Q",
      title: "Error-Based SQL Injection in Parameter 'q' (SQLite)",
      severity: "High",
      confidence: "Confirmed",
      category: "SQL Injection (Syntax Leakage)",
      endpoint: "http://127.0.0.1:8000/api/vulnerable_search?q=Termux",
      parameter: "q",
      description:
        "Submitting a harmless delimiter probe on parameter 'q' resulted in an unhandled SQLite database syntax error leaked in the HTTP response.",
      evidence:
        'DBMS: SQLite | Error: "sqlite3.OperationalError: near \'\'\': syntax error" | Balance Probe restored valid syntax.',
      remediation:
        "Replace raw query string concatenation with parameterized prepared statements: cursor.execute('... WHERE name = ?', (q,))",
      secure_code_example:
        "# SECURE PYTHON SQLITE:\ncursor.execute('SELECT id, name, category, in_stock FROM training_products WHERE name = ?', (user_input,))",
      verification_steps:
        "1. Migrate query to parameter placeholder '?'.\n2. Re-test with probe: verify HTTP 200 returned with zero database exceptions.",
      timestamp: "2026-10-25 11:45:00 UTC",
      dbms_detected: "SQLite",
      technical_details: {
        probe_type: "single_quote_boundary",
        baseline_status: 200,
        probe_status: 500,
        length_delta: -120,
      },
    },
    {
      id: "INFO-PARAM-Q",
      title: "Query Parameter Exposure Identified: 'q'",
      severity: "Low",
      confidence: "Confirmed",
      category: "Attack Surface Discovery",
      endpoint: "http://127.0.0.1:8000/api/vulnerable_search?q=Termux",
      parameter: "q",
      description: "Parameter 'q' passes dynamic values into backend queries.",
      evidence: "Observed parameter: q=Termux",
      remediation: "Ensure strict parameter binding and type validation.",
      secure_code_example: "cursor.execute('SELECT * FROM items WHERE category = ?', (cat_param,))",
      verification_steps: "Audit backend for parameterized query usage.",
      timestamp: "2026-10-25 11:45:00 UTC",
    },
  ]);
  const [selectedFinding, setSelectedFinding] = useState<FindingItem | null>(findings[0]);
  const [copiedText, setCopiedText] = useState<string | null>(null);

  // Training Lab State
  const [labSearchInput, setLabSearchInput] = useState("Termux'");
  const [labResults, setLabResults] = useState<{
    unsafeSql: string;
    unsafeStatus: "error" | "success";
    unsafeErrorText: string;
    unsafeRows: any[];
    safeSql: string;
    safeParam: string;
    safeStatus: "success";
    safeRows: any[];
  }>({
    unsafeSql: "SELECT id, name, category, in_stock FROM training_products WHERE name = 'Termux''",
    unsafeStatus: "error",
    unsafeErrorText: "sqlite3.OperationalError: unrecognized token: \"'\"",
    unsafeRows: [],
    safeSql: "SELECT id, name, category, in_stock FROM training_products WHERE name = ?",
    safeParam: "('Termux\'',)",
    safeStatus: "success",
    safeRows: [],
  });

  // Report State
  const [reportFormat, setReportFormat] = useState<"html" | "txt" | "json">("html");

  // Codebase State
  const [selectedFile, setSelectedFile] = useState<RepoFile>(REPO_FILES[0]);

  // Advisor Language Tab
  const [advisorLang, setAdvisorLang] = useState<"python" | "nodejs" | "php" | "java" | "go">("python");

  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollTop = terminalEndRef.current.scrollHeight;
    }
  }, [terminalLogs]);

  // Helper copy function
  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(id);
    setTimeout(() => setCopiedText(null), 2000);
  };

  // Run Simulated Scan
  const handleStartScan = () => {
    if (!isAuthorized) {
      alert("Target authorization declaration is required before scanning.");
      return;
    }

    const isLocal = targetUrl.includes("localhost") || targetUrl.includes("127.0.0.1");
    const safety = validateTargetSafety(targetUrl, isLocal);
    if (!safety.safe) {
      alert(`Safety check failed: ${safety.error}`);
      return;
    }

    setIsScanning(true);
    setScanProgress([]);
    const logs: string[] = [];

    const steps = [
      `[*] Normalizing target: ${redactSensitiveUrl(targetUrl)}`,
      `[+] ${safety.message}`,
      `[*] Phase 1: Passive surface inspection on parameters...`,
      scanMode === "safe-active"
        ? `[*] Phase 2: Sending harmless single delimiter boundary probe (')...`
        : `[*] Passive mode: Skipping active boundary tests.`,
      scanMode === "safe-active"
        ? `[*] Phase 3: Checking paired quote balance probe ('')...`
        : null,
      scanMode === "safe-active"
        ? `[*] Phase 4: Matching error signatures against SQLite, MySQL, Postgres, MSSQL...`
        : null,
      `[+] Differential analysis complete. Building findings and metrics...`,
    ].filter(Boolean) as string[];

    let currentStep = 0;
    const interval = setInterval(() => {
      if (currentStep < steps.length) {
        const line = steps[currentStep];
        logs.push(line);
        setScanProgress([...logs]);
        currentStep++;
      } else {
        clearInterval(interval);
        setIsScanning(false);

        // Populate realistic findings based on target
        if (targetUrl.includes("vulnerable")) {
          const vulnFinding: FindingItem = {
            id: "VULN-SQLI-ERR-Q",
            title: "Error-Based SQL Injection in Parameter 'q' (SQLite)",
            severity: "High",
            confidence: "Confirmed",
            category: "SQL Injection (Syntax Leakage)",
            endpoint: redactSensitiveUrl(targetUrl),
            parameter: "q",
            description:
              "Submitting a harmless delimiter probe on parameter 'q' resulted in an unhandled SQLite database syntax error leaked in the HTTP response.",
            evidence:
              'DBMS: SQLite | Error: "sqlite3.OperationalError: near \'\'\': syntax error" | Balanced Probe restored valid syntax.',
            remediation:
              "Replace raw string formatting with parameterized queries: cursor.execute('... WHERE name = ?', (param,))",
            secure_code_example:
              "# SECURE CODE (Python sqlite3):\ncursor.execute('SELECT id, name, category, in_stock FROM training_products WHERE name = ?', (user_input,))",
            verification_steps:
              "1. Replace query concatenation with parameter binding.\n2. Re-run SQLGuard scanner: ensure HTTP 200 is returned with zero SQL exceptions.",
            timestamp: new Date().toISOString(),
            dbms_detected: "SQLite",
            technical_details: {
              probe_type: "single_quote_boundary",
              baseline_status: 200,
              probe_status: 500,
              length_delta: -120,
            },
          };
          const surfaceFinding: FindingItem = {
            id: "INFO-PARAM-Q",
            title: "Query Parameter Exposure Identified: 'q'",
            severity: "Low",
            confidence: "Confirmed",
            category: "Attack Surface Discovery",
            endpoint: redactSensitiveUrl(targetUrl),
            parameter: "q",
            description: "Parameter 'q' observed passing values into query logic.",
            evidence: "Observed parameter: q=Termux",
            remediation: "Ensure strict parameter binding and type validation.",
            secure_code_example: "cursor.execute('SELECT * FROM items WHERE category = ?', (cat_param,))",
            verification_steps: "Ensure unit tests confirm SQL syntax errors cannot be induced.",
            timestamp: new Date().toISOString(),
          };
          setFindings([vulnFinding, surfaceFinding]);
          setSelectedFinding(vulnFinding);
        } else if (targetUrl.includes("secure")) {
          const safeFinding: FindingItem = {
            id: "INFO-CLEAN-001",
            title: "Defended Endpoint — Zero SQL Errors Leaked",
            severity: "Informational",
            confidence: "Confirmed",
            category: "Defensive Architecture Verification",
            endpoint: redactSensitiveUrl(targetUrl),
            parameter: "q",
            description:
              "The target handled benign delimiter probes gracefully without syntax errors or unhandled status divergences.",
            evidence:
              "Baseline HTTP 200 (148 bytes) == Probe HTTP 200 (148 bytes). No database errors detected.",
            remediation: "Maintain parameterized queries and automated regression checks.",
            secure_code_example:
              "# Secure Implementation Verified:\ncursor.execute('SELECT * FROM products WHERE name = ?', (param,))",
            verification_steps: "Continue enforcing CI/CD static security code analysis.",
            timestamp: new Date().toISOString(),
          };
          setFindings([safeFinding]);
          setSelectedFinding(safeFinding);
        } else {
          // Custom target
          const genericFinding: FindingItem = {
            id: "INFO-SURFACE-CUSTOM",
            title: "Audited 2 Query Parameters ('category', 'sort')",
            severity: "Informational",
            confidence: "Confirmed",
            category: "Reconnaissance",
            endpoint: redactSensitiveUrl(targetUrl),
            parameter: "category",
            description: "Inspected query surface. No unhandled database syntax error messages disclosed.",
            evidence: "HTTP 200 OK. Error signatures evaluated: 0 matches.",
            remediation: "Ensure all parameters use prepared statements.",
            secure_code_example: "# Prepared statement binding recommended for all query parameters.",
            verification_steps: "Verify backend ORM or prepared statement implementation.",
            timestamp: new Date().toISOString(),
          };
          setFindings([genericFinding]);
          setSelectedFinding(genericFinding);
        }

        // Also add log to terminal
        setTerminalLogs((prev) => [
          ...prev,
          `\u001b[32m[+] Scan completed for ${redactSensitiveUrl(targetUrl)}\u001b[0m`,
          `\u001b[90m    Mode: ${scanMode} | Findings: ${findings.length}\u001b[0m`,
        ]);
      }
    }, 450);
  };

  // Run Training Lab evaluation
  const handleLabInput = (val: string) => {
    setLabSearchInput(val);
    const mockProducts = [
      { id: 1, name: "Termux Keyboard", category: "Accessories", in_stock: 15 },
      { id: 2, name: "OTG Adapter USB-C", category: "Adapters", in_stock: 50 },
      { id: 3, name: "Android Debug Bridge Cable", category: "Cables", in_stock: 30 },
      { id: 4, name: "YubiKey 5C NFC", category: "Security", in_stock: 25 },
    ];

    // Unsafe simulation (concatenation)
    const unsafeSql = `SELECT id, name, category, in_stock FROM training_products WHERE name = '${val}'`;
    let unsafeStatus: "error" | "success" = "success";
    let unsafeError = "";
    let unsafeRows: any[] = [];

    // Check for syntax error induction
    if (val.includes("'") && !val.includes("''") && !val.toLowerCase().includes("' or '1'='1")) {
      unsafeStatus = "error";
      unsafeError = `sqlite3.OperationalError: near "'": syntax error`;
      unsafeRows = [];
    } else if (val.toLowerCase().includes("' or '1'='1") || val.toLowerCase().includes("' or 1=1")) {
      // Classic tautology in concatenated SQL
      unsafeStatus = "success";
      unsafeRows = mockProducts; // Dumps all products due to broken syntax logic!
    } else {
      unsafeStatus = "success";
      unsafeRows = mockProducts.filter((p) => p.name.toLowerCase().includes(val.toLowerCase()));
    }

    // Safe simulation (parameterized)
    const safeSql = `SELECT id, name, category, in_stock FROM training_products WHERE name = ?`;
    const safeRows = mockProducts.filter((p) => p.name.toLowerCase() === val.toLowerCase());

    setLabResults({
      unsafeSql,
      unsafeStatus,
      unsafeErrorText: unsafeError,
      unsafeRows,
      safeSql,
      safeParam: `('${val}',)`,
      safeStatus: "success",
      safeRows,
    });
  };

  // Run Terminal Commands
  const handleRunCommand = (cmd: string) => {
    const trimmed = cmd.trim();
    if (!trimmed) return;

    const newLogs = [...terminalLogs, `\u001b[32mtermux@sqlguard:~$ \u001b[0m${trimmed}`];

    if (trimmed === "clear") {
      setTerminalLogs([]);
      setTerminalInput("");
      return;
    } else if (trimmed === "help") {
      newLogs.push(
        "\u001b[36mSQLGuard AI Termux Commands:\u001b[0m",
        "  python main.py                     - Run interactive CLI menu",
        "  python main.py --lab               - Toggle local SQLite training lab server",
        "  python main.py --demo-secure       - Run in-memory SQLite parameterized queries demo",
        "  python main.py --target <URL> ...  - Run defensive assessment with safety boundary check",
        "  pytest tests/ -v                   - Run unit test suite for analyzer, SSRF, and reports",
        "  cat config.json                    - View rate limits, redaction rules & timeouts",
        "  ls -la                             - List directory tree",
        "  clear                              - Clear console window"
      );
    } else if (trimmed === "ls" || trimmed === "ls -la") {
      newLogs.push(
        "total 64",
        "drwxr-xr-x 6 termux termux 4096 Oct 25 11:40 .",
        "drwxr-xr-x 3 termux termux 4096 Oct 25 11:38 ..",
        "-rw-r--r-- 1 termux termux 1024 Oct 25 11:42 config.json",
        "-rwxr-xr-x 1 termux termux 6214 Oct 25 11:43 main.py",
        "-rw-r--r-- 1 termux termux 4820 Oct 25 11:42 README.md",
        "-rw-r--r-- 1 termux termux   32 Oct 25 11:40 requirements.txt",
        "drwxr-xr-x 2 termux termux 4096 Oct 25 11:41 lab",
        "drwxr-xr-x 2 termux termux 4096 Oct 25 11:42 reports",
        "drwxr-xr-x 2 termux termux 4096 Oct 25 11:41 scanner",
        "drwxr-xr-x 2 termux termux 4096 Oct 25 11:43 tests"
      );
    } else if (trimmed.includes("pytest")) {
      newLogs.push(
        "\u001b[36m============================= test session starts ==============================\u001b[0m",
        "platform linux -- Python 3.11.8, pytest-8.1.1, pluggy-1.4.0",
        "rootdir: /data/data/com.termux/files/home/sqlguard-ai",
        "collected 9 items",
        "",
        "tests/test_analyzer.py::test_url_normalization \u001b[32mPASSED\u001b[0m [ 11%]",
        "tests/test_analyzer.py::test_unapproved_private_host_blocked_in_external_mode \u001b[32mPASSED\u001b[0m [ 22%]",
        "tests/test_analyzer.py::test_local_host_allowed_in_lab_mode \u001b[32mPASSED\u001b[0m [ 33%]",
        "tests/test_analyzer.py::test_sensitive_value_redaction \u001b[32mPASSED\u001b[0m [ 44%]",
        "tests/test_analyzer.py::test_sqlite_syntax_error_detection \u001b[32mPASSED\u001b[0m [ 55%]",
        "tests/test_analyzer.py::test_mysql_syntax_error_detection \u001b[32mPASSED\u001b[0m [ 66%]",
        "tests/test_analyzer.py::test_postgres_syntax_error_detection \u001b[32mPASSED\u001b[0m [ 77%]",
        "tests/test_reports.py::test_json_report_generation \u001b[32mPASSED\u001b[0m [ 88%]",
        "tests/test_reports.py::test_html_report_generation \u001b[32mPASSED\u001b[0m [100%]",
        "",
        "\u001b[32m\u001b[1m============================== 9 passed in 0.42s ===============================\u001b[0m"
      );
    } else if (trimmed.includes("--demo-secure") || trimmed === "python lab/secure_examples.py") {
      newLogs.push(
        "======================================================================",
        "SQLGuard AI - Secure Coding Demonstration: Unsafe vs Parameterized SQL",
        "======================================================================",
        "",
        "[Test Case] Single Quote Boundary Probe",
        "User Input: Hardware'",
        "  - VULNERABLE (Concatenation):",
        "      Constructed SQL: SELECT * FROM products WHERE name = 'Hardware''",
        "      Status:          ERROR LEAKED: sqlite3.OperationalError: near \"'\": syntax error",
        "  - SECURE (Parameterized Query):",
        "      Pre-compiled SQL: SELECT * FROM products WHERE name = ?",
        "      Bound Parameter: ('Hardware\'',)",
        "      Status:          OK: Query executed with parameterized binding (Safe from injection).",
        "      Records Fetched: 0 (Literal exact match only)",
        "",
        "KEY TAKEAWAYS FOR DEFENDERS:",
        "1. Parameterized queries enforce separation of CODE (commands) and DATA (user values).",
        "2. The database parser never evaluates user inputs as SQL tokens or syntax."
      );
    } else if (trimmed.includes("--lab") || trimmed === "python lab/vulnerable_app.py") {
      newLogs.push(
        "\u001b[36m[*] SQLGuard Training Lab running on http://127.0.0.1:8000\u001b[0m",
        "[*] Endpoints active:",
        "    - /api/vulnerable_search?q=...  (Unsafe concatenation)",
        "    - /api/secure_search?q=...      (Safe prepared statements)",
        "[*] Ready for defensive assessment queries."
      );
    } else if (trimmed.includes("main.py") && trimmed.includes("--target")) {
      newLogs.push(
        "\u001b[36m[*] Initializing SQLGuard AI Assessment...\u001b[0m",
        `[*] Target: ${targetUrl}`,
        `\u001b[32m[+] Safety Boundary Verified: Target approved under Controlled Local Lab policy.\u001b[0m`,
        `[*] Step 1/2: Running passive surface discovery...`,
        `[+] Passive surface review completed (2 surface notes).`,
        `[*] Step 2/2: Executing safe, non-destructive boundary probes...`,
        `    \u001b[90m> Establishing baseline response for ${redactSensitiveUrl(targetUrl)}...\u001b[0m`,
        `    \u001b[90m> Reviewing parameter 'q' with safe non-destructive probes...\u001b[0m`,
        `    \u001b[31m[!] Finding identified on parameter 'q': Error-Based SQL Injection Detected in 'q' (SQLite)\u001b[0m`,
        `\u001b[32m[+] Reports successfully generated:\u001b[0m`,
        `    - TXT:  ./reports/sqlguard_report_20261025.txt`,
        `    - JSON: ./reports/sqlguard_report_20261025.json`,
        `    - HTML: ./reports/sqlguard_report_20261025.html`
      );
    } else if (trimmed === "python main.py") {
      newLogs.push(
        "\u001b[36m--- SQLGuard AI Interactive CLI Menu ---\u001b[0m",
        "  [1] Run Security Assessment (URL Input)",
        "  [2] Practice in Local Training Lab (SQLite)",
        "  [3] Secure Coding Demonstration (Concatenation vs Prepared Statements)",
        "  [4] Run Automated Test Suite (pytest)",
        "  [5] Exit",
        "Enter selection (1-5) or run with arguments."
      );
    } else {
      newLogs.push(`Executed: ${trimmed}`);
    }

    setTerminalLogs(newLogs);
    setTerminalInput("");
  };

  // Severity count calculation
  const severityCounts = {
    Critical: findings.filter((f) => f.severity === "Critical").length,
    High: findings.filter((f) => f.severity === "High").length,
    Medium: findings.filter((f) => f.severity === "Medium").length,
    Low: findings.filter((f) => f.severity === "Low").length,
    Informational: findings.filter((f) => f.severity === "Informational").length,
  };

  // Generate downloadable report string
  const getReportContent = (format: "html" | "txt" | "json") => {
    if (format === "json") {
      return JSON.stringify(
        {
          report_name: "SQLGuard AI Assessment Report",
          generated_at: new Date().toISOString(),
          target: targetUrl,
          mode: scanMode,
          summary: {
            total_findings: findings.length,
            severity_breakdown: severityCounts,
          },
          findings,
          limitations: [
            "Assessment was restricted to harmless, non-destructive boundary probes.",
            "Second-order SQL injection and asynchronous database tasks are not assessed.",
            "WAF rules or network throttling may suppress or alter error disclosures.",
          ],
          remediation_checklist: [
            "Migrate all dynamic SQL statements to parameterized queries / prepared statements.",
            "Enforce strict input validation using allowlists for table/column names.",
            "Disable verbose database error display and stack traces in production environments.",
            "Configure database users with least privilege access permissions.",
            "Implement automated CI/CD static security code analysis.",
          ],
        },
        null,
        2
      );
    }

    if (format === "txt") {
      return `==============================================================================
SQLGUARD AI — DEFENSIVE SQL INJECTION ASSESSMENT REPORT
==============================================================================
Generated:        ${new Date().toUTCString()}
Assessment Scope: ${targetUrl}
Mode:             ${scanMode.toUpperCase()}
Total Findings:   ${findings.length}
------------------------------------------------------------------------------
SEVERITY BREAKDOWN:
  [!] Critical:      ${severityCounts.Critical}
  [*] High:          ${severityCounts.High}
  [+] Medium:        ${severityCounts.Medium}
  [-] Low:           ${severityCounts.Low}
  [i] Informational: ${severityCounts.Informational}
==============================================================================

1. EXECUTIVE SUMMARY
------------------------------------------------------------------------------
SQLGuard AI performed an authorized, non-destructive security evaluation
to assess SQL injection exposure. Testing prioritized safe boundary parsing
and database error analysis without data tampering or exfiltration.

2. DETAILED FINDINGS & EVIDENCE
------------------------------------------------------------------------------
${findings
  .map(
    (f, idx) => `Finding #${idx + 1}: [${f.severity.toUpperCase()}] ${f.title}
  Category:    ${f.category}
  Confidence:  ${f.confidence}
  Endpoint:    ${f.endpoint}
  Parameter:   ${f.parameter || "N/A"}
  Description: ${f.description}
  Evidence:    ${f.evidence}
  Remediation: ${f.remediation}
  Secure Code Example:
${f.secure_code_example
  .split("\n")
  .map((l) => "    " + l)
  .join("\n")}
  Verification Steps:
    ${f.verification_steps.replace(/\n/g, "\n    ")}
------------------------------------------------------------------------------`
  )
  .join("\n")}

3. ASSESSMENT LIMITATIONS
------------------------------------------------------------------------------
- Testing was strictly harmless and non-destructive; no payloads or exfiltration attempted.
- Only specified parameters and endpoints were reviewed.
- Out-of-band and blind asynchronous database interactions were not in scope.

4. FINAL DEFENSIVE SECURITY CHECKLIST
------------------------------------------------------------------------------
[ ] 1. Parameterize all SQL queries using prepared statement placeholders.
[ ] 2. Audit backend database connection accounts for least privilege.
[ ] 3. Suppress all database error details in production HTTP responses.
[ ] 4. Add automated unit and integration regression tests for special characters.
==============================================================================
End of SQLGuard AI Assessment Report.`;
    }

    // HTML format
    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SQLGuard AI Assessment Report - ${targetUrl}</title>
<style>
  body { font-family: monospace, sans-serif; background: #0b0f19; color: #f1f5f9; padding: 24px; line-height: 1.5; }
  .card { background: #131b2e; border: 1px solid #1e293b; padding: 18px; border-radius: 8px; margin-bottom: 16px; }
  .badge { padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; text-transform: uppercase; }
  pre { background: #070a12; padding: 12px; border-radius: 6px; overflow-x: auto; color: #38bdf8; }
</style>
</head>
<body>
  <h1>SQLGuard AI &mdash; Defensive Assessment Report</h1>
  <p>Target: <code>${targetUrl}</code> | Mode: ${scanMode.toUpperCase()} | Generated: ${new Date().toUTCString()}</p>
  <div style="display:flex; gap:12px; margin-bottom:20px;">
    <div class="card" style="flex:1; text-align:center;"><h3>${severityCounts.Critical}</h3><small>Critical</small></div>
    <div class="card" style="flex:1; text-align:center;"><h3>${severityCounts.High}</h3><small>High</small></div>
    <div class="card" style="flex:1; text-align:center;"><h3>${severityCounts.Medium}</h3><small>Medium</small></div>
    <div class="card" style="flex:1; text-align:center;"><h3>${severityCounts.Low}</h3><small>Low</small></div>
    <div class="card" style="flex:1; text-align:center;"><h3>${severityCounts.Informational}</h3><small>Info</small></div>
  </div>
  <h2>Findings</h2>
  ${findings
    .map(
      (f) => `
    <div class="card">
      <span class="badge" style="background:#f97316;">${f.severity}</span>
      <h3 style="margin:8px 0;">${f.title}</h3>
      <p><strong>Parameter:</strong> <code>${f.parameter || "N/A"}</code> | <strong>Confidence:</strong> ${f.confidence}</p>
      <p><strong>Evidence:</strong> <code>${f.evidence}</code></p>
      <pre><code>${f.secure_code_example}</code></pre>
      <p><strong>Remediation:</strong> ${f.remediation}</p>
    </div>
  `
    )
    .join("")}
</body>
</html>`;
  };

  const downloadReportFile = (format: "html" | "txt" | "json") => {
    const content = getReportContent(format);
    const mimeTypes = {
      html: "text/html",
      txt: "text/plain",
      json: "application/json",
    };
    const blob = new Blob([content], { type: mimeTypes[format] });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sqlguard_audit_report_${Date.now()}.${format}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Bar with Termux Branding & Safe Mode Indicator */}
      <header className="border-b border-slate-800/80 bg-slate-900/90 backdrop-blur sticky top-0 z-30 px-4 py-2.5 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="h-8 w-8 rounded-lg bg-cyan-600/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-inner">
            <Terminal className="h-4 w-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono font-bold tracking-tight text-slate-100 text-sm">SQLGuard AI</span>
              <span className="text-[11px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/50 px-1.5 py-0.5 rounded">
                v2026.1 (Termux)
              </span>
            </div>
            <p className="text-[11px] text-slate-400 hidden sm:block">
              Defensive SQL Injection Assessment &amp; Training Platform for Android
            </p>
          </div>
        </div>

        {/* Global Status Badges */}
        <div className="flex items-center gap-2 text-xs">
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-emerald-950/50 border border-emerald-800/60 text-emerald-400 font-mono text-[11px]">
            <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>Local Lab: 127.0.0.1:8000</span>
          </div>

          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-slate-300 font-mono text-[11px]">
            <ShieldCheck className="h-3.5 w-3.5 text-cyan-400" />
            <span>Defensive Boundaries Active</span>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg text-xs font-medium w-full lg:w-auto overflow-x-auto">
          <button
            onClick={() => setActiveTab("scanner")}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md transition-colors whitespace-nowrap ${
              activeTab === "scanner"
                ? "bg-cyan-600 text-white shadow-sm"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Shield className="h-3.5 w-3.5" />
            <span>Security Scanner</span>
          </button>

          <button
            onClick={() => setActiveTab("lab")}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md transition-colors whitespace-nowrap ${
              activeTab === "lab"
                ? "bg-cyan-600 text-white shadow-sm"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Database className="h-3.5 w-3.5" />
            <span>SQLite Training Lab</span>
          </button>

          <button
            onClick={() => setActiveTab("terminal")}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md transition-colors whitespace-nowrap ${
              activeTab === "terminal"
                ? "bg-cyan-600 text-white shadow-sm"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Terminal className="h-3.5 w-3.5" />
            <span>Termux Console</span>
          </button>

          <button
            onClick={() => setActiveTab("advisor")}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md transition-colors whitespace-nowrap ${
              activeTab === "advisor"
                ? "bg-cyan-600 text-white shadow-sm"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Code2 className="h-3.5 w-3.5" />
            <span>Remediation Advisor</span>
          </button>

          <button
            onClick={() => setActiveTab("reports")}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md transition-colors whitespace-nowrap ${
              activeTab === "reports"
                ? "bg-cyan-600 text-white shadow-sm"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <FileText className="h-3.5 w-3.5" />
            <span>Audit Reports</span>
          </button>

          <button
            onClick={() => setActiveTab("codebase")}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md transition-colors whitespace-nowrap ${
              activeTab === "codebase"
                ? "bg-cyan-600 text-white shadow-sm"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Smartphone className="h-3.5 w-3.5" />
            <span>Termux Setup &amp; Repo</span>
          </button>
        </nav>
      </header>

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 md:p-6 space-y-6">
        {/* =========================================================================
            TAB 1: SECURITY SCANNER & LIVE ASSESSMENT
           ========================================================================= */}
        {activeTab === "scanner" && (
          <div className="space-y-6">
            {/* Target Authorization & Setup Panel */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-800 pb-4">
                <div>
                  <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4 text-cyan-400" />
                    Target Authorization &amp; Assessment Setup
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Defensive security testing requires explicit authorization. Non-destructive probes only.
                  </p>
                </div>

                {/* Authorization Switch */}
                <label className="flex items-center gap-2.5 text-xs bg-slate-950/80 px-3 py-2 rounded-lg border border-slate-800 cursor-pointer hover:border-slate-700 transition">
                  <input
                    type="checkbox"
                    checked={isAuthorized}
                    onChange={(e) => setIsAuthorized(e.target.checked)}
                    className="rounded border-slate-700 text-cyan-500 focus:ring-cyan-500"
                  />
                  <span className="text-slate-300 font-medium">
                    I confirm ownership or written testing permission
                  </span>
                </label>
              </div>

              {/* Target Selector & Presets */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-medium text-slate-300">Target Endpoint URL</label>
                  <span className="text-[11px] text-slate-500">
                    SSRF protection active &bull; Private IP blocks enforced for external mode
                  </span>
                </div>

                <div className="flex flex-col sm:flex-row gap-2">
                  <div className="relative flex-1">
                    <input
                      type="text"
                      value={targetUrl}
                      onChange={(e) => setTargetUrl(e.target.value)}
                      placeholder="http://127.0.0.1:8000/api/vulnerable_search?q=Termux"
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                    />
                  </div>

                  {/* Mode Selector */}
                  <div className="flex items-center p-1 bg-slate-950 border border-slate-800 rounded-lg text-xs">
                    <button
                      type="button"
                      onClick={() => setScanMode("passive")}
                      className={`px-3 py-1.5 rounded transition ${
                        scanMode === "passive"
                          ? "bg-slate-800 text-cyan-300 font-medium shadow-sm"
                          : "text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      Passive Mode (Zero Payloads)
                    </button>
                    <button
                      type="button"
                      onClick={() => setScanMode("safe-active")}
                      className={`px-3 py-1.5 rounded transition ${
                        scanMode === "safe-active"
                          ? "bg-cyan-600 text-white font-medium shadow-sm"
                          : "text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      Safe Active (Boundary Delimiters)
                    </button>
                  </div>

                  <button
                    type="button"
                    onClick={handleStartScan}
                    disabled={isScanning || !isAuthorized}
                    className="flex items-center justify-center gap-1.5 px-5 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 disabled:opacity-50 text-white font-medium text-xs rounded-lg transition shadow-md shadow-cyan-950 cursor-pointer"
                  >
                    {isScanning ? (
                      <>
                        <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                        <span>Evaluating...</span>
                      </>
                    ) : (
                      <>
                        <Play className="h-3.5 w-3.5 fill-current" />
                        <span>Start Assessment</span>
                      </>
                    )}
                  </button>
                </div>

                {/* Preset Target Quick Pickers */}
                <div className="pt-2 flex flex-wrap gap-2 text-xs">
                  <span className="text-slate-500 text-[11px] self-center">Quick Targets:</span>
                  {TARGET_PRESETS.map((p, idx) => (
                    <button
                      key={idx}
                      type="button"
                      onClick={() => setTargetUrl(p.url)}
                      className={`text-[11px] font-mono px-2.5 py-1 rounded border transition ${
                        targetUrl === p.url
                          ? "bg-cyan-950/60 border-cyan-700 text-cyan-300"
                          : "bg-slate-950/60 border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-300"
                      }`}
                    >
                      {p.name}
                    </button>
                  ))}
                </div>
              </div>

              {/* Live Scan Pipeline Progress */}
              {isScanning && (
                <div className="p-3.5 rounded-lg bg-slate-950 border border-cyan-900/60 space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono text-cyan-400 flex items-center gap-2">
                      <RefreshCw className="h-3 w-3 animate-spin" />
                      Testing Engine Active
                    </span>
                    <span className="text-slate-500 text-[11px]">
                      Rate limit delay 350ms &bull; Circuit breaker active
                    </span>
                  </div>
                  <div className="space-y-1 font-mono text-[11px]">
                    {scanProgress.map((line, idx) => (
                      <div key={idx} className="text-slate-300 flex items-center gap-1.5">
                        <ChevronRight className="h-3 w-3 text-cyan-400 shrink-0" />
                        <span>{line}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Assessment Dashboard Metrics */}
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
              <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-xl">
                <span className="text-slate-400 text-[11px] block uppercase font-mono tracking-wider">
                  Endpoints Audited
                </span>
                <span className="text-xl font-bold font-mono text-slate-100 mt-1 block">1</span>
                <span className="text-[10px] text-slate-500 mt-0.5 block">1 parameter tested</span>
              </div>

              <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-xl">
                <span className="text-slate-400 text-[11px] block uppercase font-mono tracking-wider">
                  Critical
                </span>
                <span className="text-xl font-bold font-mono text-rose-500 mt-1 block">
                  {severityCounts.Critical}
                </span>
                <span className="text-[10px] text-slate-500 mt-0.5 block">Exploitable vectors</span>
              </div>

              <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-xl">
                <span className="text-slate-400 text-[11px] block uppercase font-mono tracking-wider">
                  High Severity
                </span>
                <span className="text-xl font-bold font-mono text-amber-500 mt-1 block">
                  {severityCounts.High}
                </span>
                <span className="text-[10px] text-slate-500 mt-0.5 block">SQL error disclosures</span>
              </div>

              <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-xl">
                <span className="text-slate-400 text-[11px] block uppercase font-mono tracking-wider">
                  Medium
                </span>
                <span className="text-xl font-bold font-mono text-yellow-400 mt-1 block">
                  {severityCounts.Medium}
                </span>
                <span className="text-[10px] text-slate-500 mt-0.5 block">Behavioral anomalies</span>
              </div>

              <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-xl">
                <span className="text-slate-400 text-[11px] block uppercase font-mono tracking-wider">
                  Low / Info
                </span>
                <span className="text-xl font-bold font-mono text-blue-400 mt-1 block">
                  {severityCounts.Low + severityCounts.Informational}
                </span>
                <span className="text-[10px] text-slate-500 mt-0.5 block">Surface discoveries</span>
              </div>

              <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-xl">
                <span className="text-slate-400 text-[11px] block uppercase font-mono tracking-wider">
                  Testing Mode
                </span>
                <span className="text-sm font-bold font-mono text-cyan-400 mt-2 block uppercase">
                  {scanMode}
                </span>
                <span className="text-[10px] text-slate-500 mt-0.5 block">Harmless delimiters</span>
              </div>
            </div>

            {/* Two-Column Findings & Evidence Inspector */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              {/* Findings List */}
              <div className="lg:col-span-5 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono">
                    Documented Findings ({findings.length})
                  </h3>
                  <span className="text-[11px] text-slate-500">Click to view evidence &amp; remediation</span>
                </div>

                <div className="space-y-2.5">
                  {findings.map((f) => {
                    const isSelected = selectedFinding?.id === f.id;
                    const sevColor =
                      f.severity === "Critical"
                        ? "border-rose-500/60 bg-rose-950/20 text-rose-300"
                        : f.severity === "High"
                        ? "border-amber-500/60 bg-amber-950/20 text-amber-300"
                        : f.severity === "Medium"
                        ? "border-yellow-500/60 bg-yellow-950/20 text-yellow-300"
                        : f.severity === "Low"
                        ? "border-blue-500/60 bg-blue-950/20 text-blue-300"
                        : "border-slate-700 bg-slate-900/60 text-slate-400";

                    return (
                      <div
                        key={f.id}
                        onClick={() => setSelectedFinding(f)}
                        className={`p-3.5 rounded-xl border cursor-pointer transition ${
                          isSelected
                            ? "bg-slate-900 border-cyan-500 shadow-md shadow-cyan-950/50"
                            : "bg-slate-900/70 border-slate-800 hover:border-slate-700"
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2 mb-1.5">
                          <span
                            className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded border font-semibold ${sevColor}`}
                          >
                            {f.severity}
                          </span>
                          <span className="text-[10px] font-mono text-slate-500">
                            Confidence: {f.confidence}
                          </span>
                        </div>

                        <h4 className="text-xs font-medium text-slate-100">{f.title}</h4>

                        <div className="flex items-center gap-2 mt-2 text-[11px] text-slate-400 font-mono truncate">
                          <span>Param: {f.parameter || "N/A"}</span>
                          <span>&bull;</span>
                          <span className="truncate">{f.category}</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Detailed Finding Deep-Dive Panel */}
              <div className="lg:col-span-7">
                {selectedFinding ? (
                  <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
                    <div className="border-b border-slate-800 pb-3 flex items-start justify-between gap-3">
                      <div>
                        <div className="flex items-center gap-2 mb-1">
                          <span
                            className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded font-bold ${
                              selectedFinding.severity === "High"
                                ? "bg-amber-500/20 text-amber-300 border border-amber-500/40"
                                : "bg-blue-500/20 text-blue-300 border border-blue-500/40"
                            }`}
                          >
                            {selectedFinding.severity}
                          </span>
                          <span className="text-xs font-mono text-slate-400">
                            ID: {selectedFinding.id}
                          </span>
                          {selectedFinding.dbms_detected && (
                            <span className="text-[10px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-800 px-1.5 py-0.5 rounded">
                              Engine: {selectedFinding.dbms_detected}
                            </span>
                          )}
                        </div>
                        <h3 className="text-sm font-semibold text-slate-100">{selectedFinding.title}</h3>
                      </div>

                      <button
                        onClick={() =>
                          copyToClipboard(
                            `${selectedFinding.title}\nEvidence: ${selectedFinding.evidence}\nRemediation: ${selectedFinding.remediation}`,
                            selectedFinding.id
                          )
                        }
                        className="text-xs text-slate-400 hover:text-cyan-400 p-1.5 rounded bg-slate-950 border border-slate-800 flex items-center gap-1 transition"
                      >
                        <Copy className="h-3 w-3" />
                        <span>{copiedText === selectedFinding.id ? "Copied" : "Copy"}</span>
                      </button>
                    </div>

                    {/* Description */}
                    <div>
                      <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                        Vulnerability Mechanics
                      </span>
                      <p className="text-xs text-slate-300 leading-relaxed">
                        {selectedFinding.description}
                      </p>
                    </div>

                    {/* Evidence Snippet */}
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/80">
                      <span className="text-[11px] font-mono text-amber-400 uppercase tracking-wider block mb-1 flex items-center gap-1.5">
                        <AlertTriangle className="h-3 w-3 text-amber-400" />
                        Diagnostic Evidence &amp; Error Leakage
                      </span>
                      <code className="text-xs font-mono text-slate-300 block break-all">
                        {selectedFinding.evidence}
                      </code>
                    </div>

                    {/* Recommended Secure Code */}
                    <div>
                      <span className="text-[11px] font-mono text-emerald-400 uppercase tracking-wider block mb-1 flex items-center gap-1.5">
                        <CheckCircle2 className="h-3 w-3 text-emerald-400" />
                        Remediation &amp; Secure Code
                      </span>
                      <p className="text-xs text-slate-400 mb-2">{selectedFinding.remediation}</p>
                      <pre className="p-3 bg-slate-950 border border-emerald-950/80 rounded-lg text-emerald-300 font-mono text-xs overflow-x-auto leading-relaxed">
                        <code>{selectedFinding.secure_code_example}</code>
                      </pre>
                    </div>

                    {/* Verification Steps */}
                    <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
                      <span className="text-[11px] font-mono text-cyan-400 uppercase tracking-wider block mb-1">
                        Post-Patch Verification Steps
                      </span>
                      <p className="text-xs text-slate-300 whitespace-pre-line font-mono text-[11px]">
                        {selectedFinding.verification_steps}
                      </p>
                    </div>
                  </div>
                ) : (
                  <div className="h-full min-h-[300px] flex items-center justify-center border border-dashed border-slate-800 rounded-xl text-slate-500 text-xs font-mono">
                    Select a finding to inspect diagnostics
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* =========================================================================
            TAB 2: SQLITE TRAINING LAB & AST INSPECTOR
           ========================================================================= */}
        {activeTab === "lab" && (
          <div className="space-y-6">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 shadow-lg">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-800 pb-3">
                <div>
                  <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                    <Database className="h-4 w-4 text-cyan-400" />
                    Interactive Local SQLite Training Lab
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Demonstrating why string concatenation breaks query syntax while parameterized queries neutralize injection.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono text-emerald-400 bg-emerald-950/50 border border-emerald-800 px-2 py-1 rounded">
                    Active SQLite Schema: training_products
                  </span>
                </div>
              </div>

              {/* Live Input Controls */}
              <div className="space-y-2">
                <label className="text-xs font-medium text-slate-300 block">
                  Simulate User Search Input (Try entering quotes or SQL tokens):
                </label>
                <div className="flex flex-col sm:flex-row gap-2">
                  <input
                    type="text"
                    value={labSearchInput}
                    onChange={(e) => handleLabInput(e.target.value)}
                    placeholder="Enter search term, e.g. Termux'"
                    className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
                  />
                  <div className="flex flex-wrap gap-1.5">
                    {[
                      { label: "Normal (Termux)", val: "Termux" },
                      { label: "Quote Break (Termux')", val: "Termux'" },
                      { label: "Pair Balance (Termux'')", val: "Termux''" },
                      { label: "Tautology (' OR '1'='1)", val: "Termux' OR '1'='1" },
                    ].map((btn, idx) => (
                      <button
                        key={idx}
                        type="button"
                        onClick={() => handleLabInput(btn.val)}
                        className="text-[11px] font-mono px-2.5 py-1.5 rounded bg-slate-950 border border-slate-800 hover:border-slate-700 text-slate-300"
                      >
                        {btn.label}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              {/* Side-by-Side Comparison */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 pt-2">
                {/* 1. Unsafe Concatenation Card */}
                <div className="bg-slate-950 border border-rose-900/60 rounded-xl p-4 space-y-3">
                  <div className="flex items-center justify-between border-b border-rose-950 pb-2">
                    <span className="text-xs font-mono font-bold text-rose-400 flex items-center gap-1.5">
                      <XCircle className="h-3.5 w-3.5 text-rose-400" />
                      1. VULNERABLE: String Concatenation
                    </span>
                    <span className="text-[10px] font-mono text-rose-300 bg-rose-950/60 px-2 py-0.5 rounded border border-rose-800">
                      f&quot;SELECT ... '{labSearchInput}'&quot;
                    </span>
                  </div>

                  <div>
                    <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                      Constructed Raw SQL String:
                    </span>
                    <div className="p-2.5 bg-slate-900 border border-slate-800 rounded font-mono text-xs text-rose-300 break-all">
                      <code>{labResults.unsafeSql}</code>
                    </div>
                  </div>

                  {/* Execution Outcome */}
                  <div>
                    <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                      Database Engine Evaluation:
                    </span>
                    {labResults.unsafeStatus === "error" ? (
                      <div className="p-3 bg-rose-950/30 border border-rose-800/80 rounded-lg text-rose-200 font-mono text-xs">
                        <div className="font-bold mb-1 flex items-center gap-1">
                          <AlertTriangle className="h-3.5 w-3.5 text-rose-400" />
                          SQL Syntax Parser Error Triggered:
                        </div>
                        <div className="text-[11px] bg-rose-950/80 p-2 rounded border border-rose-900">
                          {labResults.unsafeErrorText}
                        </div>
                        <p className="mt-2 text-[11px] text-slate-400 font-sans">
                          Why this happened: The single quote broke out of the literal string context and was interpreted by the SQLite parser as an incomplete SQL command token.
                        </p>
                      </div>
                    ) : (
                      <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg font-mono text-xs text-slate-300">
                        <div className="text-emerald-400 text-xs mb-1 font-bold">
                          Query Executed (Syntax Accepted):
                        </div>
                        <div className="text-[11px] text-slate-400">
                          Records returned: {labResults.unsafeRows.length} items
                        </div>
                        {labResults.unsafeRows.length > 1 && (
                          <div className="mt-1 text-[11px] text-amber-300 bg-amber-950/40 p-2 rounded border border-amber-900">
                            Notice: All database records dumped because tautology condition ('1'='1) evaluated to true for every row.
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>

                {/* 2. Safe Parameterized Card */}
                <div className="bg-slate-950 border border-emerald-900/60 rounded-xl p-4 space-y-3">
                  <div className="flex items-center justify-between border-b border-emerald-950 pb-2">
                    <span className="text-xs font-mono font-bold text-emerald-400 flex items-center gap-1.5">
                      <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                      2. DEFENSIVE: Parameterized Prepared Statement
                    </span>
                    <span className="text-[10px] font-mono text-emerald-300 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800">
                      cursor.execute(sql, (param,))
                    </span>
                  </div>

                  <div>
                    <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                      Pre-Compiled SQL Statement (Code):
                    </span>
                    <div className="p-2.5 bg-slate-900 border border-slate-800 rounded font-mono text-xs text-emerald-300 break-all">
                      <code>{labResults.safeSql}</code>
                    </div>
                  </div>

                  <div>
                    <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                      Bound Data Tuple (Pure Data):
                    </span>
                    <div className="p-2.5 bg-slate-900 border border-slate-800 rounded font-mono text-xs text-cyan-300 break-all">
                      <code>{labResults.safeParam}</code>
                    </div>
                  </div>

                  {/* Execution Outcome */}
                  <div>
                    <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                      Database Engine Evaluation:
                    </span>
                    <div className="p-3 bg-emerald-950/30 border border-emerald-800/80 rounded-lg text-emerald-200 font-mono text-xs">
                      <div className="font-bold mb-1 flex items-center gap-1">
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                        Safe Execution: Zero Syntax Breaks
                      </div>
                      <p className="text-[11px] text-slate-300 font-sans leading-relaxed">
                        The SQLite query planner compiled the abstract syntax tree <strong>before</strong> the input value was bound. The input is treated strictly as an atomic literal data value. Delimiters like <code className="text-cyan-300">&apos;</code> or <code className="text-cyan-300">OR 1=1</code> can never alter the SQL execution logic.
                      </p>
                      <div className="mt-2 text-[11px] text-slate-400">
                        Exact Literal Matches: {labResults.safeRows.length} item(s) found.
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* AST Conceptual Diagram */}
              <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-2">
                <span className="text-xs font-mono font-semibold text-cyan-300 uppercase tracking-wider block">
                  Why Parameterization is Defensively Absolute: Code vs Data Separation
                </span>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono text-slate-400 pt-1">
                  <div className="p-3 rounded bg-slate-900 border border-slate-800">
                    <div className="text-rose-400 font-bold mb-1">String Concatenation AST:</div>
                    <p className="font-sans text-slate-300 text-xs">
                      The parser sees: <code className="text-rose-300">[SELECT] [FROM] [WHERE] [name=] [&apos;input&apos;] [OR] [TOKEN...]</code>. User input actively creates new syntactic branches and operators in the compiler tree.
                    </p>
                  </div>

                  <div className="p-3 rounded bg-slate-900 border border-slate-800">
                    <div className="text-emerald-400 font-bold mb-1">Prepared Statement AST:</div>
                    <p className="font-sans text-slate-300 text-xs">
                      The parser sees: <code className="text-emerald-300">[SELECT] [FROM] [WHERE] [name=] [PARAMETER_PLACEHOLDER]</code>. The tree is frozen. User input is streamed into the placeholder slot as raw bytes without compiler re-evaluation.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* =========================================================================
            TAB 3: TERMUX CONSOLE (AUTHENTIC TERMINAL UI)
           ========================================================================= */}
        {activeTab === "terminal" && (
          <div className="space-y-4">
            <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-2xl">
              {/* Termux Terminal Titlebar */}
              <div className="bg-slate-950 px-4 py-2.5 border-b border-slate-800 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="h-3 w-3 rounded-full bg-rose-500/80 inline-block" />
                  <span className="h-3 w-3 rounded-full bg-amber-500/80 inline-block" />
                  <span className="h-3 w-3 rounded-full bg-emerald-500/80 inline-block" />
                  <span className="ml-2 font-mono text-xs text-slate-400">
                    Termux &bull; bash &bull; com.termux (Android)
                  </span>
                </div>

                <div className="flex items-center gap-2 text-xs font-mono text-slate-500">
                  <span>session: #1</span>
                  <span>utf-8</span>
                </div>
              </div>

              {/* Termux Android Extra Keyboard Row */}
              <div className="bg-slate-900/90 border-b border-slate-800/80 px-3 py-1.5 flex flex-wrap items-center gap-1 text-[11px] font-mono text-slate-400">
                {["ESC", "TAB", "CTRL", "ALT", "-", "|", "/", "~", "UP", "DOWN"].map((k) => (
                  <button
                    key={k}
                    type="button"
                    onClick={() => {
                      if (k === "TAB") setTerminalInput((prev) => prev + "    ");
                      if (k === "-") setTerminalInput((prev) => prev + "-");
                      if (k === "/") setTerminalInput((prev) => prev + "/");
                    }}
                    className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 hover:border-slate-700 hover:text-slate-200 transition"
                  >
                    {k}
                  </button>
                ))}
                <span className="ml-auto text-[10px] text-slate-500">Termux Virtual Keypad</span>
              </div>

              {/* Console Screen Output */}
              <div
                ref={terminalEndRef}
                className="p-4 bg-slate-950 min-h-[380px] max-h-[500px] overflow-y-auto font-mono text-xs leading-relaxed space-y-1 text-slate-200 selection:bg-cyan-500/30"
              >
                {terminalLogs.map((log, index) => (
                  <div key={index} className="whitespace-pre-wrap break-all">
                    {/* Render basic ANSI colors in log strings */}
                    {log
                      .replace(/\u001b\[36m/g, "")
                      .replace(/\u001b\[32m/g, "")
                      .replace(/\u001b\[31m/g, "")
                      .replace(/\u001b\[33m/g, "")
                      .replace(/\u001b\[35m/g, "")
                      .replace(/\u001b\[90m/g, "")
                      .replace(/\u001b\[1m/g, "")
                      .replace(/\u001b\[0m/g, "")}
                  </div>
                ))}

                {/* Prompt Line */}
                <div className="flex items-center gap-2 pt-2">
                  <span className="text-emerald-400 font-bold select-none">termux@sqlguard:~$</span>
                  <input
                    type="text"
                    value={terminalInput}
                    onChange={(e) => setTerminalInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        handleRunCommand(terminalInput);
                      }
                    }}
                    placeholder="Enter command (e.g. 'python main.py', 'pytest', 'help')..."
                    className="flex-1 bg-transparent text-cyan-300 font-mono text-xs outline-none focus:ring-0"
                    autoFocus
                  />
                </div>
              </div>

              {/* Termux Quick-Action Command Chips */}
              <div className="bg-slate-900 border-t border-slate-800 p-3 flex flex-wrap items-center gap-2 text-xs">
                <span className="text-[11px] font-mono text-slate-400">Quick Commands:</span>
                {[
                  {
                    label: "python main.py",
                    cmd: "python main.py",
                  },
                  {
                    label: "Safe Scan Lab",
                    cmd: "python main.py --target http://127.0.0.1:8000/api/vulnerable_search?q=Termux --mode safe-active --confirm-auth",
                  },
                  {
                    label: "Secure Coding Demo",
                    cmd: "python main.py --demo-secure",
                  },
                  {
                    label: "Toggle Lab Server",
                    cmd: "python main.py --lab",
                  },
                  {
                    label: "pytest test suite",
                    cmd: "pytest tests/ -v",
                  },
                  {
                    label: "ls -la",
                    cmd: "ls -la",
                  },
                  {
                    label: "clear",
                    cmd: "clear",
                  },
                ].map((item, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => handleRunCommand(item.cmd)}
                    className="font-mono text-[11px] px-2.5 py-1 rounded bg-slate-950 border border-slate-800 hover:border-cyan-600 hover:text-cyan-300 text-slate-300 transition"
                  >
                    {item.label}
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* =========================================================================
            TAB 4: REMEDIATION ADVISOR & MULTI-LANGUAGE CODE DIFFS
           ========================================================================= */}
        {activeTab === "advisor" && (
          <div className="space-y-6">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-5 shadow-lg">
              <div className="border-b border-slate-800 pb-3">
                <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                  <Code2 className="h-4 w-4 text-cyan-400" />
                  Defensive Remediation Advisor &amp; Code Blueprints
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Production-tested patterns for replacing dynamic SQL string concatenation with prepared statements.
                </p>
              </div>

              {/* Language Navigation */}
              <div className="flex flex-wrap gap-2 text-xs">
                {[
                  { id: "python", name: "Python (sqlite3 & SQLAlchemy)" },
                  { id: "nodejs", name: "Node.js (pg & Prisma)" },
                  { id: "php", name: "PHP (PDO Prepared Statements)" },
                  { id: "java", name: "Java (JDBC PreparedStatement)" },
                  { id: "go", name: "Go (database/sql)" },
                ].map((l) => (
                  <button
                    key={l.id}
                    onClick={() => setAdvisorLang(l.id as any)}
                    className={`px-3 py-1.5 rounded-lg font-mono text-xs transition ${
                      advisorLang === l.id
                        ? "bg-cyan-600 text-white font-medium"
                        : "bg-slate-950 border border-slate-800 text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    {l.name}
                  </button>
                ))}
              </div>

              {/* Code Snippets & Explanations */}
              <div className="space-y-4">
                {advisorLang === "python" && (
                  <div className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="p-3.5 bg-slate-950 border border-rose-950 rounded-lg">
                        <span className="text-[11px] font-mono text-rose-400 font-bold block mb-1">
                          ❌ INSECURE: Python String Formatting
                        </span>
                        <pre className="text-xs font-mono text-slate-300 overflow-x-auto leading-relaxed">
                          <code>{`# Flawed: input string spliced directly into SQL
query = f"SELECT * FROM users WHERE username = '{user_input}'"
cursor.execute(query)`}</code>
                        </pre>
                      </div>

                      <div className="p-3.5 bg-slate-950 border border-emerald-950 rounded-lg">
                        <span className="text-[11px] font-mono text-emerald-400 font-bold block mb-1">
                          ✅ SECURE: Python SQLite Parameterization
                        </span>
                        <pre className="text-xs font-mono text-emerald-300 overflow-x-auto leading-relaxed">
                          <code>{`# Safe: question-mark placeholder with parameter tuple
query = "SELECT id, username FROM users WHERE username = ?"
cursor.execute(query, (user_input,))`}</code>
                        </pre>
                      </div>
                    </div>

                    <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-lg">
                      <span className="text-[11px] font-mono text-cyan-400 font-bold block mb-1">
                        ORMs: SQLAlchemy Parameterized Filter
                      </span>
                      <pre className="text-xs font-mono text-cyan-200 overflow-x-auto leading-relaxed">
                        <code>{`# Safe: SQLAlchemy automatically compiles parameterized query
records = db.query(User).filter(User.username == user_input).all()`}</code>
                      </pre>
                    </div>
                  </div>
                )}

                {advisorLang === "nodejs" && (
                  <div className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="p-3.5 bg-slate-950 border border-rose-950 rounded-lg">
                        <span className="text-[11px] font-mono text-rose-400 font-bold block mb-1">
                          ❌ INSECURE: Template Literals
                        </span>
                        <pre className="text-xs font-mono text-slate-300 overflow-x-auto leading-relaxed">
                          <code>{`// Flawed: template strings permit syntax breakout
const sql = \`SELECT * FROM users WHERE email = '\${userInput}'\`;
await client.query(sql);`}</code>
                        </pre>
                      </div>

                      <div className="p-3.5 bg-slate-950 border border-emerald-950 rounded-lg">
                        <span className="text-[11px] font-mono text-emerald-400 font-bold block mb-1">
                          ✅ SECURE: Node-Postgres ($1 Placeholders)
                        </span>
                        <pre className="text-xs font-mono text-emerald-300 overflow-x-auto leading-relaxed">
                          <code>{`// Safe: parameterized values passed in second argument array
const sql = 'SELECT id, email FROM users WHERE email = $1';
const { rows } = await client.query(sql, [userInput]);`}</code>
                        </pre>
                      </div>
                    </div>
                  </div>
                )}

                {advisorLang === "php" && (
                  <div className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="p-3.5 bg-slate-950 border border-rose-950 rounded-lg">
                        <span className="text-[11px] font-mono text-rose-400 font-bold block mb-1">
                          ❌ INSECURE: PHP Concatenation
                        </span>
                        <pre className="text-xs font-mono text-slate-300 overflow-x-auto leading-relaxed">
                          <code>{`$sql = "SELECT * FROM accounts WHERE id = " . $_GET['id'];
$pdo->query($sql);`}</code>
                        </pre>
                      </div>

                      <div className="p-3.5 bg-slate-950 border border-emerald-950 rounded-lg">
                        <span className="text-[11px] font-mono text-emerald-400 font-bold block mb-1">
                          ✅ SECURE: PDO Prepared Statements
                        </span>
                        <pre className="text-xs font-mono text-emerald-300 overflow-x-auto leading-relaxed">
                          <code>{`$stmt = $pdo->prepare('SELECT id, name FROM accounts WHERE id = :id');
$stmt->execute(['id' => $_GET['id']]);
$user = $stmt->fetch();`}</code>
                        </pre>
                      </div>
                    </div>
                  </div>
                )}

                {advisorLang === "java" && (
                  <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-lg">
                    <span className="text-[11px] font-mono text-emerald-400 font-bold block mb-1">
                      ✅ SECURE: Java JDBC PreparedStatement
                    </span>
                    <pre className="text-xs font-mono text-emerald-200 overflow-x-auto leading-relaxed">
                      <code>{`String sql = "SELECT id, balance FROM accounts WHERE user_id = ?";
PreparedStatement pstmt = conn.prepareStatement(sql);
pstmt.setInt(1, userId);
ResultSet rs = pstmt.executeQuery();`}</code>
                    </pre>
                  </div>
                )}

                {advisorLang === "go" && (
                  <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-lg">
                    <span className="text-[11px] font-mono text-emerald-400 font-bold block mb-1">
                      ✅ SECURE: Go database/sql
                    </span>
                    <pre className="text-xs font-mono text-emerald-200 overflow-x-auto leading-relaxed">
                      <code>{`// Safe: Query parameters bound cleanly
row := db.QueryRow("SELECT id, username FROM users WHERE id = ?", userID)`}</code>
                    </pre>
                  </div>
                )}
              </div>

              {/* Defense-in-Depth Checklist */}
              <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-2">
                <span className="text-xs font-mono text-cyan-300 uppercase font-semibold">
                  Defensive Security Best Practices (OWASP A03:2021)
                </span>
                <ul className="text-xs text-slate-300 space-y-1.5 list-disc pl-4 font-sans leading-relaxed">
                  <li>
                    <strong>Prepared Statements:</strong> Ensure every single SQL query uses placeholders for user-supplied data.
                  </li>
                  <li>
                    <strong>Least Privilege Database Users:</strong> Web application database accounts should only possess <code className="text-cyan-400 font-mono text-[11px]">SELECT, INSERT, UPDATE</code> permissions, never administrative <code className="text-cyan-400 font-mono text-[11px]">DROP</code> or table modification rights.
                  </li>
                  <li>
                    <strong>Suppress Error Disclosures:</strong> Disable verbose database syntax messages in production environments. Replace stack traces with generic HTTP 500 error pages.
                  </li>
                  <li>
                    <strong>Allowlist Dynamic Column Names:</strong> When parameterization cannot be used for column or table names in sorting, validate names against a strict internal allowlist.
                  </li>
                </ul>
              </div>
            </div>
          </div>
        )}

        {/* =========================================================================
            TAB 5: AUDIT REPORTS (TXT, JSON, HTML)
           ========================================================================= */}
        {activeTab === "reports" && (
          <div className="space-y-6">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 shadow-lg">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
                <div>
                  <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                    <FileText className="h-4 w-4 text-cyan-400" />
                    Security Assessment Report Generator
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Exports reports in TXT, JSON, and standalone HTML. Sensitive credentials automatically redacted.
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  {/* Format Selector */}
                  <div className="flex items-center p-1 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono">
                    {(["html", "txt", "json"] as const).map((fmt) => (
                      <button
                        key={fmt}
                        onClick={() => setReportFormat(fmt)}
                        className={`px-3 py-1 rounded transition uppercase ${
                          reportFormat === fmt
                            ? "bg-cyan-600 text-white font-bold"
                            : "text-slate-400 hover:text-slate-200"
                        }`}
                      >
                        {fmt}
                      </button>
                    ))}
                  </div>

                  <button
                    onClick={() => downloadReportFile(reportFormat)}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium rounded-lg transition"
                  >
                    <Download className="h-3.5 w-3.5" />
                    <span>Download .{reportFormat}</span>
                  </button>
                </div>
              </div>

              {/* Report Preview */}
              <div className="border border-slate-800 rounded-lg overflow-hidden bg-slate-950">
                <div className="p-2.5 bg-slate-900/80 border-b border-slate-800 flex items-center justify-between text-xs font-mono text-slate-400">
                  <span>Preview &bull; sqlguard_report_{new Date().toISOString().slice(0, 10)}.{reportFormat}</span>
                  <button
                    onClick={() => copyToClipboard(getReportContent(reportFormat), "report-content")}
                    className="flex items-center gap-1 text-slate-400 hover:text-cyan-300"
                  >
                    <Copy className="h-3 w-3" />
                    <span>{copiedText === "report-content" ? "Copied!" : "Copy Full Report"}</span>
                  </button>
                </div>

                {reportFormat === "html" ? (
                  <div className="p-4 overflow-x-auto max-h-[500px]">
                    <div
                      className="prose prose-invert max-w-none text-xs"
                      dangerouslySetInnerHTML={{ __html: getReportContent("html") }}
                    />
                  </div>
                ) : (
                  <pre className="p-4 text-xs font-mono text-slate-300 max-h-[500px] overflow-auto whitespace-pre-wrap leading-relaxed">
                    <code>{getReportContent(reportFormat)}</code>
                  </pre>
                )}
              </div>
            </div>
          </div>
        )}

        {/* =========================================================================
            TAB 6: TERMUX SETUP GUIDE & FULL SOURCE CODEBASE EXPLORER
           ========================================================================= */}
        {activeTab === "codebase" && (
          <div className="space-y-6">
            {/* Termux Android Setup Commands Card */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 shadow-lg">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div>
                  <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                    <Smartphone className="h-4 w-4 text-cyan-400" />
                    Termux Android Quickstart Guide
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Run these commands on your Android device inside the Termux application.
                  </p>
                </div>

                <button
                  onClick={() =>
                    copyToClipboard(
                      `pkg update && pkg upgrade -y\npkg install python git -y\npython -m pip install requests pytest\ngit clone https://github.com/security/sqlguard-ai.git\ncd sqlguard-ai\npython main.py`,
                      "termux-script"
                    )
                  }
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-950 border border-slate-800 hover:border-cyan-600 text-xs font-mono text-cyan-300 rounded-lg transition"
                >
                  <Copy className="h-3.5 w-3.5" />
                  <span>{copiedText === "termux-script" ? "Copied Commands!" : "Copy Setup Script"}</span>
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-2">
                  <span className="text-cyan-400 font-bold block">1. System Packages &amp; Python</span>
                  <div className="text-slate-300 space-y-1">
                    <div>pkg update &amp;&amp; pkg upgrade -y</div>
                    <div>pkg install python git -y</div>
                    <div>python -m pip install requests pytest</div>
                  </div>
                </div>

                <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-2">
                  <span className="text-cyan-400 font-bold block">2. Project Directory &amp; Run</span>
                  <div className="text-slate-300 space-y-1">
                    <div>mkdir sqlguard-ai &amp;&amp; cd sqlguard-ai</div>
                    <div>python -m venv .venv &amp;&amp; source .venv/bin/activate</div>
                    <div>python main.py</div>
                  </div>
                </div>
              </div>
            </div>

            {/* In-App Code Repository Browser */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
              <div className="p-4 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div>
                  <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                    <FileCode className="h-4 w-4 text-cyan-400" />
                    SQLGuard AI Python Codebase Browser
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Browse all source files, unit tests, and training lab modules.
                  </p>
                </div>

                <button
                  onClick={() => copyToClipboard(selectedFile.content, selectedFile.path)}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-950 border border-slate-800 hover:border-slate-700 text-xs font-mono text-slate-300 rounded-lg transition"
                >
                  <Copy className="h-3.5 w-3.5 text-cyan-400" />
                  <span>{copiedText === selectedFile.path ? "Copied File!" : "Copy File"}</span>
                </button>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-12 min-h-[450px]">
                {/* File Tree Navigator */}
                <div className="lg:col-span-4 border-r border-slate-800 bg-slate-950/60 p-3 space-y-1 text-xs font-mono">
                  <div className="text-[11px] text-slate-500 uppercase px-2 py-1 font-bold">
                    Project Tree
                  </div>
                  {REPO_FILES.map((file) => (
                    <button
                      key={file.path}
                      type="button"
                      onClick={() => setSelectedFile(file)}
                      className={`w-full text-left px-2.5 py-1.5 rounded transition flex items-center justify-between ${
                        selectedFile.path === file.path
                          ? "bg-cyan-950/80 text-cyan-300 border border-cyan-800 font-semibold"
                          : "text-slate-400 hover:bg-slate-900 hover:text-slate-200"
                      }`}
                    >
                      <span className="truncate">{file.path}</span>
                      <span className="text-[10px] text-slate-600 font-sans">{file.category}</span>
                    </button>
                  ))}
                </div>

                {/* File Content Viewer */}
                <div className="lg:col-span-8 p-4 bg-slate-950 overflow-x-auto flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between pb-2 mb-3 border-b border-slate-800/80 text-xs font-mono text-slate-400">
                      <span className="text-cyan-400 font-bold">{selectedFile.path}</span>
                      <span>language: {selectedFile.language}</span>
                    </div>

                    <pre className="text-xs font-mono text-slate-300 whitespace-pre-wrap leading-relaxed max-h-[420px] overflow-y-auto">
                      <code>{selectedFile.content}</code>
                    </pre>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950 px-4 py-3 text-center text-xs text-slate-500">
        <p>
          SQLGuard AI &bull; Defensive Security Testing &amp; Vulnerability Remediation Engine for Android Termux (2026).
          Strictly for authorized environments and local training.
        </p>
      </footer>
    </div>
  );
}
