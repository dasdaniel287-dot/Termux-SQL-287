# SQLGuard AI — Advanced SQL Injection Security Scanner for Termux (2026)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: Android Termux](https://img.shields.io/badge/Platform-Android%20Termux-green.svg)](#)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](#)
[![Defense: OWASP Top 10](https://img.shields.io/badge/OWASP-A03%3A2021--Injection-red.svg)](#)

**SQLGuard AI** is a professional, Python-based defensive security scanner and training platform designed specifically for **Android with Termux**. It enables security learners, developers, and authorized penetration testers to detect SQL injection vulnerabilities safely, audit error leakage, and implement robust remediations using parameterized queries.

---

## ⚠️ Authorized Use & Ethical Boundaries
- **Strictly for Authorized Testing**: Only scan applications you personally own or have explicit, signed written authorization to assess.
- **Harmless & Non-Destructive**: SQLGuard AI uses benign boundary checks and passive reconnaissance. It **never** extracts data, alters database records, bypasses authentication, or executes destructive queries.
- **Default Local-Lab Safeguard**: Blocks private-network scanning and external targets unless explicit authorization confirmation is provided.

---

## 📱 Termux Installation Guide (Android)

Run the following commands inside your Termux terminal on Android:

```bash
# 1. Update Termux system packages
pkg update && pkg upgrade -y

# 2. Install Python, Git, and OpenSSL
pkg install python git -y

# 3. Clone or create the project directory
git clone https://github.com/security/sqlguard-ai.git
cd sqlguard-ai

# 4. (Optional but recommended) Create Python virtual environment
python -m venv .venv
source .venv/bin/activate

# 5. Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Quick Start & Usage

### 1. Interactive Terminal Menu (Recommended on Termux)
Simply launch `main.py` without arguments:
```bash
python main.py
```
This launches the tactile Termux dashboard with numerical navigation.

### 2. Practice in the Local Training Lab (Safe Sandbox)
Launch the local training HTTP server:
```bash
python main.py --lab
```
In another Termux session (or background), assess the vulnerable training endpoint:
```bash
python main.py --target "http://127.0.0.1:8000/api/vulnerable_search?q=Termux" --mode safe-active --confirm-auth
```

### 3. Passive Assessment Mode (No Payloads)
```bash
python main.py --target "https://your-authorized-app.example.com/search?item=widget" --mode passive --confirm-auth
```

### 4. Safe Active Testing Mode (Harmless Boundary Delimiters)
```bash
python main.py --target "https://your-authorized-app.example.com/search?item=widget" --mode safe-active --confirm-auth
```

### 5. Secure Coding Demonstration (Unsafe vs Parameterized)
Run the in-memory SQLite demonstration:
```bash
python main.py --demo-secure
```

### 6. Run Automated Quality Assurance Test Suite
```bash
pytest tests/ -v
```

---

## 📂 Project Structure

```
sqlguard-ai/
├── main.py                  # Interactive CLI entry point and argument router
├── config.json              # Rate limits, timeouts, and redaction rules
├── requirements.txt         # requests, pytest
├── README.md                # Documentation and Termux quickstart guide
├── scanner/
│   ├── __init__.py          # Package exports
│   ├── passive_checks.py    # URL normalization, SSRF guard, surface discovery
│   ├── safe_tests.py        # Harmless delimiter testing, rate limiting, circuit breaker
│   ├── response_analyzer.py # 5+ DBMS error signatures, differential analysis
│   ├── severity.py          # Severity (Critical-Info) & Finding data models
│   └── report_generator.py  # TXT, JSON, HTML multi-format report builder
├── reports/                 # Output folder for generated security audit reports
├── tests/
│   ├── __init__.py
│   ├── test_analyzer.py     # Tests for SSRF blocking, redaction, error detection
│   └── test_reports.py      # Tests for JSON, TXT, HTML generation
└── lab/
    ├── README.md            # Lab documentation
    ├── vulnerable_app.py    # Standalone mock training server with SQLite
    └── secure_examples.py   # Parameterized query vs string concatenation demo
```

---

## 🛡️ Defensive Remediation: Parameterized Queries

### Why String Concatenation Fails:
```python
# ❌ VULNERABLE: Direct string concatenation allows input to alter query syntax
cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
```

### The Fix: Prepared Statements / Parameterized Queries:
```python
# ✅ SECURE: The database engine compiles SQL structure BEFORE binding input
cursor.execute("SELECT id, username FROM users WHERE username = ?", (username,))
```
When using parameterized queries, characters like `'`, `"`, `--`, or `OR 1=1` are treated purely as **literal data**, making SQL injection structurally impossible.

---

## 📋 Final Security Verification Checklist
- [ ] Ensure all SQL queries across all services use parameterized queries or trusted ORM mappings.
- [ ] Confirm no user input is ever concatenated into SQL strings.
- [ ] Verify database connection accounts operate under least privilege (e.g. read-only where write is not needed).
- [ ] Enforce global exception handling in your web framework to prevent database syntax error leakage.
- [ ] Add regression tests in CI/CD verifying application response to delimiters (`'`, `"`, `\`).

---

## 🔧 Troubleshooting on Android Termux
- **Package install error**: Run `termux-change-repo` and select a fast mirror.
- **Storage permission**: Run `termux-setup-storage` if saving reports to internal phone storage.
- **Port already in use**: If port 8000 is occupied, launch the lab with custom port or kill previous tasks (`pkill python`).
