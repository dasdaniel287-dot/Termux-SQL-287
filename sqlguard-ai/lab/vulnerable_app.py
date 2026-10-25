"""
Local SQL Injection Training Application for Android Termux.
Provides an isolated localhost server with intentionally vulnerable and defended endpoints
for practicing defensive scanning and verifying SQLGuard AI detection.
"""

import json
import sqlite3
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


def init_database() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE training_products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            category TEXT,
            in_stock INTEGER
        )
    """)
    cursor.executemany(
        "INSERT INTO training_products VALUES (?, ?, ?, ?)",
        [
            (1, "Termux Keyboard", "Accessories", 15),
            (2, "OTG Adapter USB-C", "Adapters", 50),
            (3, "Android Debug Bridge Cable", "Cables", 30),
            (4, "YubiKey 5C NFC", "Security", 25),
        ]
    )
    conn.commit()
    return conn


DB_CONN = init_database()


class TrainingLabHandler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, data: dict):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Powered-By", "SQLGuard-Training-Lab/2026")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))

    def _send_html(self, status: int, html_content: str):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html_content.encode("utf-8"))

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == "/":
            html = """
            <!doctype html>
            <html>
            <head><title>SQLGuard Training Lab</title></head>
            <body style="font-family:sans-serif; background:#0f172a; color:#f8fafc; padding:30px;">
                <h1 style="color:#38bdf8;">SQLGuard AI - Local Defensive Training Lab</h1>
                <p>Use these endpoints to test passive and safe active assessments:</p>
                <ul>
                    <li><strong>Vulnerable Search:</strong> <code>/api/vulnerable_search?q=Termux</code> (demonstrates unhandled syntax errors)</li>
                    <li><strong>Defended Search:</strong> <code>/api/secure_search?q=Termux</code> (uses parameterized queries)</li>
                </ul>
            </body>
            </html>
            """
            self._send_html(200, html)
            return

        if parsed.path == "/api/vulnerable_search":
            query_val = params.get("q", [""])[0]
            cursor = DB_CONN.cursor()
            # Deliberately unsafe string concatenation for practice
            raw_sql = f"SELECT id, name, category, in_stock FROM training_products WHERE name = '{query_val}'"
            try:
                cursor.execute(raw_sql)
                rows = cursor.fetchall()
                results = [{"id": r[0], "name": r[1], "category": r[2], "in_stock": r[3]} for r in rows]
                self._send_json(200, {"status": "success", "endpoint": "vulnerable", "query": raw_sql, "results": results})
            except sqlite3.OperationalError as e:
                # Simulates typical verbose backend error leakage
                self._send_json(500, {
                    "status": "error",
                    "error_type": "DatabaseSyntaxError",
                    "details": f"sqlite3.OperationalError: {str(e)}",
                    "raw_sql": raw_sql
                })
            return

        if parsed.path == "/api/secure_search":
            query_val = params.get("q", [""])[0]
            cursor = DB_CONN.cursor()
            # Properly parameterized query
            safe_sql = "SELECT id, name, category, in_stock FROM training_products WHERE name = ?"
            try:
                cursor.execute(safe_sql, (query_val,))
                rows = cursor.fetchall()
                results = [{"id": r[0], "name": r[1], "category": r[2], "in_stock": r[3]} for r in rows]
                self._send_json(200, {"status": "success", "endpoint": "secure", "results": results})
            except Exception as e:
                self._send_json(500, {"status": "error", "message": "An internal server error occurred."})
            return

        self._send_json(404, {"error": "Endpoint not found"})

    def log_message(self, format, *args):
        # Keep terminal log clean
        sys.stderr.write(f"[TrainingLab] {self.address_string()} - {format % args}\n")


def run_lab_server(port: int = 8000):
    server = HTTPServer(("127.0.0.1", port), TrainingLabHandler)
    print(f"[*] SQLGuard Training Lab running on http://127.0.0.1:{port}")
    print("[*] Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down training lab.")
        server.server_close()


if __name__ == "__main__":
    run_lab_server()
