"""
Defensive Security Demonstration: Unsafe vs Parameterized SQL Queries
Demonstrates why string concatenation fails and how prepared statements
fundamentally prevent SQL Injection at the database engine parser level.
"""

import sqlite3
from typing import List, Tuple, Any


def initialize_in_memory_db() -> sqlite3.Connection:
    """Sets up an isolated, in-memory SQLite database populated with practice data."""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()

    # Create dummy tables
    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            price REAL NOT NULL
        )
    """)

    # Seed mock records
    users_data = [
        ("alice_dev", "alice@corp.internal", "admin"),
        ("bob_security", "bob@corp.internal", "auditor"),
        ("charlie_guest", "charlie@public.org", "member"),
    ]
    cursor.executemany("INSERT INTO users (username, email, role) VALUES (?, ?, ?)", users_data)

    products_data = [
        ("Hardware Security Key", "Security", 49.99),
        ("Encrypted Flash Drive", "Security", 29.50),
        ("Mechanical Keyboard", "Hardware", 119.00),
        ("Noise Cancelling Headset", "Audio", 189.99),
    ]
    cursor.executemany("INSERT INTO products (name, category, price) VALUES (?, ?, ?)", products_data)

    conn.commit()
    return conn


def vulnerable_lookup(conn: sqlite3.Connection, search_term: str) -> Tuple[List[Any], str, str]:
    """
    DANGEROUS / VULNERABLE PATTERN:
    Constructs SQL query via string concatenation or format string.
    User input breaks out of the intended string literal context and is parsed as SQL syntax.
    """
    cursor = conn.cursor()
    # Flawed concatenation
    raw_query = f"SELECT id, name, category, price FROM products WHERE name = '{search_term}'"

    try:
        cursor.execute(raw_query)
        results = cursor.fetchall()
        return results, raw_query, "OK: Query executed successfully (Vulnerable syntax parsing)."
    except sqlite3.OperationalError as e:
        return [], raw_query, f"ERROR LEAKED: sqlite3.OperationalError: {str(e)}"


def secure_lookup(conn: sqlite3.Connection, search_term: str) -> Tuple[List[Any], str, str]:
    """
    DEFENSIVE / RECOMMENDED PATTERN:
    Uses Parameterized Queries (Prepared Statement placeholders '?').
    The database engine compiles the query structure *BEFORE* user input is bound.
    Input is treated strictly as literal data, making SQL injection mathematically impossible.
    """
    cursor = conn.cursor()
    # Parameterized SQL query
    safe_query = "SELECT id, name, category, price FROM products WHERE name = ?"

    try:
        # User input is passed as a separate tuple parameter, NEVER concatenated
        cursor.execute(safe_query, (search_term,))
        results = cursor.fetchall()
        return results, safe_query, "OK: Query executed with parameterized binding (Safe from injection)."
    except sqlite3.OperationalError as e:
        return [], safe_query, f"ERROR: {str(e)}"


def run_demonstration():
    print("=" * 70)
    print("SQLGuard AI - Secure Coding Demonstration: Unsafe vs Parameterized SQL")
    print("=" * 70)

    conn = initialize_in_memory_db()

    test_inputs = [
        ("Legitimate Product Search", "Hardware Security Key"),
        ("Single Quote Boundary Probe", "Hardware'"),
        ("Benign OR Condition Probe", "Hardware' OR '1'='1"),
    ]

    for label, user_input in test_inputs:
        print(f"\n[Test Case] {label}")
        print(f"User Input: {user_input}")

        # Run Vulnerable
        vuln_res, vuln_query, vuln_status = vulnerable_lookup(conn, user_input)
        print("  - VULNERABLE (Concatenation):")
        print(f"      Constructed SQL: {vuln_query}")
        print(f"      Status:          {vuln_status}")
        print(f"      Records Fetched: {len(vuln_res)}")

        # Run Secure
        sec_res, sec_query, sec_status = secure_lookup(conn, user_input)
        print("  - SECURE (Parameterized Query):")
        print(f"      Pre-compiled SQL: {sec_query}")
        print(f"      Bound Parameter: ('{user_input}',)")
        print(f"      Status:          {sec_status}")
        print(f"      Records Fetched: {len(sec_res)} (Literal exact match only)")

    print("\n" + "=" * 70)
    print("KEY TAKEAWAYS FOR DEFENDERS:")
    print("1. Parameterized queries enforce strict separation of CODE (SQL commands) and DATA (user values).")
    print("2. The database parser never evaluates special characters in parameters as SQL delimiters or tokens.")
    print("3. Input filtering and sanitization are insufficient alone; parameterization is mandatory.")
    print("=" * 70)


if __name__ == "__main__":
    run_demonstration()
