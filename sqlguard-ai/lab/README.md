# SQLGuard AI — Defensive Training Lab

This directory contains defensive security demonstrations and a local mock laboratory for hands-on learning without risking live third-party systems.

## Files
1. `secure_examples.py`:
   - Interactive command-line comparison of string concatenation vs parameterized SQL queries.
   - Shows why parameterized queries prevent SQL injection at the database parser level.
   - Run with: `python lab/secure_examples.py`

2. `vulnerable_app.py`:
   - Lightweight, dependency-free HTTP server running SQLite in memory.
   - Exposes:
     - `/api/vulnerable_search?q=...` (Unsafe concatenation)
     - `/api/secure_search?q=...` (Safe parameterized queries)
   - Run with: `python lab/vulnerable_app.py`
   - Test using SQLGuard:
     ```bash
     python main.py --target "http://127.0.0.1:8000/api/vulnerable_search?q=Termux" --mode safe-active --confirm-auth
     ```
