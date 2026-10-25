#!/usr/bin/env python3
"""
SQLGuard AI — Advanced SQL Injection Security Scanner for Android Termux (2026)
Educational & Defensive Security Assessment Platform.
"""

import argparse
import json
import logging
import os
import sys
import time
from typing import List

# Ensure local scanner modules are importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.severity import Finding, Severity, Confidence
from scanner.passive_checks import PassiveScanner, TargetValidationError
from scanner.safe_tests import SafeActiveEngine
from scanner.report_generator import ReportGenerator

# Termux ANSI Colors
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_CYAN = "\033[36m"
C_GREEN = "\033[32m"
C_YELLOW = "\033[33m"
C_RED = "\033[31m"
C_MAGENTA = "\033[35m"
C_GRAY = "\033[90m"

BANNER = f"""{C_CYAN}{C_BOLD}
  ____   ___  _      ____                     _      _    ___ 
 / ___| / _ \\| |    / ___|_   _  __ _ _ __ __| |    / \\  |_ _|
 \\___ \\| | | | |   | |  _| | | |/ _` | '__/ _` |   / _ \\  | | 
  ___) | |_| | |___| |_| | |_| | (_| | | | (_| |  / ___ \\ | | 
 |____/ \\__\\_\\_____|\\____|\\__,_|\\__,_|_|  \\__,_| /_/   \\_\\___|
{C_RESET}{C_GRAY}   Advanced Defensive SQL Injection Scanner for Termux [2026.1]
   Strict Safe-Testing & Defensive Remediation Engine{C_RESET}
"""


def setup_logger():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S"
    )


def load_config() -> dict:
    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"scanner": {}, "safety_guardrails": {}}


def display_dashboard(target: str, mode: str, duration: float, findings: List[Finding]):
    print(f"\n{C_BOLD}{C_CYAN}{'='*68}{C_RESET}")
    print(f"{C_BOLD}  SQLGuard AI — Security Assessment Dashboard{C_RESET}")
    print(f"{C_CYAN}{'='*68}{C_RESET}")
    print(f"  Target:     {C_BOLD}{target}{C_RESET}")
    print(f"  Mode:       {mode.upper()}")
    print(f"  Duration:   {duration:.2f} seconds")
    print(f"  Findings:   {len(findings)} issues documented")

    # Severity distribution
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print(f"\n  {C_BOLD}Severity Distribution:{C_RESET}")
    print(f"    {C_RED}[!] Critical:      {counts[Severity.CRITICAL]}{C_RESET}")
    print(f"    {C_YELLOW}[*] High:          {counts[Severity.HIGH]}{C_RESET}")
    print(f"    {C_MAGENTA}[+] Medium:        {counts[Severity.MEDIUM]}{C_RESET}")
    print(f"    {C_CYAN}[-] Low:           {counts[Severity.LOW]}{C_RESET}")
    print(f"    {C_GRAY}[i] Informational: {counts[Severity.INFORMATIONAL]}{C_RESET}")
    print(f"{C_CYAN}{'='*68}{C_RESET}\n")

    if findings:
        print(f"{C_BOLD}Remediation Highlights:{C_RESET}")
        for idx, f in enumerate(findings, 1):
            color = C_RED if f.severity in (Severity.CRITICAL, Severity.HIGH) else C_YELLOW
            print(f"  {idx}. {color}[{f.severity.value}]{C_RESET} {f.title}")
            print(f"     {C_GRAY}Fix:{C_RESET} {f.remediation[:110]}...")
        print()


def execute_scan(target_url: str, mode: str, confirmed_auth: bool):
    if not confirmed_auth:
        print(f"{C_RED}[!] Error: Target authorization not verified.{C_RESET}")
        print("    You must explicitly verify you own or have written permission to test this target.")
        print("    Use: --confirm-auth (CLI) or accept the interactive authorization prompt.")
        return

    start_time = time.time()
    config = load_config()
    scanner_conf = config.get("scanner", {})

    print(f"\n{C_CYAN}[*] Initializing SQLGuard AI Assessment...{C_RESET}")
    print(f"[*] Target: {target_url}")
    print(f"[*] Mode:   {mode.upper()}")

    # Step 1: Safety & SSRF boundary check
    is_local_target = "127.0.0.1" in target_url or "localhost" in target_url
    passive = PassiveScanner(allow_local_lab=is_local_target)

    try:
        norm_url = passive.normalize_url(target_url)
        is_safe, msg = passive.validate_target_safety(norm_url)
        print(f"{C_GREEN}[+] Safety Boundary Verified: {msg}{C_RESET}")
    except TargetValidationError as e:
        print(f"{C_RED}[!] Safety Boundary Violation: {e}{C_RESET}")
        return

    findings: List[Finding] = []

    # Step 2: Passive Surface Checks
    print(f"{C_CYAN}[*] Step 1/2: Running passive surface discovery...{C_RESET}")
    surface_findings = passive.inspect_url_surface(norm_url)
    findings.extend(surface_findings)
    print(f"[+] Passive surface review completed ({len(surface_findings)} surface notes).")

    # Step 3: Active Testing if mode is safe-active
    if mode == "safe-active":
        print(f"{C_CYAN}[*] Step 2/2: Executing safe, non-destructive boundary probes...{C_RESET}")
        active_engine = SafeActiveEngine(
            timeout=scanner_conf.get("timeout_seconds", 5.0),
            rate_limit_delay=scanner_conf.get("rate_limit_delay_seconds", 0.35),
            max_requests_per_endpoint=scanner_conf.get("max_requests_per_endpoint", 12),
            stop_on_repeated_errors=scanner_conf.get("stop_on_repeated_errors", 3)
        )

        def progress(msg: str):
            print(f"    {C_GRAY}> {msg}{C_RESET}")

        try:
            active_findings = active_engine.run_safe_assessment(
                target_url=norm_url,
                is_authorized=True,
                progress_callback=progress
            )
            findings.extend(active_findings)
        except Exception as e:
            print(f"{C_YELLOW}[!] Safe active check completed with note: {e}{C_RESET}")

    duration = time.time() - start_time

    # Display Terminal Dashboard
    display_dashboard(norm_url, mode, duration, findings)

    # Generate Reports
    print(f"{C_CYAN}[*] Generating Multi-Format Security Reports...{C_RESET}")
    rep_gen = ReportGenerator(
        target_url=norm_url,
        findings=findings,
        scan_metadata={
            "mode": mode,
            "duration_seconds": duration,
            "version": scanner_conf.get("version", "2026.1.0")
        }
    )
    saved_paths = rep_gen.save_all("./reports")
    print(f"{C_GREEN}[+] Reports successfully generated:{C_RESET}")
    for fmt, p in saved_paths.items():
        print(f"    - {fmt.upper()}: {p}")


def interactive_menu():
    while True:
        print(BANNER)
        print("  [1] Run Security Assessment (URL Input)")
        print("  [2] Practice in Local Training Lab (SQLite)")
        print("  [3] Secure Coding Demonstration (Concatenation vs Prepared Statements)")
        print("  [4] Run Automated Test Suite (pytest)")
        print("  [5] Exit")
        print()

        try:
            choice = input(f"{C_CYAN}termux@sqlguard:~$ {C_RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting SQLGuard AI. Stay secure!")
            break

        if choice == "1":
            print(f"\n{C_BOLD}--- Target Authorization Required ---{C_RESET}")
            target = input("Enter target URL (e.g. http://127.0.0.1:8000/api/vulnerable_search?q=test): ").strip()
            if not target:
                print("Target URL cannot be empty.")
                continue

            print(f"\n{C_YELLOW}AUTHORIZATION DECLARATION:{C_RESET}")
            print("Do you own this system or hold explicit, written permission from the owner to test it?")
            confirm = input("Type 'YES' to confirm authorization: ").strip()
            if confirm != "YES":
                print(f"{C_RED}[!] Authorization not confirmed. Assessment cancelled.{C_RESET}")
                continue

            print("\nSelect Mode:")
            print("  [p] Passive Assessment (Header/Surface inspection, zero payloads)")
            print("  [a] Safe Active Testing (Controlled, harmless delimiter checks)")
            m_input = input("Mode [p/a, default: p]: ").strip().lower()
            mode = "safe-active" if m_input == "a" else "passive"

            execute_scan(target, mode, confirmed_auth=True)
            input(f"\n{C_GRAY}Press Enter to return to menu...{C_RESET}")

        elif choice == "2":
            print(f"\n{C_CYAN}[*] Launching Local Training Lab...{C_RESET}")
            from lab.vulnerable_app import run_lab_server
            print("[*] Training lab will run on http://127.0.0.1:8000")
            print("[*] Press Ctrl+C anytime to return.")
            try:
                run_lab_server()
            except KeyboardInterrupt:
                print("\nLab server stopped.")

        elif choice == "3":
            from lab.secure_examples import run_demonstration
            run_demonstration()
            input(f"\n{C_GRAY}Press Enter to return to menu...{C_RESET}")

        elif choice == "4":
            print(f"\n{C_CYAN}[*] Running pytest automated test suite...{C_RESET}\n")
            os.system("pytest tests/ -v")
            input(f"\n{C_GRAY}Press Enter to return to menu...{C_RESET}")

        elif choice == "5":
            print("\nExiting SQLGuard AI. Defensive testing only!")
            break


def main():
    parser = argparse.ArgumentParser(description="SQLGuard AI — Defensive SQL Injection Scanner for Termux (2026)")
    parser.add_argument("--target", help="Target URL to assess")
    parser.add_argument("--mode", choices=["passive", "safe-active"], default="passive", help="Assessment mode")
    parser.add_argument("--confirm-auth", action="store_true", help="Confirm ownership or written testing authorization")
    parser.add_argument("--lab", action="store_true", help="Launch local training lab server")
    parser.add_argument("--demo-secure", action="store_true", help="Run SQLite parameterized query demo")

    args = parser.parse_args()

    if args.lab:
        from lab.vulnerable_app import run_lab_server
        run_lab_server()
    elif args.demo_secure:
        from lab.secure_examples import run_demonstration
        run_demonstration()
    elif args.target:
        execute_scan(args.target, args.mode, args.confirm_auth)
    else:
        interactive_menu()


if __name__ == "__main__":
    main()
