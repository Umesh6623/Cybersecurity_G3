"""SQLite database initialization, connection management, and per-module reset helpers."""

import hashlib
import sqlite3
from pathlib import Path
from app.config import DB_PATH


def hash_password(password: str) -> str:
    """Deterministic SHA-256 hash for simulated demo accounts (academic lab only)."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def get_connection(db_path: Path = None) -> sqlite3.Connection:
    target = db_path or DB_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Path = None) -> None:
    """Create all tables and seed initial demonstration data if empty."""
    conn = get_connection(db_path)
    try:
        cur = conn.cursor()
        # Module 1: SQLi Authentication Bypass users
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS sqli_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                full_name TEXT NOT NULL,
                department TEXT NOT NULL
            )
            """
        )

        # Module 2: Stored XSS persistent comments
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS stored_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                author TEXT NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )

        # Module 5: CSRF simulated wallet accounts & transactions
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS csrf_accounts (
                username TEXT PRIMARY KEY,
                full_name TEXT NOT NULL,
                balance REAL NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS csrf_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_user TEXT NOT NULL,
                to_user TEXT NOT NULL,
                amount REAL NOT NULL,
                method TEXT NOT NULL,
                mode TEXT NOT NULL,
                origin_label TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()

        # Seed if empty
        if cur.execute("SELECT COUNT(*) FROM sqli_users").fetchone()[0] == 0:
            seed_sqli_users(conn)
        if cur.execute("SELECT COUNT(*) FROM stored_comments").fetchone()[0] == 0:
            seed_stored_comments(conn)
        if cur.execute("SELECT COUNT(*) FROM csrf_accounts").fetchone()[0] == 0:
            seed_csrf_data(conn)
    finally:
        conn.close()


def seed_sqli_users(conn: sqlite3.Connection) -> None:
    users = [
        ("admin", hash_password("IIITA_Admin#2026"), "Administrator", "Dr. Lab Admin", "Information Technology"),
        ("alice", hash_password("AlicePass!99"), "Student Researcher", "Alice Verma", "IT-30001 Lab"),
        ("bob", hash_password("BobSecure$42"), "Teaching Assistant", "Bob Sharma", "Information Technology"),
    ]
    conn.executemany(
        "INSERT OR IGNORE INTO sqli_users (username, password_hash, role, full_name, department) VALUES (?, ?, ?, ?, ?)",
        users,
    )
    conn.commit()


def seed_stored_comments(conn: sqlite3.Connection) -> None:
    comments = [
        (
            "Alice Verma",
            "Welcome to IT-30001 Security Advisory Board",
            "Please post your lab observations on input validation and output encoding here.",
            "2026-11-10 09:30:00",
        ),
        (
            "Bob Sharma (TA)",
            "Reminder: Test only inside localhost",
            "All demonstrations must remain strictly on 127.0.0.1 using harmless academic payloads.",
            "2026-11-11 14:15:00",
        ),
    ]
    conn.executemany(
        "INSERT INTO stored_comments (author, title, content, created_at) VALUES (?, ?, ?, ?)",
        comments,
    )
    conn.commit()


def seed_csrf_data(conn: sqlite3.Connection) -> None:
    accounts = [
        ("student_victim", "Aarav Patel (Victim Session)", 10000.00),
        ("attacker_acct", "External Attacker Wallet", 500.00),
        ("campus_cafeteria", "IIITA Campus Cafeteria", 2500.00),
    ]
    conn.executemany(
        "INSERT OR REPLACE INTO csrf_accounts (username, full_name, balance) VALUES (?, ?, ?)",
        accounts,
    )
    conn.execute(
        """
        INSERT INTO csrf_transactions (from_user, to_user, amount, method, mode, origin_label, created_at)
        VALUES ('student_victim', 'campus_cafeteria', 150.00, 'POST', 'secured', 'Legitimate User Action', '2026-11-12 12:05:00')
        """
    )
    conn.commit()


def reset_module_db(module_slug: str, db_path: Path = None) -> None:
    """Restore initial clean state for a specific module."""
    conn = get_connection(db_path)
    try:
        if module_slug == "sqli-auth":
            conn.execute("DELETE FROM sqli_users")
            seed_sqli_users(conn)
        elif module_slug == "xss-stored":
            conn.execute("DELETE FROM stored_comments")
            seed_stored_comments(conn)
        elif module_slug == "csrf-get":
            conn.execute("DELETE FROM csrf_transactions")
            conn.execute("DELETE FROM csrf_accounts")
            seed_csrf_data(conn)
        conn.commit()
    finally:
        conn.close()
