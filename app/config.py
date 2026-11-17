"""Central configuration and academic metadata for the IIITA IT-30001 Security Lab."""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

LAB_HOST = os.environ.get("LAB_HOST", "127.0.0.1")
LAB_PORT = int(os.environ.get("LAB_PORT", "8000"))
LAB_SECRET_KEY = os.environ.get("LAB_SECRET_KEY", "iiita-it30001-local-demo-key")
DB_PATH = Path(os.environ.get("LAB_DB_PATH", str(DATA_DIR / "cybersec_lab.db")))
if not DB_PATH.is_absolute():
    DB_PATH = BASE_DIR / DB_PATH

COURSE_INFO = {
    "institute": "Indian Institute of Information Technology Allahabad",
    "short_institute": "IIIT Allahabad",
    "department": "Department of Information Technology",
    "course_code": "IT-30001",
    "course_name": "Cyber Security",
    "semester": "Autumn Semester 2026",
    "assignment": "Web Server Security – Exploitation and Mitigation of Four Vulnerability Categories",
    "instructor": "Dr. Soumyadev Maity",
    "project_title": "SecLab // IIITA Web Security Workbench",
    "project_subtitle": "Interactive Exploitation, Telemetry & Mitigation Platform",
}

# Configurable group member placeholders (update with actual names & roll numbers before submission)
GROUP_MEMBERS = [
    {
        "member_id": "member_1",
        "label": "Member 1",
        "name": "Shankar",
        "roll_number": "IIT2024079",
        "category": "SQL Injection",
        "variant": "Authentication Bypass",
        "module_slug": "sqli-auth",
        "route": "/modules/sqli-auth",
        "implemented_mitigation": "Parameterized Queries (Prepared Statements)",
        "summary": "Demonstrates how string-concatenated SQL login queries allow logic manipulation to bypass authentication, and how parameterized queries bind inputs strictly as data.",
    },
    {
        "member_id": "member_2",
        "label": "Member 2",
        "name": "Milan",
        "roll_number": "IIT2024053",
        "category": "Cross-Site Scripting (XSS)",
        "variant": "Reflected XSS",
        "module_slug": "xss-reflected",
        "route": "/modules/xss-reflected",
        "implemented_mitigation": "Context-Aware HTML Output Encoding",
        "summary": "Demonstrates how unsanitized HTTP GET query parameters reflected in HTML responses execute arbitrary browser JavaScript, and how HTML entity encoding neutralizes it.",
    },
    {
        "member_id": "member_3",
        "label": "Member 3",
        "name": "Umesh",
        "roll_number": "IIT2024080",
        "category": "Cross-Site Scripting (XSS)",
        "variant": "Stored XSS",
        "module_slug": "xss-stored",
        "route": "/modules/xss-stored",
        "implemented_mitigation": "Context-Aware Output Encoding on Render",
        "summary": "Demonstrates how untrusted comments persisted in SQLite execute on every page load when rendered without HTML output encoding.",
    },
    {
        "member_id": "member_4",
        "label": "Member 4",
        "name": "Pranav",
        "roll_number": "IIT2024048",
        "category": "OS Command Injection",
        "variant": "In-Band (Command Output Returned)",
        "module_slug": "cmd-injection",
        "route": "/modules/cmd-injection",
        "implemented_mitigation": "Allow-List Validation + Argument Vector (shell=False)",
        "summary": "Demonstrates how shell metacharacters injected into a diagnostic command execute arbitrary OS commands in-band, and how argument-vector execution blocks shell interpretation.",
    },
    {
        "member_id": "member_5",
        "label": "Member 5",
        "name": "Mast Ram",
        "roll_number": "IIT2024067",
        "category": "Cross-Site Request Forgery (CSRF)",
        "variant": "GET-Based Forged Action",
        "module_slug": "csrf-get",
        "route": "/modules/csrf-get",
        "implemented_mitigation": "Reject State-Changing GET + POST with Synchronizer Anti-CSRF Token",
        "summary": "Demonstrates how an external attacker page triggers an authenticated state-changing GET transfer via the victim's browser session, mitigated by method enforcement and anti-CSRF tokens.",
    },
]
