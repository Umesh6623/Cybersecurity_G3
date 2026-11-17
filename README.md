# SecLab // IIITA Web Security Workbench

**Institute:** Indian Institute of Information Technology Allahabad  
**Department:** Department of Information Technology  
**Course:** Cyber Security (IT-30001) — Autumn Semester 2026  
**Instructor:** Dr. Soumyadev Maity  
**Assignment:** Web Server Security – Exploitation and Mitigation of Four Vulnerability Categories

## Project Overview

This repository contains an original, localhost-only cybersecurity demonstration platform built with **FastAPI**, **SQLite**, **Jinja2**, **HTML5**, **CSS3**, and **Vanilla JavaScript**. It implements five independent vulnerability variants across four OWASP categories, each featuring:

- Separate **Vulnerable** and **Secured** execution paths
- Live **Source-Code Inspection** reading real Python lines from disk
- **Side-by-Side Comparison** running the identical payload in both modes
- A persistent **Right-Side Live Execution Observation Panel** streaming real-time, secret-sanitized telemetry
- **Root Cause**, **Alternative Mitigations**, and **Viva Preparation** tabs
- Independent **Reset Demo** controls

## Technology Stack

- **Backend:** Python 3.11+, FastAPI 0.92, Uvicorn, Jinja2, MarkupSafe
- **Database:** SQLite (`sqlite3` built-in)
- **Frontend:** Responsive dark-slate cybersecurity UI (HTML5, CSS3, Fetch API)
- **Testing:** `unittest` + Starlette/FastAPI `TestClient` (`httpx`)

## Installation & Setup

```bash
# 1. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) Copy environment template
cp .env.example .env
```

## Database Initialization & Running Locally

The SQLite database (`data/cybersec_lab.db`) is automatically initialized and seeded on startup:

```bash
python3 run.py
```

Open your browser at **http://127.0.0.1:8000** (restricted to `127.0.0.1` by default for academic safety).

## Five Vulnerability Modules

| # | Category | Selected Variant | Route | Implemented Mitigation |
|---|---|---|---|---|
| 1 | SQL Injection | Authentication Bypass | `/modules/sqli-auth` | Parameterized Queries (`?` placeholders) |
| 2 | Cross-Site Scripting (XSS) | Stored XSS | `/modules/xss-stored` | Context-Aware Output Encoding on Render |
| 3 | Cross-Site Scripting (XSS) | Reflected XSS | `/modules/xss-reflected` | Context-Aware HTML Output Encoding |
| 4 | OS Command Injection | In-Band (Command Output Returned) | `/modules/cmd-injection` | Allow-List Validation + `shell=False` Argument Vector |
| 5 | Cross-Site Request Forgery (CSRF) | GET-Based Forged Action | `/modules/csrf-get` | Reject State-Changing GET + POST Synchronizer CSRF Token |

## Running Automated Tests

```bash
python3 -m unittest discover -s tests -v
```
