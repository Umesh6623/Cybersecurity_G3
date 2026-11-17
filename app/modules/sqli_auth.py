"""Module 1 (Member 1): SQL Injection — Authentication Bypass."""

import secrets
from typing import Any, Dict, Optional
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.config import BASE_DIR, COURSE_INFO, GROUP_MEMBERS
from app.db import get_connection, hash_password, reset_module_db
from app.logger import event_logger
from app.source_inspector import get_module_source_pair

router = APIRouter(prefix="/modules/sqli-auth", tags=["Module 1: SQLi Auth Bypass"])
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

MODULE_KEY = "sqli-auth"
MEMBER_INFO = GROUP_MEMBERS[0]

# In-memory simulated session store (never logged)
_SQLI_SESSIONS: Dict[str, Dict[str, Any]] = {}

EXAMPLE_PAYLOADS = [
    {
        "label": "Comment-Out Password Check (Admin Bypass)",
        "username": "admin' -- ",
        "password": "anything",
        "description": "Closes the username string literal and comments out the rest of the WHERE clause, logging in as 'admin' without knowing the password.",
    },
    {
        "label": "Tautology Bypass (' OR '1'='1')",
        "username": "' OR '1'='1' -- ",
        "password": "wrong_password",
        "description": "Makes the WHERE condition always evaluate to TRUE, returning the first user row (admin) from the table.",
    },
    {
        "label": "Valid Credentials (Control Test)",
        "username": "alice",
        "password": "AlicePass!99",
        "description": "Legitimate student account credentials that succeed in both vulnerable and secured modes.",
    },
]

ALTERNATIVE_MITIGATIONS = [
    {
        "name": "Parameterized Queries (Prepared Statements)",
        "status": "IMPLEMENTED",
        "idea": "Separate SQL structure from user-supplied values using placeholders (? or :name). The database driver binds user input strictly as literal scalar data, never as SQL syntax.",
        "why_effective": "Even if input contains quotes (') or comment tokens (--), the SQL parser has already compiled the query AST, so injection cannot alter query logic.",
    },
    {
        "name": "Allow-List Input Validation",
        "status": "THEORETICAL",
        "idea": "Validate usernames against a strict pattern (e.g., ^[a-zA-Z0-9_]{3,20}$) before the database layer is reached, rejecting unexpected characters such as quotes, spaces, or semicolons.",
        "why_effective": "Provides defense-in-depth by dropping malformed payloads early, though it should never replace parameterized queries.",
    },
    {
        "name": "Least-Privilege Database Accounts",
        "status": "THEORETICAL",
        "idea": "Run the web application's database connection with a restricted role that only has SELECT/INSERT permissions on required tables rather than administrative privileges (DROP, ALTER,xp_cmdshell).",
        "why_effective": "Limits the blast radius if an injection flaw exists, preventing schema destruction or privilege escalation.",
    },
    {
        "name": "Safe Error Handling",
        "status": "THEORETICAL",
        "idea": "Return generic authentication failure messages (e.g., 'Invalid credentials') to the client while logging detailed database exceptions only to secure server logs.",
        "why_effective": "Prevents attackers from harvesting table names, column names, and SQL dialect details via error-based reconnaissance.",
    },
]

VIVA_QA = [
    {
        "q": "Why does \"admin' -- \" bypass authentication in the vulnerable query?",
        "a": "The single quote closes the string literal around 'admin', and '--' starts an SQL comment that causes SQLite to ignore the 'AND password_hash = ...' check completely.",
    },
    {
        "q": "Why doesn't escaping single quotes manually guarantee safety?",
        "a": "Manual escaping can miss edge cases (character encodings, numeric contexts without quotes, or backslash handling). Parameterized queries separate code from data at the protocol/driver level.",
    },
    {
        "q": "How does SQLite handle prepared statements under the hood?",
        "a": "sqlite3 compiles the SQL template with '?' placeholders first into bytecode, then binds parameters into registers as typed values—they are never re-parsed as SQL tokens.",
    },
    {
        "q": "What is the difference between Authentication Bypass and UNION-based SQLi?",
        "a": "Authentication Bypass manipulates boolean/comment logic in a login WHERE clause to gain unauthorized session access, whereas UNION-based SQLi appends a second SELECT query to exfiltrate data from other tables.",
    },
]


# [SOURCE_INSPECT:VULNERABLE_START]
def authenticate_vulnerable(username: str, password: str) -> Dict[str, Any]:
    """VULNERABLE: Direct string formatting embeds user input into SQL syntax."""
    pw_hash = hash_password(password)
    # FLAW: User input is concatenated directly into the SQL command string
    query = (
        f"SELECT id, username, role, full_name, department "
        f"FROM sqli_users "
        f"WHERE username = '{username}' AND password_hash = '{pw_hash}'"
    )
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(query)
        row = cur.fetchone()
        return {
            "authenticated": row is not None,
            "user": dict(row) if row else None,
            "executed_query": (
                f"SELECT id, username, role, full_name, department "
                f"FROM sqli_users WHERE username = '{username}' AND password_hash = '***HASH_REDACTED***'"
            ),
            "error": None,
        }
    except Exception as exc:
        return {
            "authenticated": False,
            "user": None,
            "executed_query": (
                f"SELECT id, username, role, full_name, department "
                f"FROM sqli_users WHERE username = '{username}' AND password_hash = '***HASH_REDACTED***'"
            ),
            "error": str(exc),
        }
    finally:
        conn.close()
# [SOURCE_INSPECT:VULNERABLE_END]


# [SOURCE_INSPECT:SECURED_START]
def authenticate_secured(username: str, password: str) -> Dict[str, Any]:
    """SECURED: Parameterized query binds user input strictly as data."""
    pw_hash = hash_password(password)
    query_template = (
        "SELECT id, username, role, full_name, department "
        "FROM sqli_users "
        "WHERE username = ? AND password_hash = ?"
    )
    conn = get_connection()
    try:
        cur = conn.cursor()
        # SAFE: Tuple parameters are bound by sqlite3 driver, never parsed as SQL
        cur.execute(query_template, (username, pw_hash))
        row = cur.fetchone()
        return {
            "authenticated": row is not None,
            "user": dict(row) if row else None,
            "executed_query": f"{query_template}  -- params: ({username!r}, '***HASH_REDACTED***')",
            "error": None,
        }
    finally:
        conn.close()
# [SOURCE_INSPECT:SECURED_END]


def _evaluate_auth(username: str, password: str, mode: str) -> Dict[str, Any]:
    if mode == "vulnerable":
        return authenticate_vulnerable(username, password)
    return authenticate_secured(username, password)


@router.get("", response_class=HTMLResponse)
async def sqli_page(request: Request, mode: str = "vulnerable"):
    session_id = request.cookies.get("sqli_session")
    current_user = _SQLI_SESSIONS.get(session_id) if session_id else None
    source_code = get_module_source_pair("sqli_auth.py")

    return templates.TemplateResponse(
        "modules/sqli_auth.html",
        {
            "request": request,
            "course": COURSE_INFO,
            "member": MEMBER_INFO,
            "module_key": MODULE_KEY,
            "mode": mode if mode in ("vulnerable", "secured") else "vulnerable",
            "current_user": current_user,
            "example_payloads": EXAMPLE_PAYLOADS,
            "alternatives": ALTERNATIVE_MITIGATIONS,
            "viva_qa": VIVA_QA,
            "source_code": source_code,
            "result": None,
            "submitted_username": "",
        },
    )


@router.post("/login")
async def sqli_login(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    mode: str = Form("vulnerable"),
):
    mode = mode if mode in ("vulnerable", "secured") else "vulnerable"
    is_json = "application/json" in request.headers.get("accept", "") or request.headers.get("x-requested-with") == "fetch"

    event_logger.log(
        MODULE_KEY,
        "HTTP_REQ",
        "Login Request Received",
        f"POST /modules/sqli-auth/login in {mode.upper()} mode",
        mode=mode,
        method="POST",
        endpoint="/modules/sqli-auth/login",
        params={"username": username, "password": password, "mode": mode},
        payload=username,
    )

    result = _evaluate_auth(username, password, mode)

    event_logger.log(
        MODULE_KEY,
        "DB_OP",
        "SQLite Query Executed",
        result["executed_query"],
        mode=mode,
        details={"error": result["error"], "row_returned": result["authenticated"]},
    )

    is_injection_syntax = any(tok in username for tok in ("'", "--", "/*", "OR ", "or ", "="))
    session_id: Optional[str] = None

    if result["authenticated"]:
        session_id = secrets.token_hex(16)
        _SQLI_SESSIONS[session_id] = {
            **result["user"],
            "auth_mode": mode,
            "bypassed": mode == "vulnerable" and is_injection_syntax,
        }
        if mode == "vulnerable" and is_injection_syntax:
            event_logger.log(
                MODULE_KEY,
                "EXPLOIT_SUCCESS",
                "Authentication Bypassed via SQL Injection",
                f"Logged in as '{result['user']['username']}' ({result['user']['role']}) without valid password!",
                mode=mode,
                payload=username,
                details={"matched_account": result["user"]["username"], "role": result["user"]["role"]},
            )
        else:
            event_logger.log(
                MODULE_KEY,
                "INFO",
                "Valid Authentication Succeeded",
                f"Authenticated user '{result['user']['username']}' cleanly.",
                mode=mode,
            )
    else:
        if mode == "secured" and is_injection_syntax:
            event_logger.log(
                MODULE_KEY,
                "MITIGATION_BLOCKED",
                "SQL Injection Payload Neutralized",
                "Parameterized query treated the injected SQL syntax as a literal username string. No user matched.",
                mode=mode,
                payload=username,
            )
        elif result["error"]:
            event_logger.log(
                MODULE_KEY,
                "WARNING",
                "SQL Syntax Error",
                f"Malformed SQL triggered database error: {result['error']}",
                mode=mode,
                payload=username,
            )
        else:
            event_logger.log(
                MODULE_KEY,
                "INFO",
                "Authentication Failed",
                "No matching user record found for provided credentials.",
                mode=mode,
            )

    if is_json:
        resp = JSONResponse(
            {
                "ok": True,
                "mode": mode,
                "authenticated": result["authenticated"],
                "user": result["user"],
                "executed_query": result["executed_query"],
                "error": result["error"],
                "bypassed": bool(result["authenticated"] and mode == "vulnerable" and is_injection_syntax),
            }
        )
        if session_id:
            resp.set_cookie("sqli_session", session_id, httponly=True, samesite="lax")
        return resp

    source_code = get_module_source_pair("sqli_auth.py")
    current_user = _SQLI_SESSIONS.get(session_id) if session_id else None
    resp = templates.TemplateResponse(
        "modules/sqli_auth.html",
        {
            "request": request,
            "course": COURSE_INFO,
            "member": MEMBER_INFO,
            "module_key": MODULE_KEY,
            "mode": mode,
            "current_user": current_user,
            "example_payloads": EXAMPLE_PAYLOADS,
            "alternatives": ALTERNATIVE_MITIGATIONS,
            "viva_qa": VIVA_QA,
            "source_code": source_code,
            "result": result,
            "submitted_username": username,
        },
    )
    if session_id:
        resp.set_cookie("sqli_session", session_id, httponly=True, samesite="lax")
    return resp


@router.post("/compare")
async def sqli_compare(username: str = Form("admin' -- "), password: str = Form("anything")):
    """Run the exact same payload in both vulnerable and secured modes for side-by-side comparison."""
    vuln = authenticate_vulnerable(username, password)
    sec = authenticate_secured(username, password)
    event_logger.log(
        MODULE_KEY,
        "INFO",
        "Side-by-Side Comparison Executed",
        f"Tested identical payload across Vulnerable and Secured modes.",
        payload=username,
        details={
            "vulnerable_authenticated": vuln["authenticated"],
            "secured_authenticated": sec["authenticated"],
        },
    )
    return {"payload": username, "vulnerable": vuln, "secured": sec}


@router.post("/logout")
async def sqli_logout(request: Request):
    sid = request.cookies.get("sqli_session")
    if sid and sid in _SQLI_SESSIONS:
        _SQLI_SESSIONS.pop(sid, None)
    event_logger.log(MODULE_KEY, "INFO", "Session Terminated", "User logged out and session cookie cleared.")
    is_json = "application/json" in request.headers.get("accept", "") or request.headers.get("x-requested-with") == "fetch"
    if is_json:
        resp = JSONResponse({"ok": True})
    else:
        resp = RedirectResponse(url="/modules/sqli-auth", status_code=303)
    resp.delete_cookie("sqli_session")
    return resp


@router.post("/reset")
async def sqli_reset(request: Request):
    sid = request.cookies.get("sqli_session")
    if sid:
        _SQLI_SESSIONS.pop(sid, None)
    _SQLI_SESSIONS.clear()
    reset_module_db(MODULE_KEY)
    event_logger.clear_logs(MODULE_KEY)
    event_logger.log(MODULE_KEY, "INFO", "Module Reset", "Restored simulated user accounts and cleared active sessions.")
    resp = JSONResponse({"ok": True, "message": "Module 1 reset complete."})
    resp.delete_cookie("sqli_session")
    return resp
