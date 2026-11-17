"""Module 5 (Member 5): Cross-Site Request Forgery (CSRF) — GET-Based Forged Action."""

from datetime import datetime
import secrets
from typing import Any, Dict, List
from fastapi import APIRouter, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.config import BASE_DIR, COURSE_INFO, GROUP_MEMBERS
from app.db import get_connection, reset_module_db
from app.logger import event_logger
from app.source_inspector import get_module_source_pair

router = APIRouter(prefix="/modules/csrf-get", tags=["Module 5: CSRF GET-Based"])
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

MODULE_KEY = "csrf-get"
MEMBER_INFO = GROUP_MEMBERS[4]

# Simulated victim browser session store (CSRF tokens kept server-side, never logged)
_CSRF_SESSIONS: Dict[str, Dict[str, str]] = {}

EXAMPLE_PAYLOADS = [
    {
        "label": "Forged GET Transfer (₹250 to attacker_acct)",
        "to_user": "attacker_acct",
        "amount": 250.0,
        "url": "/modules/csrf-get/transfer?to=attacker_acct&amount=250&mode=vulnerable",
        "description": "State-changing GET URL embedded in an external attacker page (e.g., <img> tag or prize link).",
    },
    {
        "label": "Forged GET Transfer (₹500 to attacker_acct)",
        "to_user": "attacker_acct",
        "amount": 500.0,
        "url": "/modules/csrf-get/transfer?to=attacker_acct&amount=500&mode=vulnerable",
        "description": "Larger forged GET transfer executed silently using the victim's active session cookie.",
    },
]

ALTERNATIVE_MITIGATIONS = [
    {
        "name": "Avoiding State-Changing GET Requests",
        "status": "IMPLEMENTED",
        "idea": "Enforce HTTP semantics: GET requests must be read-only/idempotent. Reject state-changing GET requests (HTTP 405) and require POST for mutations.",
        "why_effective": "Eliminates trivial CSRF vectors via <img>, <link>, or hyperlink navigation.",
    },
    {
        "name": "Synchronizer Anti-CSRF Tokens",
        "status": "IMPLEMENTED",
        "idea": "Generate a cryptographically random token bound to the user's session, embed it in legitimate POST forms, and validate it server-side on submission.",
        "why_effective": "An external attacker site cannot read the victim's secret CSRF token due to the Same-Origin Policy, so forged POSTs fail validation.",
    },
    {
        "name": "SameSite Cookies",
        "status": "THEORETICAL",
        "idea": "Set SameSite=Lax (modern browser default) or SameSite=Strict on session cookies so browsers withhold cookies on cross-site subrequests (<img>, fetch, POST forms).",
        "why_effective": "Prevents the victim's session cookie from being attached to forged cross-site requests. Note: Cross-origin vs cross-site matters—subdomains on the same eTLD+1 site (e.g., evil.example.com -> bank.example.com) are same-site even though cross-origin!",
    },
    {
        "name": "Re-Authentication for Sensitive Actions",
        "status": "THEORETICAL",
        "idea": "Require the user to re-enter their password, PIN, or OTP before executing high-impact state changes such as fund transfers or email changes.",
        "why_effective": "Even if a forged request carries a valid cookie, the attacker cannot supply the fresh credential.",
    },
]

VIVA_QA = [
    {
        "q": "Why does a forged GET request succeed in vulnerable mode?",
        "a": "Because the server accepts state-changing transfers over HTTP GET without proof of user intent, and the victim's browser automatically attaches their active session cookie to requests targeting the application's origin.",
    },
    {
        "q": "What is the difference between Cross-Origin and Cross-Site requests?",
        "a": "Origin is defined by (scheme, host, port). Site is defined by (scheme, eTLD+1 registrable domain). Two subdomains like attacker.iiita.local and bank.iiita.local are cross-origin (different hosts) yet same-site (same registrable domain), so SameSite=Lax cookies may still be sent on top-level GET navigations!",
    },
    {
        "q": "Why isn't SameSite=Lax alone a complete CSRF defense?",
        "a": "SameSite=Lax still sends cookies on top-level cross-site GET navigations (like clicking an <a href='...'> link), which is why state-changing GET endpoints remain vulnerable even in modern browsers!",
    },
    {
        "q": "How does the Synchronizer Token Pattern stop CSRF?",
        "a": "The server ties a random secret token to the victim's session and places it in a hidden form field. A third-party attacker cannot read this token across origins (Same-Origin Policy), so any forged request lacks the valid token and is rejected with 403 Forbidden.",
    },
]


def _ensure_victim_session(request: Request) -> Dict[str, str]:
    sid = request.cookies.get("csrf_victim_session")
    if sid and sid in _CSRF_SESSIONS:
        return {"sid": sid, **_CSRF_SESSIONS[sid], "new": False}
    new_sid = secrets.token_hex(16)
    csrf_tok = secrets.token_urlsafe(24)
    _CSRF_SESSIONS[new_sid] = {"username": "student_victim", "csrf_token": csrf_tok}
    return {"sid": new_sid, "username": "student_victim", "csrf_token": csrf_tok, "new": True}


def _get_wallet_state() -> Dict[str, Any]:
    conn = get_connection()
    try:
        accounts = [dict(r) for r in conn.execute("SELECT username, full_name, balance FROM csrf_accounts ORDER BY username").fetchall()]
        victim = next((a for a in accounts if a["username"] == "student_victim"), None)
        txs = [
            dict(r)
            for r in conn.execute(
                "SELECT id, from_user, to_user, amount, method, mode, origin_label, created_at FROM csrf_transactions ORDER BY id DESC LIMIT 15"
            ).fetchall()
        ]
        return {"accounts": accounts, "victim": victim, "transactions": txs}
    finally:
        conn.close()


def _execute_transfer(from_user: str, to_user: str, amount: float, method: str, mode: str, origin_label: str) -> Dict[str, Any]:
    conn = get_connection()
    try:
        victim = conn.execute("SELECT balance FROM csrf_accounts WHERE username = ?", (from_user,)).fetchone()
        recipient = conn.execute("SELECT balance FROM csrf_accounts WHERE username = ?", (to_user,)).fetchone()
        if not victim or not recipient:
            return {"ok": False, "reason": "Account not found."}
        if amount <= 0 or amount > victim["balance"]:
            return {"ok": False, "reason": "Invalid or insufficient balance."}

        conn.execute("UPDATE csrf_accounts SET balance = balance - ? WHERE username = ?", (amount, from_user))
        conn.execute("UPDATE csrf_accounts SET balance = balance + ? WHERE username = ?", (amount, to_user))
        conn.execute(
            """
            INSERT INTO csrf_transactions (from_user, to_user, amount, method, mode, origin_label, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (from_user, to_user, amount, method, mode, origin_label, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        )
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


# [SOURCE_INSPECT:VULNERABLE_START]
@router.get("/transfer")
async def csrf_vulnerable_get_transfer(
    request: Request,
    to: str = Query("attacker_acct"),
    amount: float = Query(250.0),
    mode: str = Query("vulnerable"),
    source: str = Query("Forged Cross-Site GET"),
):
    """VULNERABLE (when mode='vulnerable'): State-changing GET endpoint accepts transfer without CSRF proof."""
    sess = _ensure_victim_session(request)
    is_json = "application/json" in request.headers.get("accept", "") or request.headers.get("x-requested-with") == "fetch"

    event_logger.log(
        MODULE_KEY,
        "HTTP_REQ",
        "GET Transfer Request Received",
        f"GET /modules/csrf-get/transfer?to={to}&amount={amount}&mode={mode}",
        mode=mode,
        method="GET",
        endpoint="/modules/csrf-get/transfer",
        params={"to": to, "amount": amount, "mode": mode, "source": source},
        payload=f"GET /modules/csrf-get/transfer?to={to}&amount={amount}",
    )

    if mode != "vulnerable":
        # SECURED BEHAVIOR: Reject state-changing GET requests!
        event_logger.log(
            MODULE_KEY,
            "MITIGATION_BLOCKED",
            "State-Changing GET Request Rejected (HTTP 405)",
            "Secured mode enforces HTTP semantics: state-changing transfers are forbidden over GET. Use POST with valid anti-CSRF token.",
            mode="secured",
            payload=f"GET ?to={to}&amount={amount}",
        )
        if is_json:
            return JSONResponse(
                {"ok": False, "blocked": True, "reason": "Method Not Allowed: State-changing GET requests are disabled in Secured mode."},
                status_code=405,
            )
        return HTMLResponse(
            content='''<!DOCTYPE html><html><head><meta charset="UTF-8"><title>405 Blocked</title><link rel="stylesheet" href="/static/css/style.css"></head><body style="display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px;"><div class="card" style="max-width:560px;border-color:var(--sec-border);"><span class="tag tag-sec">HTTP 405 // MITIGATION BLOCKED</span><h2 style="margin-top:10px;">Forged GET Transfer Rejected</h2><p style="color:var(--text-secondary);">Secured mode enforces HTTP semantics: state-changing transfers are forbidden over GET. Legitimate transfers require POST with a valid Synchronizer Anti-CSRF Token.</p><a href="/modules/csrf-get?mode=secured" class="btn btn-primary">Return to Victim Wallet (Secured Mode)</a></div></body></html>''',
            status_code=405,
        )

    # FLAW: Mutates database state on an HTTP GET using only the victim's ambient session cookie
    tx_res = _execute_transfer(sess["username"], to, amount, "GET", "vulnerable", source)
    if tx_res["ok"]:
        event_logger.log(
            MODULE_KEY,
            "EXPLOIT_SUCCESS",
            "Forged GET Transfer Executed via Victim Session",
            f"Transferred ₹{amount:.2f} from '{sess['username']}' to '{to}' without user confirmation or CSRF token.",
            mode="vulnerable",
            payload=f"GET ?to={to}&amount={amount}",
        )

    if is_json:
        resp = JSONResponse({"ok": tx_res["ok"], "mode": "vulnerable", "state": _get_wallet_state()})
    else:
        resp = RedirectResponse(url="/modules/csrf-get?mode=vulnerable&forged=1", status_code=303)
    resp.set_cookie("csrf_victim_session", sess["sid"], httponly=True, samesite="lax")
    return resp
# [SOURCE_INSPECT:VULNERABLE_END]


# [SOURCE_INSPECT:SECURED_START]
@router.post("/transfer-secure")
async def csrf_secured_post_transfer(
    request: Request,
    to: str = Form("campus_cafeteria"),
    amount: float = Form(100.0),
    csrf_token: str = Form(""),
    mode: str = Form("secured"),
):
    """SECURED: Requires HTTP POST + valid session-bound Synchronizer Anti-CSRF Token."""
    sess = _ensure_victim_session(request)
    is_json = "application/json" in request.headers.get("accept", "") or request.headers.get("x-requested-with") == "fetch"

    event_logger.log(
        MODULE_KEY,
        "HTTP_REQ",
        "POST Transfer Request Received",
        f"POST /modules/csrf-get/transfer-secure",
        mode=mode,
        method="POST",
        endpoint="/modules/csrf-get/transfer-secure",
        params={"to": to, "amount": amount, "csrf_token": csrf_token},
    )

    # SAFE: Constant-time comparison of submitted token against server session token
    if not csrf_token or not secrets.compare_digest(csrf_token, sess["csrf_token"]):
        event_logger.log(
            MODULE_KEY,
            "MITIGATION_BLOCKED",
            "Invalid or Missing Anti-CSRF Token (HTTP 403)",
            "Rejected POST transfer because the Synchronizer Anti-CSRF token was missing or did not match the victim's session.",
            mode="secured",
        )
        return JSONResponse({"ok": False, "blocked": True, "reason": "Forbidden: Invalid or missing CSRF token."}, status_code=403)

    tx_res = _execute_transfer(sess["username"], to, amount, "POST", "secured", "Legitimate POST + CSRF Token")
    if tx_res["ok"]:
        event_logger.log(
            MODULE_KEY,
            "INFO",
            "Authenticated POST Transfer Succeeded",
            f"Verified Synchronizer Anti-CSRF token and transferred ₹{amount:.2f} to '{to}'.",
            mode="secured",
        )

    if is_json:
        resp = JSONResponse({"ok": tx_res["ok"], "mode": "secured", "state": _get_wallet_state()})
    else:
        resp = RedirectResponse(url="/modules/csrf-get?mode=secured", status_code=303)
    resp.set_cookie("csrf_victim_session", sess["sid"], httponly=True, samesite="lax")
    return resp
# [SOURCE_INSPECT:SECURED_END]


@router.get("", response_class=HTMLResponse)
async def csrf_page(request: Request, mode: str = "vulnerable", forged: int = 0):
    mode = mode if mode in ("vulnerable", "secured") else "vulnerable"
    sess = _ensure_victim_session(request)
    wallet = _get_wallet_state()
    source_code = get_module_source_pair("csrf_get.py")

    resp = templates.TemplateResponse(
        "modules/csrf_get.html",
        {
            "request": request,
            "course": COURSE_INFO,
            "member": MEMBER_INFO,
            "module_key": MODULE_KEY,
            "mode": mode,
            "victim": wallet["victim"],
            "accounts": wallet["accounts"],
            "transactions": wallet["transactions"],
            "csrf_token": sess["csrf_token"],
            "forged": bool(forged),
            "example_payloads": EXAMPLE_PAYLOADS,
            "alternatives": ALTERNATIVE_MITIGATIONS,
            "viva_qa": VIVA_QA,
            "source_code": source_code,
        },
    )
    resp.set_cookie("csrf_victim_session", sess["sid"], httponly=True, samesite="lax")
    return resp


@router.get("/attacker", response_class=HTMLResponse)
async def csrf_attacker_page(request: Request, mode: str = "vulnerable"):
    """Separate simulated third-party attacker webpage that triggers a forged GET request."""
    mode = mode if mode in ("vulnerable", "secured") else "vulnerable"
    return templates.TemplateResponse(
        "modules/csrf_attacker.html",
        {
            "request": request,
            "course": COURSE_INFO,
            "mode": mode,
        },
    )


@router.post("/compare")
async def csrf_compare():
    event_logger.log(
        MODULE_KEY,
        "INFO",
        "Side-by-Side Comparison Viewed",
        "Compared GET-based state mutation (Vulnerable) vs 405 GET rejection + POST Synchronizer Token (Secured).",
    )
    return {
        "payload": "GET /modules/csrf-get/transfer?to=attacker_acct&amount=250",
        "vulnerable": {"status": "200 OK / 303 Redirect", "mutated_state": True, "reason": "Accepted state change on GET using ambient session cookie."},
        "secured": {"status": "405 Method Not Allowed", "mutated_state": False, "reason": "State-changing GET rejected; legitimate transfers require POST + session CSRF token."},
    }


@router.post("/reset")
async def csrf_reset(request: Request):
    reset_module_db(MODULE_KEY)
    event_logger.clear_logs(MODULE_KEY)
    event_logger.log(MODULE_KEY, "INFO", "Module Reset", "Restored simulated wallet balances (₹10,000.00) and transaction history.")
    return JSONResponse({"ok": True, "message": "Module 5 reset complete."})
