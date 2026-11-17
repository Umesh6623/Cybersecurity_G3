"""Module 2 (Member 2): Cross-Site Scripting (XSS) — Stored XSS."""

from datetime import datetime
from typing import Any, Dict, List
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape

from app.config import BASE_DIR, COURSE_INFO, GROUP_MEMBERS
from app.db import get_connection, reset_module_db
from app.logger import event_logger
from app.source_inspector import get_module_source_pair

router = APIRouter(prefix="/modules/xss-stored", tags=["Module 2: Stored XSS"])
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

MODULE_KEY = "xss-stored"
MEMBER_INFO = GROUP_MEMBERS[1]

EXAMPLE_PAYLOADS = [
    {
        "label": "Persistent IMG Onerror Payload",
        "title": "Lab Feedback Note",
        "content": '<img src="x" onerror="window.labXssNotify(\'Stored XSS Executed on Page Load!\')">',
        "description": "Stored in SQLite and triggers automatically every time any user loads or refreshes the discussion board.",
    },
    {
        "label": "Persistent SVG Onload Payload",
        "title": "Course Review",
        "content": '<svg onload="window.labXssNotify(\'Persistent SVG XSS!\')">',
        "description": "Persists an inline SVG event handler in the database.",
    },
    {
        "label": "Benign Discussion Post (Control)",
        "title": "Input Validation Note",
        "content": "Always encode untrusted user content before rendering in HTML templates.",
        "description": "Clean comment stored and displayed safely in both modes.",
    },
]

ALTERNATIVE_MITIGATIONS = [
    {
        "name": "Context-Aware Output Encoding",
        "status": "IMPLEMENTED",
        "idea": "Escape stored database content with HTML entity encoding (< -> &lt;, > -> &gt;) at render time before inserting into the HTML response.",
        "why_effective": "Even if malicious markup is already saved in the database, encoding at render time prevents the browser from interpreting it as executable HTML/JS.",
    },
    {
        "name": "Framework Auto-Escaping",
        "status": "THEORETICAL",
        "idea": "Use template engines (Jinja2 default autoescape, React JSX) that automatically escape every interpolated database field.",
        "why_effective": "Protects all rendered views consistently without relying on manual escape() calls on every field.",
    },
    {
        "name": "HTML Sanitization (for Rich Text)",
        "status": "THEORETICAL",
        "idea": "If users need rich formatting (Markdown/HTML), sanitize stored HTML with an allow-list library (DOMPurify / Bleach) removing scripts and event attributes.",
        "why_effective": "Allows safe formatting tags while stripping all active script execution vectors.",
    },
    {
        "name": "Content Security Policy (CSP)",
        "status": "THEORETICAL",
        "idea": "Enforce strict script-src 'self' headers to block inline scripts and eval() even if stored markup bypasses encoding.",
        "why_effective": "Provides browser-enforced execution containment as defense-in-depth.",
    },
    {
        "name": "HttpOnly Cookies",
        "status": "THEORETICAL",
        "idea": "Mark authentication cookies HttpOnly so injected scripts cannot access document.cookie.",
        "why_effective": "Reduces impact by preventing direct session token theft via stored scripts.",
    },
    {
        "name": "Safe DOM Sinks",
        "status": "THEORETICAL",
        "idea": "When rendering stored JSON comments via JavaScript, assign text via element.textContent rather than element.innerHTML.",
        "why_effective": "Avoids client-side HTML re-parsing of stored strings.",
    },
]

VIVA_QA = [
    {
        "q": "How does Stored XSS differ from Reflected XSS?",
        "a": "In Reflected XSS, the payload is part of a single HTTP request and echoed back only in that response. In Stored XSS, the payload is persisted in the server's database and executes automatically for every user who later loads or refreshes the page—no crafted link is needed.",
    },
    {
        "q": "Why should XSS mitigation happen at output rendering rather than only stripping tags on input?",
        "a": "Data stored in a database might be rendered in multiple contexts (HTML, JSON, CSV, mobile app), and naive input stripping can break legitimate text (like 'a < b') or be bypassed. Context-aware output encoding at render time guarantees safety in the exact output context.",
    },
    {
        "q": "Why does refreshing the page still trigger Stored XSS?",
        "a": "Because the malicious payload was committed to the SQLite 'stored_comments' table; every subsequent GET request queries those rows and renders them into the DOM.",
    },
]


def _has_xss_syntax(text: str) -> bool:
    lower = text.lower()
    return any(tok in lower for tok in ("<script", "<img", "<svg", "onerror=", "onload=", "javascript:", "<iframe"))


def _fetch_comments() -> List[Dict[str, Any]]:
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT id, author, title, content, created_at FROM stored_comments ORDER BY id DESC"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# [SOURCE_INSPECT:VULNERABLE_START]
def render_comments_vulnerable(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """VULNERABLE: Stored database rows are marked safe and rendered unescaped."""
    rendered = []
    for row in rows:
        # FLAW: Markup() bypasses HTML escaping on persistent database content
        rendered.append(
            {
                **row,
                "rendered_title": Markup(row["title"]),
                "rendered_content": Markup(row["content"]),
                "raw_html_snippet": row["content"],
            }
        )
    return rendered
# [SOURCE_INSPECT:VULNERABLE_END]


# [SOURCE_INSPECT:SECURED_START]
def render_comments_secured(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """SECURED: Context-aware HTML output encoding applied when rendering stored rows."""
    rendered = []
    for row in rows:
        # SAFE: escape() neutralizes stored HTML/JS tags into literal text entities
        safe_title = escape(row["title"])
        safe_content = escape(row["content"])
        rendered.append(
            {
                **row,
                "rendered_title": safe_title,
                "rendered_content": safe_content,
                "raw_html_snippet": str(safe_content),
            }
        )
    return rendered
# [SOURCE_INSPECT:SECURED_END]


@router.get("", response_class=HTMLResponse)
async def stored_xss_page(request: Request, mode: str = "vulnerable"):
    mode = mode if mode in ("vulnerable", "secured") else "vulnerable"
    rows = _fetch_comments()
    comments = render_comments_vulnerable(rows) if mode == "vulnerable" else render_comments_secured(rows)
    source_code = get_module_source_pair("xss_stored.py")

    stored_xss_count = sum(1 for r in rows if _has_xss_syntax(r["content"]) or _has_xss_syntax(r["title"]))
    if stored_xss_count > 0:
        if mode == "vulnerable":
            event_logger.log(
                MODULE_KEY,
                "EXPLOIT_SUCCESS",
                "Stored XSS Rendered from Database on Page Load",
                f"Loaded {len(rows)} persisted comment(s) ({stored_xss_count} containing active XSS payload) without output encoding.",
                mode=mode,
                details={"stored_xss_posts": stored_xss_count},
            )
        else:
            event_logger.log(
                MODULE_KEY,
                "MITIGATION_BLOCKED",
                "Stored XSS Neutralized on Render",
                f"Loaded {len(rows)} persisted comment(s) ({stored_xss_count} containing XSS syntax). HTML entity encoding rendered them as inert text.",
                mode=mode,
                details={"stored_xss_posts": stored_xss_count},
            )

    resp = templates.TemplateResponse(
        "modules/xss_stored.html",
        {
            "request": request,
            "course": COURSE_INFO,
            "member": MEMBER_INFO,
            "module_key": MODULE_KEY,
            "mode": mode,
            "comments": comments,
            "example_payloads": EXAMPLE_PAYLOADS,
            "alternatives": ALTERNATIVE_MITIGATIONS,
            "viva_qa": VIVA_QA,
            "source_code": source_code,
        },
    )
    if mode == "secured":
        resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@router.post("/submit")
async def stored_xss_submit(
    request: Request,
    author: str = Form("Student Demo"),
    title: str = Form("Security Observation"),
    content: str = Form(""),
    mode: str = Form("vulnerable"),
):
    mode = mode if mode in ("vulnerable", "secured") else "vulnerable"
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    event_logger.log(
        MODULE_KEY,
        "HTTP_REQ",
        "Comment Submission Received",
        f"POST /modules/xss-stored/submit in {mode.upper()} mode",
        mode=mode,
        method="POST",
        endpoint="/modules/xss-stored/submit",
        params={"author": author, "title": title, "content": content, "mode": mode},
        payload=content,
    )

    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO stored_comments (author, title, content, created_at) VALUES (?, ?, ?, ?)",
            (author.strip() or "Anonymous", title.strip() or "Untitled", content, created_at),
        )
        conn.commit()
    finally:
        conn.close()

    event_logger.log(
        MODULE_KEY,
        "DB_OP",
        "Comment Persisted to SQLite",
        "Inserted new row into 'stored_comments' table. Payload will persist across page refreshes.",
        mode=mode,
        payload=content,
    )

    is_json = "application/json" in request.headers.get("accept", "") or request.headers.get("x-requested-with") == "fetch"
    if is_json:
        return JSONResponse({"ok": True, "mode": mode})
    return RedirectResponse(url=f"/modules/xss-stored?mode={mode}", status_code=303)


@router.post("/compare")
async def stored_compare(content: str = Form('<img src="x" onerror="window.labXssNotify(\'Stored XSS\')">')):
    sample = [{"id": 999, "author": "Demo", "title": "Comparison Post", "content": content, "created_at": "Now"}]
    vuln = render_comments_vulnerable(sample)[0]
    sec = render_comments_secured(sample)[0]
    event_logger.log(
        MODULE_KEY,
        "INFO",
        "Side-by-Side Comparison Executed",
        "Compared unescaped stored rendering vs HTML-escaped rendering.",
        payload=content,
    )
    return {
        "payload": content,
        "vulnerable": {"raw_html": str(vuln["rendered_content"]), "encoded": False},
        "secured": {"raw_html": sec["raw_html_snippet"], "encoded": True},
    }


@router.post("/browser-event")
async def stored_browser_event(payload: str = Form(""), mode: str = Form("vulnerable")):
    event_logger.log(
        MODULE_KEY,
        "BROWSER_EXEC",
        "Persistent Browser Execution Confirmed",
        "Browser executed stored XSS payload during page render/refresh.",
        mode=mode,
        payload=payload,
    )
    return {"ok": True}


@router.post("/reset")
async def stored_reset():
    reset_module_db(MODULE_KEY)
    event_logger.clear_logs(MODULE_KEY)
    event_logger.log(MODULE_KEY, "INFO", "Module Reset", "Cleared user-submitted comments and restored initial seeded board.")
    return JSONResponse({"ok": True, "message": "Module 2 reset complete."})
