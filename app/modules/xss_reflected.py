"""Module 3 (Member 2): Cross-Site Scripting (XSS) — Reflected XSS."""

from typing import Any, Dict
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape

from app.config import BASE_DIR, COURSE_INFO, GROUP_MEMBERS
from app.logger import event_logger
from app.source_inspector import get_module_source_pair

router = APIRouter(prefix="/modules/xss-reflected", tags=["Module 3: Reflected XSS"])
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

MODULE_KEY = "xss-reflected"
MEMBER_INFO = GROUP_MEMBERS[1]

EXAMPLE_PAYLOADS = [
    {
        "label": "IMG Onerror DOM Execution",
        "payload": '<img src="invalid" onerror="window.labXssNotify(\'Reflected XSS Executed!\')">',
        "description": "Injects an <img> tag whose error handler immediately executes JavaScript in the victim's browser.",
    },
    {
        "label": "SVG Onload Script Trigger",
        "payload": '<svg onload="window.labXssNotify(\'SVG Reflected XSS!\')">',
        "description": "Uses an inline SVG element's onload event to execute JavaScript without requiring a <script> tag.",
    },
    {
        "label": "Classic Script Tag Alert",
        "payload": "<script>alert('IIITA-Reflected-XSS')</script>",
        "description": "Classic reflected <script> payload returned directly in the HTTP GET response body.",
    },
    {
        "label": "Benign Search Query (Control)",
        "payload": "SQL Injection Mitigation",
        "description": "Normal search term that renders safely in both vulnerable and secured modes.",
    },
]

ALTERNATIVE_MITIGATIONS = [
    {
        "name": "Context-Aware Output Encoding",
        "status": "IMPLEMENTED",
        "idea": "Convert special HTML characters (<, >, &, \", ') into harmless HTML entities (&lt;, &gt;, &amp;, &#34;, &#39;) right before rendering into HTML body context.",
        "why_effective": "The browser's HTML parser treats encoded entities strictly as character data (text nodes), never as executable tags or event-handler attributes.",
    },
    {
        "name": "Framework Auto-Escaping",
        "status": "THEORETICAL",
        "idea": "Rely on modern template engines (Jinja2, React JSX, Angular) that automatically HTML-escape {{ variable }} expressions unless explicitly bypassed with |safe or dangerouslySetInnerHTML.",
        "why_effective": "Eliminates developer forgetfulness by making safe encoding the default behavior across all views.",
    },
    {
        "name": "HTML Sanitization (for Rich Text)",
        "status": "THEORETICAL",
        "idea": "When formatted HTML (bold, links) must be allowed, parse and strip dangerous tags (<script>, <iframe>) and event attributes (onerror, onload) using an allow-list sanitizer like Bleach or DOMPurify.",
        "why_effective": "Permits safe structural markup while removing all scriptable execution vectors.",
    },
    {
        "name": "Content Security Policy (CSP)",
        "status": "THEORETICAL",
        "idea": "Send an HTTP response header (e.g., Content-Security-Policy: default-src 'self'; script-src 'self') restricting which scripts the browser may execute and blocking inline scripts.",
        "why_effective": "Acts as a strong defense-in-depth layer: even if an injection reaches the DOM, the browser refuses to run inline <script> or event handlers.",
    },
    {
        "name": "HttpOnly Cookies",
        "status": "THEORETICAL",
        "idea": "Set the HttpOnly flag on session cookies so client-side JavaScript (document.cookie) cannot read them.",
        "why_effective": "Does not prevent XSS execution itself, but blocks session-hijacking via cookie exfiltration if XSS occurs.",
    },
    {
        "name": "Safe DOM Sinks",
        "status": "THEORETICAL",
        "idea": "Use textContent or innerText instead of dangerous sinks like innerHTML, outerHTML, or document.write() when updating the DOM with client-side JavaScript.",
        "why_effective": "textContent inserts raw strings as text nodes without invoking the HTML parser.",
    },
]

VIVA_QA = [
    {
        "q": "Why does reflected user input become executable browser content?",
        "a": "Because the server embeds unescaped query parameters directly into an HTTP text/html response. The browser's HTML parser cannot distinguish server-authored markup from user-supplied tags like <script> or <img onerror=...>.",
    },
    {
        "q": "How is Reflected XSS typically delivered to a victim?",
        "a": "Via a crafted URL (e.g., ?q=<payload>) sent over email, chat, or a malicious link. When the victim clicks it, the server reflects the payload in the immediate response.",
    },
    {
        "q": "Why must output encoding be context-aware?",
        "a": "HTML body encoding (&lt;) protects against tag injection inside HTML, whereas JavaScript string contexts, URL attributes, and CSS contexts have different delimiters and require context-specific encoding.",
    },
    {
        "q": "Does HttpOnly prevent Reflected XSS?",
        "a": "No. HttpOnly only prevents JavaScript from reading document.cookie; it does not stop injected scripts from executing actions in the victim's browser.",
    },
]

_KNOWLEDGE_BASE = [
    {"title": "OWASP Top 10: Injection", "tag": "A03:2021", "summary": "Untrusted data sent to an interpreter as part of a command or query."},
    {"title": "Context-Aware Output Encoding", "tag": "XSS Defense", "summary": "Neutralizes active HTML/JS syntax at render time."},
    {"title": "HTTP GET Idempotency", "tag": "RFC 9110", "summary": "GET requests must be safe and never trigger state mutations."},
]


# [SOURCE_INSPECT:VULNERABLE_START]
def render_search_vulnerable(query: str) -> Dict[str, Any]:
    """VULNERABLE: Unescaped user input is marked safe and reflected directly into HTML."""
    # FLAW: Markup() disables Jinja2 auto-escaping and reflects raw HTML/JS
    raw_banner_html = Markup(
        f'<div class="search-echo">Showing threat advisory results for: <strong>{query}</strong></div>'
    )
    matches = [item for item in _KNOWLEDGE_BASE if query.lower() in item["title"].lower() or query.lower() in item["summary"].lower()]
    return {
        "rendered_html": raw_banner_html,
        "raw_response_snippet": f'<div class="search-echo">Showing threat advisory results for: <strong>{query}</strong></div>',
        "matches": matches,
        "encoded": False,
    }
# [SOURCE_INSPECT:VULNERABLE_END]


# [SOURCE_INSPECT:SECURED_START]
def render_search_secured(query: str) -> Dict[str, Any]:
    """SECURED: Context-aware HTML output encoding escapes all special characters."""
    # SAFE: escape() converts <, >, &, ", ' into harmless HTML entities
    safe_query = escape(query)
    safe_banner_html = Markup(
        f'<div class="search-echo">Showing threat advisory results for: <strong>{safe_query}</strong></div>'
    )
    matches = [item for item in _KNOWLEDGE_BASE if query.lower() in item["title"].lower() or query.lower() in item["summary"].lower()]
    return {
        "rendered_html": safe_banner_html,
        "raw_response_snippet": f'<div class="search-echo">Showing threat advisory results for: <strong>{safe_query}</strong></div>',
        "matches": matches,
        "encoded": True,
    }
# [SOURCE_INSPECT:SECURED_END]


def _has_xss_syntax(text: str) -> bool:
    lower = text.lower()
    return any(tok in lower for tok in ("<script", "<img", "<svg", "onerror=", "onload=", "javascript:", "<iframe"))


@router.get("", response_class=HTMLResponse)
async def reflected_xss_page(request: Request, q: str = "", mode: str = "vulnerable"):
    mode = mode if mode in ("vulnerable", "secured") else "vulnerable"
    source_code = get_module_source_pair("xss_reflected.py")
    search_result = None

    if q:
        event_logger.log(
            MODULE_KEY,
            "HTTP_REQ",
            "GET Search Request Received",
            f"GET /modules/xss-reflected?q=...&mode={mode}",
            mode=mode,
            method="GET",
            endpoint="/modules/xss-reflected",
            params={"q": q, "mode": mode},
            payload=q,
        )
        search_result = render_search_vulnerable(q) if mode == "vulnerable" else render_search_secured(q)
        xss_detected = _has_xss_syntax(q)

        if mode == "vulnerable" and xss_detected:
            event_logger.log(
                MODULE_KEY,
                "EXPLOIT_SUCCESS",
                "Reflected XSS Payload Injected into HTML Response",
                "Server reflected raw HTML/JavaScript without output encoding. Browser will parse and execute payload.",
                mode=mode,
                payload=q,
                details={"response_snippet": search_result["raw_response_snippet"]},
            )
        elif mode == "secured" and xss_detected:
            event_logger.log(
                MODULE_KEY,
                "MITIGATION_BLOCKED",
                "Reflected XSS Neutralized via HTML Encoding",
                "Special characters (<, >, \", ') were escaped to HTML entities. Browser renders payload as inert text.",
                mode=mode,
                payload=q,
                details={"response_snippet": search_result["raw_response_snippet"]},
            )
        else:
            event_logger.log(
                MODULE_KEY,
                "INFO",
                "Benign Search Rendered",
                f"Displayed search results for '{q}'.",
                mode=mode,
            )

    resp = templates.TemplateResponse(
        "modules/xss_reflected.html",
        {
            "request": request,
            "course": COURSE_INFO,
            "member": MEMBER_INFO,
            "module_key": MODULE_KEY,
            "mode": mode,
            "query_value": q,
            "search_result": search_result,
            "example_payloads": EXAMPLE_PAYLOADS,
            "alternatives": ALTERNATIVE_MITIGATIONS,
            "viva_qa": VIVA_QA,
            "source_code": source_code,
        },
    )
    if mode == "secured":
        resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@router.post("/compare")
async def reflected_compare(q: str = Form('<img src="invalid" onerror="window.labXssNotify(\'Reflected XSS\')">')):
    vuln = render_search_vulnerable(q)
    sec = render_search_secured(q)
    event_logger.log(
        MODULE_KEY,
        "INFO",
        "Side-by-Side Comparison Executed",
        "Compared raw reflection vs HTML entity encoding for the same GET payload.",
        payload=q,
    )
    return {
        "payload": q,
        "vulnerable": {"raw_html": vuln["raw_response_snippet"], "encoded": False},
        "secured": {"raw_html": sec["raw_response_snippet"], "encoded": True},
    }


@router.post("/browser-event")
async def reflected_browser_event(payload: str = Form(""), mode: str = Form("vulnerable")):
    event_logger.log(
        MODULE_KEY,
        "BROWSER_EXEC",
        "Browser JavaScript Execution Confirmed",
        "Client browser DOM confirmed execution of the reflected JavaScript payload.",
        mode=mode,
        payload=payload,
    )
    return {"ok": True}


@router.post("/reset")
async def reflected_reset():
    event_logger.clear_logs(MODULE_KEY)
    event_logger.log(MODULE_KEY, "INFO", "Module Reset", "Cleared Reflected XSS query state and execution logs.")
    return JSONResponse({"ok": True, "message": "Module 3 reset complete."})
