"""FastAPI entrypoint for the IIIT Allahabad Cyber Security (IT-30001) Web Security Lab."""

from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import markdown

from app.config import BASE_DIR, COURSE_INFO, GROUP_MEMBERS
from app.db import init_db
from app.logger import event_logger
from app.modules import cmd_injection, csrf_get, sqli_auth, xss_reflected, xss_stored

app = FastAPI(
    title=COURSE_INFO["project_title"],
    description=COURSE_INFO["assignment"],
    version="1.0.0",
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Register all five independent module routers
app.include_router(sqli_auth.router)
app.include_router(xss_reflected.router)
app.include_router(xss_stored.router)
app.include_router(cmd_injection.router)
app.include_router(csrf_get.router)

ALLOWED_DOCS = {
    "README.md": "Project README & Setup",
    "OWNERSHIP.md": "Group Ownership Declaration",
    "ARCHITECTURE.md": "System Architecture",
    "DEMONSTRATION_GUIDE.md": "Step-by-Step Demo Guide",
    "VIVA_PREPARATION.md": "Viva Preparation Q&A",
    "VIDEO_SCRIPT.md": "Group Video Script",
}


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "course": COURSE_INFO,
            "members": GROUP_MEMBERS,
            "docs": ALLOWED_DOCS,
            "module_key": "dashboard",
        },
    )


@app.get("/docs/{doc_name}", response_class=HTMLResponse)
async def view_doc(request: Request, doc_name: str):
    if doc_name not in ALLOWED_DOCS:
        raise HTTPException(status_code=404, detail="Documentation file not found")
    doc_path = BASE_DIR / doc_name
    if not doc_path.exists():
        raise HTTPException(status_code=404, detail="Documentation file missing on disk")
    raw_md = doc_path.read_text(encoding="utf-8")
    rendered_html = markdown.markdown(raw_md, extensions=["tables", "fenced_code"])
    return templates.TemplateResponse(
        "docs_viewer.html",
        {
            "request": request,
            "course": COURSE_INFO,
            "members": GROUP_MEMBERS,
            "doc_name": doc_name,
            "doc_title": ALLOWED_DOCS[doc_name],
            "doc_html": rendered_html,
            "docs": ALLOWED_DOCS,
            "module_key": "docs",
        },
    )


@app.get("/api/logs/{module_key}")
async def get_module_logs(module_key: str):
    return JSONResponse({"module": module_key, "logs": event_logger.get_logs(module_key)})


@app.post("/api/logs/{module_key}/clear")
async def clear_module_logs(module_key: str):
    event_logger.clear_logs(module_key)
    event_logger.log(module_key, "INFO", "Logs Cleared", "Observation panel logs cleared by demonstrator.")
    return JSONResponse({"ok": True})


@app.get("/health")
async def health():
    return {"status": "ok", "course": COURSE_INFO["course_code"], "localhost_only": True}
