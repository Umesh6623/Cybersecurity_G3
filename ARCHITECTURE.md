# System Architecture

## 1. Directory Structure

- `run.py`: Localhost-only (`127.0.0.1:8000`) launcher that initializes SQLite and starts Uvicorn.
- `app/main.py`: FastAPI application mounting static assets, Jinja2 templates, all five module routers, documentation viewer (`/docs/{doc_name}`), and live log API (`/api/logs/{module_key}`).
- `app/config.py`: Course metadata, configurable group member declarations, and localhost/database paths.
- `app/db.py`: SQLite schema creation, deterministic seeding, and per-module reset helpers.
- `app/logger.py`: Thread-safe in-memory ring-buffer `LiveEventLogger` with automatic redaction of passwords, hashes, and session/CSRF tokens.
- `app/source_inspector.py`: Reads actual `.py` files between `# [SOURCE_INSPECT:*]` markers so the UI displays live code and line numbers.
- `app/modules/*.py`: Five independent FastAPI `APIRouter` modules.

## 2. Backend / Frontend Interaction

1. Each module renders a Jinja2 template extending `templates/base.html` with a persistent right-side Observation Panel (`templates/partials/observation_panel.html`).
2. User actions (form submissions or `fetch()` calls) hit the module's endpoint with `mode=vulnerable` or `mode=secured`.
3. The backend executes either the vulnerable or mitigated function, records structured events to `event_logger`, and returns the rendered HTML or JSON response.
4. `static/js/app.js` polls `/api/logs/{module_key}` after actions and renders categorized, expandable technical telemetry.

## 3. Database Design (`data/cybersec_lab.db`)

- `sqli_users (id, username, password_hash, role, full_name, department)` — Module 1 simulated accounts.
- `stored_comments (id, author, title, content, created_at)` — Module 2 persistent advisory board posts.
- `csrf_accounts (username, full_name, balance)` & `csrf_transactions (id, from_user, to_user, amount, method, mode, origin_label, created_at)` — Module 5 wallet state and audit trail.

## 4. Live Logging & Secret Sanitization Workflow

Every log entry passes through `sanitize_dict()` in `app/logger.py`. Keys matching `password`, `password_hash`, `secret`, `token`, `cookie`, or `authorization` are replaced with `***REDACTED***`, and 64-character hex hashes are masked as `***HASH_REDACTED***`.
