# Viva Preparation Guide (IT-30001)

## 1. SQL Injection (Authentication Bypass)
- **Root Cause:** String concatenation mixes SQL control syntax with untrusted user input.
- **Implemented Mitigation:** Parameterized queries (`cursor.execute("... WHERE username = ? AND password_hash = ?", (u, h))`).
- **Theoretical Alternatives:**
  1. **Allow-List Input Validation:** Restrict usernames to `^[a-zA-Z0-9_]{3,20}$` before querying.
  2. **Least-Privilege DB Accounts:** Grant only required `SELECT`/`INSERT` permissions to the web app DB user.
  3. **Safe Error Handling:** Return generic login errors to users; log detailed SQL exceptions privately.
- **Key Viva Q:** *Why doesn't escaping quotes suffice?* Character encoding edge cases and numeric contexts can bypass naive escaping; prepared statements separate code from data at the driver level.

## 2. Reflected & Stored XSS
- **Root Cause:** Untrusted input is inserted into `text/html` without HTML entity encoding, causing the browser to parse data as executable DOM/JavaScript.
- **Reflected vs. Stored:** Reflected XSS echoes a single request's parameter immediately; Stored XSS persists in the database and runs automatically for every user who loads/refreshes the page.
- **Implemented Mitigation:** Context-aware HTML output encoding (`markupsafe.escape()`).
- **Theoretical Alternatives:**
  1. **Framework Auto-Escaping** (Jinja2/React default escaping)
  2. **HTML Sanitization** (DOMPurify/Bleach for rich text)
  3. **Content Security Policy (CSP)** (`script-src 'self'` blocks inline scripts)
  4. **HttpOnly Cookies** (blocks `document.cookie` theft)
  5. **Safe DOM Sinks** (`element.textContent` instead of `innerHTML`)

## 3. OS Command Injection (In-Band)
- **Root Cause:** Passing user-concatenated strings to `subprocess.run(..., shell=True)` invokes `/bin/sh -c`, which interprets `;`, `&&`, and `|` as command separators.
- **Implemented Mitigation:** Allow-list validation (`{'localhost', '127.0.0.1'}`) + argument-vector execution (`shell=False`).
- **Theoretical Alternatives:** Avoiding the shell, Parameterized execution with argument vectors, Allow-list validation, Least privilege OS user.

## 4. CSRF (GET-Based Forged Action)
- **Root Cause:** Server mutates state on `GET` without proof of intent while the browser automatically attaches ambient session cookies.
- **Implemented Mitigation:** Reject state-changing `GET` (HTTP 405) + require `POST` with session-bound Synchronizer Anti-CSRF Token.
- **Theoretical Alternatives:** Synchronizer anti-CSRF tokens, `SameSite` cookies (`Lax`/`Strict`), Re-authentication for sensitive actions, Avoiding state-changing GET requests.
- **Key Viva Q:** *Cross-Origin vs. Cross-Site?* Origin = `(scheme, host, port)`; Site = `(scheme, eTLD+1)`. Subdomains are cross-origin yet same-site, and `SameSite=Lax` still sends cookies on top-level cross-site `GET` links.
