# Step-by-Step Demonstration Guide

Start the application via `python3 run.py` and open **http://127.0.0.1:8000**.

## Module 1: SQL Injection — Authentication Bypass (`/modules/sqli-auth`)
- **Source Location:** `app/modules/sqli_auth.py` (`authenticate_vulnerable` vs. `authenticate_secured`)
- **Payload:** Username = `admin' -- `, Password = `anything`
- **Vulnerable Result:** Query becomes `WHERE username = 'admin' -- ' AND ...`. SQLite ignores the password check and logs in as `admin` (`Administrator`). Observation Panel logs `EXPLOIT_SUCCESS`.
- **Secured Result:** Switch to **Secured Mode** and submit the exact same payload. Parameterized query binds `'admin\' -- '` as a literal string; authentication fails (`MITIGATION_BLOCKED`).

## Module 2: Stored XSS (`/modules/xss-stored`)
- **Source Location:** `app/modules/xss_stored.py` (`render_comments_vulnerable` vs. `render_comments_secured`)
- **Payload:** `<img src="x" onerror="window.labXssNotify('Stored XSS Executed on Page Load!')">`
- **Vulnerable Result:** Submit comment; refresh the page (`window.location.reload()`). Payload persists in SQLite `stored_comments` and executes on every load.
- **Secured Result:** Switch to **Secured Mode** and refresh. Stored payload is HTML-escaped on render and displayed safely as text. Click **Clear Demo Data** to reset.

## Module 3: Reflected XSS (`/modules/xss-reflected`)
- **Source Location:** `app/modules/xss_reflected.py` (`render_search_vulnerable` vs. `render_search_secured`)
- **Payload:** `<img src="invalid" onerror="window.labXssNotify('Reflected XSS Executed!')">`
- **Vulnerable Result:** `GET /modules/xss-reflected?q=...&mode=vulnerable` reflects raw HTML; browser executes `onerror` and displays the execution banner (`EXPLOIT_SUCCESS` + `BROWSER_EXEC`).
- **Secured Result:** Switch to **Secured Mode**. `markupsafe.escape()` encodes `<` and `>` to `&lt;` and `&gt;`; payload renders harmlessly as plain text (`MITIGATION_BLOCKED`).

## Module 4: OS Command Injection — In-Band (`/modules/cmd-injection`)
- **Source Location:** `app/modules/cmd_injection.py` (`run_diagnostic_vulnerable` vs. `run_diagnostic_secured`)
- **Payload:** `localhost; id`
- **Vulnerable Result:** `subprocess.run("getent hosts localhost; id", shell=True)` executes both commands and returns `uid=...` in-band (`EXPLOIT_SUCCESS`).
- **Secured Result:** Switch to **Secured Mode** and submit `localhost; id`. Allow-list validation rejects the input (`MITIGATION_BLOCKED`), and `shell=False` prevents shell invocation.

## Module 5: CSRF — GET-Based Forged Action (`/modules/csrf-get`)
- **Source Location:** `app/modules/csrf_get.py` (`csrf_vulnerable_get_transfer` vs. `csrf_secured_post_transfer`)
- **Payload:** `GET /modules/csrf-get/transfer?to=attacker_acct&amount=250&mode=vulnerable` (via **Open Simulated Attacker Page** or **Simulate Forged GET**)
- **Vulnerable Result:** Victim balance drops from ₹10,000.00 to ₹9,750.00 and `attacker_acct` increases by ₹250.00 (`EXPLOIT_SUCCESS`).
- **Secured Result:** Switch to **Secured Mode** and trigger the same forged GET. Server rejects with **HTTP 405 Method Not Allowed** (`MITIGATION_BLOCKED`). Legitimate transfers succeed via the **POST + Synchronizer Anti-CSRF Token** form.
