# Group Video Demonstration Script (2–3 Minutes per Member)

## Member 1 — Shankar (IIT2024079): SQL Injection (Authentication Bypass) [~2.5 min]
1. **Intro:** State name, roll number, and variant (SQL Injection – Authentication Bypass).
2. **Vulnerable Code:** Open *Source-Code Inspection* tab and highlight `authenticate_vulnerable()` using f-string concatenation.
3. **Exploit:** In *Vulnerable Mode*, click `Comment-Out Password Check` (`admin' -- `) and execute login. Point out the protected admin dashboard and `EXPLOIT_SUCCESS` in the right-side Observation Panel.
4. **Root Cause:** Explain how `'` closes the literal and `--` comments out the password check.
5. **Mitigation:** Switch to *Secured Mode*, submit the exact same `admin' -- ` payload, and show `ACCESS DENIED` + `MITIGATION_BLOCKED`.
6. **Theory:** Briefly summarize Allow-List Validation, Least-Privilege DB Accounts, and Safe Error Handling.

## Member 2 — Milan (IIT2024053): Reflected XSS [~2.5 min]
1. **Intro:** State name, roll number, and variant (Reflected XSS).
2. **Vulnerable Code:** Show `render_search_vulnerable()` using `Markup()` without escaping.
3. **Exploit:** Submit `<img src="invalid" onerror="window.labXssNotify('Reflected XSS Executed!')">` via `GET` in *Vulnerable Mode*. Show the execution banner and `BROWSER_EXEC` log.
4. **Root Cause:** Explain why unescaped `GET` input in `text/html` is parsed as active DOM markup.
5. **Mitigation:** Switch to *Secured Mode* with the same payload; show it rendered literally as text (`MITIGATION_BLOCKED`).
6. **Theory:** Summarize the XSS defense alternatives.

## Member 3 — Umesh (IIT2024080): Stored XSS [~2.5 min]
1. **Intro:** State name, roll number, and variant (Stored XSS).
2. **Vulnerable Code:** Show `render_comments_vulnerable()` rendering SQLite rows via `Markup()`.
3. **Exploit:** Submit the persistent `<img>` payload, then click **Refresh Page** to prove persistence from SQLite.
4. **Root Cause & Difference:** Contrast Stored XSS (persisted in DB, affects every visitor) with Reflected XSS (single request/response).
5. **Mitigation:** Switch to *Secured Mode* and refresh; show the stored payload rendered safely as text. Click **Clear Demo Data**.
6. **Theory:** Summarize Framework Auto-Escaping, HTML Sanitization, CSP, HttpOnly Cookies, and Safe DOM Sinks.

## Member 4 — Pranav (IIT2024048): OS Command Injection (In-Band) [~2.5 min]
1. **Intro:** State name, roll number, and variant (OS Command Injection – In-Band).
2. **Vulnerable Code:** Show `run_diagnostic_vulnerable()` using `shell=True`.
3. **Exploit:** Submit `localhost; id` in *Vulnerable Mode* and highlight the returned `uid=...` output and duration in the Observation Panel.
4. **Root Cause:** Explain `/bin/sh -c` interpreting `;` as a command separator.
5. **Mitigation:** Switch to *Secured Mode*, submit `localhost; id`, and show `ValidationError` (`MITIGATION_BLOCKED`) + `shell=False` argument vector.
6. **Theory:** Summarize Avoiding the Shell, Argument Vectors, Allow-Lists, and Least Privilege.

## Member 5 — Mast Ram (IIT2024067): CSRF (GET-Based Forged Action) [~2.5 min]
1. **Intro:** State name, roll number, and variant (CSRF – GET-Based Forged Action).
2. **Vulnerable Code:** Show `csrf_vulnerable_get_transfer()` mutating balance on `GET`.
3. **Exploit:** Note victim balance (₹10,000.00), open the **Simulated Attacker Page**, click the deceptive voucher link, and show balance dropping to ₹9,750.00.
4. **Root Cause:** Explain ambient session cookies + state-changing `GET` + Cross-Origin vs. Cross-Site.
5. **Mitigation:** Switch to *Secured Mode*, trigger the forged `GET` (blocked with HTTP 405), then submit a legitimate transfer using the **POST + Synchronizer Anti-CSRF Token** form.
6. **Theory:** Summarize Synchronizer Tokens, `SameSite` Cookies, Re-authentication, and Avoiding State-Changing GETs.
