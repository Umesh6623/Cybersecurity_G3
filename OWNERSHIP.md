# Group Ownership Declaration (Table 3)

**Institute:** Indian Institute of Information Technology Allahabad  
**Course:** Cyber Security (IT-30001) | Autumn Semester 2026  
**Instructor:** Dr. Soumyadev Maity

| Member | Name | Roll Number | Vulnerability Category | Selected Variant | Module File & Route | Individual Responsibility |
|---|---|---|---|---|---|---|
| **Member 1** | Shankar | IIT2024079 | SQL Injection | Authentication Bypass | `app/modules/sqli_auth.py` (`/modules/sqli-auth`) | Vulnerable string-concatenated SQL login, authentication bypass demo, parameterized query mitigation, session/reset controls, and SQLi viva theory. |
| **Member 2** | Milan | IIT2024053 | Cross-Site Scripting (XSS) | Stored XSS | `app/modules/xss_stored.py` (`/modules/xss-stored`) | SQLite-backed discussion board, persistent XSS across page refreshes, render-time HTML escaping mitigation, and data reset. |
| **Member 3** | Umesh | IIT2024080 | Cross-Site Scripting (XSS) | Reflected XSS | `app/modules/xss_reflected.py` (`/modules/xss-reflected`) | GET-based search reflection, unescaped `Markup` exploit demo, context-aware HTML output encoding mitigation, and XSS theory. |
| **Member 4** | Pranav | IIT2024048 | OS Command Injection | In-Band (Command Output Returned) | `app/modules/cmd_injection.py` (`/modules/cmd-injection`) | Local host diagnostic tool, `shell=True` in-band command injection with safety guardrail, allow-list + `shell=False` argument-vector mitigation. |
| **Member 5** | Mast Ram | IIT2024067 | Cross-Site Request Forgery (CSRF) | GET-Based Forged Action | `app/modules/csrf_get.py` (`/modules/csrf-get`) | Simulated wallet & session context, separate attacker webpage, state-changing GET exploit, HTTP 405 GET rejection + POST Synchronizer Anti-CSRF Token. |
