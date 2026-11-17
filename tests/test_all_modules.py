"""Comprehensive automated tests for all five vulnerability modules, routes, logs, and resets."""

import re
import unittest
from fastapi.testclient import TestClient

from app.db import init_db
from app.main import app


class TestWebSecurityLab(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        init_db()
        cls.client = TestClient(app)

    def test_01_navigation_and_docs_routes(self):
        for route in [
            "/",
            "/health",
            "/modules/sqli-auth",
            "/modules/xss-reflected",
            "/modules/xss-stored",
            "/modules/cmd-injection",
            "/modules/csrf-get",
            "/modules/csrf-get/attacker",
            "/docs/README.md",
            "/docs/OWNERSHIP.md",
            "/docs/ARCHITECTURE.md",
            "/docs/DEMONSTRATION_GUIDE.md",
            "/docs/VIVA_PREPARATION.md",
            "/docs/VIDEO_SCRIPT.md",
        ]:
            res = self.client.get(route)
            self.assertEqual(res.status_code, 200, f"Route failed: {route}")

    def test_01b_payload_presets_render_valid_event_handlers(self):
        """Payload chips must preserve JSON strings inside their HTML attributes."""
        expected_handlers = {
            "/modules/sqli-auth": 'onclick=\'document.getElementById("sqli-user").value=',
            "/modules/xss-reflected": 'onclick=\'document.getElementById("xss-ref-input").value=',
            "/modules/xss-stored": 'onclick=\'document.getElementById("xss-st-title").value=',
            "/modules/cmd-injection": 'onclick=\'document.getElementById("cmd-target").value=',
        }
        for route, handler_start in expected_handlers.items():
            res = self.client.get(route)
            self.assertIn(handler_start, res.text, f"Preset handler is malformed on {route}")

    def test_02_sqli_auth_bypass_and_mitigation(self):
        self.client.post("/modules/sqli-auth/reset")

        # Vulnerable mode: authentication bypass without valid password
        res_vuln = self.client.post(
            "/modules/sqli-auth/login",
            data={"username": "admin' -- ", "password": "wrong_password", "mode": "vulnerable"},
            headers={"Accept": "application/json"},
        )
        self.assertEqual(res_vuln.status_code, 200)
        data_vuln = res_vuln.json()
        self.assertTrue(data_vuln["authenticated"])
        self.assertTrue(data_vuln["bypassed"])
        self.assertEqual(data_vuln["user"]["username"], "admin")

        # Secured mode: exact same payload must fail
        res_sec = self.client.post(
            "/modules/sqli-auth/login",
            data={"username": "admin' -- ", "password": "wrong_password", "mode": "secured"},
            headers={"Accept": "application/json"},
        )
        self.assertEqual(res_sec.status_code, 200)
        data_sec = res_sec.json()
        self.assertFalse(data_sec["authenticated"])

        # Valid credentials work in secured mode
        res_valid = self.client.post(
            "/modules/sqli-auth/login",
            data={"username": "alice", "password": "AlicePass!99", "mode": "secured"},
            headers={"Accept": "application/json"},
        )
        self.assertTrue(res_valid.json()["authenticated"])

        # Verify no raw password appears in live logs
        logs = self.client.get("/api/logs/sqli-auth").json()["logs"]
        logs_str = str(logs)
        self.assertNotIn("wrong_password", logs_str)
        self.assertNotIn("AlicePass!99", logs_str)
        self.assertIn("***REDACTED***", logs_str)

    def test_03_reflected_xss_and_mitigation(self):
        self.client.post("/modules/xss-reflected/reset")
        payload = '<img src="invalid" onerror="window.labXssNotify(\'ReflectedXSS\')">'

        # Vulnerable mode reflects raw unescaped payload
        res_vuln = self.client.get("/modules/xss-reflected", params={"q": payload, "mode": "vulnerable"})
        self.assertEqual(res_vuln.status_code, 200)
        self.assertIn(f"<strong>{payload}</strong>", res_vuln.text)

        # Secured mode escapes HTML entities
        res_sec = self.client.get("/modules/xss-reflected", params={"q": payload, "mode": "secured"})
        self.assertEqual(res_sec.status_code, 200)
        self.assertNotIn(f"<strong>{payload}</strong>", res_sec.text)
        self.assertIn("&lt;img src=", res_sec.text)

    def test_04_stored_xss_persistence_mitigation_and_reset(self):
        self.client.post("/modules/xss-stored/reset")
        payload = '<img src="x" onerror="window.labXssNotify(\'StoredXSS\')">'

        # Submit persistent payload
        res_sub = self.client.post(
            "/modules/xss-stored/submit",
            data={"author": "Tester", "title": "Stored Test", "content": payload, "mode": "vulnerable"},
            headers={"Accept": "application/json"},
        )
        self.assertEqual(res_sub.status_code, 200)

        # Vulnerable render outputs unescaped payload on subsequent GET (persistence)
        res_vuln = self.client.get("/modules/xss-stored", params={"mode": "vulnerable"})
        self.assertIn(payload, res_vuln.text)

        # Secured render escapes persisted payload
        res_sec = self.client.get("/modules/xss-stored", params={"mode": "secured"})
        self.assertNotIn(payload, res_sec.text)
        self.assertIn("&lt;img src=", res_sec.text)

        # Reset clears submitted payload
        self.client.post("/modules/xss-stored/reset")
        res_after_reset = self.client.get("/modules/xss-stored", params={"mode": "vulnerable"})
        self.assertNotIn(payload, res_after_reset.text)

    def test_05_cmd_injection_inband_guardrail_and_mitigation(self):
        self.client.post("/modules/cmd-injection/reset")

        # Vulnerable mode executes chained 'id' in-band
        res_vuln = self.client.post(
            "/modules/cmd-injection/run",
            data={"target": "localhost; id", "mode": "vulnerable"},
            headers={"Accept": "application/json"},
        )
        self.assertEqual(res_vuln.status_code, 200)
        data_vuln = res_vuln.json()["result"]
        self.assertTrue(data_vuln["injected"])
        self.assertIn("uid=", data_vuln["stdout"])

        # Lab safety guardrail blocks destructive/unapproved commands even in vulnerable mode
        res_guard = self.client.post(
            "/modules/cmd-injection/run",
            data={"target": "localhost; cat /etc/passwd", "mode": "vulnerable"},
            headers={"Accept": "application/json"},
        )
        self.assertEqual(res_guard.json()["result"]["status"], "sandbox_blocked")

        # Secured mode rejects 'localhost; id' via allow-list
        res_sec = self.client.post(
            "/modules/cmd-injection/run",
            data={"target": "localhost; id", "mode": "secured"},
            headers={"Accept": "application/json"},
        )
        data_sec = res_sec.json()["result"]
        self.assertEqual(data_sec["status"], "rejected")
        self.assertNotIn("uid=", data_sec["stdout"])

        # Benign target works in secured mode
        res_ok = self.client.post(
            "/modules/cmd-injection/run",
            data={"target": "localhost", "mode": "secured"},
            headers={"Accept": "application/json"},
        )
        self.assertEqual(res_ok.json()["result"]["status"], "executed")
        self.assertIn("localhost", res_ok.json()["result"]["stdout"])

    def test_06_csrf_get_forged_action_and_mitigation(self):
        self.client.post("/modules/csrf-get/reset")

        # Load victim page to obtain session cookie + CSRF token
        page = self.client.get("/modules/csrf-get", params={"mode": "vulnerable"})
        self.assertEqual(page.status_code, 200)
        m = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
        self.assertIsNotNone(m)
        csrf_token = m.group(1)

        # Vulnerable mode: forged GET mutates balance (10000 -> 9750)
        res_forged = self.client.get(
            "/modules/csrf-get/transfer",
            params={"to": "attacker_acct", "amount": "250", "mode": "vulnerable"},
            headers={"Accept": "application/json"},
        )
        self.assertEqual(res_forged.status_code, 200)
        victim_bal = res_forged.json()["state"]["victim"]["balance"]
        self.assertAlmostEqual(victim_bal, 9750.0)

        # Secured mode: forged GET is rejected with HTTP 405
        res_blocked = self.client.get(
            "/modules/csrf-get/transfer",
            params={"to": "attacker_acct", "amount": "250", "mode": "secured"},
            headers={"Accept": "application/json"},
        )
        self.assertEqual(res_blocked.status_code, 405)

        # Secured POST without CSRF token is rejected with HTTP 403
        res_no_tok = self.client.post(
            "/modules/csrf-get/transfer-secure",
            data={"to": "campus_cafeteria", "amount": "100", "csrf_token": "invalid", "mode": "secured"},
            headers={"Accept": "application/json"},
        )
        self.assertEqual(res_no_tok.status_code, 403)

        # Secured POST with valid CSRF token succeeds (9750 -> 9650)
        res_valid_post = self.client.post(
            "/modules/csrf-get/transfer-secure",
            data={"to": "campus_cafeteria", "amount": "100", "csrf_token": csrf_token, "mode": "secured"},
            headers={"Accept": "application/json"},
        )
        self.assertEqual(res_valid_post.status_code, 200)
        self.assertAlmostEqual(res_valid_post.json()["state"]["victim"]["balance"], 9650.0)

        # Reset restores 10000.0
        self.client.post("/modules/csrf-get/reset")
        page_reset = self.client.get("/modules/csrf-get")
        self.assertIn("10000.00", page_reset.text)


if __name__ == "__main__":
    unittest.main()
