"""Spec section 15: panel security, wildcard dialog, and end-to-end flow."""

import http.client
import http.server
import os
import sys
import tempfile
import threading
import unittest
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from argon2 import PasswordHasher

from approval_broker import db
from approval_broker.broker import Broker
from approval_broker.config import Config
from approval_broker.panel import LOGIN_MAX_FAILURES, Handler, PanelApp, serve

REPO = os.path.join(os.path.dirname(__file__), "..")
PASSWORD = "correct horse"


def make_config(tmp):
    return Config(
        {
            "paths": {
                "db": os.path.join(tmp, "broker.db"),
                "decisions_log": os.path.join(tmp, "decisions.log"),
                "tld_list": os.path.join(REPO, "data", "tlds.txt"),
                "blocked_domains": os.path.join(REPO, "data", "blocked-domains.txt"),
                "public_suffix_list": os.path.join(
                    REPO, "data", "public-suffix-list.dat"),
            }
        }
    )


class PanelHarness(unittest.TestCase):
    """One live panel server per test class, backed by a temp database."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.cfg = make_config(cls.tmp)
        cls.app = PanelApp(cls.cfg)
        db.set_setting(cls.app.conn, "panel_password_hash",
                       PasswordHasher().hash(PASSWORD))
        Handler.app = cls.app
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        # The broker shares the same database file, as in production.
        cls.broker = Broker(cls.cfg)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    # -- tiny client -----------------------------------------------------

    def request(self, method, path, body=None, cookie=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        headers = {}
        if body is not None:
            body = urllib.parse.urlencode(body)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if cookie:
            headers["Cookie"] = cookie
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        data = response.read().decode()
        conn.close()
        return response, data

    def login(self):
        response, _ = self.request("POST", "/login", {"password": PASSWORD})
        self.assertEqual(response.status, 303)
        cookie = response.getheader("Set-Cookie").split(";")[0]
        token = cookie.split("=", 1)[1]
        csrf = self.app.sessions[token]["csrf"]
        return cookie, csrf


class PanelSecurity(PanelHarness):
    def test_unauthenticated_refused_on_every_route(self):
        for path in ["/", "/allowlist", "/activity", "/add"]:
            response, _ = self.request("GET", path)
            self.assertEqual(response.status, 303, path)
            self.assertEqual(response.getheader("Location"), "/login")
        for path in ["/decide", "/add", "/add-confirm", "/revoke", "/logout"]:
            response, _ = self.request("POST", path, {})
            self.assertEqual(response.status, 303, path)

    def test_csp_header_on_every_response(self):
        for path in ["/login", "/"]:
            response, _ = self.request("GET", path)
            csp = response.getheader("Content-Security-Policy")
            self.assertIn("default-src 'none'", csp)
            self.assertNotIn("unsafe-inline", csp)

    def test_wrong_password_refused(self):
        response, body = self.request("POST", "/login", {"password": "nope"})
        self.assertEqual(response.status, 200)
        self.assertIn("Wrong password", body)

    def test_session_cookie_flags(self):
        response, _ = self.request("POST", "/login", {"password": PASSWORD})
        set_cookie = response.getheader("Set-Cookie")
        self.assertIn("HttpOnly", set_cookie)
        self.assertIn("SameSite=Strict", set_cookie)
        self.assertNotIn("Secure", set_cookie)  # HTTP over Tailscale by design

    def test_script_rationale_renders_inert(self):
        self.broker.submit(
            {"host": "inert.example.com", "port": 443,
             "reason": "<script>alert(1)</script>"}
        )
        cookie, _ = self.login()
        _, body = self.request("GET", "/", cookie=cookie)
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertIn("&lt;script&gt;", body)
        self.assertIn("UNTRUSTED INPUT", body)

    def test_csrf_required_on_state_changes(self):
        cookie, _ = self.login()
        for path, form in [
            ("/decide", {"req_id": "1", "action": "deny"}),
            ("/add", {"pattern": "x.example.com", "scope": "24h"}),
            ("/revoke", {"entry_id": "1"}),
        ]:
            response, _ = self.request("POST", path, form, cookie=cookie)
            self.assertEqual(response.status, 403, path)

    def test_login_lockout_does_not_block_correct_password(self):
        # An attacker spamming wrong passwords must not lock the operator out.
        for _ in range(LOGIN_MAX_FAILURES + 2):
            self.request("POST", "/login", {"password": "wrong"})
        response, _ = self.request("POST", "/login", {"password": PASSWORD})
        self.assertEqual(response.status, 303)
        self.app.login_failures.clear()

    def test_non_numeric_ids_do_not_crash(self):
        cookie, csrf = self.login()
        for path, form in [
            ("/decide", {"req_id": "abc", "action": "deny", "csrf": csrf}),
            ("/revoke", {"entry_id": "xyz", "csrf": csrf}),
        ]:
            response, _ = self.request("POST", path, form, cookie=cookie)
            self.assertIn(response.status, (303, 400), path)


class Wildcards(PanelHarness):
    def test_manual_wildcard_triggers_dialog(self):
        cookie, csrf = self.login()
        response, body = self.request(
            "POST", "/add",
            {"pattern": "*.zendesk.com", "scope": "24h", "csrf": csrf},
            cookie=cookie,
        )
        self.assertEqual(response.status, 200)
        self.assertIn("approve every subdomain?", body)
        self.assertIn("Can a stranger sign up", body)
        self.assertIn("enter the exact hostname instead", body)
        # zendesk.com is not a PSL zone: no override alarm on this dialog.
        self.assertNotIn("public registration zone", body)

    def test_psl_zone_wildcard_shows_prominent_alarm_and_confirms(self):
        cookie, csrf = self.login()
        response, body = self.request(
            "POST", "/add",
            {"pattern": "*.github.io", "scope": "24h", "csrf": csrf},
            cookie=cookie,
        )
        self.assertEqual(response.status, 200)
        self.assertIn("github.io is a public registration zone", body)
        self.assertIn("recorded in the activity log as an override", body)
        self.assertIn("approve every subdomain?", body)
        response, _ = self.request(
            "POST", "/add-confirm",
            {"pattern": "*.github.io", "typed": "github.io", "scope": "24h",
             "csrf": csrf},
            cookie=cookie,
        )
        self.assertEqual(response.status, 303)
        row = self.app.conn.execute(
            "SELECT COUNT(*) AS n FROM allowlist WHERE pattern = 'github.io'"
            " AND kind = 'wildcard'"
        ).fetchone()
        self.assertEqual(row["n"], 1)

    def test_typed_confirmation_required(self):
        cookie, csrf = self.login()
        response, body = self.request(
            "POST", "/add-confirm",
            {"pattern": "*.zendesk.com", "typed": "wrong.com", "scope": "24h",
             "csrf": csrf},
            cookie=cookie,
        )
        self.assertEqual(response.status, 400)
        self.assertIn("does not match", body)

    def test_confirmed_wildcard_defaults_to_24h(self):
        cookie, csrf = self.login()
        response, _ = self.request(
            "POST", "/add-confirm",
            {"pattern": "*.pypi.org", "typed": "pypi.org", "scope": "24h",
             "csrf": csrf},
            cookie=cookie,
        )
        self.assertEqual(response.status, 303)
        row = self.app.conn.execute(
            "SELECT * FROM allowlist WHERE pattern = 'pypi.org'"
            " AND kind = 'wildcard'"
        ).fetchone()
        self.assertLessEqual(abs(row["expires_at"] - (db.now() + 86400)), 60)

    def test_tailscale_refused_from_every_panel_path(self):
        cookie, csrf = self.login()
        for path, form in [
            ("/add", {"pattern": "tailscale.com", "scope": "24h", "csrf": csrf}),
            ("/add", {"pattern": "*.tailscale.com", "scope": "24h",
                      "csrf": csrf}),
            ("/add-confirm", {"pattern": "*.tailscale.com",
                              "typed": "tailscale.com", "scope": "24h",
                              "csrf": csrf}),
        ]:
            response, body = self.request("POST", path, form, cookie=cookie)
            self.assertIn("DOMAIN_PERMANENTLY_BLOCKED", body, path)
            row = self.app.conn.execute(
                "SELECT COUNT(*) AS n FROM allowlist"
                " WHERE pattern LIKE '%tailscale%'"
            ).fetchone()
            self.assertEqual(row["n"], 0)


class EndToEnd(PanelHarness):
    def test_submit_approve_deny_expire(self):
        cookie, csrf = self.login()

        # Agent requests a new host; it appears in the queue with rationale.
        reply = self.broker.submit(
            {"host": "e2e.example.org", "port": 443, "reason": "needed for X"}
        )
        self.assertEqual(reply["code"], "PENDING")
        _, body = self.request("GET", "/", cookie=cookie)
        self.assertIn("e2e.example.org:443", body)
        self.assertIn("needed for X", body)
        req = [r for r in db.pending_requests(self.app.conn)
               if r["host"] == "e2e.example.org"][0]

        # Approve; the agent's next attempt succeeds.
        response, _ = self.request(
            "POST", "/decide",
            {"req_id": str(req["id"]), "action": "approve", "scope": "session",
             "csrf": csrf},
            cookie=cookie,
        )
        self.assertEqual(response.status, 303)
        self.assertTrue(
            self.broker.acl_check({"host": "e2e.example.org", "port": 443})["allow"]
        )

        # Deny another with a reason; the reason reaches the agent.
        self.broker.submit({"host": "no.example.org", "port": 443})
        req = [r for r in db.pending_requests(self.app.conn)
               if r["host"] == "no.example.org"][0]
        self.request(
            "POST", "/decide",
            {"req_id": str(req["id"]), "action": "deny",
             "reason": "not for this project", "csrf": csrf},
            cookie=cookie,
        )
        reply = self.broker.submit({"host": "no.example.org", "port": 443})
        self.assertEqual(reply["code"], "DENIED_BY_ADMIN")
        self.assertIn("not for this project", reply["message"])
        self.assertFalse(
            self.broker.acl_check({"host": "no.example.org", "port": 443})["allow"]
        )

        # Expire the approval; access stops without any restart.
        self.app.conn.execute(
            "UPDATE allowlist SET expires_at = ? WHERE pattern = 'e2e.example.org'",
            (db.now() - 1,),
        )
        self.app.conn.commit()
        self.assertFalse(
            self.broker.acl_check({"host": "e2e.example.org", "port": 443})["allow"]
        )

    def test_revoke_stops_access(self):
        cookie, csrf = self.login()
        ids = db.add_allowlist(
            self.app.conn, "gone.example.org", "exact", 443, "operator",
            "permanent", None, "manual",
        )
        self.assertTrue(
            self.broker.acl_check({"host": "gone.example.org", "port": 443})["allow"]
        )
        response, _ = self.request(
            "POST", "/revoke", {"entry_id": str(ids[0]), "csrf": csrf},
            cookie=cookie,
        )
        self.assertEqual(response.status, 303)
        self.assertFalse(
            self.broker.acl_check({"host": "gone.example.org", "port": 443})["allow"]
        )

    def test_revoke_covers_www_form(self):
        # A bare domain is one row; the www spelling folds onto it at lookup,
        # so revoking the entry retires both spellings.
        cookie, csrf = self.login()
        ids = db.add_allowlist(
            self.app.conn, "twin.org", "exact", 443, "operator", "permanent",
            None, "manual",
        )
        self.assertEqual(len(ids), 1)
        self.assertTrue(
            self.broker.acl_check({"host": "www.twin.org", "port": 443})["allow"]
        )
        self.request(
            "POST", "/revoke", {"entry_id": str(ids[0]), "csrf": csrf},
            cookie=cookie,
        )
        self.assertFalse(
            self.broker.acl_check({"host": "twin.org", "port": 443})["allow"]
        )
        self.assertFalse(
            self.broker.acl_check({"host": "www.twin.org", "port": 443})["allow"]
        )

    def test_manual_add_folds_www(self):
        status, ids = self.app.manual_add("www.folded.org", "permanent")
        self.assertEqual(status, "added")
        row = self.app.conn.execute(
            "SELECT pattern FROM allowlist WHERE id = ?", (ids[0],)
        ).fetchone()
        self.assertEqual(row["pattern"], "folded.org")
        for spelling in ("folded.org", "www.folded.org"):
            self.assertTrue(
                self.broker.acl_check({"host": spelling, "port": 443})["allow"]
            )

    def test_allowlist_filter_and_pagination(self):
        cookie, _ = self.login()
        for i in range(120):
            db.add_allowlist(
                self.app.conn, "bulk%03d.example.com" % i, "exact", 443,
                "operator", "permanent", None, "manual",
            )
        # Filtered page 1 at the default size of 50: first row present,
        # a row beyond the page absent.
        _, body = self.request("GET", "/allowlist?q=bulk", cookie=cookie)
        self.assertIn("bulk000.example.com", body)
        self.assertNotIn("bulk119.example.com", body)
        self.assertIn("120 matching entries", body)
        # Page 3 of the same filter holds the tail.
        _, body = self.request(
            "GET", "/allowlist?q=bulk&size=50&page=3", cookie=cookie
        )
        self.assertIn("bulk119.example.com", body)
        self.assertNotIn("bulk000.example.com", body)
        # A narrow filter isolates one row and counts it in the singular.
        _, body = self.request("GET", "/allowlist?q=bulk047", cookie=cookie)
        self.assertIn("bulk047.example.com", body)
        self.assertNotIn("bulk048.example.com", body)
        self.assertIn("1 matching entry", body)
        # Bogus parameters fall back to safe defaults rather than erroring.
        response, _ = self.request(
            "GET", "/allowlist?size=999&page=banana", cookie=cookie
        )
        self.assertEqual(response.status, 200)

    def test_pause_enforcement_window(self):
        cookie, csrf = self.login()
        # Unlisted host denied before the pause.
        self.assertFalse(
            self.broker.acl_check({"host": "unlisted-pause.net", "port": 443})["allow"]
        )
        response, _ = self.request(
            "POST", "/pause", {"minutes": "15", "csrf": csrf}, cookie=cookie
        )
        self.assertEqual(response.status, 303)
        # During the pause: valid hosts allowed, blocked domains still refused,
        # disallowed ports still refused.
        reply = self.broker.acl_check({"host": "unlisted-pause.net", "port": 443})
        self.assertEqual(reply, {"allow": True, "code": "PAUSED_ALLOW"})
        self.assertFalse(
            self.broker.acl_check({"host": "tailscale.com", "port": 443})["allow"]
        )
        self.assertFalse(
            self.broker.acl_check({"host": "unlisted-pause.net", "port": 80})["allow"]
        )
        # Banner with the resume control shows on every page.
        _, body = self.request("GET", "/allowlist", cookie=cookie)
        self.assertIn("enforcement is paused", body)
        # Resume closes the gate immediately.
        response, _ = self.request(
            "POST", "/resume", {"csrf": csrf}, cookie=cookie
        )
        self.assertEqual(response.status, 303)
        self.assertFalse(
            self.broker.acl_check({"host": "unlisted-pause.net", "port": 443})["allow"]
        )
        _, body = self.request("GET", "/allowlist", cookie=cookie)
        self.assertNotIn("enforcement is paused", body)
        # Expiry is evaluated live: a window already in the past is closed.
        db.set_setting(self.app.conn, "enforcement_paused_until",
                       str(db.now() - 1))
        self.assertFalse(
            self.broker.acl_check({"host": "unlisted-pause.net", "port": 443})["allow"]
        )
        # Bogus duration is rejected.
        response, _ = self.request(
            "POST", "/pause", {"minutes": "999", "csrf": csrf}, cookie=cookie
        )
        self.assertEqual(response.status, 400)

    def test_enforcement_off_switch(self):
        cookie, csrf = self.login()
        response, _ = self.request(
            "POST", "/pause", {"minutes": "off", "csrf": csrf}, cookie=cookie
        )
        self.assertEqual(response.status, 303)
        # Indefinitely off: unlisted hosts allowed, blocked still refused.
        self.assertTrue(
            self.broker.acl_check({"host": "off-switch-test.net", "port": 443})["allow"]
        )
        self.assertFalse(
            self.broker.acl_check({"host": "tailscale.com", "port": 443})["allow"]
        )
        # The banner names the OFF state and survives (no expiry).
        _, body = self.request("GET", "/", cookie=cookie)
        self.assertIn("enforcement is OFF", body)
        self.assertIn("turned back on", body)
        # The log stamp carries the token the monthly review greps.
        events = [r["detail"] for r in db.recent_events(self.app.conn)
                  if r["event"] == "enforcement_pause"]
        self.assertTrue(any("ENFORCEMENT PAUSE indefinite" in d for d in events))
        # Resume is the ON switch.
        self.request("POST", "/resume", {"csrf": csrf}, cookie=cookie)
        self.assertFalse(
            self.broker.acl_check({"host": "off-switch-test.net", "port": 443})["allow"]
        )

    def test_once_approval_has_expiry_backstop(self):
        cookie, csrf = self.login()
        self.broker.submit({"host": "single.example.org", "port": 443})
        req = [r for r in db.pending_requests(self.app.conn)
               if r["host"] == "single.example.org"][0]
        self.request(
            "POST", "/decide",
            {"req_id": str(req["id"]), "action": "approve", "scope": "once",
             "csrf": csrf},
            cookie=cookie,
        )
        row = self.app.conn.execute(
            "SELECT expires_at FROM allowlist WHERE pattern = 'single.example.org'"
        ).fetchone()
        # Never NULL: an unused 'once' grant must not read as permanent.
        self.assertIsNotNone(row["expires_at"])
        self.assertLessEqual(abs(row["expires_at"] - (db.now() + 3600)), 60)


class ServeGuard(unittest.TestCase):
    def test_serve_refuses_loopback_and_unset(self):
        tmp = tempfile.mkdtemp()
        for bad in [None, "127.0.0.1", "0.0.0.0"]:
            cfg = make_config(tmp)
            cfg._data["panel"] = {"bind_ip": bad}
            with self.subTest(bad=bad):
                with self.assertRaises(SystemExit):
                    serve(cfg)


if __name__ == "__main__":
    unittest.main()
