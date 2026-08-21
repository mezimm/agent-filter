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
from approval_broker.panel import (
    LOGIN_MAX_FAILURES, TS_CLI_CANDIDATES, Handler, PanelApp, serve,
)

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
        csrf = self.app.session_for(token)["csrf"]
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

    def test_session_cookie_lasts_thirty_days_by_default(self):
        response, _ = self.request("POST", "/login", {"password": PASSWORD})
        self.assertIn("Max-Age=%d" % (30 * 86400),
                      response.getheader("Set-Cookie"))

    def test_session_survives_panel_restart(self):
        cookie, _ = self.login()
        # A fresh PanelApp over the same database is what a service restart
        # or a reboot produces; the phone's cookie must still be good.
        restarted = PanelApp(self.cfg, conn=db.open_db(self.cfg.get("paths", "db")))
        token = cookie.split("=", 1)[1]
        self.assertIsNotNone(restarted.session_for(token))

    def test_expired_session_is_refused_and_swept(self):
        cookie, _ = self.login()
        token = cookie.split("=", 1)[1]
        self.app.conn.execute(
            "UPDATE panel_sessions SET expires_at = ? WHERE token_hash = ?",
            (db.now() - 1, db._session_key(token)),
        )
        self.app.conn.commit()
        self.assertIsNone(self.app.session_for(token))
        response, _ = self.request("GET", "/", cookie=cookie)
        self.assertEqual(response.status, 303)
        self.login()  # the next login sweeps expired rows
        gone = self.app.conn.execute(
            "SELECT 1 FROM panel_sessions WHERE token_hash = ?",
            (db._session_key(token),),
        ).fetchone()
        self.assertIsNone(gone)

    def test_tokens_are_stored_hashed(self):
        cookie, _ = self.login()
        token = cookie.split("=", 1)[1]
        stored = [r[0] for r in self.app.conn.execute(
            "SELECT token_hash FROM panel_sessions")]
        self.assertNotIn(token, stored)
        self.assertIn(db._session_key(token), stored)

    def test_logout_removes_session_everywhere(self):
        cookie, csrf = self.login()
        token = cookie.split("=", 1)[1]
        response, _ = self.request("POST", "/logout", {"csrf": csrf}, cookie)
        self.assertEqual(response.status, 303)
        self.assertIn("Max-Age=0", response.getheader("Set-Cookie"))
        self.assertIsNone(self.app.session_for(token))

    def test_password_change_signs_every_device_out(self):
        first, _ = self.login()
        second, _ = self.login()
        db.clear_sessions(self.app.conn)  # what brokerctl set-password does
        for cookie in (first, second):
            response, _ = self.request("GET", "/", cookie=cookie)
            self.assertEqual(response.status, 303)

    def test_pages_are_mobile_ready(self):
        # A viewport meta is what stops phones rendering the page at desktop
        # width and shrinking it to a thumbnail; every page shares one shell.
        for path, cookie in (("/login", None), ("/", self.login()[0])):
            _, body = self.request("GET", path, cookie=cookie)
            self.assertIn('name="viewport"', body)
            self.assertIn('content="width=device-width, initial-scale=1"', body)
            self.assertIn('<html lang="en">', body)
        response, css = self.request("GET", "/style.css")
        self.assertIn("text/css", response.getheader("Content-Type"))
        self.assertIn("@media (max-width:", css)
        self.assertIn("prefers-color-scheme: dark", css)

    def test_nav_marks_current_page_and_pending_count(self):
        cookie, csrf = self.login()
        self.request("POST", "/add", {"csrf": csrf, "scope": "permanent",
                                      "pattern": "labelled.example.com"}, cookie)
        _, body = self.request("GET", "/allowlist", cookie=cookie)
        self.assertIn('<a href="/allowlist" class="active" aria-current="page">',
                      body)
        self.assertNotIn('<a href="/" class="active"', body)
        # Tables carry their header in every cell so the narrow-screen
        # layout can label the stacked rows.
        self.assertIn('data-label="Pattern"', body)

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


class PanelListIO(PanelHarness):
    """Export, paste-import, erase-with-confirm, and the description field."""

    def test_add_with_description_shows_in_allowlist(self):
        cookie, csrf = self.login()
        response, _ = self.request("POST", "/add", {
            "csrf": csrf, "pattern": "described.example.com",
            "scope": "permanent", "note": "A described service",
        }, cookie)
        self.assertEqual(response.status, 303)
        _, body = self.request("GET", "/allowlist?q=described", cookie=cookie)
        self.assertIn("A described service", body)
        self.assertIn(">you<", body)

    def test_export_is_plain_text_with_descriptions(self):
        cookie, csrf = self.login()
        self.request("POST", "/add", {
            "csrf": csrf, "pattern": "exported.example.com",
            "scope": "permanent", "note": "for export",
        }, cookie)
        response, body = self.request("GET", "/export", cookie=cookie)
        self.assertEqual(response.status, 200)
        self.assertIn("text/plain", response.getheader("Content-Type"))
        self.assertIn("attachment", response.getheader("Content-Disposition"))
        self.assertIn("exported.example.com 443  # for export", body)

    def test_import_reports_rejects_and_requires_csrf(self):
        cookie, csrf = self.login()
        response, _ = self.request("POST", "/import", {
            "csrf": "wrong", "text": "x.example.com\n"}, cookie)
        self.assertNotEqual(response.status, 200)
        response, body = self.request("POST", "/import", {
            "csrf": csrf,
            "text": "imported.example.com 443  # pasted\n*.bulk.example.com\n",
        }, cookie)
        self.assertEqual(response.status, 200)
        self.assertIn("Added <strong>1</strong>", body)
        self.assertIn("rejected <strong>1</strong>", body)
        self.assertIn("Add form", body)

    def test_erase_confirms_then_empties(self):
        cookie, csrf = self.login()
        self.request("POST", "/add", {
            "csrf": csrf, "pattern": "victim.example.com",
            "scope": "permanent", "note": "",
        }, cookie)
        response, body = self.request("POST", "/erase",
                                      {"csrf": csrf}, cookie)
        self.assertEqual(response.status, 200)
        self.assertIn("Erase the entire allowlist?", body)
        response, _ = self.request("POST", "/erase-confirm",
                                   {"csrf": csrf}, cookie)
        self.assertEqual(response.status, 303)
        self.assertEqual(db.count_allowlist(self.app.conn, db.now()), 0)

    def test_source_filter_in_page(self):
        cookie, csrf = self.login()
        self.request("POST", "/add", {
            "csrf": csrf, "pattern": "userentry.example.com",
            "scope": "permanent", "note": "",
        }, cookie)
        _, body = self.request("GET", "/allowlist?src=user", cookie=cookie)
        self.assertIn("userentry.example.com", body)
        _, body = self.request("GET", "/allowlist?src=default", cookie=cookie)
        self.assertNotIn("userentry.example.com", body)


class ResolveBindIP(unittest.TestCase):
    """bind_ip 'auto' resolves through the tailscale CLI, CGNAT-validated."""

    @staticmethod
    def _runner(stdout="", returncode=0, raises=None):
        calls = []

        def run(args, **kwargs):
            calls.append(args)
            if raises:
                raise raises
            class R:
                pass
            r = R()
            r.returncode = returncode
            r.stdout = stdout
            return r
        run.calls = calls
        return run

    def test_literal_passes_through_without_cli(self):
        from approval_broker.panel import resolve_bind_ip
        runner = self._runner()
        self.assertEqual(resolve_bind_ip("100.1.2.3", runner), "100.1.2.3")
        self.assertEqual(runner.calls, [])

    def test_auto_returns_cgnat_address(self):
        from approval_broker.panel import resolve_bind_ip
        runner = self._runner(stdout="100.101.102.103\nfd7a::1\n")
        self.assertEqual(resolve_bind_ip("auto", runner), "100.101.102.103")

    def test_auto_refuses_non_tailscale_address(self):
        from approval_broker.panel import resolve_bind_ip
        runner = self._runner(stdout="192.168.1.5\n")
        with self.assertRaises(SystemExit):
            resolve_bind_ip("auto", runner)

    def test_auto_treats_cli_error_text_as_not_running(self):
        # The App Store CLI exits 0 with a sentence when the app is down;
        # that must read as "Tailscale not running", not as a bad address.
        from approval_broker.panel import resolve_bind_ip
        runner = self._runner(
            stdout="The Tailscale GUI failed to start: The operation"
                   " couldn\u2019t be completed. (Tailscale.CLIError error 3.)\n")
        with self.assertRaises(SystemExit) as ctx:
            resolve_bind_ip("auto", runner)
        message = str(ctx.exception)
        self.assertIn("is the Tailscale app running", message)
        self.assertIn("GUI failed to start", message)
        self.assertNotIn("refusing to bind", message)
        # every candidate was tried, none accepted as an address
        self.assertEqual(len(runner.calls), len(TS_CLI_CANDIDATES))

    def test_auto_fails_loudly_when_no_cli_answers(self):
        from approval_broker.panel import resolve_bind_ip
        runner = self._runner(raises=OSError("no such file"))
        with self.assertRaises(SystemExit):
            resolve_bind_ip("auto", runner)

    def test_auto_skips_failing_candidates(self):
        from approval_broker.panel import resolve_bind_ip
        answers = [OSError("missing"), None]

        def run(args, **kwargs):
            step = answers.pop(0)
            if step is not None:
                raise step
            class R:
                returncode = 0
                stdout = "100.64.0.9\n"
            return R()
        self.assertEqual(resolve_bind_ip("auto", run), "100.64.0.9")


class PanelShippedRestore(PanelHarness):
    def test_erase_then_load_shipped_restores_default_list(self):
        import os as _os
        self.app.cfg._data.setdefault("paths", {})["default_allowlist"] = \
            _os.path.join(self.tmp, "default-allowlist.txt")
        base = _os.path.dirname(self.app.cfg.get("paths", "default_allowlist"))
        with open(_os.path.join(base, "starter-allowlist.txt"), "w") as fh:
            fh.write("# Guide hosts\nrestoreme.example.com\n")
        cookie, csrf = self.login()
        self.request("POST", "/erase-confirm", {"csrf": csrf}, cookie)
        self.assertEqual(db.count_allowlist(self.app.conn, db.now()), 0)
        response, _ = self.request("POST", "/load-shipped",
                                   {"csrf": csrf}, cookie)
        self.assertEqual(response.status, 303)
        row = self.app.conn.execute(
            "SELECT source, note FROM allowlist WHERE pattern ="
            " 'restoreme.example.com' AND expires_at IS NULL").fetchone()
        self.assertEqual(row["source"], "starter")
        self.assertEqual(row["note"], "Guide hosts")
