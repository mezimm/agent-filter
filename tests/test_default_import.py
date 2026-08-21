"""Default-list import: shared loader, schema migration, and panel flow."""

import http.client
import http.server
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from argon2 import PasswordHasher

from approval_broker import db, validation
from approval_broker.config import Config
from approval_broker.panel import Handler, PanelApp

REPO = os.path.join(os.path.dirname(__file__), "..")
PASSWORD = "correct horse"

LIST_BODY = """\
# comment line
example.org          # inline comment
docs.example.org
sub.deep.example.net 8443
"""


def write_list(tmp, body=LIST_BODY, name="default-allowlist.txt"):
    path = os.path.join(tmp, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    return path


def make_config(tmp, list_path):
    return Config(
        {
            "paths": {
                "db": os.path.join(tmp, "broker.db"),
                "decisions_log": os.path.join(tmp, "decisions.log"),
                "tld_list": os.path.join(REPO, "data", "tlds.txt"),
                "blocked_domains": os.path.join(REPO, "data", "blocked-domains.txt"),
                "default_allowlist": list_path,
            }
        }
    )


class ImportListFile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.conn = db.open_db(os.path.join(self.tmp, "broker.db"))
        self.tlds = validation.load_tlds(os.path.join(REPO, "data", "tlds.txt"))
        self.blocked = validation.load_blocked(
            os.path.join(REPO, "data", "blocked-domains.txt")
        )
        self.psl = validation.load_psl(
            os.path.join(REPO, "data", "public-suffix-list.dat")
        )

    def load(self, body=LIST_BODY):
        path = write_list(self.tmp, body)
        return db.import_list_file(self.conn, path, self.tlds, self.blocked,
                                   self.psl, "operator", "default",
                                   "default list")

    def test_import_adds_permanent_entries_with_source_default(self):
        added, skipped = self.load()
        self.assertEqual((added, skipped), (3, 0))
        ts = db.now()
        row = db.active_match(self.conn, "docs.example.org", 443, ts)
        self.assertEqual(row["source"], "default")
        self.assertEqual(row["scope"], "permanent")
        self.assertIsNone(row["expires_at"])
        # www folding happens at the trust boundaries, not in the db layer:
        # only the bare form is stored and matched here.
        self.assertIsNotNone(db.active_match(self.conn, "example.org", 443, ts))
        self.assertIsNone(db.active_match(self.conn, "www.example.org", 443, ts))
        self.assertIsNotNone(
            db.active_match(self.conn, "sub.deep.example.net", 8443, ts)
        )

    def test_reimport_is_idempotent(self):
        self.load()
        added, skipped = self.load()
        self.assertEqual(added, 0)
        self.assertEqual(skipped, 3)

    def test_existing_active_entry_is_skipped_not_duplicated(self):
        db.add_allowlist(self.conn, "docs.example.org", "exact", 443,
                         "operator", "permanent", None, "manual")
        added, skipped = self.load()
        self.assertEqual((added, skipped), (2, 1))
        rows = self.conn.execute(
            "SELECT COUNT(*) AS n FROM allowlist WHERE pattern = 'docs.example.org'"
        ).fetchone()
        self.assertEqual(rows["n"], 1)

    def test_blocked_domain_aborts_with_nothing_imported(self):
        with self.assertRaises(ValueError) as caught:
            self.load(LIST_BODY + "vpn.tailscale.com\n")
        self.assertIn("line 5", str(caught.exception))
        count = self.conn.execute("SELECT COUNT(*) AS n FROM allowlist").fetchone()
        self.assertEqual(count["n"], 0)

    def test_wildcard_line_refused(self):
        with self.assertRaises(ValueError):
            self.load("*.example.org\n")

    def test_invalid_hostname_names_the_line(self):
        with self.assertRaises(ValueError) as caught:
            self.load("example.org\nnot..valid\n")
        self.assertIn("line 2", str(caught.exception))

    def test_revoke_by_source_spares_other_sources(self):
        self.load()
        db.add_allowlist(self.conn, "keep.example.com", "exact", 443,
                         "operator", "permanent", None, "manual")
        ts = db.now()
        removed = db.revoke_by_source(self.conn, "default", ts)
        self.assertEqual(removed, 3)  # the 3 listed entries
        self.assertEqual(db.active_count_by_source(self.conn, "default", ts + 1), 0)
        self.assertIsNotNone(
            db.active_match(self.conn, "keep.example.com", 443, ts + 1)
        )

    def test_shipped_default_list_imports_cleanly(self):
        path = os.path.join(REPO, "data", "default-allowlist.txt")
        added, skipped = db.import_list_file(
            self.conn, path, self.tlds, self.blocked, self.psl,
            "operator", "default", "default list",
        )
        self.assertEqual(skipped, 0)
        self.assertGreaterEqual(added, 1000)


class SourceCheckMigration(unittest.TestCase):
    def test_old_check_constraint_is_rebuilt(self):
        # A 0.1.x database whose source CHECK lacks 'default' must be rebuilt
        # on open, keeping legacy rows, so an in-place upgrade can import.
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "old.db")
        old = sqlite3.connect(path)
        old.execute(
            "CREATE TABLE allowlist (id INTEGER PRIMARY KEY, pattern TEXT NOT NULL,"
            " kind TEXT NOT NULL CHECK (kind IN ('exact', 'wildcard')),"
            " port INTEGER NOT NULL, created_at INTEGER NOT NULL,"
            " created_by TEXT NOT NULL, expires_at INTEGER,"
            " scope TEXT NOT NULL DEFAULT 'permanent',"
            " source TEXT NOT NULL CHECK (source IN ('approval', 'manual', 'starter')),"
            " note TEXT, group_id INTEGER, consumed_at INTEGER)"
        )
        old.execute(
            "INSERT INTO allowlist (pattern, kind, port, created_at, created_by,"
            " scope, source) VALUES ('old.example.com', 'exact', 443, 1, 'legacy',"
            " 'permanent', 'starter')"
        )
        old.commit()
        old.close()

        conn = db.open_db(path)
        ts = db.now()
        self.assertIsNotNone(db.active_match(conn, "old.example.com", 443, ts))
        ids = db.add_allowlist(conn, "docs.example.org", "exact", 443,
                               "operator", "permanent", None, "default")
        self.assertTrue(ids)
        self.assertEqual(db.active_count_by_source(conn, "default", ts), 1)


class PanelDefaultImport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.list_path = write_list(self.tmp)
        self.cfg = make_config(self.tmp, self.list_path)
        self.app = PanelApp(self.cfg)
        db.set_setting(self.app.conn, "panel_password_hash",
                       PasswordHasher().hash(PASSWORD))
        Handler.app = self.app
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()

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
        cookie = response.getheader("Set-Cookie").split(";")[0]
        token = cookie.split("=", 1)[1]
        return cookie, self.app.session_for(token)["csrf"]

    def test_add_page_offers_import_with_count(self):
        cookie, _ = self.login()
        _, body = self.request("GET", "/add", cookie=cookie)
        self.assertIn("Load the whole catalog (3 hosts)", body)
        self.assertNotIn("Remove all imported", body)

    def test_import_then_remove_via_panel(self):
        cookie, csrf = self.login()
        response, _ = self.request("POST", "/import-defaults",
                                   {"csrf": csrf}, cookie=cookie)
        self.assertEqual(response.status, 303)
        ts = db.now()
        self.assertEqual(db.active_count_by_source(self.app.conn, "default", ts), 3)
        _, body = self.request("GET", "/add", cookie=cookie)
        self.assertIn("Remove all catalog entries (3 active)", body)
        events = [r["event"] for r in db.recent_events(self.app.conn)]
        self.assertIn("default_import", events)

        response, _ = self.request("POST", "/remove-defaults",
                                   {"csrf": csrf}, cookie=cookie)
        self.assertEqual(response.status, 303)
        self.assertEqual(
            db.active_count_by_source(self.app.conn, "default", db.now() + 1), 0
        )
        events = [r["event"] for r in db.recent_events(self.app.conn)]
        self.assertIn("default_remove", events)

    def test_import_requires_csrf(self):
        cookie, _ = self.login()
        response, _ = self.request("POST", "/import-defaults",
                                   {"csrf": "wrong"}, cookie=cookie)
        self.assertEqual(response.status, 403)
        self.assertEqual(
            db.active_count_by_source(self.app.conn, "default", db.now()), 0
        )

    def test_missing_file_reports_error_not_crash(self):
        os.remove(self.list_path)
        cookie, csrf = self.login()
        response, body = self.request("POST", "/import-defaults",
                                      {"csrf": csrf}, cookie=cookie)
        self.assertEqual(response.status, 200)
        self.assertIn("no default list file", body)
        _, body = self.request("GET", "/add", cookie=cookie)
        self.assertIn("No catalog file is installed", body)

    def test_bad_file_reports_line_and_imports_nothing(self):
        with open(self.list_path, "a", encoding="utf-8") as fh:
            fh.write("derp.ts.net\n")
        cookie, csrf = self.login()
        response, body = self.request("POST", "/import-defaults",
                                      {"csrf": csrf}, cookie=cookie)
        self.assertEqual(response.status, 200)
        self.assertIn("default list rejected", body)
        self.assertEqual(
            db.active_count_by_source(self.app.conn, "default", db.now()), 0
        )


if __name__ == "__main__":
    unittest.main()


class MergeWwwRows(unittest.TestCase):
    """Upgrade path: databases from before the canonical fold carry www rows."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.conn = db.open_db(os.path.join(self.tmp, "broker.db"))
        self.psl = validation.load_psl(
            os.path.join(REPO, "data", "public-suffix-list.dat")
        )

    def _insert(self, pattern, kind="exact", port=443):
        cur = self.conn.execute(
            "INSERT INTO allowlist (pattern, kind, port, created_at,"
            " created_by, expires_at, scope, source) VALUES"
            " (?, ?, ?, ?, 'test', NULL, 'permanent', 'manual')",
            (pattern, kind, port, db.now()),
        )
        self.conn.commit()
        return cur.lastrowid

    def test_twin_deleted_lone_renamed_zones_and_wildcards_kept(self):
        self._insert("pair.com")
        twin = self._insert("www.pair.com")
        lone = self._insert("www.lonely.org")
        wild = self._insert("www.keepwild.com", kind="wildcard")
        zone = self._insert("www.co.uk")
        db.merge_www_rows(self.conn, self.psl)
        rows = {
            r["id"]: r["pattern"]
            for r in self.conn.execute("SELECT id, pattern FROM allowlist")
        }
        self.assertNotIn(twin, rows)
        self.assertEqual(rows[lone], "lonely.org")
        self.assertEqual(rows[wild], "www.keepwild.com")
        self.assertEqual(rows[zone], "www.co.uk")
        # Idempotent: a second run changes nothing.
        db.merge_www_rows(self.conn, self.psl)
        again = {
            r["id"]: r["pattern"]
            for r in self.conn.execute("SELECT id, pattern FROM allowlist")
        }
        self.assertEqual(again, rows)
